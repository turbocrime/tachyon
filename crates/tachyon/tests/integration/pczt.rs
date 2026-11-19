#![allow(clippy::ref_patterns, reason = "test code")]

use core::{convert::Infallible, error::Error};

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, StrippedStamp, action, bundle, effect, entropy::ActionEntropy, pczt, value,
};

use super::fixtures::{
    application, mock_sighash,
    pool::PoolSim,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pczt_roles_and_redaction_round_trip() {
    let rng = &mut StdRng::seed_from_u64(42);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(1000);
    let spendable = wallet.spendable_init(app, PoolSim::shared(), &note, BlockHeight(1));
    let anchor = spendable.data().2;
    let spend = action::Plan::<effect::Spend> {
        note,
        theta: ActionEntropy::random(rng),
        rcv: value::Trapdoor::random(rng),
        authority: wallet.pak.ak,
    };
    let first = output_plan(rng, wallet.random_note(100));
    let second = output_plan(rng, wallet.random_note(200));
    let plan = bundle::Plan::new(
        vec![spend],
        vec![first, second],
        wallet.random_note(10),
        vec![7],
    )
    .unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let find_index = |desc| plan.effects().actions.binary_search(&desc).unwrap();
    let spend_idx = find_index(spend.descriptor());
    let first_idx = find_index(first.descriptor());
    let second_idx = find_index(second.descriptor());
    let path = pczt::Zip32Derivation::new([8; 32], vec![0x8000_0001]);
    section
        .update_with(|mut updater| -> Result<(), Box<dyn Error>> {
            updater.set_anchor(anchor);
            updater.set_zip32_derivation(first_idx, path.clone())?;
            updater.set_pak(spend_idx, wallet.pak)?;
            updater.set_lineage(
                spend_idx,
                pczt::SpendLineage::new(wallet.note_secret(app, note), spendable, vec![]),
            )?;
            Ok(())
        })
        .unwrap();
    let sighash = mock_sighash(plan.effects().commitment());
    section.finalize_io(sighash, rng).unwrap();
    let base = section.to_mirror();

    let mut compact = base.clone();
    compact.value_balance = None;
    compact.max_fee.cv_feemax = None;
    compact.bsk = None;
    for action in &mut compact.actions {
        action.descriptor = None;
        action.sig = None;
        if let Some(ref mut witness) = action.witness
            && let pczt::mirror::ActionWitness::Spend(ref mut spend_witness) = *witness
        {
            spend_witness.pak = None;
            spend_witness.lineage = None;
        }
    }
    let mut signer = pczt::Bundle::parse(compact).unwrap();
    assert_eq!(
        signer.plan().unwrap().effects().commitment(),
        plan.effects().commitment()
    );
    signer
        .sign_at(spend_idx, sighash, &wallet.sk.derive_auth_private(), rng)
        .unwrap();
    let sig = signer.actions()[spend_idx].sig().unwrap();
    section.apply_signature_at(spend_idx, sighash, sig).unwrap();

    let mut redacted = base.clone();
    redacted.actions[second_idx].note.psi = None;
    let mut layered = pczt::Bundle::parse(redacted).unwrap();
    assert!(matches!(layered.plan(), Err(pczt::ReviewError::Missing(_))));
    layered
        .sign_at(spend_idx, sighash, &wallet.sk.derive_auth_private(), rng)
        .unwrap();
    assert!(layered.actions()[spend_idx].sig().is_some());
    let serialized = layered.to_mirror();
    assert!(serialized.actions[second_idx].note.psi.is_none());
    let preserved = serialized.actions[first_idx]
        .witness
        .as_ref()
        .is_some_and(|witness| {
            matches!(*witness, pczt::mirror::ActionWitness::Output(ref output)
            if output.zip32_derivation.as_ref() == Some(&path))
        });
    assert!(preserved);

    let for_prover = |selected: &[usize]| {
        let mut mirror = base.clone();
        mirror.bsk = None;
        mirror.proprietary.clear();
        mirror.max_fee.note.pk = None;
        mirror.max_fee.note.value = None;
        mirror.max_fee.note.psi = None;
        mirror.max_fee.note.rcm = None;
        mirror.max_fee.zip32_derivation = None;
        mirror.max_fee.proprietary.clear();
        for (index, action) in mirror.actions.iter_mut().enumerate() {
            action.sig = None;
            action.proprietary.clear();
            let own = selected.contains(&index);
            if !own || index == spend_idx {
                action.note.pk = None;
                action.note.value = None;
                action.note.psi = None;
                action.note.rcm = None;
            }
            if !own {
                action.theta = None;
                action.rcv = None;
                action.witness = None;
            }
            if let Some(ref mut witness) = action.witness {
                match *witness {
                    pczt::mirror::ActionWitness::Spend(ref mut spend_fields) => {
                        spend_fields.ak = None;
                        spend_fields.zip32_derivation = None;
                    },
                    pczt::mirror::ActionWitness::Output(ref mut output) => {
                        output.zip32_derivation = None;
                        output.user_address = None;
                    },
                }
            }
        }
        pczt::Bundle::parse(mirror).unwrap()
    };
    let mut prover = for_prover(&[spend_idx]);
    prover.prove_actions(rng, app, &[spend_idx]).unwrap();
    let span = PoolSim::shared().anchor_span(app, BlockHeight(1)..=BlockHeight(2));
    let later = span.data().1;
    prover.lift_actions_proof(0, rng, app, vec![span]).unwrap();
    let mut other = for_prover(&[first_idx, second_idx]);
    prover
        .update_with(|mut updater| {
            updater.set_anchor(later);
            Ok::<_, Infallible>(())
        })
        .unwrap();
    other
        .update_with(|mut updater| {
            updater.set_anchor(later);
            Ok::<_, Infallible>(())
        })
        .unwrap();
    section
        .update_with(|mut updater| {
            updater.set_anchor(later);
            Ok::<_, Infallible>(())
        })
        .unwrap();
    other
        .prove_actions(rng, app, &[first_idx, second_idx])
        .unwrap();
    let combined = prover.combine(other).unwrap();
    let mut complete = section.combine(combined).unwrap();
    complete
        .apply_fee(rng, app, value::Positive::try_from(2u64).unwrap())
        .unwrap();
    let encoded = complete.to_mirror();
    assert_eq!(
        pczt::Bundle::parse(encoded.clone()).unwrap().to_mirror(),
        encoded
    );

    let mut extractor = encoded;
    extractor.actions_proofs.clear();
    extractor.anchor = None;
    extractor.max_fee.note.pk = None;
    extractor.max_fee.note.value = None;
    extractor.max_fee.note.psi = None;
    extractor.max_fee.note.rcm = None;
    for action in &mut extractor.actions {
        action.note.pk = None;
        action.note.value = None;
        action.note.psi = None;
        action.note.rcm = None;
        action.theta = None;
        action.rcv = None;
        action.witness = None;
    }
    let unbound = pczt::Bundle::parse(extractor).unwrap().extract().unwrap();
    let built = unbound.apply_binding_signature(sighash, rng);
    built
        .verify::<_, StrippedStamp>(rng, app, &sighash, &[])
        .unwrap();
}

#[test]
fn pczt_present_actionless_section_needs_stamp() {
    let rng = &mut StdRng::seed_from_u64(37);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let plan = bundle::Plan::new(vec![], vec![], wallet.random_note(0), vec![]).unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let sighash = mock_sighash(section.effects().commitment());
    section.finalize_io(sighash, rng).unwrap();
    assert!(matches!(
        section.clone().extract(),
        Err(pczt::TxExtractorError::Missing(_))
    ));
    section
        .update_with(|mut updater| {
            updater.set_anchor(Anchor::random(rng));
            Ok::<_, Infallible>(())
        })
        .unwrap();
    section.apply_fee(rng, app, value::Positive::ZERO).unwrap();
    let encoded = section.to_mirror();
    let parsed = pczt::Bundle::parse(encoded.clone()).unwrap();
    assert_eq!(parsed.to_mirror(), encoded);
    parsed
        .extract()
        .unwrap()
        .apply_binding_signature(sighash, rng)
        .verify::<_, StrippedStamp>(rng, app, &sighash, &[])
        .unwrap();
}
