use core::error::Error;

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{BlockHeight, action, bundle, effect, entropy::ActionEntropy, pczt, value};

use super::fixtures::{
    application,
    pool::PoolSim,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pczt_updater_fields_survive_the_mirror() {
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
    let output = output_plan(rng, wallet.random_note(100));
    let plan =
        bundle::Plan::new(vec![spend], vec![output], wallet.random_note(10), vec![]).unwrap();
    let spend_index = plan
        .effects()
        .actions
        .binary_search(&spend.descriptor())
        .unwrap();
    let output_index = plan
        .effects()
        .actions
        .binary_search(&output.descriptor())
        .unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let path = pczt::Zip32Derivation::new([8; 32], vec![0x8000_0001]);
    section
        .update_with(|mut updater| -> Result<(), Box<dyn Error>> {
            updater.set_anchor(anchor);
            updater.set_pak(spend_index, wallet.pak)?;
            updater.set_lineage(
                spend_index,
                pczt::SpendLineage::new(wallet.note_secret(app, note), spendable, vec![]),
            )?;
            updater.set_zip32_derivation(spend_index, path.clone())?;
            updater.set_max_fee_zip32_derivation(path.clone());
            updater.set_user_address(output_index, "recipient".into())?;
            updater.set_proprietary("section".into(), vec![1]);
            updater.set_action_proprietary(spend_index, "action".into(), vec![2])?;
            updater.set_max_fee_proprietary("fee".into(), vec![3]);
            Ok(())
        })
        .unwrap();
    let encoded = section.to_mirror();
    let parsed = pczt::Bundle::parse(encoded.clone()).unwrap();
    assert_eq!(parsed.to_mirror(), encoded);
    assert_eq!(parsed.anchor(), Some(anchor));
    assert_eq!(encoded.proprietary.get("section"), Some(&vec![1]));
    assert_eq!(
        encoded.actions[spend_index].proprietary.get("action"),
        Some(&vec![2])
    );
    assert_eq!(encoded.max_fee.proprietary.get("fee"), Some(&vec![3]));
    assert_eq!(encoded.max_fee.zip32_derivation, Some(path.clone()));
    let Some(pczt::mirror::ActionWitness::Spend(spend_witness)) =
        encoded.actions[spend_index].witness.clone()
    else {
        unreachable!()
    };
    assert!(spend_witness.pak.is_some());
    assert!(spend_witness.lineage.is_some());
    assert_eq!(spend_witness.zip32_derivation.as_ref(), Some(&path));
    let Some(pczt::mirror::ActionWitness::Output(output_witness)) =
        encoded.actions[output_index].witness.clone()
    else {
        unreachable!()
    };
    assert_eq!(output_witness.user_address.as_deref(), Some("recipient"));
}
