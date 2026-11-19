use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{BlockHeight, action, bundle, effect, entropy::ActionEntropy, pczt, value};

use super::fixtures::{
    application,
    pool::PoolSim,
    wallet::{WalletSim, shared_sk},
};

#[test]
fn pczt_proves_lifts_and_reapplies_fee() {
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
    let plan = bundle::Plan::new(vec![spend], vec![], wallet.random_note(10), vec![]).unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let span = PoolSim::shared().anchor_span(app, BlockHeight(1)..=BlockHeight(2));
    let later = span.data().1;
    section
        .update_with(|mut updater| updater.set_pak(0, wallet.pak))
        .unwrap();
    section
        .update_with(|mut updater| {
            updater.set_anchor(anchor);
            updater.set_lineage(
                0,
                pczt::SpendLineage::new(wallet.note_secret(app, note), spendable, vec![]),
            )
        })
        .unwrap();
    section.prove_actions(rng, app, &[0]).unwrap();
    section.lift_actions_proof(0, rng, app, vec![span]).unwrap();
    assert_eq!(section.actions_proofs()[0].anchor, later);
    section.apply_fee(rng, app, value::Positive::ZERO).unwrap();
    let fee = value::Positive::try_from(2u64).unwrap();
    section.apply_fee(rng, app, fee).unwrap();
    let encoded = section.to_mirror();
    let parsed = pczt::Bundle::parse(encoded.clone()).unwrap();
    assert_eq!(parsed.to_mirror(), encoded);
    assert_eq!(parsed.actions_proofs().len(), 1);
    assert_eq!(parsed.autonome_parts().unwrap().fee, fee);
}
