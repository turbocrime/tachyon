use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{Anchor, stamp::ActionsPlan};

use super::fixtures::{
    application,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pre_fee_proof_covers_action() {
    let rng = &mut StdRng::seed_from_u64(12);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let action = output_plan(rng, wallet.random_note(100));
    let anchor = Anchor::random(rng);
    let proof = ActionsPlan::new(
        vec![],
        vec![(action.descriptor(), action.theta, action.note, action.rcv)],
        anchor,
    )
    .prove(rng, app, vec![])
    .unwrap();
    assert_eq!(proof.pairs.len(), 1);
    let pcd = proof.proof.carry::<zcash_tachyon::stamp::proof::stamp::Actions>(anchor);
    assert!(app.verify_uncompressed(&pcd, rng).unwrap());
}

#[test]
fn pre_fee_proofs_lift_and_merge_at_a_common_anchor() {
    use zcash_tachyon::{BlockHeight, stamp::proof::stamp::Actions};

    let rng = &mut StdRng::seed_from_u64(13);
    let app = &application();
    let pool = super::fixtures::pool::PoolSim::shared();
    let span = pool.anchor_span(app, BlockHeight(1)..=BlockHeight(2));
    let from = pool.block(BlockHeight(1)).anchor();
    let to = pool.block(BlockHeight(2)).anchor();
    let wallet = WalletSim::new(shared_sk());
    let first = output_plan(rng, wallet.random_note(101));
    let second = output_plan(rng, wallet.random_note(102));
    let proof = ActionsPlan::new(
        vec![],
        vec![(first.descriptor(), first.theta, first.note, first.rcv)],
        from,
    )
    .prove(rng, app, vec![])
    .unwrap()
    .lift(rng, app, vec![span])
    .unwrap();
    assert_eq!(proof.anchor, to);
    let other = ActionsPlan::new(
        vec![],
        vec![(second.descriptor(), second.theta, second.note, second.rcv)],
        to,
    )
    .prove(rng, app, vec![])
    .unwrap();
    let merged = proof.merge(rng, app, other).unwrap();
    assert_eq!(merged.pairs.len(), 2);
    let pcd = merged.proof.carry::<Actions>(to);
    assert!(app.verify_uncompressed(&pcd, rng).unwrap());
}
