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
}
