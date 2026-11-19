use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{Anchor, stamp::ActionsPlan, value};

use super::fixtures::{
    application,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pre_fee_proof_supports_fee_replacement() {
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
    let max_fee = wallet.random_note(10);
    let first = proof
        .clone()
        .fee(rng, app, max_fee, value::Positive::ZERO)
        .unwrap();
    let fee = value::Positive::try_from(2u64).unwrap();
    let second = proof.fee(rng, app, max_fee, fee).unwrap();
    assert_eq!(first.pairs, second.pairs);
    assert_eq!(second.fee, fee);
}
