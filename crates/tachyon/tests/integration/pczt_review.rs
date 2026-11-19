use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{bundle, pczt};

use super::fixtures::wallet::{WalletSim, output_plan, shared_sk};

#[test]
fn pczt_review_reconstructs_the_plan() {
    let rng = &mut StdRng::seed_from_u64(12);
    let wallet = WalletSim::new(shared_sk());
    let plan = bundle::Plan::new(
        vec![],
        vec![output_plan(rng, wallet.random_note(100))],
        wallet.random_note(10),
        vec![1],
    )
    .unwrap();
    let section = pczt::Bundle::from_plan(&plan);
    section.actions().first().unwrap().verify_opening().unwrap();
    assert_eq!(
        section.plan().unwrap().effects().commitment(),
        plan.effects().commitment()
    );
}
