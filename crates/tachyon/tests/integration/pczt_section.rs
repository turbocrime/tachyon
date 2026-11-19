use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::pczt;

use super::fixtures::{
    mock_sighash,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pczt_checked_plan_round_trips_and_retains_signatures() {
    let rng = &mut StdRng::seed_from_u64(12);
    let wallet = WalletSim::new(shared_sk());
    let action = output_plan(rng, wallet.random_note(100));
    let opening = (action.note, action.theta, action.rcv);
    let fee = wallet.random_note(10);
    assert!(matches!(
        pczt::Plan::new(vec![], vec![opening, opening], fee, vec![]),
        Err(pczt::ConstructError::Duplicate)
    ));
    let plan = pczt::Plan::new(vec![], vec![opening], fee, vec![1]).unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let sighash = mock_sighash(plan.effects().commitment());
    section.finalize_io(sighash, rng).unwrap();
    let original = section.to_mirror();
    section.finalize_io(sighash, rng).unwrap();
    assert_eq!(section.to_mirror(), original);
    let mut compact = original;
    compact.actions[0].descriptor = None;
    compact.value_balance = None;
    compact.max_fee.cv_feemax = None;
    let reviewed = pczt::Bundle::parse(compact).unwrap().plan().unwrap();
    assert_eq!(reviewed.effects().commitment(), plan.effects().commitment());
}
