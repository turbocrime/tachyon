use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    action, bundle, effect,
    entropy::ActionEntropy,
    pczt::{
        self,
        mirror::{ActionWitness, ParseError},
    },
    value,
};

use super::fixtures::{
    pool::PoolSim,
    wallet::{WalletSim, shared_sk},
};

#[test]
fn pczt_mirror_round_trips_spend_keys() {
    let rng = &mut StdRng::seed_from_u64(42);
    let wallet = WalletSim::new(shared_sk());
    let spend = action::Plan::<effect::Spend> {
        note: PoolSim::shared_note(1000),
        theta: ActionEntropy::random(rng),
        rcv: value::Trapdoor::random(rng),
        authority: wallet.pak.ak,
    };
    let plan = bundle::Plan::new(vec![spend], vec![], wallet.random_note(10), vec![]).unwrap();
    let mut mirror = pczt::Bundle::from_plan(&plan).to_mirror();
    let Some(ActionWitness::Spend(mut witness)) = mirror.actions[0].witness.take() else {
        unreachable!()
    };
    let owner = witness.ak.unwrap();
    witness.pak = Some([owner, [1; 32]]);
    mirror.actions[0].witness = Some(ActionWitness::Spend(witness.clone()));
    assert_eq!(
        pczt::Bundle::parse(mirror.clone()).unwrap().to_mirror(),
        mirror
    );

    let other = WalletSim::random(rng);
    let alternate = action::Plan::<effect::Spend> {
        authority: other.pak.ak,
        ..spend
    };
    let other_plan =
        bundle::Plan::new(vec![alternate], vec![], other.random_note(10), vec![]).unwrap();
    let mut other_mirror = pczt::Bundle::from_plan(&other_plan).to_mirror();
    let Some(ActionWitness::Spend(other_witness)) = other_mirror.actions[0].witness.take() else {
        unreachable!()
    };
    witness.pak = Some([other_witness.ak.unwrap(), [1; 32]]);
    mirror.actions[0].witness = Some(ActionWitness::Spend(witness));
    assert!(matches!(
        pczt::Bundle::parse(mirror),
        Err(ParseError::KeyMismatch(0))
    ));
}
