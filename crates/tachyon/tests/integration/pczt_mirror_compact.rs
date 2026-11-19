use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    bundle,
    pczt::{
        self,
        mirror::{ActionWitness, OutputWitness},
    },
};

use super::fixtures::wallet::{WalletSim, output_plan, shared_sk};

#[test]
fn pczt_mirror_round_trips_a_compact_witness() {
    let rng = &mut StdRng::seed_from_u64(12);
    let wallet = WalletSim::new(shared_sk());
    let plan = bundle::Plan::new(
        vec![],
        vec![output_plan(rng, wallet.random_note(100))],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let mut mirror = pczt::Bundle::from_plan(&plan).to_mirror();
    assert_eq!(
        mirror.actions[0].witness,
        Some(ActionWitness::Output(OutputWitness {
            zip32_derivation: None,
            user_address: None
        }))
    );
    mirror.actions[0].witness = Some(ActionWitness::Output(OutputWitness {
        zip32_derivation: None,
        user_address: Some("recipient".into()),
    }));
    let mut compact = mirror.clone();
    compact.actions[0].descriptor = None;
    compact.value_balance = None;
    assert_eq!(pczt::Bundle::parse(compact).unwrap().to_mirror(), mirror);
}
