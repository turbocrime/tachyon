use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, bundle,
    pczt::{self, mirror},
    value,
};

use super::fixtures::{
    application,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pczt_mirror_round_trips_proof_contributions() {
    let rng = &mut StdRng::seed_from_u64(12);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let plan = bundle::Plan::new(
        vec![],
        vec![output_plan(rng, wallet.random_note(100))],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let anchor = Anchor::random(rng);
    let pre_fee = plan.actions_plan(anchor).prove(rng, app, vec![]).unwrap();
    let mut encoded = pczt::Bundle::from_plan(&plan).to_mirror();
    let pairs: Vec<_> = pre_fee
        .pairs
        .iter()
        .map(|(desc, &(left, right))| {
            let mut descriptor = [0; 64];
            let mut first = [0; 32];
            let mut second = [0; 32];
            desc.write(descriptor.as_mut_slice()).unwrap();
            left.write(first.as_mut_slice()).unwrap();
            right.write(second.as_mut_slice()).unwrap();
            mirror::ActionPair {
                descriptor,
                pair: [first, second],
            }
        })
        .collect();
    let mut anchor_bytes = [0; 32];
    anchor.write(anchor_bytes.as_mut_slice()).unwrap();
    encoded.actions_proofs.push(mirror::ActionsProof {
        pairs: pairs.clone(),
        anchor: anchor_bytes,
        proof: pre_fee.proof.to_bytes().unwrap(),
    });
    let parts = pre_fee
        .fee(rng, app, plan.max_fee_note(), value::Positive::ZERO)
        .unwrap();
    let mut stamp = Vec::new();
    let mut cm_change = [0; 32];
    parts.stamp.write(&mut stamp).unwrap();
    parts.cm_change.write(cm_change.as_mut_slice()).unwrap();
    encoded.autonome_parts = Some(mirror::AutonomeParts {
        stamp,
        pairs,
        fee: parts.fee.into(),
        cm_change,
    });
    assert_eq!(
        pczt::Bundle::parse(encoded.clone()).unwrap().to_mirror(),
        encoded
    );
}
