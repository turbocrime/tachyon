use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{bundle, pczt};

use super::fixtures::wallet::{WalletSim, output_plan, shared_sk};

#[test]
fn pczt_combines_redactions_but_rejects_conflicting_signatures() {
    let rng = &mut StdRng::seed_from_u64(42);
    let wallet = WalletSim::new(shared_sk());
    let plan = bundle::Plan::new(
        vec![],
        vec![output_plan(rng, wallet.random_note(100))],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    section.finalize_io([1; 32], rng).unwrap();
    let base = section.to_mirror();
    let mut conflicting = base.clone();
    conflicting.actions[0].sig = Some([0; 64]);
    assert!(matches!(
        section
            .clone()
            .combine(pczt::Bundle::parse(conflicting).unwrap()),
        Err(pczt::CombineError::FieldConflict(
            pczt::ConflictField::Signature(0)
        ))
    ));
    let mut redacted = base.clone();
    redacted.actions[0].note.psi = None;
    let left = pczt::Bundle::parse(redacted).unwrap();
    let mut other_redaction = base.clone();
    other_redaction.actions[0].sig = None;
    let right = pczt::Bundle::parse(other_redaction).unwrap();
    assert_eq!(
        left.clone().combine(right.clone()).unwrap().to_mirror(),
        base
    );
    assert_eq!(right.combine(left).unwrap().to_mirror(), base);
}
