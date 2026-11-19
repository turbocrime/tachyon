use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Note, action, bundle, effect,
    entropy::ActionEntropy,
    keys::{PaymentKey, private},
    note, nullifier,
    pasta::Fp,
    pczt::{ApplySignatureError, Bundle, IoFinalizerError, SignError},
    value,
};
#[test]
fn pczt_authorization_retains_occupied_slots() {
    let rng = &mut StdRng::seed_from_u64(4);
    let ask = private::SpendingKey::random(rng).derive_auth_private();
    let note = Note {
        pk: PaymentKey::from(Fp::from(1)),
        value: value::Positive::ZERO,
        rcm: note::CommitmentTrapdoor::from(Fp::from(2)),
        psi: nullifier::Trapdoor::from(Fp::from(3)),
    };
    let spend = action::Plan::<effect::Spend> {
        note,
        theta: ActionEntropy::random(rng),
        rcv: value::Trapdoor::random(rng),
        authority: ask.derive_auth_public(),
    };
    let output = action::Plan::<effect::Output> {
        note,
        theta: ActionEntropy::random(rng),
        rcv: value::Trapdoor::random(rng),
        authority: (),
    };
    let plan = bundle::Plan::new(vec![spend], vec![output], note, vec![]).unwrap();
    let index = plan
        .effects()
        .actions
        .binary_search(&spend.descriptor())
        .unwrap();
    let mut section = Bundle::from_plan(&plan);
    let sighash = [1; 32];
    section.finalize_io(sighash, rng).unwrap();
    section.sign_at(index, sighash, &ask, rng).unwrap();
    let original = section.to_mirror();
    section.finalize_io(sighash, rng).unwrap();
    section.sign_at(index, sighash, &ask, rng).unwrap();
    assert_eq!(section.to_mirror(), original);
    assert!(matches!(
        section.finalize_io([2; 32], rng),
        Err(IoFinalizerError::InvalidStoredSignature(_))
    ));
    assert!(matches!(
        section.sign_at(index, [2; 32], &ask, rng),
        Err(SignError::InvalidStoredSignature)
    ));
    assert_eq!(section.to_mirror(), original);
    let sig = section.actions().get(index).unwrap().sig().unwrap();
    section.apply_signature_at(index, sighash, sig).unwrap();
    assert!(matches!(
        section.apply_signature_at(index, [2; 32], sig),
        Err(ApplySignatureError::InvalidSignature)
    ));
}
