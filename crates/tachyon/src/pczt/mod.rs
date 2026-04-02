//! Partially Created Zcash Transaction (PCZT) support for Tachyon.
//!
//! A [`PartialBundle`] is a mutable container for constructing a Tachyon
//! bundle across multiple devices and roles.
//!
//! ## Role ordering
//!
//! ```text
//! Constructor → IO Finalizer → { Signer, stamp_plan → Prover } → Extractor
//! ```
//!
//! - **Constructor**: populates all fields from a [`bundle::Plan`].
//! - **IO Finalizer**: computes binding signing key from rcvs, signs.
//! - **Signer**: signs each action using theta + ask.
//! - **stamp_plan**: derives alpha from theta, builds a [`stamp::Plan`] for the
//!   prover. The prover never sees theta.
//! - **Extractor**: assembles the final [`Stamped`](crate::Stamped) bundle.

extern crate alloc;

use alloc::vec::Vec;
use core::{error, fmt, marker::PhantomData};

use crate::{
    action, bundle,
    entropy::ActionEntropy,
    keys::public,
    note::Note,
    primitives::{
        ActionDigest, ActionDigestError, Anchor, Effect, Epoch, effect, multiset::Multiset,
    },
    stamp::{self, Stamp},
    value,
};

mod extractor;
mod io_finalizer;
mod parse;
mod signer;
mod verify;

pub use extractor::ExtractError;
pub use io_finalizer::IoFinalizerError;
pub use parse::{ParseError, RawNote};
pub use signer::SignerError;
pub use verify::VerifyError;

/// A Tachyon bundle under construction.
///
/// Notes and theta are always present — value_balance is derived from
/// notes at extraction time, and alpha is derived from theta at stamp
/// plan time. Only `sig` on each action is filled during the flow.
#[derive(Clone, Debug)]
#[expect(
    clippy::multiple_inherent_impl,
    reason = "role methods split across submodules"
)]
pub struct PartialBundle {
    /// Spend actions under construction.
    pub spends: Vec<PartialAction<effect::Spend>>,

    /// Output actions under construction.
    pub outputs: Vec<PartialAction<effect::Output>>,

    /// Accumulator anchor — needed by Prover.
    pub anchor: Option<Anchor>,

    /// Epoch — needed by Prover.
    pub epoch: Option<Epoch>,

    /// Binding signature — set by IO Finalizer.
    pub binding_sig: Option<bundle::Signature>,

    /// Proof stamp — set by the prover via stamp_plan().prove().
    pub stamp: Option<Stamp>,
}

/// A single Tachyon action under construction, parameterized by effect.
#[derive(Clone, Debug)]
#[expect(
    clippy::multiple_inherent_impl,
    reason = "role methods split across submodules"
)]
#[expect(clippy::partial_pub_fields, reason = "phantom data")]
pub struct PartialAction<E: Effect> {
    /// Value commitment.
    pub cv: value::Commitment,

    /// Randomized action verification key.
    pub rk: public::ActionVerificationKey,

    /// The note being spent or created.
    pub note: Note,

    /// Per-action entropy for alpha derivation.
    ///
    /// The signer derives alpha from theta + cm to sign. The
    /// [`stamp_plan`](PartialBundle::stamp_plan) method derives alpha
    /// and passes it to the prover — theta never leaves the
    /// PartialBundle.
    pub theta: ActionEntropy,

    /// Value commitment trapdoor.
    pub rcv: value::CommitmentTrapdoor,

    /// Action authorization signature — set by Signer.
    pub sig: Option<action::Signature>,

    _effect: PhantomData<E>,
}

impl PartialBundle {
    /// Construct a PCZT bundle from a complete [`bundle::Plan`].
    #[must_use]
    pub fn new(plan: &bundle::Plan, anchor: Anchor, epoch: Epoch) -> Self {
        let spends = plan
            .spends
            .iter()
            .map(|ap| {
                PartialAction {
                    cv: ap.cv(),
                    rk: ap.rk,
                    note: ap.note,
                    theta: ap.theta,
                    rcv: ap.rcv,
                    sig: None,
                    _effect: PhantomData,
                }
            })
            .collect();

        let outputs = plan
            .outputs
            .iter()
            .map(|ap| {
                PartialAction {
                    cv: ap.cv(),
                    rk: ap.rk,
                    note: ap.note,
                    theta: ap.theta,
                    rcv: ap.rcv,
                    sig: None,
                    _effect: PhantomData,
                }
            })
            .collect();

        Self {
            spends,
            outputs,
            anchor: Some(anchor),
            epoch: Some(epoch),
            binding_sig: None,
            stamp: None,
        }
    }

    /// Derive value_balance from note values.
    ///
    /// $\mathsf{v\_balance} = \sum_i v_{\text{spend},i} - \sum_j
    /// v_{\text{output},j}$
    #[must_use]
    pub fn value_balance(&self) -> i64 {
        let spend_sum: i64 = self
            .spends
            .iter()
            .map(|action| i64::from(action.note.value))
            .sum();
        let output_sum: i64 = self
            .outputs
            .iter()
            .map(|action| i64::from(action.note.value))
            .sum();
        spend_sum - output_sum
    }

    /// Bundle commitment for sighash derivation.
    ///
    /// Computed from (cv, rk) pairs and value_balance.
    pub fn commitment(&self) -> Result<[u8; 64], ActionDigestError> {
        let digests: Result<Vec<ActionDigest>, _> = self
            .spends
            .iter()
            .map(|action| ActionDigest::new(action.cv, action.rk))
            .chain(
                self.outputs
                    .iter()
                    .map(|action| ActionDigest::new(action.cv, action.rk)),
            )
            .collect();
        let action_acc = Multiset::from(digests?.as_slice());
        bundle::digest_bundle(&action_acc, self.value_balance())
    }

    /// Build a [`stamp::Plan`] for the prover.
    ///
    /// Derives alpha from theta + note commitment for each action.
    /// The returned plan carries alpha but not theta — the prover
    /// never sees theta.
    pub fn stamp_plan(&self) -> Result<stamp::Plan, StampPlanError> {
        let anchor = self.anchor.ok_or(StampPlanError::MissingAnchor)?;
        let epoch = self.epoch.ok_or(StampPlanError::MissingEpoch)?;

        let actions = self
            .spends
            .iter()
            .map(|action| {
                let alpha = action
                    .theta
                    .randomizer::<effect::Spend>(&action.note.commitment());
                (
                    (action.cv, action.rk),
                    (alpha.into(), action.note, action.rcv),
                )
            })
            .chain(self.outputs.iter().map(|action| {
                let alpha = action
                    .theta
                    .randomizer::<effect::Output>(&action.note.commitment());
                (
                    (action.cv, action.rk),
                    (alpha.into(), action.note, action.rcv),
                )
            }))
            .collect();

        Ok(stamp::Plan::new(actions, anchor, epoch))
    }
}

/// Errors from building a stamp plan.
#[derive(Debug)]
#[non_exhaustive]
pub enum StampPlanError {
    /// Bundle is missing anchor.
    MissingAnchor,
    /// Bundle is missing epoch.
    MissingEpoch,
}

impl fmt::Display for StampPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::MissingAnchor => write!(f, "missing anchor"),
            | Self::MissingEpoch => write!(f, "missing epoch"),
        }
    }
}

impl error::Error for StampPlanError {}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        action,
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note},
        primitives::{Anchor, Epoch},
    };

    fn mock_sighash(bundle_digest: [u8; 64]) -> [u8; 32] {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"pretend sighash")
            .to_state()
            .update(&bundle_digest)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    fn build_plan(rng: &mut StdRng) -> bundle::Plan {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();

        let spend_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        };
        let output_note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(700u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut *rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut *rng)),
        };

        let theta_spend = ActionEntropy::random(&mut *rng);
        let theta_output = ActionEntropy::random(&mut *rng);
        let spend_rcv = value::CommitmentTrapdoor::random(&mut *rng);
        let output_rcv = value::CommitmentTrapdoor::random(&mut *rng);

        let spend_plan = action::Plan::spend(spend_note, theta_spend, spend_rcv, move |alpha| {
            pak.ak().derive_action_public(&alpha)
        });
        let output_plan = action::Plan::output(output_note, theta_output, output_rcv);

        bundle::Plan::new(vec![spend_plan], vec![output_plan])
    }

    /// Constructor → IO Finalizer → Signer → stamp_plan → prove → Extractor.
    #[test]
    fn full_flow_sign_then_prove() {
        let mut rng = StdRng::seed_from_u64(700);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let plan = build_plan(&mut rng);
        let mut pczt = PartialBundle::new(&plan, anchor, epoch);
        let sighash = mock_sighash(pczt.commitment().unwrap());

        pczt.finalize_io(&sighash, &mut rng).unwrap();

        for spend in &mut pczt.spends {
            spend.sign(&sighash, &ask, &mut rng).unwrap();
        }
        for output in &mut pczt.outputs {
            output.sign(&sighash, &mut rng).unwrap();
        }

        let stamp = pczt.stamp_plan().unwrap().prove(&mut rng, &pak).unwrap();
        pczt.stamp = Some(stamp);

        let stamped = pczt.extract().unwrap();
        stamped
            .verify_signatures(&sighash)
            .expect("stamped bundle should verify");
    }

    /// Constructor → IO Finalizer → stamp_plan → prove → Signer → Extractor.
    #[test]
    fn full_flow_prove_then_sign() {
        let mut rng = StdRng::seed_from_u64(701);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let pak = sk.derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let plan = build_plan(&mut rng);
        let mut pczt = PartialBundle::new(&plan, anchor, epoch);
        let sighash = mock_sighash(pczt.commitment().unwrap());

        pczt.finalize_io(&sighash, &mut rng).unwrap();

        let stamp = pczt.stamp_plan().unwrap().prove(&mut rng, &pak).unwrap();
        pczt.stamp = Some(stamp);

        for spend in &mut pczt.spends {
            spend.sign(&sighash, &ask, &mut rng).unwrap();
        }
        for output in &mut pczt.outputs {
            output.sign(&sighash, &mut rng).unwrap();
        }

        let stamped = pczt.extract().unwrap();
        stamped
            .verify_signatures(&sighash)
            .expect("stamped bundle should verify");
    }

    /// apply_signature rejects invalid sigs.
    #[test]
    fn apply_signature_rejects_bad_sig() {
        let mut rng = StdRng::seed_from_u64(702);
        let plan = build_plan(&mut rng);
        let pczt = PartialBundle::new(&plan, Anchor::from(Fp::ZERO), Epoch::from(0u32));
        let sighash = mock_sighash(pczt.commitment().unwrap());

        let mut spend = pczt.spends[0].clone();
        let bad_sig = action::Signature::from([0u8; 64]);

        assert!(spend.apply_signature(&sighash, bad_sig).is_err());
    }

    /// Extract rejects missing signatures.
    #[test]
    fn extract_rejects_missing_sig() {
        let mut rng = StdRng::seed_from_u64(703);
        let pak = private::SpendingKey::from([0x42u8; 32]).derive_proof_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let plan = build_plan(&mut rng);
        let mut pczt = PartialBundle::new(&plan, anchor, epoch);
        let sighash = mock_sighash(pczt.commitment().unwrap());

        pczt.finalize_io(&sighash, &mut rng).unwrap();

        let stamp = pczt.stamp_plan().unwrap().prove(&mut rng, &pak).unwrap();
        pczt.stamp = Some(stamp);
        // Deliberately skip signing.

        assert!(matches!(
            pczt.extract(),
            Err(ExtractError::MissingActionSig)
        ));
    }

    /// Extract rejects missing stamp.
    #[test]
    fn extract_rejects_missing_stamp() {
        let mut rng = StdRng::seed_from_u64(704);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let anchor = Anchor::from(Fp::ZERO);
        let epoch = Epoch::from(0u32);

        let plan = build_plan(&mut rng);
        let mut pczt = PartialBundle::new(&plan, anchor, epoch);
        let sighash = mock_sighash(pczt.commitment().unwrap());

        pczt.finalize_io(&sighash, &mut rng).unwrap();
        for spend in &mut pczt.spends {
            spend.sign(&sighash, &ask, &mut rng).unwrap();
        }
        for output in &mut pczt.outputs {
            output.sign(&sighash, &mut rng).unwrap();
        }
        // Deliberately skip proving.

        assert!(matches!(pczt.extract(), Err(ExtractError::MissingStamp)));
    }

    /// verify_cv catches a tampered value commitment.
    #[test]
    fn verify_cv_detects_mismatch() {
        let mut rng = StdRng::seed_from_u64(710);
        let plan = build_plan(&mut rng);
        let pczt = PartialBundle::new(&plan, Anchor::from(Fp::ZERO), Epoch::from(0u32));

        pczt.spends[0].verify_cv().unwrap();
        pczt.outputs[0].verify_cv().unwrap();

        let mut bad_spend = pczt.spends[0].clone();
        bad_spend.cv = pczt.outputs[0].cv;
        assert!(matches!(
            bad_spend.verify_cv(),
            Err(VerifyError::CvMismatch)
        ));
    }

    /// verify_rk catches a tampered randomized key.
    #[test]
    fn verify_rk_detects_mismatch() {
        let mut rng = StdRng::seed_from_u64(711);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let plan = build_plan(&mut rng);
        let pczt = PartialBundle::new(&plan, Anchor::from(Fp::ZERO), Epoch::from(0u32));

        pczt.spends[0].verify_rk(&ask).unwrap();
        pczt.outputs[0].verify_rk().unwrap();

        let mut bad_spend = pczt.spends[0].clone();
        bad_spend.rk = pczt.outputs[0].rk;
        assert!(matches!(
            bad_spend.verify_rk(&ask),
            Err(VerifyError::RkMismatch)
        ));

        let mut bad_output = pczt.outputs[0].clone();
        bad_output.rk = pczt.spends[0].rk;
        assert!(matches!(
            bad_output.verify_rk(),
            Err(VerifyError::RkMismatch)
        ));
    }
}
