//! Stamps and anchors.
//!
//! A stamp carries the tachygram list, the epoch anchor, and the proof:
//!
//! - **Tachygrams**: Listed individually
//! - **Anchor**: Accumulator state reference (epoch)
//! - **Proof**: The Ragu PCD proof (rerandomized)
//!
//! The PCD header data `(action_commitment, tachygram_commitment, anchor)`
//! is **not serialized** on the stamp — the verifier reconstructs polynomial
//! commitments from public data and passes them as the header to Ragu
//! `verify()`.

extern crate alloc;

pub mod proof;

use alloc::vec::Vec;
use core::{error::Error, fmt};

pub use proof::Proof;
use rand::CryptoRng;

use self::proof::{ActionStep, ActionWitness, MergeStep, MergeWitness, PROOF_SYSTEM, StampHeader};
use crate::{
    ActionDigest,
    action::{Action, Effect},
    keys::ProofAuthorizingKey,
    primitives::{ActionDigestError, Anchor, Tachygram, multiset::Multiset},
    witness::ActionPrivate,
};

/// Marker for the absence of a stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stampless;

/// Error during stamp verification.
#[derive(Clone, Debug)]
pub enum VerificationError {
    /// An action's cv or rk is the identity point.
    ActionDigest(ActionDigestError),
    /// The proof system returned an error.
    ProofSystem,
    /// The proof did not verify against the reconstructed header.
    Disproved,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | &Self::ActionDigest(err) => write!(f, "action digest error: {err}"),
            | &Self::ProofSystem => write!(f, "proof system error"),
            | &Self::Disproved => write!(f, "proof did not verify"),
        }
    }
}

impl Error for VerificationError {}

/// A stamp carrying tachygrams, anchor, and proof.
///
/// Present in [`Stamped`](crate::Stamped) bundles.
/// Stripped during aggregation and merged into the aggregate's stamp.
///
/// The PCD header `(action_acc, tachygram_acc, anchor)` is not stored
/// here — the verifier reconstructs it from public data and passes it as
/// the header to Ragu `verify()`.
#[derive(Clone, Debug)]
pub struct Stamp {
    /// Tachygrams (nullifiers and note commitments) for data availability.
    ///
    /// The number of tachygrams can be greater than the number of actions.
    pub tachygrams: Vec<Tachygram>,

    /// Reference to tachyon accumulator state (epoch).
    pub anchor: Anchor,

    /// The Ragu proof bytes.
    pub proof: Proof,
}

impl Stamp {
    /// Creates a leaf stamp for a single action (ACTION STEP).
    ///
    /// The circuit derives the tachygram and returns it through `Aux` for
    /// data availability on the stamp. The proof is rerandomized before
    /// returning.
    ///
    /// Leaf stamps are combined via [`prove_merge`](Self::prove_merge).
    #[expect(clippy::type_complexity, reason = "deal with it")]
    pub fn prove_action<RNG: CryptoRng>(
        rng: &mut RNG,
        witness: &ActionPrivate,
        action: &Action,
        effect: Effect,
        anchor: Anchor,
        pak: &ProofAuthorizingKey,
    ) -> Result<(Self, (Multiset<ActionDigest>, Multiset<Tachygram>)), mock_ragu::Error> {
        let app = &*PROOF_SYSTEM;
        let action_witness = ActionWitness {
            action,
            witness,
            effect,
            anchor,
            pak,
        };
        let (proof, (tachygram, action_acc, tachygram_acc)) =
            app.seed(rng, &ActionStep, action_witness)?;

        let header = (action_acc.commit(), tachygram_acc.commit(), anchor);
        let carried = proof.carry::<StampHeader>(header);
        let rerand = app.rerandomize(carried, rng)?;

        Ok((
            Self {
                tachygrams: alloc::vec![tachygram],
                anchor,
                proof: rerand.proof,
            },
            (action_acc, tachygram_acc),
        ))
    }

    /// Merges this stamp with another, combining tachygrams and proofs.
    ///
    /// Assuming the anchor is an append-only accumulator, a later anchor should
    /// be a superset of an earlier anchor.
    ///
    /// The accumulators (`action_acc`, `tachygram_acc`) are merged inside the
    /// circuit via polynomial multiplication. [`MergeStep`] multiplies the
    /// polynomials, recommits, and takes the max anchor.
    #[expect(clippy::type_complexity, reason = "deal with it")]
    pub fn prove_merge<RNG: CryptoRng>(
        self,
        (self_action_acc, self_tachygram_acc): (Multiset<ActionDigest>, Multiset<Tachygram>),
        other: Self,
        (other_action_acc, other_tachygram_acc): (Multiset<ActionDigest>, Multiset<Tachygram>),
        rng: &mut RNG,
    ) -> Result<(Self, (Multiset<ActionDigest>, Multiset<Tachygram>)), mock_ragu::Error> {
        let app = &*PROOF_SYSTEM;

        let self_header = (
            self_action_acc.commit(),
            self_tachygram_acc.commit(),
            self.anchor,
        );
        let other_header = (
            other_action_acc.commit(),
            other_tachygram_acc.commit(),
            other.anchor,
        );
        let left_pcd = self.proof.carry::<StampHeader>(self_header);
        let right_pcd = other.proof.carry::<StampHeader>(other_header);

        let merge_witness = MergeWitness {
            left_action_acc: self_action_acc,
            left_tachygram_acc: self_tachygram_acc,
            right_action_acc: other_action_acc,
            right_tachygram_acc: other_tachygram_acc,
        };

        let (proof, (merged_action_acc, merged_tachygram_acc)) =
            app.fuse(rng, &MergeStep, merge_witness, left_pcd, right_pcd)?;

        let merged_anchor = self.anchor.max(other.anchor);
        let merged_tachygrams = [self.tachygrams, other.tachygrams].concat();

        let merged_header = (
            merged_action_acc.commit(),
            merged_tachygram_acc.commit(),
            merged_anchor,
        );
        let carried = proof.carry::<StampHeader>(merged_header);
        let rerand = app.rerandomize(carried, rng)?;

        Ok((
            Self {
                tachygrams: merged_tachygrams,
                anchor: merged_anchor,
                proof: rerand.proof,
            },
            (merged_action_acc, merged_tachygram_acc),
        ))
    }

    /// Verifies this stamp's proof by reconstructing the PCD header from public
    /// data.
    ///
    /// The verifier recomputes the action and tachygram polynomial commitments
    /// from the public actions and tachygrams, constructs the PCD header,
    /// and calls Ragu `verify(Pcd { proof, data: header })`. The proof
    /// only verifies against the header that matches the circuit's honest
    /// execution — a mismatched header causes verification failure.
    pub fn verify(&self, actions: &[Action]) -> Result<(), VerificationError> {
        let app = &*PROOF_SYSTEM;

        let action_commitment = <Multiset<ActionDigest>>::try_from(actions)
            .map_err(VerificationError::ActionDigest)?
            .commit();

        let tachygram_commitment = <Multiset<Tachygram>>::from(self.tachygrams.as_slice()).commit();

        let pcd = self.proof.clone().carry::<StampHeader>((
            action_commitment,
            tachygram_commitment,
            self.anchor,
        ));

        let valid = app
            .verify(&pcd, rand::thread_rng())
            .map_err(|_err| VerificationError::ProofSystem)?;

        if valid {
            Ok(())
        } else {
            Err(VerificationError::Disproved)
        }
    }
}
