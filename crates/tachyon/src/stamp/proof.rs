//! Tachyon proofs via Ragu PCD.
//!
//! Tachyon uses **Ragu PCD** (Proof-Carrying Data) for proof generation and
//! aggregation. A single Ragu proof per aggregate covers all actions across
//! multiple bundles.
//!
//! ## Verification
//!
//! The header is not transmitted on the wire. The verifier reconstructs the PCD
//! header from public data according to consensus rules.
//!
//! 1. Recompute `action_acc` from the bundle's actions
//! 2. Recompute `tachygram_acc` from the listed tachygrams
//! 3. Construct the PCD header (`action_acc`, `tachygram_acc`, `anchor`)
//! 4. Call Ragu `verify(Pcd { proof, data: header })`
//!
//! A successful verification with a reconstructed header demonstrates that
//! consensus rules were followed.
//!
//! ## Proving
//!
//! The prover supplies an [`ActionPrivate`] per action, containing private
//! inputs that the circuit checks against the public action and tachygram.

extern crate alloc;

use alloc::vec::Vec;
use std::sync::LazyLock;

use ff::PrimeField as _;
pub use mock_ragu::Proof;
use mock_ragu::{
    self, Application, ApplicationBuilder, Commitment, Header, Index, Polynomial, Step, Suffix,
};
use pasta_curves::Fp;

use crate::{
    action::{Action, Effect},
    keys::ProofAuthorizingKey,
    primitives::{ActionDigest, Anchor, Epoch, Tachygram, digest_tachygram},
    witness::ActionPrivate,
};

// ---------------------------------------------------------------------------
// PCD header
// ---------------------------------------------------------------------------

/// PCD header data: `(action_commitment, tachygram_commitment, anchor)`.
///
/// Carried by the Ragu proof. Not serialized on the wire — the verifier
/// reconstructs it from public data.
pub type HeaderData = (Commitment, Commitment, Anchor);

/// PCD header type for Tachyon stamps.
pub(crate) struct StampHeader;

impl Header for StampHeader {
    type Data<'source> = (Commitment, Commitment, Anchor);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &(Commitment, Commitment, Anchor)) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        let action_bytes: [u8; 32] = data.0.into();
        let tachygram_bytes: [u8; 32] = data.1.into();
        out.extend_from_slice(&action_bytes);
        out.extend_from_slice(&tachygram_bytes);
        let anchor_bytes: [u8; 32] = Fp::from(data.2).to_repr();
        out.extend_from_slice(&anchor_bytes);
        out
    }
}

// ---------------------------------------------------------------------------
// Action step (leaf / seed)
// ---------------------------------------------------------------------------

/// Witness data for a single action proof.
pub(crate) struct ActionWitness<'action> {
    /// The authorized action (cv, rk, sig).
    pub(crate) action: &'action Action,
    /// Private witness (note, alpha, rcv).
    pub(crate) witness: &'action ActionPrivate,
    /// Whether this is a spend or output.
    pub(crate) effect: Effect,
    /// Accumulator state reference.
    pub(crate) anchor: Anchor,
    /// Wallet-wide proof authorizing key.
    pub(crate) pak: &'action ProofAuthorizingKey,
}

/// Leaf step: produces a proof for a single action.
pub(crate) struct ActionStep;

impl Step for ActionStep {
    type Aux<'source> = (HeaderData, Tachygram, Polynomial, Polynomial);
    type Left = ();
    type Output = StampHeader;
    type Right = ();
    type Witness<'source> = ActionWitness<'source>;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Derive tachygram (the raw value stays inside the circuit; the caller
        // receives it through Aux for data availability on the stamp).
        let tachygram: Tachygram = match witness.effect {
            | Effect::Spend => {
                todo!("derive epoch from anchor");
                let epoch = Epoch::from(0u32);
                let nf = witness.witness.note.nullifier(witness.pak.nk(), epoch);
                nf.into()
            },
            | Effect::Output => {
                let cm = witness.witness.note.commitment();
                cm.into()
            },
        };

        // Compute action root (Poseidon digest → polynomial root).
        let action_root: Fp = ActionDigest::try_from(witness.action)
            .map_err(|_err| mock_ragu::Error)?
            .into();
        let action_poly = Polynomial::from_roots(&[action_root]);
        let action_commitment = action_poly.commit();

        // Compute tachygram root, build polynomial, commit.
        let tg_root = digest_tachygram(tachygram);
        let tg_poly = Polynomial::from_roots(&[tg_root]);
        let tg_commitment = tg_poly.commit();

        let header = (action_commitment, tg_commitment, witness.anchor);
        Ok((header, (header, tachygram, action_poly, tg_poly)))
    }
}

// ---------------------------------------------------------------------------
// Merge step (fuse)
// ---------------------------------------------------------------------------

/// Polynomials from both sides, needed for merge.
#[expect(
    clippy::struct_field_names,
    reason = "left/right prefix is semantically necessary"
)]
pub(crate) struct MergeWitness {
    pub(crate) left_action_poly: Polynomial,
    pub(crate) left_tg_poly: Polynomial,
    pub(crate) right_action_poly: Polynomial,
    pub(crate) right_tg_poly: Polynomial,
}

/// Merge step: combines two stamp proofs.
pub(crate) struct MergeStep;

impl Step for MergeStep {
    type Aux<'source> = (HeaderData, Polynomial, Polynomial);
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = StampHeader;
    type Witness<'source> = MergeWitness;

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let merged_action_poly = witness
            .left_action_poly
            .multiply(&witness.right_action_poly);
        let merged_tg_poly = witness.left_tg_poly.multiply(&witness.right_tg_poly);

        let action_commitment = merged_action_poly.commit();
        let tg_commitment = merged_tg_poly.commit();
        let anchor = left.2.max(right.2);

        let header = (action_commitment, tg_commitment, anchor);
        Ok((header, (header, merged_action_poly, merged_tg_poly)))
    }
}

// ---------------------------------------------------------------------------
// Application helper
// ---------------------------------------------------------------------------

/// Ragu application with the Tachyon stamp steps registered.
#[expect(clippy::expect_used, reason = "registration is infallible")]
pub(crate) static PROOF_SYSTEM: LazyLock<Application> = LazyLock::new(|| {
    ApplicationBuilder::new()
        .register(ActionStep)
        .expect("register ActionStep")
        .register(MergeStep)
        .expect("register MergeStep")
        .finalize()
        .expect("finalize")
});
