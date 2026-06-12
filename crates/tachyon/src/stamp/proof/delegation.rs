//! MiMC nullifier-derivation chain: prove a contiguous range of a note's
//! per-epoch nullifiers `N_e = E_mk(psi' + e)`. Wallet-only; every range
//! header carries `cm` for its consumers.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use pasta_curves::Fp;
use ragu::{Commitment, Header, Index, Polynomial, Step, Suffix, enforce_poly_concat, generators};

use crate::{
    constants::EPOCH_MAX,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly},
};

/// The note's keyset, input salt, and commitment `([mk_0..mk_{κ-1}], mk_s,
/// cm)`. Wallet-only.
///
/// Carrying the raw keyset and `mk_s` is required: they are the witness
/// anchors every derivation step proves against. The header is private to
/// the wallet's own proof tree and is never published.
#[derive(Clone, Debug)]
pub struct NfMasterHeader;

impl Header for NfMasterHeader {
    type Data = (NoteMasterKey, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * NoteMasterKey::LENGTH + 32 + 32);
        for key in <[Fp; NoteMasterKey::LENGTH]>::from(data.0) {
            out.extend_from_slice(&key.to_repr());
        }
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(range_commit, start_epoch, end_epoch, cm)`: `range_commit` commits to
/// the half-open range `[N_start, .., N_{end-1}]` (`N_e = E_mk(psi' + e)`)
/// at degree 0; `cm` lets every consumer bind the range to the real note.
#[derive(Clone, Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    type Data = (NfSeqCommit, EpochIndex, EpochIndex, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 32);
        let commit_bytes: [u8; 32] = Commitment::from(data.0).into();
        out.extend_from_slice(&commit_bytes);
        out.extend_from_slice(&data.1.0.to_le_bytes());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out
    }
}

/// Seed the derivation chain at the note's master secrets.
///
/// Witnesses the note and `pak`, proves the keyset and `mk_s` are the
/// note's master secrets (`note.pk == pak.derive_payment_key()` pins `nk`,
/// and the keyset and `mk_s` are Poseidon outputs of `(psi, nk)`), and
/// emits `([mk_0..mk_{κ-1}], mk_s, cm)`.
#[derive(Debug)]
pub struct NfMasterSeed;

impl Step for NfMasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NfMasterHeader;
    type Right = ();
    type Witness<'source> = (Note, ProofAuthorizingKey);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, pak): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(ragu::Error("NfMasterSeed: pak not related to note"));
        }
        let master = pak.nk.derive_note_private(&note.psi);
        let cm = note.commitment();
        Ok(((master, cm), ()))
    }
}

/// Derive one epoch's nullifier into a rank-1 [`NullifierHeader`].
///
/// Witnesses a free `epoch`; the nullifier is `E_mk(mk_s + epoch)` and the
/// range commits to it alone at degree 0, spanning the single epoch
/// `[epoch, epoch + 1)`. The epoch is published on the header; which epoch
/// matters is bound downstream by every consumer. The epoch-space bound
/// keeps witnessed epochs inside the protocol's epoch space and rules out
/// `next()` overflow.
#[derive(Debug)]
pub struct NullifierStep;

impl Step for NullifierStep {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NullifierHeader;
    type Right = ();
    type Witness<'source> = (EpochIndex,);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (epoch,): Self::Witness<'source>,
        (mk, cm): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if epoch.0 > EPOCH_MAX {
            return Err(ragu::Error("NullifierStep: epoch exceeds epoch space"));
        }
        let nf = mk.derive_nullifier(epoch);
        let range_commit = NfSeqCommit::from(generators::g(0) * Fp::from(nf));
        Ok(((range_commit, epoch, epoch.next(), cm), ()))
    }
}

/// Merge two adjacent derived ranges into one (`left ++ right`).
///
/// Requires the same `cm` and contiguity (`right.start == left.end`). Witnesses
/// the two range polynomials and their concatenation, binds each by
/// commit-equality, and proves the concat at `offset = left.end - left.start`
/// via the faithful opening relation.
#[derive(Debug)]
pub struct NullifierFuse;

impl Step for NullifierFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = NullifierHeader;
    type Right = NullifierHeader;
    /// `(left_poly, right_poly, merged)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_poly, right_poly, merged): Self::Witness<'source>,
        (left_commit, left_start, left_end, left_cm): <Self::Left as Header>::Data,
        (right_commit, right_start, right_end, right_cm): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_cm != right_cm {
            return Err(ragu::Error("NullifierFuse: note commitments differ"));
        }
        if right_start != left_end {
            return Err(ragu::Error("NullifierFuse: ranges not contiguous"));
        }
        if left_poly.commit() != left_commit {
            return Err(ragu::Error(
                "NullifierFuse: left polynomial does not match header",
            ));
        }
        if right_poly.commit() != right_commit {
            return Err(ragu::Error(
                "NullifierFuse: right polynomial does not match header",
            ));
        }
        let merged_commit = merged.commit();
        let offset = usize::try_from(left_end.0 - left_start.0)
            .map_err(|_too_long| ragu::Error("NullifierFuse: range length exceeds usize"))?;
        enforce_poly_concat(
            ctx,
            &Polynomial::from(left_poly),
            &Polynomial::from(right_poly),
            offset,
            &Polynomial::from(merged),
        )
        .map_err(|_relation_err| {
            ragu::Error("NullifierFuse: merged is not the concat of the halves")
        })?;
        Ok(((merged_commit, left_start, right_end, left_cm), ()))
    }
}
