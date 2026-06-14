//! MiMC nullifier derivation: prove a note's per-epoch nullifiers
//! `nf_e = E_mk(mk_s + e)`. Wallet-only; every range header carries `cm`
//! for its consumers.
//!
//! Two paths mint the same coefficient-basis [`NullifierHeader`] and are
//! interchangeable behind the seam: the per-element chain ([`NullifierStep`]
//! then [`NullifierFuse`]) derives one epoch at a time and concatenates,
//! while [`NullifierEraStep`] proves a whole 128-epoch era in a single
//! trace-based step.

extern crate alloc;

use alloc::vec::Vec;
use core::array;

use ff::{Field as _, FromUniformBytes as _, PrimeField as _};
use group::GroupEncoding as _;
use pasta_curves::Fp;
use ragu::{Commitment, Header, Index, Polynomial, Step, Suffix, enforce_poly_concat, generators};
use zcash_mimc::{Spec as _, tachyon::TachyonP5R64};

use super::relations::{
    enforce_final_column_reduction, enforce_first_column_values, enforce_row_recurrence,
};
use crate::{
    constants::{EPOCH_MAX, ERA_EPOCHS},
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly, NullifierEraTrace},
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
        let mut out = Vec::with_capacity(NoteMasterKey::KEY_BYTES + 32 + 32 + 32);
        out.extend_from_slice(&<[u8; NoteMasterKey::KEY_BYTES]>::from(data.0));
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(range_commit, start_epoch, end_epoch, cm)`: `range_commit` commits to
/// the half-open range `[N_start, .., N_{end-1}]` (`N_e = E_mk(mk_s + e)`)
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

/// Prove a whole 128-epoch era of a note's nullifier sequence in one
/// trace-based step, emitting the same coefficient-basis [`NullifierHeader`]
/// the per-element chain produces over the same span.
///
/// The witness is the prover-built trace `T`, the three per-constraint
/// quotients (`Q_round` as [`ROUND_QUOTIENT_SPLITS`] splits, `Q_boundary`,
/// `Q_s`), the converter reduction `G`, the output sequence `N`, and the era
/// `start`. The body is pure orchestration: it builds the public structural
/// data from the threaded keyset and witnessed `start`, then defers to three
/// generic vanishing relations plus the constant-term conversion.
///
/// - `enforce_first_column_values` applies round 0 (the salt step) outside the
///   trace, pinning each row-start cell to `(mk_s + start + row + k_0)^5` and
///   fixing `start`.
/// - `enforce_row_recurrence` pins the remaining cipher rounds 1.. of `T`.
/// - `enforce_final_column_reduction` pins `G = T·w mod Z_D` for the converter
///   weight `w` built from the reduction parameter `β`.
/// - The constant-term check ties `N` to `T`'s output cells at `β`.
///
/// `β` is the reduction parameter, derived identically here and in the
/// builder from `commit(T) + commit(N)`; see the inline `TODO(#139)`.
#[derive(Debug)]
pub struct NullifierEraStep;

/// Maximum era start index.
#[expect(
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    reason = "safe conversion"
)]
pub const MAX_ERA_START: EpochIndex = EpochIndex(EPOCH_MAX - (ERA_EPOCHS as u32));

/// Cells per trace row: one state per cipher round.
pub const TRACE_ROW_SIZE: usize = 64;

/// Committed splits of the masked-quintic transition quotient (degree
/// `5·8191 + 128` over an 8192-capacity commitment).
pub const ROUND_QUOTIENT_SPLITS: usize = 5;

/// The era trace size, equal to the commitment capacity and the quotient split
/// stride.
///
/// TODO: need a const from ragu
#[expect(clippy::as_conversions, reason = "safe conversion")]
pub const TRACE_SIZE: u64 = (TRACE_ROW_SIZE * ERA_EPOCHS) as u64;

/// TODO: add more tests
impl Step for NullifierEraStep {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NullifierHeader;
    type Right = ();
    /// `(start, trace, Q_round splits, Q_boundary, Q_s, reduction, range)`.
    type Witness<'source> = (
        EpochIndex,                          // era start
        NullifierEraTrace,                   // era derivation trace
        [Polynomial; ROUND_QUOTIENT_SPLITS], // round quotient splits
        Polynomial,                          // boundary quotient
        Polynomial,                          // sumcheck quotient
        Polynomial,                          // reduction
        NfSeqPoly,                           // era nullifiers
    );

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (
            start,
            era_trace,
            round_quotient,
            boundary_quotient,
            sumcheck_quotient,
            reduction,
            nf_range,
        ): Self::Witness<'source>,
        (keyset, cm): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let range = Polynomial::from(nf_range);
        let trace = Polynomial::from(era_trace);

        let end = start.era();
        if end.0 > EPOCH_MAX {
            return Err(ragu::Error("NullifierEraStep: era end exceeds epoch space"));
        }

        let trace_commit = trace.commit();
        let range_commit = range.commit();
        let reduction_commit = reduction.commit();

        // TODO(#139): placeholder Eq->bytes->Fp reduction; swap for a principled
        // commitment-bound derivation. Must stay bit-identical to the step's
        // reduction in `keys/note.rs`.
        let beta = {
            let beta_eq = *trace_commit.inner() + *range_commit.inner();
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&beta_eq.to_bytes());
            Fp::from_uniform_bytes(&bytes)
        };

        // Round 0, the salt step. The cipher input `mk_s + start + row` is
        // not stored in the trace, so round 0 is applied here rather than by
        // the recurrence: each row's first cell is pinned to round 0's output
        // `(mk_s + start + row + k_0)^5` (with `c_0 = 0`). The targets are
        // S-boxed here so the relation stays a generic first-column pinning;
        // the prover's boundary quotient pins the same values.
        {
            let base = keyset.salt() + Fp::from(start);
            let first_key = keyset.round_key(0);
            let boundary: [Fp; ERA_EPOCHS] = array::from_fn(|row| {
                #[expect(clippy::as_conversions, reason = "row index conversion")]
                let cipher_in = base + Fp::from(row as u64) + first_key;
                cipher_in.square().square() * cipher_in
            });
            enforce_first_column_values(ctx, &trace, &boundary_quotient, Fp::ZERO, &boundary)?;
        }

        // Rounds 1..63: advance each row through the rest of the cipher. The
        // recurrence enforces every in-row step `T[cell + 1] = (T[cell] +
        // schedule[cell])^5` as one round; `schedule[cell]` is that round's
        // additive `key + constant`, the same per-column layout for all rows.
        // Cell `cell` holds round `cell`'s output, so the step out of it is
        // round `cell + 1` (round 0 is pinned above, not a step). The last
        // cell's successor is the next row, so its offset is unused: `get(64)`
        // is `None` -> `Fp::ZERO`, and the recurrence masks that row-wrap step.
        {
            let schedule: [Fp; TRACE_ROW_SIZE] = array::from_fn(|cell| {
                TachyonP5R64::CONSTANTS
                    .get(cell + 1)
                    .map_or(Fp::ZERO, |round_const| {
                        keyset.round_key(cell + 1) + round_const
                    })
            });

            enforce_row_recurrence(ctx, &trace, &round_quotient, &schedule, TachyonP5R64::POW)?;
        }

        // Output reduction: fold each row's final cell -- round 64's output,
        // the nullifier before whitening -- into a single β-weighted sum, so
        // the constant-term conversion below can tie the whole output column
        // to the published sequence `N` at β. `weights[r] = β^r` is the
        // per-row weight the relation places on the output column; it pins
        // `reduction = T·w mod Z_D`, whose constant term `G(0)` is that sum.
        {
            let mut weights = [Fp::ZERO; ERA_EPOCHS];
            let mut power = Fp::ONE;
            for slot in &mut weights {
                *slot = power;
                power *= beta;
            }

            enforce_final_column_reduction(ctx, &trace, &sumcheck_quotient, &reduction, &weights)?;
        }

        // Constant-term conversion: `N(β) = |D|·G(0) + mk_w·(β^128−1)/(β−1)`.
        let range_at_beta = range.eval(beta);
        let reduction_at_zero = reduction.eval(Fp::ZERO);
        let geometric_inverse = (beta - Fp::ONE)
            .invert()
            .expect("beta should not equal reduction");

        #[expect(clippy::as_conversions, reason = "safe conversion")]
        let correction = {
            keyset.round_key(TachyonP5R64::ROUNDS)
                * (beta.pow_vartime([ERA_EPOCHS as u64]) - Fp::ONE)
                * geometric_inverse
        };

        if range_at_beta != Fp::from(TRACE_SIZE) * reduction_at_zero + correction {
            return Err(ragu::Error(
                "NullifierEraStep: output conversion fails at the reduction parameter",
            ));
        }
        ctx.enforce_poly_query(range_commit, beta, range_at_beta)?;
        ctx.enforce_poly_query(reduction_commit, Fp::ZERO, reduction_at_zero)?;

        Ok(((NfSeqCommit::from(range_commit), start, end, cm), ()))
    }
}
