//! Prove a fusable range of a note's per-epoch nullifiers. Wallet-only; every
//! range header carries `cm` for its consumers.
//!
//! Three steps. [`NfMasterSeed`] certifies the note's commitment and master
//! key; [`NfDerive`] runs one sponge group and exports a masked contiguous run
//! of its outputs; and [`NullifierFuse`] concatenates adjacent ranges.

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::array;

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Step, Suffix,
    constraint::{enforce_equal_point, enforce_zero},
};
use ragu_arithmetic::PoseidonPermutation as _;
use ragu_pasta::PoseidonFp;

use crate::{
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::{self, Note},
    nullifier::Nullifier,
    primitives::{EpochIndex, NfSeqCommit, NfSeqPoly},
    relations::enforce::enforce_shifted_combination,
};

/// A note's certified commitment and master key (wallet-only).
///
/// `mk` is derived natively from the note's secrets and certified here, so
/// every consuming [`NfDerive`] threads a genuine master key without
/// re-witnessing the note. `cm` rides along for the derivation's consumers to
/// bind against.
#[derive(Clone, Debug)]
pub struct NfMasterHeader;

impl Header for NfMasterHeader {
    /// `(cm, mk)`.
    type Data = (note::Commitment, NoteMasterKey);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, mk) = *data;
        (vec![Fp::from(cm), mk.0], Vec::new(), Vec::new(), Vec::new())
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(cm, (epoch_start, nf_start), nf_seq_commit, (epoch_end, nf_end))`: `cm`
/// lets every consumer bind the range to the real note; `nf_seq_commit` (the
/// nullifier sequence) sits between its boundary `(epoch, nullifier)` pairs and
/// commits to the half-open range `[nf_start, .., nf_end]` at degree 0,
/// sentinel-terminated (see [`NfSeqPoly`]) so the commitment is never the
/// identity point. `nf_start`/`nf_end` are the genuine boundary members, so a
/// consumer can bind them without opening the sequence.
#[derive(Clone, Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    type Data = (
        note::Commitment,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
    );

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, (epoch_start, nf_start), nf_seq_commit, (epoch_end, nf_end)) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(nf_start),
                Fp::from(u64::from(epoch_end.0)),
                Fp::from(nf_end),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(nf_seq_commit)],
        )
    }
}

/// Certify a note's commitment and master key.
///
/// Seed step. Witnesses the note and its proof authorizing key, proves the
/// key belongs to the note (`note.pk == pak.derive_payment_key()`, which pins
/// `nk`), derives `mk` from `nk` and the note's trapdoor, and computes `cm`.
/// `nk` never leaves the step; only `pk`, which preimage-hides it, enters
/// `cm`.
///
/// # Soundness
///
/// A seed can invent a note, so `cm` closes downstream, at
/// [`SpendableInit`](super::spendable::SpendableInit) and
/// [`SpendStamp`](super::stamp::SpendStamp). What this step establishes is
/// the pairing: `mk` is *this* `cm`'s master key.
#[derive(Debug)]
pub struct NfMasterSeed;

impl Step for NfMasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NfMasterHeader;
    type Right = ();
    /// `(note, pak)`.
    type Witness<'source> = (Note, ProofAuthorizingKey);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, pak): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(note.pk) - Fp::from(pak.derive_payment_key()),
            "NfMasterSeed: pak not related to note",
        )?;
        let mk = pak.nk.derive_note_private(note.psi);
        let cm = note.commitment();
        Ok(((cm, mk), ()))
    }
}

/// Derive one sponge group of nullifiers and export a masked contiguous run
/// of it as a [`NullifierHeader`].
///
/// `Left = NfMasterSeed`. Witnesses the window start epoch $w$ (constrained
/// group-aligned, $w \bmod \mathsf{RATE} = 0$), a
/// `[bool; PoseidonFp::RATE]` mask selecting which of the window's epochs
/// the exported range covers, and the range's sequence polynomial. One sponge
/// absorbs $(\mathtt{NF\_DOMAIN}, \mathsf{mk}, w)$ and squeezes the window's
/// `PoseidonFp::RATE` nullifiers (one permutation each way); the mask then
/// shifts the exported `epoch_start` past the leading unselected epochs and
/// sizes the range at the run's length, so the step emits an exact-fit span
/// of one to `PoseidonFp::RATE` epochs.
///
/// With mask bits $m_j$, rising edges $e_j = (1 - m_{j-1})\,m_j$ (taking
/// $m_{-1} = 0$) and falling edges $f_j = m_j\,(1 - m_{j+1})$ (taking
/// $m_4 = 0$), the constraints are:
///
/// $$m_j (m_j - 1) = 0, \qquad \textstyle\sum_j e_j = 1$$
///
/// (booleanity, and exactly one contiguous nonempty run), and the sequence
/// bind at a transcript challenge $z$ derived from the sequence commitment:
///
/// $$\mathsf{seq}(z) \cdot \sum_j e_j z^j
///   = \sum_j m_j\,\mathsf{nf}_j\,z^j + \sum_j f_j z^{j+1}$$
///
/// since $\sum_j e_j z^j = z^{\mathsf{lead}}$, the masked members sit at
/// absolute degrees $\mathsf{lead}..\mathsf{lead}+\mathsf{count}$, and
/// $\sum_j f_j z^{j+1} = z^{\mathsf{lead}+\mathsf{count}}$ is the sentinel's
/// absolute slot. By Schwartz–Zippel this pins $\mathsf{seq}$ to exactly
/// $\sum_p \mathsf{nf}_{\mathsf{lead}+p} X^p + X^{\mathsf{count}}$.
///
/// # Soundness
///
/// `mk` is threaded from the left header, so it is the note's genuine master
/// key by PCD soundness. The opening's only free operand is the range
/// sequence, committed before $z$ exists and independent of it.
///
/// The window start and the mask are free witnesses, pinned by the header
/// they produce: with $w$ constrained group-aligned,
/// $\mathsf{epoch\_start} = w + \mathsf{lead}$ with $\mathsf{lead}$ inside
/// the window is an injective decomposition, and $\mathsf{count} =
/// \mathsf{epoch\_end} - \mathsf{epoch\_start}$, so the emitted span
/// determines both. The boundary nullifiers are edge-selected from the
/// sponge outputs of the threaded `mk`, pinned in-circuit.
///
/// Committed-polynomial inventory: one witnessed polynomial (the range
/// sequence), opened once at $z$.
#[derive(Debug)]
pub struct NfDerive;

impl Step for NfDerive {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NullifierHeader;
    type Right = ();
    /// `(window_start, mask, seq)`.
    type Witness<'source> = (EpochIndex, [bool; PoseidonFp::RATE], NfSeqPoly);

    const INDEX: Index = Index::new(1);

    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "mask offsets and the alignment remainder are bounded by the \
                  fixed group width"
    )]
    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (window_start, mask, seq): Self::Witness<'source>,
        (cm, mk): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(u64::from(window_start.0 % PoseidonFp::RATE as u32)),
            "NfDerive: window start is not group-aligned",
        )?;
        let nullifiers = mk.derive_group(window_start).map(Fp::from);

        let bits: [Fp; PoseidonFp::RATE] = mask.map(|selected| Fp::from(u64::from(selected)));
        for bit in bits {
            enforce_zero(bit * (bit - Fp::ONE), "NfDerive: mask entry is not boolean")?;
        }
        let rise: [Fp; PoseidonFp::RATE] = array::from_fn(|j| {
            let prev = if j == 0 { Fp::ZERO } else { bits[j - 1] };
            (Fp::ONE - prev) * bits[j]
        });
        let fall: [Fp; PoseidonFp::RATE] = array::from_fn(|j| {
            let next = if j + 1 == PoseidonFp::RATE {
                Fp::ZERO
            } else {
                bits[j + 1]
            };
            bits[j] * (Fp::ONE - next)
        });
        enforce_zero(
            rise.iter().sum::<Fp>() - Fp::ONE,
            "NfDerive: mask is not one contiguous nonempty run",
        )?;

        let lead = mask.iter().take_while(|selected| !**selected).count() as u32;
        let count = mask.iter().filter(|selected| **selected).count() as u32;
        let epoch_start = EpochIndex(window_start.0 + lead);
        let epoch_end = EpochIndex(epoch_start.0 + count);

        // Pin the emitted span to the witnessed window start and mask.
        let lead_selected: Fp = (0u64..).zip(rise).map(|(j, edge)| Fp::from(j) * edge).sum();
        let count_selected: Fp = bits.iter().sum();
        enforce_zero(
            Fp::from(epoch_start) - (Fp::from(window_start) + lead_selected),
            "NfDerive: epoch_start does not match the mask shift",
        )?;
        enforce_zero(
            Fp::from(epoch_end) - (Fp::from(window_start) + lead_selected + count_selected),
            "NfDerive: epoch_end does not match the mask run",
        )?;

        // The boundary members, edge-selected from the sponge outputs.
        let nf_start: Fp = rise
            .iter()
            .zip(nullifiers)
            .map(|(edge, nf)| *edge * nf)
            .sum();
        let nf_end: Fp = fall
            .iter()
            .zip(nullifiers)
            .map(|(edge, nf)| *edge * nf)
            .sum();

        // `z`: a fresh transcript challenge over the sequence commitment. The
        // polynomial is fixed before it exists, so the single opening below
        // is not vacuous.
        let z = ctx.derive_challenge(&[seq.commit().into()])?;
        let seq_at_z = seq.eval(z);
        ctx.enforce_poly_query(seq.commit().into(), z, seq_at_z)?;

        let mut z_pows = [Fp::ONE; PoseidonFp::RATE + 1];
        for j in 1..z_pows.len() {
            z_pows[j] = z_pows[j - 1] * z;
        }
        let z_lead: Fp = rise.iter().zip(z_pows).map(|(edge, pow)| *edge * pow).sum();
        let members_at_z: Fp = (0..PoseidonFp::RATE)
            .map(|j| bits[j] * nullifiers[j] * z_pows[j])
            .sum();
        let sentinel_at_z: Fp = (0..PoseidonFp::RATE).map(|j| fall[j] * z_pows[j + 1]).sum();
        enforce_zero(
            seq_at_z * z_lead - members_at_z - sentinel_at_z,
            "NfDerive: sequence does not match the masked run",
        )?;

        Ok((
            (
                cm,
                (epoch_start, Nullifier::from(nf_start)),
                seq.commit(),
                (epoch_end, Nullifier::from(nf_end)),
            ),
            (),
        ))
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
    /// `(left_seq, merged_seq, right_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_seq, merged_seq, right_seq): Self::Witness<'source>,
        (
            left_cm,
            (left_epoch_start, left_nf_start),
            left_nf_seq_commit,
            (left_epoch_end, _left_nf_end),
        ): <Self::Left as Header>::Data,
        (
            right_cm,
            (right_epoch_start, right_nf_start),
            right_nf_seq_commit,
            (right_epoch_end, right_nf_end),
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_cm) - Fp::from(right_cm),
            "NullifierFuse: note commitments differ",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end),
            "NullifierFuse: ranges not contiguous",
        )?;
        enforce_equal_point(
            Eq::from(left_seq.commit()),
            Eq::from(left_nf_seq_commit),
            "NullifierFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_seq.commit()),
            Eq::from(right_nf_seq_commit),
            "NullifierFuse: right polynomial does not match header",
        )?;
        let merged_nf_seq_commit = merged_seq.commit();
        let offset = left_epoch_end - left_epoch_start;
        // Sentinel concat: a sequence of `k` members is `Σ n_i·X^i + X^k`, so
        // `merged = left ++ right` is the shifted combination
        // `merged(X) = left(X) + X^offset·right(X) - X^offset`. The `-X^offset`
        // monomial cancels left's sentinel, right's first member lands in the
        // vacated slot, and right's own sentinel re-terminates `merged`. The
        // monomial's constant coefficient is trivially challenge-independent,
        // and `offset` is left's header-fixed span.
        enforce_shifted_combination(
            ctx,
            [(left_seq.as_ref(), 0), (right_seq.as_ref(), offset.into())],
            [(-Fp::ONE, offset.into())],
            merged_seq.as_ref(),
            "NullifierFuse: merged is not the concat of the halves",
        )?;
        // Pin the boundary nullifiers that sit at a queryable degree-0 position:
        // the merged sequence opens to `left_nf_start` (its first leaf), and the
        // right half opens to `right_nf_start`. Each ties a witnessed sequence to
        // the header value its seed proved by construction. (`left_nf_end` is the
        // left half's top coefficient, not extractable by a single opening.)
        ctx.enforce_poly_query(
            merged_nf_seq_commit.into(),
            Fp::ZERO,
            Fp::from(left_nf_start),
        )?;
        ctx.enforce_poly_query(
            right_nf_seq_commit.into(),
            Fp::ZERO,
            Fp::from(right_nf_start),
        )?;
        Ok((
            (
                left_cm,
                (left_epoch_start, left_nf_start),
                merged_nf_seq_commit,
                (right_epoch_end, right_nf_end),
            ),
            (),
        ))
    }
}
