//! Prove a fusable range of a note's per-epoch nullifiers.

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

/// A note commitment and master key.
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

/// A proven contiguous range of derived nullifiers.
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

/// Derive a note commitment and master key.
///
/// # Soundness
///
/// The note commitment binds downstream at [`super::spendable::SpendableInit`]
/// and [`super::stamp::SpendStamp`].
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

/// Derive one window of nullifiers at sponge rate.
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
        enforce_shifted_combination(
            ctx,
            [(left_seq.as_ref(), 0), (right_seq.as_ref(), offset.into())],
            [(-Fp::ONE, offset.into())],
            merged_seq.as_ref(),
            "NullifierFuse: merged is not the concat of the halves",
        )?;

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
