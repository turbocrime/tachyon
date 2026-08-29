//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Header, Polynomial, Step};

use crate::{
    collections,
    keys::ProofAuthorizingKey,
    note::Note,
    nullifier::Nullifier,
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochGroup, EpochIndex, NfSeqPoly, QrDiscriminant,
        Tachygram, TachygramSetPoly,
    },
    stamp::proof::{
        delegation::{NfDerive, NfMasterSeed, NullifierFuse},
        pool::{AnchorSeed, EndEpochUnspentSeed, UnspentBind, UnspentFuse, UnspentSeed},
        qr::{
            MAX_QR_DEPTH, MAX_STAMP_TACHYGRAMS, QrBucket, QrBucketAbsorb, QrBucketLeftDecomp,
            QrBucketRightDecomp, QrBucketSeed, QrUnspentLift,
        },
        spend::SpendBind,
        spendable::SpendableInit,
        stamp::MergeStamp,
    },
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`NfMasterSeed`]: `(note, pak)`.
#[must_use]
pub const fn nf_master_seed(
    (_left, _right): (StepLeft<NfMasterSeed>, StepRight<NfMasterSeed>),
    note: Note,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, NfMasterSeed> {
    (note, pak)
}

/// Prepare the witness for [`NfDerive`]: `(group, seq)`.
///
/// Reads `mk` off the seed header and lays the group's whole window out as the
/// sequence. A longer span fuses windows via [`NullifierFuse`].
#[must_use]
pub fn nf_derive(
    (left, _right): (StepLeft<NfDerive>, StepRight<NfDerive>),
    group: EpochGroup,
) -> StepWitness<'static, NfDerive> {
    let (_cm, mk) = left;
    (
        group,
        NfSeqPoly::new(group.start_epoch(), &mk.derive_window(group)),
    )
}

/// Prepare the witness for [`NullifierFuse`]:
/// `(left_seq, merged_seq, right_seq)`.
#[must_use]
pub fn nullifier_fuse(
    (left, right): (StepLeft<NullifierFuse>, StepRight<NullifierFuse>),
    left_nfs: &[Nullifier],
    right_nfs: &[Nullifier],
) -> StepWitness<'static, NullifierFuse> {
    let (_, left_epoch_start, ..) = left;
    let (_, right_epoch_start, ..) = right;
    let merged = [left_nfs, right_nfs].concat();
    (
        NfSeqPoly::new(left_epoch_start, left_nfs),
        NfSeqPoly::new(left_epoch_start, &merged),
        NfSeqPoly::new(right_epoch_start, right_nfs),
    )
}

/// Prepare the witness for [`UnspentSeed`]: `(anchor_prev, (epoch, nf),
/// tg_set, elapsed_seq)`.
#[must_use]
pub fn unspent_seed(
    (_left, _right): (StepLeft<UnspentSeed>, StepRight<UnspentSeed>),
    anchor_prev: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
    nf: Nullifier,
) -> StepWitness<'static, UnspentSeed> {
    (
        anchor_prev,
        (epoch, nf),
        tgs.iter().copied().collect::<TachygramSetPoly>(),
        NfSeqPoly::new(epoch, &[nf]),
    )
}

/// Prepare the witness for [`EndEpochUnspentSeed`]:
/// `(anchor_prev, (epoch_prev, nf_prev), nf, elapsed_seq)`.
#[must_use]
pub fn end_epoch_unspent_seed(
    (_left, _right): (
        StepLeft<EndEpochUnspentSeed>,
        StepRight<EndEpochUnspentSeed>,
    ),
    anchor_prev: Anchor,
    epoch_prev: EpochIndex,
    nf_prev: Nullifier,
    nf: Nullifier,
) -> StepWitness<'static, EndEpochUnspentSeed> {
    (
        anchor_prev,
        (epoch_prev, nf_prev),
        nf,
        NfSeqPoly::new(epoch_prev, &[nf_prev, nf]),
    )
}

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
///
/// `left_elapsed` and `right_elapsed` are the halves' member lists, one per
/// covered epoch. Both include the junction epoch's member, which the
/// combined sequence keeps once.
#[must_use]
pub fn unspent_fuse(
    (left, right): (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    let (_, (left_epoch_start, _), ..) = left;
    let (_, (right_epoch_start, _), ..) = right;
    #[expect(clippy::expect_used, reason = "member lists are nonempty")]
    let (_junction, right_tail) = right_elapsed
        .split_first()
        .expect("right members include the junction");
    let combined = [left_elapsed, right_tail].concat();
    (
        NfSeqPoly::new(left_epoch_start, left_elapsed),
        NfSeqPoly::new(left_epoch_start, &combined),
        NfSeqPoly::new(right_epoch_start, right_elapsed),
    )
}

/// Prepare the witness for [`UnspentBind`]:
/// `(elapsed_seq, nf_seq, complement_seq)`.
///
/// `elapsed` is the unspent's member list, one per covered epoch. `window`
/// is the complete covering sequence, one member per epoch of the
/// derivation header's range; the complement is the window's runs on both
/// sides of the unspent's span, multiplied.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn unspent_bind(
    (unspent, deriv): (StepLeft<UnspentBind>, StepRight<UnspentBind>),
    window: &[Nullifier],
    elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentBind> {
    let (_, (epoch_start, _), _, (epoch_last, _), _) = unspent;
    let (_, deriv_start, ..) = deriv;
    let lo = (epoch_start.0 - deriv_start.0) as usize;
    let hi = (epoch_last.next().0 - deriv_start.0) as usize;
    let complement_seq = NfSeqPoly::new(deriv_start, &window[..lo])
        * NfSeqPoly::new(epoch_last.next(), &window[hi..]);
    (
        NfSeqPoly::new(epoch_start, elapsed),
        NfSeqPoly::new(deriv_start, window),
        complement_seq,
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `(pre_cm_anchor, creation_set, creation_epoch, present_nf, nf_seq,
/// complement_seq)`.
///
/// `window` is the complete covering sequence, one member per epoch of the
/// derivation header's range; `present_nf` is the member the read forces,
/// and the complement is the window's runs on both sides of the creation
/// epoch, multiplied.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn spendable_init(
    (deriv, _right): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    pre_cm_anchor: Anchor,
    creation_tgs: &[Tachygram],
    creation_epoch: EpochIndex,
    window: &[Nullifier],
) -> StepWitness<'static, SpendableInit> {
    let (_, deriv_start, ..) = deriv;
    let lo = (creation_epoch.0 - deriv_start.0) as usize;
    let complement_seq = NfSeqPoly::new(deriv_start, &window[..lo])
        * NfSeqPoly::new(creation_epoch.next(), &window[lo + 1..]);
    (
        pre_cm_anchor,
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        creation_epoch,
        window[lo],
        NfSeqPoly::new(deriv_start, window),
        complement_seq,
    )
}

/// Prepare the witness for [`SpendBind`]:
/// `(nf_seq, complement_seq, nf_next)`.
///
/// `window` is the complete covering sequence, one member per epoch of the
/// derivation header's range; `nf_next` is the next epoch's member, and the
/// complement is the window's runs on both sides of the read pair,
/// multiplied. The pair read requires the derivation range to extend at
/// least one epoch past the spendable's epoch.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn spend_bind(
    (spendable, deriv): (StepLeft<SpendBind>, StepRight<SpendBind>),
    window: &[Nullifier],
) -> StepWitness<'static, SpendBind> {
    let (_, (epoch, _), _) = spendable;
    let (_, deriv_start, ..) = deriv;
    let lo = (epoch.0 - deriv_start.0) as usize;
    let complement_seq = NfSeqPoly::new(deriv_start, &window[..lo])
        * NfSeqPoly::new(EpochIndex(epoch.0 + 2), &window[lo + 2..]);
    (
        NfSeqPoly::new(deriv_start, window),
        complement_seq,
        window[lo + 1],
    )
}

/// Prepare the witness for [`AnchorSeed`]: `(start, epoch, stamp_commit)`.
#[must_use]
pub fn anchor_seed(
    (_left, _right): (StepLeft<AnchorSeed>, StepRight<AnchorSeed>),
    start: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
) -> StepWitness<'static, AnchorSeed> {
    (
        start,
        epoch,
        tgs.iter().copied().collect::<TachygramSetPoly>().commit(),
    )
}

/// Prepare the witness for [`MergeStamp`]: `((left_action_set, left_tg_set),
/// (merged_action_set, merged_tg_set), (right_action_set, right_tg_set))`.
#[must_use]
pub fn merge_stamp(
    (_left, _right): (StepLeft<MergeStamp>, StepRight<MergeStamp>),
    left_actions: &[ActionDigest],
    left_tgs: &[Tachygram],
    right_actions: &[ActionDigest],
    right_tgs: &[Tachygram],
) -> StepWitness<'static, MergeStamp> {
    let merged_action_set = left_actions
        .iter()
        .copied()
        .chain(right_actions.iter().copied())
        .collect::<ActionSetPoly>();
    let merged_tg_set = left_tgs
        .iter()
        .copied()
        .chain(right_tgs.iter().copied())
        .collect::<TachygramSetPoly>();
    (
        (
            left_actions.iter().copied().collect::<ActionSetPoly>(),
            left_tgs.iter().copied().collect::<TachygramSetPoly>(),
        ),
        (merged_action_set, merged_tg_set),
        (
            right_actions.iter().copied().collect::<ActionSetPoly>(),
            right_tgs.iter().copied().collect::<TachygramSetPoly>(),
        ),
    )
}

/// Prepare the witness for [`QrBucketSeed`]: `(epoch, sntl)`.
#[must_use]
pub const fn qr_bucket_seed(
    (_left, _right): (StepLeft<QrBucketSeed>, StepRight<QrBucketSeed>),
    epoch: EpochIndex,
    sntl: Anchor,
) -> StepWitness<'static, QrBucketSeed> {
    (epoch, sntl)
}

/// One value's per-split classification row against the header's
/// discriminants and profile bits: `(root, bit, inverse)` per active split,
/// zeroes beyond the depth. Returns the row and whether the value matches
/// the profile at every split.
fn classification_row(
    value: Fp,
    discriminants: &[QrDiscriminant; MAX_QR_DEPTH],
    leaf_bits: &[bool],
) -> ([(Fp, bool, Fp); MAX_QR_DEPTH], bool) {
    let mut row = [(Fp::ZERO, false, Fp::ZERO); MAX_QR_DEPTH];
    let mut matches = true;
    for (slot, (&discriminant, &leaf_bit)) in
        row.iter_mut().zip(discriminants.iter().zip(leaf_bits))
    {
        let offset = Fp::from(discriminant);
        let (bit, root) = collections::qr::classify(value, offset);
        let inverse = Option::<Fp>::from((value + offset).invert()).unwrap_or(Fp::ZERO);
        *slot = (root, bit, inverse);
        matches &= bit == leaf_bit;
    }
    (row, matches)
}

/// Prepare the witness for [`QrBucketAbsorb`]:
/// `(bucket, updated_bucket, stamp_tg_set, values)`.
///
/// `bucket_members` are the accumulator's current contents;
/// `stamp_tgs` the absorbed tachygram set. Classifies every value against
/// the header's discriminants and profile, so the updated accumulator holds
/// exactly the prior contents plus the matching values.
///
/// # Panics
///
/// Panics if the set exceeds [`MAX_STAMP_TACHYGRAMS`].
#[must_use]
pub fn qr_bucket_absorb(
    (left, _right): (StepLeft<QrBucketAbsorb>, StepRight<QrBucketAbsorb>),
    bucket_members: &[Tachygram],
    stamp_tgs: &[Tachygram],
) -> StepWitness<'static, QrBucketAbsorb> {
    let (_epoch, _sntl, _last_anchor, discriminants, profile, _commit) = left;
    assert!(
        stamp_tgs.len() <= MAX_STAMP_TACHYGRAMS,
        "absorbed set exceeds the batch bound"
    );

    let leaf_bits = profile.bits();
    #[expect(
        clippy::large_stack_arrays,
        reason = "the step's fixed-shape witness array, ~150KB, within thread stacks"
    )]
    let mut values =
        [(Fp::ZERO, [(Fp::ZERO, false, Fp::ZERO); MAX_QR_DEPTH]); MAX_STAMP_TACHYGRAMS];
    let mut updated = bucket_members.to_vec();
    for (slot, &tachygram) in values.iter_mut().zip(stamp_tgs) {
        let value = Fp::from(tachygram);
        let (row, matches) = classification_row(value, &discriminants, &leaf_bits);
        *slot = (value, row);
        if matches {
            updated.push(tachygram);
        }
    }

    (
        bucket_members.iter().copied().collect::<TachygramSetPoly>(),
        updated.iter().copied().collect::<TachygramSetPoly>(),
        stamp_tgs.iter().copied().collect::<TachygramSetPoly>(),
        values,
    )
}

/// The decomposition witness both decomp steps share:
/// `(parent, residue_side, non_residue_side, residue_cert,
/// non_residue_cert)` at the split's freshly minted discriminant.
///
/// # Panics
///
/// Panics if the parent members are not distinct (consensus squarefreeness).
fn qr_decomp_witness(
    header: <QrBucket as Header>::Data,
    parent_members: &[Tachygram],
) -> (
    TachygramSetPoly,
    TachygramSetPoly,
    TachygramSetPoly,
    (Polynomial, Polynomial),
    (Polynomial, Polynomial),
) {
    let (_epoch, _sntl, last_anchor, discriminants, profile, _commit) = header;
    let previous = profile
        .depth()
        .checked_sub(1)
        .and_then(|last| discriminants.get(last).copied())
        .unwrap_or(QrDiscriminant::ZERO);
    let offset = Fp::from(previous.next(last_anchor));

    let (residue, non_residue) =
        collections::qr::split(parent_members.iter().map(|&tg| Fp::from(tg)), offset);
    #[expect(
        clippy::expect_used,
        reason = "consensus squarefreeness makes accumulator members distinct"
    )]
    let residue_cert =
        collections::qr::decomposition(&residue, offset, true).expect("distinct members decompose");
    #[expect(
        clippy::expect_used,
        reason = "consensus squarefreeness makes accumulator members distinct"
    )]
    let non_residue_cert = collections::qr::decomposition(&non_residue, offset, false)
        .expect("distinct members decompose");

    let side_poly = |points: &[(Fp, Fp)]| {
        points
            .iter()
            .map(|&(member, _)| Tachygram::from(member))
            .collect::<TachygramSetPoly>()
    };
    (
        parent_members.iter().copied().collect::<TachygramSetPoly>(),
        side_poly(&residue),
        side_poly(&non_residue),
        residue_cert,
        non_residue_cert,
    )
}

/// Prepare the witness for [`QrBucketLeftDecomp`]:
/// `(parent, residue_side, non_residue_side, residue_cert,
/// non_residue_cert)`.
#[must_use]
pub fn qr_bucket_left_decomp(
    (left, _right): (StepLeft<QrBucketLeftDecomp>, StepRight<QrBucketLeftDecomp>),
    parent_members: &[Tachygram],
) -> StepWitness<'static, QrBucketLeftDecomp> {
    qr_decomp_witness(left, parent_members)
}

/// Prepare the witness for [`QrBucketRightDecomp`]:
/// `(parent, residue_side, non_residue_side, residue_cert,
/// non_residue_cert)`.
#[must_use]
pub fn qr_bucket_right_decomp(
    (left, _right): (
        StepLeft<QrBucketRightDecomp>,
        StepRight<QrBucketRightDecomp>,
    ),
    parent_members: &[Tachygram],
) -> StepWitness<'static, QrBucketRightDecomp> {
    qr_decomp_witness(left, parent_members)
}

/// Prepare the witness for [`QrUnspentLift`]: `(bucket, classifications)`.
///
/// `bucket_members` are the evidence accumulator's contents; the tested
/// nullifier is the lineage tip's, classified against the evidence header's
/// discriminants and profile.
#[must_use]
pub fn qr_unspent_lift(
    (left, right): (StepLeft<QrUnspentLift>, StepRight<QrUnspentLift>),
    bucket_members: &[Tachygram],
) -> StepWitness<'static, QrUnspentLift> {
    let (_anchor_prev, _start, _elapsed, (_epoch_last, nf_last), _anchor_last) = left;
    let (_epoch, _sntl, _endpoint, discriminants, profile, _commit) = right;

    let (row, _matches) = classification_row(Fp::from(nf_last), &discriminants, &profile.bits());
    let mut classifications = [(Fp::ZERO, Fp::ZERO); MAX_QR_DEPTH];
    for (slot, (root, _bit, inverse)) in classifications.iter_mut().zip(row) {
        *slot = (root, inverse);
    }

    (
        bucket_members.iter().copied().collect::<TachygramSetPoly>(),
        classifications,
    )
}
