//! QR epoch evidence: one epoch's tachygrams partitioned by profile.
//!
//! Each depth classifies at a discriminant iterated from the boundary anchor
//! that closes the epoch,
//!
//! $$
//!   R_1 = H(\mathsf{boundary}), \qquad R_{j+1} = H(R_j).
//! $$
//!
//! A value takes the residue side at depth $j$ iff $x + R_j$ is a square or
//! zero.
//!
//! [`QrSummaryIntakeInit`] starts a [`QrIntake`] from a [`Summary`], and
//! [`QrStampIntakeSeed`] from one unsummarized stamp. [`QrIntakeSplit`]
//! partitions an intake at its discriminant into [`QrIntakeSides`],
//! [`QrSideDescend`] carries one side down a level, and [`QrIntakeMerge`]
//! joins two same-profile intakes whose spans meet. [`QrBucketSeal`] is the
//! only step that produces a [`QrBucket`].

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{conditional_enforce_equal, enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::{pool::ArbitraryUnspent, summary::Summary};
pub use crate::collections::qr::classify;
use crate::{
    collections::{indexed_multiset, qr::QUADRATIC_NON_RESIDUE},
    digest::poseidon,
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, QrDiscriminant, QrFilterCommit, QrFilterPoly,
        QrInterpolantPoly, QrProfile, QrQuotientPoly, Tachygram, TachygramSetCommit,
        TachygramSetPoly,
    },
    relations::enforce::enforce_poly_product,
};

/// Tachygrams under routing. Every member of `contents` takes `profile`, and
/// a split classifies at `discriminant`.
#[derive(Clone, Debug)]
pub struct QrIntake;

impl Header for QrIntake {
    /// `(epoch, anchor_prev, anchor_last, boundary, profile, discriminant,
    /// contents)`. `anchor_prev` and `anchor_last` bracket the anchor links
    /// the contents were drawn from; `boundary` is the anchor the epoch's
    /// closing tick folds to, one link past anything an intake covers.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        Anchor,
        QrProfile,
        QrDiscriminant,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, boundary, profile, discriminant, contents) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
                Fp::from(boundary),
                Fp::from(profile.depth),
                Fp::from(profile.bits),
                Fp::from(discriminant),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(contents)],
        )
    }
}

/// One intake's members partitioned at its discriminant. Extracting either
/// side attests the other.
#[derive(Clone, Debug)]
pub struct QrIntakeSides;

impl Header for QrIntakeSides {
    /// `(epoch, anchor_prev, anchor_last, boundary, profile, discriminant,
    /// residue, non_residue)`, the fields of the intake that was split with
    /// its two sides in place of its contents.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        Anchor,
        QrProfile,
        QrDiscriminant,
        TachygramSetCommit,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (
            epoch,
            anchor_prev,
            anchor_last,
            boundary,
            profile,
            discriminant,
            residue,
            non_residue,
        ) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
                Fp::from(boundary),
                Fp::from(profile.depth),
                Fp::from(profile.bits),
                Fp::from(discriminant),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(residue), Eq::from(non_residue)],
        )
    }
}

/// Start a root intake from a [`Summary`].
///
/// # Soundness
///
/// `boundary` is free; [`QrBucketSeal`] pins it to the tick folded from the
/// span's own `anchor_last`. The span binds as the summary's does, through the
/// lineage that consumes it.
#[derive(Debug)]
pub struct QrSummaryIntakeInit;

impl Step for QrSummaryIntakeInit {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = QrIntake;
    type Right = ();
    /// `(boundary)`.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(21);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (boundary,): Self::Witness<'source>,
        (summary_epoch, summary_anchor_prev, summary_anchor_last, summary_acc_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            (
                summary_epoch,
                summary_anchor_prev,
                summary_anchor_last,
                boundary,
                QrProfile::ROOT,
                QrDiscriminant::of(boundary),
                summary_acc_commit,
            ),
            (),
        ))
    }
}

/// Start a root intake from one stamp:
/// [`SummarySeed`](super::summary::SummarySeed) with a [`QrIntake`] output.
///
/// # Soundness
///
/// Every witness is unconstrained here, as at every seed. `stamp_commit` is
/// folded into `anchor_last`, [`QrBucketSeal`] pins `boundary` to the tick
/// folded from `anchor_last`, and the span binds through the lineage that
/// consumes it.
#[derive(Debug)]
pub struct QrStampIntakeSeed;

impl Step for QrStampIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor_prev, epoch, boundary, stamp_commit)`.
    type Witness<'source> = (Anchor, EpochIndex, Anchor, TachygramSetCommit);

    const INDEX: Index = Index::new(30);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, boundary, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let anchor_last = anchor_prev
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu::Error::InvalidWitness("invalid anchor step".into()))?;
        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
                boundary,
                QrProfile::ROOT,
                QrDiscriminant::of(boundary),
                stamp_commit,
            ),
            (),
        ))
    }
}

/// Join two same-profile intakes whose spans meet.
///
/// Committed polynomials: both contents, the merged contents; three oracles.
///
/// # Soundness
///
/// Both contents are pinned to their headers by commit-equality. Consensus
/// forbids republishing a tachygram within two epochs, so the sets are
/// disjoint and the product is the union's root polynomial.
#[derive(Debug)]
pub struct QrIntakeMerge;

impl Step for QrIntakeMerge {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntake;
    type Right = QrIntake;
    /// `(left_contents, right_contents, merged)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_contents, right_contents, merged): Self::Witness<'source>,
        (epoch, anchor_prev, junction, boundary, profile, discriminant, left_commit): <Self::Left as Header>::Data,
        (
            right_epoch,
            right_anchor_prev,
            anchor_last,
            right_boundary,
            right_profile,
            right_discriminant,
            right_commit,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(u64::from(epoch.0)) - Fp::from(u64::from(right_epoch.0)),
            "QrIntakeMerge: inputs cover different epochs",
        )?;
        enforce_zero(
            Fp::from(boundary) - Fp::from(right_boundary),
            "QrIntakeMerge: inputs derive from different boundary anchors",
        )?;
        enforce_zero(
            Fp::from(profile.depth) - Fp::from(right_profile.depth),
            "QrIntakeMerge: inputs sit at different depths",
        )?;
        enforce_zero(
            Fp::from(profile.bits) - Fp::from(right_profile.bits),
            "QrIntakeMerge: inputs sit at different profiles",
        )?;
        enforce_zero(
            Fp::from(discriminant) - Fp::from(right_discriminant),
            "QrIntakeMerge: inputs disagree on the discriminant",
        )?;
        enforce_zero(
            Fp::from(junction) - Fp::from(right_anchor_prev),
            "QrIntakeMerge: right input does not continue the left span",
        )?;
        enforce_equal_point(
            Eq::from(left_contents.commit()),
            Eq::from(left_commit),
            "QrIntakeMerge: left contents do not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_contents.commit()),
            Eq::from(right_commit),
            "QrIntakeMerge: right contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            left_contents.as_ref(),
            right_contents.as_ref(),
            merged.as_ref(),
            "QrIntakeMerge: merged contents are not the union of the inputs",
        )?;

        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
                boundary,
                profile,
                discriminant,
                merged.commit(),
            ),
            (),
        ))
    }
}

/// Partition an intake's members at its own discriminant.
///
/// Committed polynomials: contents, both sides; three oracles.
///
/// # Soundness
///
/// The product pins the two sides to a factorization of the contents;
/// [`QrSideDescend`] attests each child's sibling. The exceptional value $-R$
/// has root $0$ under either class, so the non-residue side must open nonzero
/// there.
#[derive(Debug)]
pub struct QrIntakeSplit;

impl Step for QrIntakeSplit {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntakeSides;
    type Right = ();
    /// `(contents, residue, non_residue)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(23);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (contents, residue, non_residue): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, boundary, profile, discriminant, contents_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(contents_commit),
            "QrIntakeSplit: contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            residue.as_ref(),
            non_residue.as_ref(),
            contents.as_ref(),
            "QrIntakeSplit: the sides do not partition the contents",
        )?;

        let exceptional = -Fp::from(discriminant);
        let non_residue_at_exceptional = non_residue.eval(exceptional);
        ctx.enforce_poly_query(
            non_residue.commit().into(),
            exceptional,
            non_residue_at_exceptional,
        )?;
        enforce_nonzero(
            non_residue_at_exceptional,
            "QrIntakeSplit: exceptional value claimed the non-residue class",
        )?;

        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
                boundary,
                profile,
                discriminant,
                residue.commit(),
                non_residue.commit(),
            ),
            (),
        ))
    }
}

/// Extract one side of a partition and carry it down one level, attesting
/// the other side's class.
///
/// With $s$ the sibling, $g$ its interpolant and $h$ the quotient,
///
/// $$
///   g(X)^2 - c\,(X + R) = s(X)\, h(X)
/// $$
///
/// at the sibling's class $c$ holds only if every root of $s$ takes that
/// side at $R$, since each root leaves $g(x)^2 = c\,(x + R)$. With the
/// split's product, every member of the extracted class is then in the
/// child.
///
/// Committed polynomials: the sibling, its interpolant, its quotient; three
/// oracles.
///
/// # Soundness
///
/// The child needs completeness, not purity: a consumer opens it nonzero at
/// a value of the child's own profile, and a stray member of the other class
/// only tightens that opening. The sibling is pinned to the header by
/// commit-equality and the challenge absorbs all three commitments; the
/// child's commitment is read off the header. Both header commitments are
/// selected by point arithmetic on `bit`, and both class identities are
/// computed with the sibling's gated in, so no constraint branches on the
/// witness. The parent's depth is checked below `u64::BITS`, so `bits` stays
/// below $2^{64} < p$ and distinct paths of one depth never share a profile.
#[derive(Debug)]
pub struct QrSideDescend;

impl Step for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = ();
    /// `(bit, sibling_contents, interpolant, quotient)`.
    type Witness<'source> = (bool, TachygramSetPoly, QrInterpolantPoly, QrQuotientPoly);

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (bit, sibling_contents, interpolant, quotient): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, boundary, profile, discriminant, residue, non_residue): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // TODO: a real circuit needs a bit decomposition of `depth` here; mock
        // ragu accepts the native comparison.
        if profile.depth >= u64::from(u64::BITS) {
            return Err(ragu::Error::InvalidWitness(
                "QrSideDescend: profile has no bit left for another side".into(),
            ));
        }
        // TODO: a real circuit must constrain `bit` boolean; the type carries it
        // under mock ragu.
        let sibling_commit = sibling_contents.commit();
        let sibling = Eq::from(residue)
            + (Eq::from(non_residue) - Eq::from(residue)) * Fp::from(u64::from(bit));
        enforce_equal_point(
            Eq::from(sibling_commit),
            sibling,
            "QrSideDescend: sibling does not match the header",
        )?;
        let selected = Eq::from(non_residue)
            + (Eq::from(residue) - Eq::from(non_residue)) * Fp::from(u64::from(bit));

        let interpolant_commit = interpolant.commit();
        let quotient_commit = quotient.commit();
        let z = ctx.derive_challenge(&[
            sibling_commit.into(),
            interpolant_commit.into(),
            quotient_commit.into(),
        ])?;
        let sibling_at_z = sibling_contents.eval(z);
        let interpolant_at_z = interpolant.eval(z);
        let quotient_at_z = quotient.eval(z);
        ctx.enforce_poly_query(sibling_commit.into(), z, sibling_at_z)?;
        ctx.enforce_poly_query(interpolant_commit.into(), z, interpolant_at_z)?;
        ctx.enforce_poly_query(quotient_commit.into(), z, quotient_at_z)?;
        let shifted = z + Fp::from(discriminant);
        let class_residual = interpolant_at_z.square() - sibling_at_z * quotient_at_z;
        conditional_enforce_equal(
            bit,
            class_residual,
            QUADRATIC_NON_RESIDUE * shifted,
            "QrSideDescend: the sibling fails the non-residue class decomposition",
        )?;
        conditional_enforce_equal(
            !bit,
            class_residual,
            shifted,
            "QrSideDescend: the sibling fails the residue class decomposition",
        )?;

        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
                boundary,
                profile.descend(bit),
                discriminant.next(),
                TachygramSetCommit::from(selected),
            ),
            (),
        ))
    }
}

/// The discriminants on one profile's path, as roots, sorted by the side
/// taken at each.
#[derive(Clone, Debug)]
pub struct QrFilter;

impl Header for QrFilter {
    /// `(epoch, boundary, profile, discriminant, residue_filter,
    /// non_residue_filter)`. `discriminant` is the one a descent from here
    /// classifies at.
    type Data = (
        EpochIndex,
        Anchor,
        QrProfile,
        QrDiscriminant,
        QrFilterCommit,
        QrFilterCommit,
    );

    const SUFFIX: Suffix = Suffix::new(16);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, boundary, profile, discriminant, residue_filter, non_residue_filter) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(boundary),
                Fp::from(profile.depth),
                Fp::from(profile.bits),
                Fp::from(discriminant),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(residue_filter), Eq::from(non_residue_filter)],
        )
    }
}

/// Open an epoch's empty filter pair.
///
/// # Soundness
///
/// `epoch` and `boundary` are free; [`QrUnspentInit`] requires the bucket to
/// agree on both.
#[derive(Debug)]
pub struct QrFilterSeed;

impl Step for QrFilterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrFilter;
    type Right = ();
    /// `(epoch, boundary)`.
    type Witness<'source> = (EpochIndex, Anchor);

    const INDEX: Index = Index::new(25);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (epoch, boundary): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            (
                epoch,
                boundary,
                QrProfile::ROOT,
                QrDiscriminant::of(boundary),
                QrFilterCommit::empty(),
                QrFilterCommit::empty(),
            ),
            (),
        ))
    }
}

/// Extend side `bit`'s filter by $(Y - \mathsf{discriminant})$ and forward the
/// other side.
///
/// Committed polynomials: the side's filter, the extended filter; two
/// oracles. The multiplier is public in circuit.
///
/// # Soundness
///
/// The selected filter is pinned to the header by commit-equality, with the
/// header commitment selected by point arithmetic on `bit`, and the challenge
/// absorbs both commitments. `discriminant` iterates from `boundary` as an
/// intake's does. The parent's depth is checked below `u64::BITS`, so
/// `bits` stays below $2^{64} < p$ and distinct paths of one depth never
/// share a profile.
#[derive(Debug)]
pub struct QrFilterDescend;

impl Step for QrFilterDescend {
    type Aux<'source> = ();
    type Left = QrFilter;
    type Output = QrFilter;
    type Right = ();
    /// `(bit, side_filter, extended)`.
    type Witness<'source> = (bool, QrFilterPoly, QrFilterPoly);

    const INDEX: Index = Index::new(26);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (bit, side_filter, extended): Self::Witness<'source>,
        (epoch, boundary, profile, discriminant, residue_filter, non_residue_filter): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // TODO: a real circuit needs a bit decomposition of `depth` here; mock
        // ragu accepts the native comparison.
        if profile.depth >= u64::from(u64::BITS) {
            return Err(ragu::Error::InvalidWitness(
                "QrFilterDescend: profile has no bit left for another side".into(),
            ));
        }
        // TODO: a real circuit must constrain `bit` boolean; the type carries it
        // under mock ragu.
        let side_commit = side_filter.commit();
        let selected = Eq::from(non_residue_filter)
            + (Eq::from(residue_filter) - Eq::from(non_residue_filter)) * Fp::from(u64::from(bit));
        enforce_equal_point(
            Eq::from(side_commit),
            selected,
            "QrFilterDescend: side filter does not match header",
        )?;

        let extended_commit = extended.commit();
        let z = ctx.derive_challenge(&[side_commit.into(), extended_commit.into()])?;
        let side_at_z = side_filter.eval(z);
        let extended_at_z = extended.eval(z);
        ctx.enforce_poly_query(side_commit.into(), z, side_at_z)?;
        ctx.enforce_poly_query(extended_commit.into(), z, extended_at_z)?;
        enforce_zero(
            extended_at_z - side_at_z * (z - Fp::from(discriminant)),
            "QrFilterDescend: extended filter does not record this discriminant",
        )?;

        let (child_residue, child_non_residue) = if bit {
            (extended_commit, non_residue_filter)
        } else {
            (residue_filter, extended_commit)
        };
        Ok((
            (
                epoch,
                boundary,
                profile.descend(bit),
                discriminant.next(),
                child_residue,
                child_non_residue,
            ),
            (),
        ))
    }
}

/// A tachygram attested residue-side at every residue-side discriminant of
/// one profile's path, with the single-member sequence naming it in `epoch`.
#[derive(Clone, Debug)]
pub struct QrProfileClaim;

impl Header for QrProfileClaim {
    /// `(epoch, boundary, profile, discriminant, value, non_residue_filter,
    /// sequence)`.
    type Data = (
        EpochIndex,
        Anchor,
        QrProfile,
        QrDiscriminant,
        Tachygram,
        QrFilterCommit,
        NfSeqCommit,
    );

    const SUFFIX: Suffix = Suffix::new(17);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, boundary, profile, discriminant, value, non_residue_filter, sequence) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(boundary),
                Fp::from(profile.depth),
                Fp::from(profile.bits),
                Fp::from(discriminant),
                Fp::from(value),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(non_residue_filter), Eq::from(sequence)],
        )
    }
}

/// Attest a tachygram's residue-side classifications against one profile's
/// filter, and bind the single-member sequence naming it in `epoch`.
///
/// With $g$ interpolating the value's root at each residue-side discriminant,
///
/// $$
///   g(Y)^2 - (\mathsf{value} + Y) = P_\mathsf{res}(Y)\, h(Y)
/// $$
///
/// reads $g(R_j)^2 = \mathsf{value} + R_j$ at every root $R_j$ of
/// $P_\mathsf{res}$, at any depth.
///
/// Committed polynomials: the residue filter, its interpolant, its quotient,
/// the sequence; four oracles.
///
/// # Soundness
///
/// The filter is pinned to the header by commit-equality; `value` is free and
/// absorbed as $G_0 \cdot \mathsf{value}$ into both challenges, so the
/// identity forces `sequence` to the emitted member. Nothing here says the
/// value is a nullifier; [`QrUnspentInit`] attests the non-residue side, opens
/// the bucket, and gives the claim its segment reading.
#[derive(Debug)]
pub struct QrProfileAttest;

impl Step for QrProfileAttest {
    type Aux<'source> = ();
    type Left = QrFilter;
    type Output = QrProfileClaim;
    type Right = ();
    /// `(value, residue_filter, interpolant, quotient, sequence)`.
    type Witness<'source> = (
        Tachygram,
        QrFilterPoly,
        QrInterpolantPoly,
        QrQuotientPoly,
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(27);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (value, residue_filter, interpolant, quotient, sequence): Self::Witness<'source>,
        (epoch, boundary, profile, discriminant, residue_commit, non_residue_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(residue_filter.commit()),
            Eq::from(residue_commit),
            "QrProfileAttest: residue filter does not match header",
        )?;
        let tested = Fp::from(value);
        enforce_nonzero(tested, "QrProfileAttest: tested value is zero")?;

        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let binding = g0 * tested;

        let interpolant_commit = interpolant.commit();
        let quotient_commit = quotient.commit();
        let y = ctx.derive_challenge(&[
            residue_commit.into(),
            interpolant_commit.into(),
            quotient_commit.into(),
            binding,
        ])?;
        let filter_at_y = residue_filter.eval(y);
        let interpolant_at_y = interpolant.eval(y);
        let quotient_at_y = quotient.eval(y);
        ctx.enforce_poly_query(residue_commit.into(), y, filter_at_y)?;
        ctx.enforce_poly_query(interpolant_commit.into(), y, interpolant_at_y)?;
        ctx.enforce_poly_query(quotient_commit.into(), y, quotient_at_y)?;
        enforce_zero(
            interpolant_at_y.square() - (tested + y) - filter_at_y * quotient_at_y,
            "QrProfileAttest: value fails the residue side of this profile",
        )?;

        let sequence_commit = sequence.commit();
        let z = ctx.derive_challenge(&[sequence_commit.into(), binding])?;
        let sequence_at_z = sequence.eval(z);
        let member_at_z = indexed_multiset::direct_eval([(u64::from(epoch), tested)], z);
        enforce_zero(
            sequence_at_z - member_at_z,
            "QrProfileAttest: sequence does not match the tested value",
        )?;
        ctx.enforce_poly_query(sequence_commit.into(), z, sequence_at_z)?;

        Ok((
            (
                epoch,
                boundary,
                profile,
                discriminant,
                value,
                non_residue_commit,
                sequence_commit,
            ),
            (),
        ))
    }
}

/// One profile's members over a whole epoch.
///
/// `anchor_prev` is the epoch's opening boundary anchor, `anchor_last` its
/// terminal anchor, and `boundary` the closing tick that seeds the
/// discriminants. The bucket spans `[anchor_prev, anchor_last]`, so it never
/// leaves its epoch.
#[derive(Clone, Debug)]
pub struct QrBucket;

impl Header for QrBucket {
    /// `(epoch, anchor_prev, anchor_last, boundary, profile, discriminant,
    /// contents)`.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        Anchor,
        QrProfile,
        QrDiscriminant,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(18);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, boundary, profile, discriminant, contents) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
                Fp::from(boundary),
                Fp::from(profile.depth),
                Fp::from(profile.bits),
                Fp::from(discriminant),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(contents)],
        )
    }
}

/// Seal a fully routed [`QrIntake`] into a [`QrBucket`], by pinning both ends
/// of the epoch:
///
/// $$
///   \mathsf{anchor\_prev} = H_\mathsf{ep}(\mathsf{prev\_last},
///   \mathsf{epoch}), \qquad \mathsf{boundary} =
///   H_\mathsf{ep}(\mathsf{anchor\_last}, \mathsf{epoch} + 1).
/// $$
///
/// Committed polynomials: none.
///
/// # Soundness
///
/// Only an epoch transition produces an anchor in the epoch domain, so an
/// `anchor_prev` of this form is an epoch's opening boundary anchor.
/// `prev_last` is free, as at every seed; the lineage that consumes the
/// segment binds it. Epoch zero's opening anchor, [`Anchor::default`], is this
/// rule at $\mathsf{prev\_last} = 0$.
///
/// `boundary` is free at every root, but every discriminant the routing used
/// iterates from it. An intake that stops short carries an `anchor_last` whose
/// tick misses the `boundary` its own routing committed to, so completeness
/// is checked here rather than left to the consuming lineage.
#[derive(Debug)]
pub struct QrBucketSeal;

impl Step for QrBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    /// `(prev_last)`, the terminal anchor of the preceding epoch.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(29);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (prev_last,): Self::Witness<'source>,
        (epoch, anchor_prev, anchor_last, boundary, profile, discriminant, contents): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(anchor_prev)
                - poseidon::anchor_next_epoch(Fp::from(prev_last), Fp::from(u64::from(epoch.0))),
            "QrBucketSeal: intake does not begin at the epoch boundary",
        )?;
        let closing = anchor_last
            .next_epoch(epoch.next())
            .map_err(|_e| ragu::Error::InvalidWitness("invalid anchor step".into()))?;
        enforce_zero(
            Fp::from(boundary) - Fp::from(closing),
            "QrBucketSeal: intake does not run to the epoch's terminal anchor",
        )?;

        Ok((
            (
                epoch,
                anchor_prev,
                anchor_last,
                boundary,
                profile,
                discriminant,
                contents,
            ),
            (),
        ))
    }
}

/// Start an [`ArbitraryUnspent`] from a [`QrBucket`]: attest the claimed
/// value's non-residue side, then open the bucket at it for nonzero.
///
/// With [`QrProfileAttest`], the value's class is fixed at every discriminant
/// of the bucket's path, so no other bucket of the epoch can hold it. The
/// emitted segment reads the value as a nullifier and covers the bucket's own
/// span, one epoch, so consecutive epochs' segments need an
/// [`EndEpochUnspentSeed`](super::pool::EndEpochUnspentSeed) between them.
///
/// Committed polynomials: the non-residue filter, its interpolant, its
/// quotient, the contents; four oracles.
///
/// # Soundness
///
/// Claim and bucket must agree on epoch, boundary, profile and discriminant;
/// the span is [`QrBucketSeal`]'s. $\mathsf{nf} = -R_j$ has root zero under
/// either class, so the non-residue filter must open nonzero at
/// $-\mathsf{nf}$, matching where [`QrIntakeSplit`] files the exceptional
/// value.
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrProfileClaim;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    /// `(non_residue_filter, interpolant, quotient, contents)`.
    type Witness<'source> = (
        QrFilterPoly,
        QrInterpolantPoly,
        QrQuotientPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(28);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (non_residue_filter, interpolant, quotient, contents): Self::Witness<'source>,
        (epoch, boundary, profile, discriminant, value, non_residue_commit, sequence_commit): <Self::Left as Header>::Data,
        (
            bucket_epoch,
            anchor_prev,
            anchor_last,
            bucket_boundary,
            bucket_profile,
            bucket_discriminant,
            bucket_commit,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(u64::from(epoch.0)) - Fp::from(u64::from(bucket_epoch.0)),
            "QrUnspentInit: claim and bucket cover different epochs",
        )?;
        enforce_zero(
            Fp::from(boundary) - Fp::from(bucket_boundary),
            "QrUnspentInit: claim and bucket derive from different boundary anchors",
        )?;
        enforce_zero(
            Fp::from(profile.depth) - Fp::from(bucket_profile.depth),
            "QrUnspentInit: claim and bucket sit at different depths",
        )?;
        enforce_zero(
            Fp::from(profile.bits) - Fp::from(bucket_profile.bits),
            "QrUnspentInit: claim and bucket sit at different profiles",
        )?;
        enforce_zero(
            Fp::from(discriminant) - Fp::from(bucket_discriminant),
            "QrUnspentInit: claim and bucket disagree on the discriminant",
        )?;
        enforce_equal_point(
            Eq::from(non_residue_filter.commit()),
            Eq::from(non_residue_commit),
            "QrUnspentInit: non-residue filter does not match header",
        )?;
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(bucket_commit),
            "QrUnspentInit: contents do not match the bucket",
        )?;

        let tested = Fp::from(value);
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let binding = g0 * tested;
        let interpolant_commit = interpolant.commit();
        let quotient_commit = quotient.commit();
        let y = ctx.derive_challenge(&[
            non_residue_commit.into(),
            interpolant_commit.into(),
            quotient_commit.into(),
            binding,
        ])?;
        let filter_at_y = non_residue_filter.eval(y);
        let interpolant_at_y = interpolant.eval(y);
        let quotient_at_y = quotient.eval(y);
        ctx.enforce_poly_query(non_residue_commit.into(), y, filter_at_y)?;
        ctx.enforce_poly_query(interpolant_commit.into(), y, interpolant_at_y)?;
        ctx.enforce_poly_query(quotient_commit.into(), y, quotient_at_y)?;
        enforce_zero(
            interpolant_at_y.square()
                - QUADRATIC_NON_RESIDUE * (tested + y)
                - filter_at_y * quotient_at_y,
            "QrUnspentInit: nullifier fails the non-residue side of this profile",
        )?;

        let filter_at_exceptional = non_residue_filter.eval(-tested);
        ctx.enforce_poly_query(non_residue_commit.into(), -tested, filter_at_exceptional)?;
        enforce_nonzero(
            filter_at_exceptional,
            "QrUnspentInit: exceptional discriminant claimed the non-residue class",
        )?;

        let contents_at_value = contents.eval(tested);
        ctx.enforce_poly_query(bucket_commit.into(), tested, contents_at_value)?;
        enforce_nonzero(
            contents_at_value,
            "QrUnspentInit: found nullifier in the bucket",
        )?;

        let nf = Nullifier::from(value);
        Ok((
            (
                anchor_prev,
                (epoch, nf),
                sequence_commit,
                (epoch, nf),
                anchor_last,
            ),
            (),
        ))
    }
}
