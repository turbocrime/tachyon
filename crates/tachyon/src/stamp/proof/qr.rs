//! QR epoch-evidence steps.
//!
//! One [`QrBucket`] lineage is a unary chain: seeded empty at its epoch's
//! opening sentinel by [`QrBucketSeed`], advanced one tachygram set per
//! [`QrBucketAbsorb`] (which folds the set's anchor in-step and classifies
//! every value against the leaf's profile), and split by
//! [`QrBucketLeftDecomp`] / [`QrBucketRightDecomp`] when it overflows. QR
//! proofs are never merged; the tree forks only at splits, where both
//! children consume the same parent proof. The lineage's right endpoint is
//! the last absorbed anchor; epoch termination is checked at the consumer
//! seam, not here.
//!
//! The consumer is [`QrUnspentLift`]: one step reading the discriminant
//! scalars off the evidence header, paying one square check per split and
//! one polynomial query.
//!
//! Every polynomial identity is an in-step oracle claim over witnessed
//! polynomials, checked on scalars opened at one challenge. A side of a
//! split is certified by its class decomposition $(g, h)$:
//!
//! $$
//!   g(X)^2 - \mathsf{class} \cdot (X + R) = q(X) \cdot h(X)
//! $$
//!
//! with $\mathsf{class} = 1$ on the residue side and the quadratic
//! non-residue $c$ otherwise, and $q$ the side's members as roots. The
//! exceptional value $-R$ is pinned to the residue side: the decomposition
//! opens $p_2(-R) \neq 0$ so the non-residue child cannot hide it, and the
//! per-value inverse guards force it onto the residue branch everywhere a
//! value is classified.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Header, Index, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::pool::ArbitraryUnspent;
use crate::primitives::{
    Anchor, EpochIndex, QrDiscriminant, QrProfile, TachygramSetCommit, TachygramSetPoly,
};

/// Maximum split depth: the header discriminant-array width and the
/// per-value classification width inside steps.
pub const MAX_QR_DEPTH: usize = 32;

/// Maximum tachygram count of one absorbed set: the absorb step's
/// per-value witness width, and the item-3 bounded-batch constant.
pub const MAX_STAMP_TACHYGRAMS: usize = 64;

/// The least quadratic non-residue of the Pallas base field, verified by
/// Euler's criterion in the native-algebra tests. Distinct from the *cubic*
/// non-residue the sequence encoding uses.
pub const QUADRATIC_NON_RESIDUE: Fp = Fp::from_raw([5, 0, 0, 0]);

/// One node of an epoch's QR evidence chain.
///
/// A bucket commits only to what it currently holds. Discriminants are
/// minted by the decomps from the momentary anchor and written as certified
/// literals — never free witnesses; unwritten slots are zero, and the
/// nonzero prefix agrees with the profile's depth by the seed/decomp
/// lockstep invariant.
#[derive(Clone, Debug)]
pub struct QrBucket;

impl Header for QrBucket {
    /// `(epoch, sntl, last_anchor, discriminants, profile, bucket_commit)`:
    /// the epoch under evidence, its opening sentinel, the last absorbed
    /// anchor, the per-split discriminants (zero beyond the depth), the
    /// self-delimiting profile literal, and the contents commit.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        [QrDiscriminant; MAX_QR_DEPTH],
        QrProfile,
        TachygramSetCommit,
    );

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, sntl, last_anchor, discriminants, profile, bucket_commit) = *data;
        let mut scalars = vec![
            Fp::from(u64::from(epoch.0)),
            Fp::from(sntl),
            Fp::from(last_anchor),
        ];
        scalars.extend(
            discriminants
                .iter()
                .map(|&discriminant| Fp::from(discriminant)),
        );
        scalars.push(Fp::from(profile));
        (
            scalars,
            Vec::new(),
            Vec::new(),
            vec![Eq::from(bucket_commit)],
        )
    }
}

/// Seed one epoch's evidence chain: the empty bucket at the epoch's
/// opening sentinel, before any absorption.
///
/// # Soundness
///
/// `epoch` and `sntl` are free here; they close at the consumer seam and
/// ultimately at the consensus canonical-anchor check.
#[derive(Debug)]
pub struct QrBucketSeed;

impl Step for QrBucketSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrBucket;
    type Right = ();
    /// `(epoch, sntl)`.
    type Witness<'source> = (EpochIndex, Anchor);

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (epoch, sntl): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            (
                epoch,
                sntl,
                sntl,
                [QrDiscriminant::ZERO; MAX_QR_DEPTH],
                QrProfile::ROOT,
                TachygramSetCommit::default(),
            ),
            (),
        ))
    }
}

/// Absorb one tachygram set into the chain: fold its anchor, classify
/// every value against the leaf's profile, and multiply in exactly the
/// matching values.
///
/// The witnessed scalar list is bound to the witnessed set polynomial by a
/// product identity at the challenge, and the set polynomial's commitment
/// is what the anchor fold absorbs — so the classified values are exactly
/// the consensus-published set, and omission or misfiling is impossible:
/// each value's bits are pinned by its blended arms, and a value enters the
/// accumulator iff its bits equal the leaf profile's.
///
/// # Soundness
///
/// The anchor fold pins the set: consensus recomputes the anchor chain
/// from published commitments, so any other set puts the lineage's
/// endpoint off the chain.
#[derive(Debug)]
pub struct QrBucketAbsorb;

impl Step for QrBucketAbsorb {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = QrBucket;
    type Right = ();
    /// `(bucket, updated_bucket, stamp_tg_set, values)`: the accumulator
    /// before and after, the absorbed tachygram set, and per value its
    /// tachygram scalar (zero = padding; real tachygrams are nonzero) with
    /// per split `(root, bit, inverse)` — the square root of
    /// $\mathsf{tg} + R_j$ (bit set) or of $c \cdot (\mathsf{tg} + R_j)$
    /// (bit clear), the value's class at that split, and the inverse of
    /// $\mathsf{tg} + R_j$ guarding the non-residue branch against the
    /// exceptional value. Split slots at or beyond the profile's depth
    /// ride unchecked.
    type Witness<'source> = (
        TachygramSetPoly,
        TachygramSetPoly,
        TachygramSetPoly,
        [(Fp, [(Fp, bool, Fp); MAX_QR_DEPTH]); MAX_STAMP_TACHYGRAMS],
    );

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (bucket, updated_bucket, stamp_tg_set, values): Self::Witness<'source>,
        (epoch, sntl, last_anchor, discriminants, profile, bucket_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(bucket.commit()),
            Eq::from(bucket_commit),
            "QrBucketAbsorb: bucket polynomial does not match header",
        )?;

        let stamp_commit = stamp_tg_set.commit();
        let folded = last_anchor
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu::Error::InvalidWitness("QrBucketAbsorb: invalid anchor step".into()))?;

        let updated_commit = updated_bucket.commit();
        let z = ctx.derive_challenge(&[
            updated_commit.into(),
            bucket.commit().into(),
            stamp_commit.into(),
        ])?;
        let bucket_at_z = bucket.eval(z);
        let updated_at_z = updated_bucket.eval(z);
        let stamp_at_z = stamp_tg_set.eval(z);
        ctx.enforce_poly_query(bucket.commit().into(), z, bucket_at_z)?;
        ctx.enforce_poly_query(updated_commit.into(), z, updated_at_z)?;
        ctx.enforce_poly_query(stamp_commit.into(), z, stamp_at_z)?;

        let leaf_bits = profile.bits();
        let mut whole_set_at_z = Fp::ONE;
        let mut absorbed_at_z = Fp::ONE;
        for (tachygram, splits) in values {
            if tachygram == Fp::ZERO {
                continue;
            }
            whole_set_at_z *= z - tachygram;

            let mut matches = true;
            for (split, &leaf_bit) in leaf_bits.iter().enumerate() {
                let (root, bit, inverse) = *splits.get(split).ok_or_else(|| {
                    ragu::Error::InvalidWitness(
                        "QrBucketAbsorb: depth exceeds classification slots".into(),
                    )
                })?;
                let discriminant = *discriminants.get(split).ok_or_else(|| {
                    ragu::Error::InvalidWitness(
                        "QrBucketAbsorb: depth exceeds discriminant slots".into(),
                    )
                })?;
                let selector = Fp::from(u64::from(bit));
                let translated = tachygram + Fp::from(discriminant);
                enforce_zero(
                    selector * (root.square() - translated)
                        + (Fp::ONE - selector)
                            * (root.square() - QUADRATIC_NON_RESIDUE * translated),
                    "QrBucketAbsorb: root does not match the claimed class",
                )?;
                enforce_zero(
                    (Fp::ONE - selector) * (translated * inverse - Fp::ONE),
                    "QrBucketAbsorb: exceptional value hidden on the non-residue branch",
                )?;
                matches &= bit == leaf_bit;
            }
            if matches {
                absorbed_at_z *= z - tachygram;
            }
        }

        // The scalar list is exactly the witnessed set: every consensus
        // value is classified, none invented.
        enforce_zero(
            stamp_at_z - whole_set_at_z,
            "QrBucketAbsorb: scalar values do not multiply to the set polynomial",
        )?;
        // Exactly the matching values enter the accumulator.
        enforce_zero(
            updated_at_z - bucket_at_z * absorbed_at_z,
            "QrBucketAbsorb: updated bucket is not bucket times the matching values",
        )?;

        Ok((
            (
                epoch,
                sntl,
                folded,
                discriminants,
                profile,
                updated_commit,
            ),
            (),
        ))
    }
}

/// Split an overflowing bucket, emitting the residue-side child (profile
/// bit $1$).
///
/// Runs the full decomposition test: mints the one new discriminant
/// in-step from the momentary anchor and the previous discriminant — never
/// a free witness — checks $p = p_1 \cdot p_2$ and both sides' class
/// decompositions at one challenge, and opens $p_2(-R) \neq 0$ so the
/// non-residue child cannot hide the exceptional value.
/// [`QrBucketRightDecomp`] runs the identical test over the same parent;
/// each child's chain-covering statement needs the whole decomposition.
#[derive(Debug)]
pub struct QrBucketLeftDecomp;

impl Step for QrBucketLeftDecomp {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = QrBucket;
    type Right = ();
    /// `(parent, residue_side, non_residue_side, residue_cert,
    /// non_residue_cert)`: the parent contents matching the header commit,
    /// its two sides ($p_1$ carries $-R$ by convention), and each side's
    /// class decomposition at the new discriminant.
    type Witness<'source> = (
        TachygramSetPoly,
        TachygramSetPoly,
        TachygramSetPoly,
        (Polynomial, Polynomial),
        (Polynomial, Polynomial),
    );

    const INDEX: Index = Index::new(19);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (parent, residue_side, non_residue_side, residue_cert, non_residue_cert): Self::Witness<
            'source,
        >,
        (epoch, sntl, last_anchor, discriminants, profile, bucket_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(parent.commit()),
            Eq::from(bucket_commit),
            "QrBucketLeftDecomp: parent polynomial does not match header",
        )?;

        // Mint the one new discriminant from the momentary anchor and the
        // previous chain value (zero at the first split).
        let depth = profile.depth();
        let previous = match depth.checked_sub(1) {
            None => QrDiscriminant::ZERO,
            Some(last) => *discriminants.get(last).ok_or_else(|| {
                ragu::Error::InvalidWitness(
                    "QrBucketLeftDecomp: profile depth exceeds discriminant slots".into(),
                )
            })?,
        };
        let new_discriminant = previous.next(last_anchor);
        let mut extended = discriminants;
        let slot = extended.get_mut(depth).ok_or_else(|| {
            ragu::Error::InvalidWitness("QrBucketLeftDecomp: bucket is at maximum depth".into())
        })?;
        enforce_zero(
            Fp::from(*slot),
            "QrBucketLeftDecomp: the next discriminant slot is already written",
        )?;
        *slot = new_discriminant;

        let residue_commit = residue_side.commit();
        let non_residue_commit = non_residue_side.commit();
        let z = ctx.derive_challenge(&[
            parent.commit().into(),
            residue_commit.into(),
            non_residue_commit.into(),
        ])?;

        let parent_at_z = parent.eval(z);
        let residue_at_z = residue_side.eval(z);
        let non_residue_at_z = non_residue_side.eval(z);
        ctx.enforce_poly_query(parent.commit().into(), z, parent_at_z)?;
        ctx.enforce_poly_query(residue_commit.into(), z, residue_at_z)?;
        ctx.enforce_poly_query(non_residue_commit.into(), z, non_residue_at_z)?;
        enforce_zero(
            parent_at_z - residue_at_z * non_residue_at_z,
            "QrBucketLeftDecomp: sides do not multiply to the parent",
        )?;

        let residue_interpolant_at_z = residue_cert.0.eval(z);
        let residue_quotient_at_z = residue_cert.1.eval(z);
        ctx.enforce_poly_query(residue_cert.0.commit(), z, residue_interpolant_at_z)?;
        ctx.enforce_poly_query(residue_cert.1.commit(), z, residue_quotient_at_z)?;
        enforce_zero(
            residue_interpolant_at_z.square()
                - (z + Fp::from(new_discriminant))
                - residue_at_z * residue_quotient_at_z,
            "QrBucketLeftDecomp: residue side fails its decomposition",
        )?;

        let non_residue_interpolant_at_z = non_residue_cert.0.eval(z);
        let non_residue_quotient_at_z = non_residue_cert.1.eval(z);
        ctx.enforce_poly_query(non_residue_cert.0.commit(), z, non_residue_interpolant_at_z)?;
        ctx.enforce_poly_query(non_residue_cert.1.commit(), z, non_residue_quotient_at_z)?;
        enforce_zero(
            non_residue_interpolant_at_z.square()
                - QUADRATIC_NON_RESIDUE * (z + Fp::from(new_discriminant))
                - non_residue_at_z * non_residue_quotient_at_z,
            "QrBucketLeftDecomp: non-residue side fails its decomposition",
        )?;

        // The exceptional value is pinned to the residue side: the
        // non-residue child must not vanish at -R.
        let at_exceptional = non_residue_side.eval(-Fp::from(new_discriminant));
        ctx.enforce_poly_query(
            non_residue_commit.into(),
            -Fp::from(new_discriminant),
            at_exceptional,
        )?;
        enforce_nonzero(
            at_exceptional,
            "QrBucketLeftDecomp: exceptional value hidden on the non-residue side",
        )?;

        Ok((
            (
                epoch,
                sntl,
                last_anchor,
                extended,
                profile.child(true),
                residue_commit,
            ),
            (),
        ))
    }
}

/// Split an overflowing bucket, emitting the non-residue-side child
/// (profile bit $0$).
///
/// Runs the identical decomposition test as [`QrBucketLeftDecomp`] over the
/// same parent; each child's chain-covering statement needs the whole test.
#[derive(Debug)]
pub struct QrBucketRightDecomp;

impl Step for QrBucketRightDecomp {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = QrBucket;
    type Right = ();
    /// `(parent, residue_side, non_residue_side, residue_cert,
    /// non_residue_cert)`: the parent contents matching the header commit,
    /// its two sides ($p_1$ carries $-R$ by convention), and each side's
    /// class decomposition at the new discriminant.
    type Witness<'source> = (
        TachygramSetPoly,
        TachygramSetPoly,
        TachygramSetPoly,
        (Polynomial, Polynomial),
        (Polynomial, Polynomial),
    );

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (parent, residue_side, non_residue_side, residue_cert, non_residue_cert): Self::Witness<
            'source,
        >,
        (epoch, sntl, last_anchor, discriminants, profile, bucket_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(parent.commit()),
            Eq::from(bucket_commit),
            "QrBucketRightDecomp: parent polynomial does not match header",
        )?;

        // Mint the one new discriminant from the momentary anchor and the
        // previous chain value (zero at the first split).
        let depth = profile.depth();
        let previous = match depth.checked_sub(1) {
            None => QrDiscriminant::ZERO,
            Some(last) => *discriminants.get(last).ok_or_else(|| {
                ragu::Error::InvalidWitness(
                    "QrBucketRightDecomp: profile depth exceeds discriminant slots".into(),
                )
            })?,
        };
        let new_discriminant = previous.next(last_anchor);
        let mut extended = discriminants;
        let slot = extended.get_mut(depth).ok_or_else(|| {
            ragu::Error::InvalidWitness("QrBucketRightDecomp: bucket is at maximum depth".into())
        })?;
        enforce_zero(
            Fp::from(*slot),
            "QrBucketRightDecomp: the next discriminant slot is already written",
        )?;
        *slot = new_discriminant;

        let residue_commit = residue_side.commit();
        let non_residue_commit = non_residue_side.commit();
        let z = ctx.derive_challenge(&[
            parent.commit().into(),
            residue_commit.into(),
            non_residue_commit.into(),
        ])?;

        let parent_at_z = parent.eval(z);
        let residue_at_z = residue_side.eval(z);
        let non_residue_at_z = non_residue_side.eval(z);
        ctx.enforce_poly_query(parent.commit().into(), z, parent_at_z)?;
        ctx.enforce_poly_query(residue_commit.into(), z, residue_at_z)?;
        ctx.enforce_poly_query(non_residue_commit.into(), z, non_residue_at_z)?;
        enforce_zero(
            parent_at_z - residue_at_z * non_residue_at_z,
            "QrBucketRightDecomp: sides do not multiply to the parent",
        )?;

        let residue_interpolant_at_z = residue_cert.0.eval(z);
        let residue_quotient_at_z = residue_cert.1.eval(z);
        ctx.enforce_poly_query(residue_cert.0.commit(), z, residue_interpolant_at_z)?;
        ctx.enforce_poly_query(residue_cert.1.commit(), z, residue_quotient_at_z)?;
        enforce_zero(
            residue_interpolant_at_z.square()
                - (z + Fp::from(new_discriminant))
                - residue_at_z * residue_quotient_at_z,
            "QrBucketRightDecomp: residue side fails its decomposition",
        )?;

        let non_residue_interpolant_at_z = non_residue_cert.0.eval(z);
        let non_residue_quotient_at_z = non_residue_cert.1.eval(z);
        ctx.enforce_poly_query(non_residue_cert.0.commit(), z, non_residue_interpolant_at_z)?;
        ctx.enforce_poly_query(non_residue_cert.1.commit(), z, non_residue_quotient_at_z)?;
        enforce_zero(
            non_residue_interpolant_at_z.square()
                - QUADRATIC_NON_RESIDUE * (z + Fp::from(new_discriminant))
                - non_residue_at_z * non_residue_quotient_at_z,
            "QrBucketRightDecomp: non-residue side fails its decomposition",
        )?;

        // The exceptional value is pinned to the residue side: the
        // non-residue child must not vanish at -R.
        let at_exceptional = non_residue_side.eval(-Fp::from(new_discriminant));
        ctx.enforce_poly_query(
            non_residue_commit.into(),
            -Fp::from(new_discriminant),
            at_exceptional,
        )?;
        enforce_nonzero(
            at_exceptional,
            "QrBucketRightDecomp: exceptional value hidden on the non-residue side",
        )?;

        Ok((
            (
                epoch,
                sntl,
                last_anchor,
                extended,
                profile.child(false),
                non_residue_commit,
            ),
            (),
        ))
    }
}

/// Test one nullifier against one epoch's QR evidence, advancing an
/// unspent lineage across the whole epoch in one step.
///
/// The lineage's member for the epoch is already present (its tick seed
/// supplied it); this step proves the member excluded from the epoch's
/// tachygrams via one bucket query instead of a per-stamp walk, and
/// advances the anchor to the bucket endpoint — which the next tick's
/// `anchor_prev` must meet at the fuse seam.
///
/// # Soundness
///
/// Discriminants are READ from the evidence header — consumers derive
/// nothing. The bits come from the header profile, not witness data; per
/// active split the arm forces the witnessed root to the bit's class and
/// the inverse guard forces $-R_j$ onto the residue branch. A wrong-side
/// classification is caught here and nowhere else: this step is the sole
/// gatekeeper of that lie.
#[derive(Debug)]
pub struct QrUnspentLift;

impl Step for QrUnspentLift {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    /// `(bucket, classifications)`: the bucket accumulator matching the
    /// evidence header's commit, and per split the tested nullifier's
    /// `(root, inverse)` — the square root of $\mathsf{nf} + R_j$ (profile
    /// bit set) or of $c \cdot (\mathsf{nf} + R_j)$, and the inverse of
    /// $\mathsf{nf} + R_j$ guarding the non-residue branch against the
    /// exceptional value. Slots at or beyond the bucket's depth ride
    /// unchecked.
    type Witness<'source> = (TachygramSetPoly, [(Fp, Fp); MAX_QR_DEPTH]);

    const INDEX: Index = Index::new(21);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (bucket, classifications): Self::Witness<'source>,
        (
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_last, unspent_nf_last),
            unspent_anchor_last,
        ): <Self::Left as Header>::Data,
        (bucket_epoch, bucket_sntl, bucket_last_anchor, discriminants, profile, bucket_commit): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(unspent_anchor_last) - Fp::from(bucket_sntl),
            "QrUnspentLift: lineage does not end at the bucket's sentinel",
        )?;
        enforce_zero(
            Fp::from(u64::from(unspent_epoch_last.0)) - Fp::from(u64::from(bucket_epoch.0)),
            "QrUnspentLift: lineage tip epoch does not match the evidence",
        )?;
        enforce_equal_point(
            Eq::from(bucket.commit()),
            Eq::from(bucket_commit),
            "QrUnspentLift: bucket polynomial does not match header",
        )?;

        // Classification: discriminants read from the header, bits from
        // the header profile; the fixed-loop form is the uniform per-slot
        // select over the scalar array.
        let tested = Fp::from(unspent_nf_last);
        for (split, &bit) in profile.bits().iter().enumerate() {
            let (root, inverse) = *classifications.get(split).ok_or_else(|| {
                ragu::Error::InvalidWitness(
                    "QrUnspentLift: depth exceeds classification slots".into(),
                )
            })?;
            let discriminant = *discriminants.get(split).ok_or_else(|| {
                ragu::Error::InvalidWitness(
                    "QrUnspentLift: depth exceeds discriminant slots".into(),
                )
            })?;
            let translated = tested + Fp::from(discriminant);
            let arm = if bit {
                root.square() - translated
            } else {
                root.square() - QUADRATIC_NON_RESIDUE * translated
            };
            enforce_zero(arm, "QrUnspentLift: root does not match the bit's class")?;
            if !bit {
                enforce_zero(
                    translated * inverse - Fp::ONE,
                    "QrUnspentLift: exceptional value hidden on the non-residue branch",
                )?;
            }
        }

        // The exclusion query: one member, one bucket, one epoch.
        let eval = bucket.eval(tested);
        ctx.enforce_poly_query(bucket_commit.into(), tested, eval)?;
        enforce_nonzero(eval, "QrUnspentLift: found nullifier in the bucket")?;

        Ok((
            (
                unspent_anchor_prev,
                (unspent_epoch_start, unspent_nf_start),
                unspent_elapsed,
                (unspent_epoch_last, unspent_nf_last),
                bucket_last_anchor,
            ),
            (),
        ))
    }
}
