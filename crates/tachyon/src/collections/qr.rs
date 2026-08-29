//! # Quadratic-residue classification
//!
//! Fix an offset $R$. Every field element $x$ falls on exactly one side of
//! $R$ according to the quadratic character of the shift:
//!
//! $$
//!   \chi(x + R) \neq -1
//!       \quad \iff \quad
//!   x \text{ is on the residue side of } R
//! $$
//!
//! The exceptional value $x = -R$ has $\chi(0) = 0$ and is pinned to the
//! residue side by this convention.
//!
//! ## Certificates
//!
//! A side is certified for a whole set at once. With
//! $q(X) = \prod_i (X - x_i)$, an interpolant $g$ through the classification
//! roots and a quotient $h$ witness
//!
//! $$
//!   g(X)^2 - \mathsf{class} \cdot (X + R) = q(X) \cdot h(X)
//! $$
//!
//! where $\mathsf{class} = 1$ on the residue side and the quadratic
//! non-residue $c$ on the other. The identity holds identically in $X$ only
//! when every root of $q$ lies on the claimed side, so checking it at a
//! random challenge certifies the whole set.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use ragu::Polynomial;
use ragu_arithmetic as arithmetic;

pub(crate) const QUADRATIC_NON_RESIDUE: Fp = Fp::from_raw([5, 0, 0, 0]);

/// Maximum bucket size $B$.
pub(crate) const MAX_BUCKET_SIZE: usize = 8096;

/// Classify $x$ relative to `offset`.
///
/// The bit is $1$ iff $x + R$ is a square or zero (the $-R$ convention). The
/// returned root satisfies $\mathsf{root}^2 = x + R$ on the residue side and
/// $\mathsf{root}^2 = c \cdot (x + R)$ on the non-residue side.
pub(crate) fn classify(value: Fp, offset: Fp) -> (bool, Fp) {
    let shifted = value + offset;
    if let Some(root) = Option::<Fp>::from(shifted.sqrt()) {
        return (true, root);
    }
    // The character is multiplicative and c is a non-residue, so exactly
    // one of the two character branches has a root.
    let root = Option::<Fp>::from((QUADRATIC_NON_RESIDUE * shifted).sqrt());
    #[expect(
        clippy::expect_used,
        reason = "one of the two character branches always has a root"
    )]
    (false, root.expect("non-residue branch has a root"))
}

/// One side's classification points $(x_i, y_i)$: each $y_i$ is the
/// member's classification root.
pub(crate) type ClassificationPoints = Vec<(Fp, Fp)>;

/// Split members by their side of `offset`, in evaluation form.
///
/// Returns the residue-side and non-residue-side classification points.
/// Every member lands in exactly one side; the exceptional value $-R$
/// lands on the residue side.
pub(crate) fn split(
    members: impl IntoIterator<Item = Fp>,
    offset: Fp,
) -> (ClassificationPoints, ClassificationPoints) {
    let mut residue = Vec::new();
    let mut non_residue = Vec::new();
    for member in members {
        let (bit, root) = classify(member, offset);
        if bit {
            residue.push((member, root));
        } else {
            non_residue.push((member, root));
        }
    }
    (residue, non_residue)
}

/// Class decomposition $(g, h)$ of one side from its classification points:
///
/// $$
///   g(X)^2 - \mathsf{class} \cdot (X + R) = q(X) \cdot h(X)
/// $$
///
/// where $q$ has the members as roots and $\mathsf{class}$ is $1$ when
/// `side` is the residue side and $c$ otherwise. The points must be
/// [`split`] (or [`classify`]) output for `side` at `offset`.
///
/// Returns `None` when the members are not distinct — the honest-builder
/// failure surface.
pub(crate) fn decomposition(
    points: &[(Fp, Fp)],
    offset: Fp,
    side: bool,
) -> Option<(Polynomial, Polynomial)> {
    let g_coeffs = super::interpolate(points)?;
    let class = if side { Fp::ONE } else { QUADRATIC_NON_RESIDUE };

    // With $N = g^2 - \mathsf{class} \cdot (X + R)$ and squarefree $q$,
    // differentiating $N = q h$ gives $h(x_i) = N'(x_i) / q'(x_i)$ at each
    // root, where $N' = 2 g g' - \mathsf{class}$ and $g(x_i)$ is the
    // classification root. For the empty side $q = 1$ and $h = N$.
    let h_coeffs = if points.is_empty() {
        [-class * offset, -class].to_vec()
    } else {
        let members: Vec<Fp> = points.iter().map(|&(member, _)| member).collect();
        let g_derivative = super::derivative(&g_coeffs);
        let q_derivative = super::derivative(&arithmetic::poly_with_roots(&members));
        let h_points: Vec<(Fp, Fp)> = points
            .iter()
            .map(|&(member, root)| {
                let numerator_slope = root.double() * g_derivative.eval(member) - class;
                let normalizer = Option::<Fp>::from(q_derivative.eval(member).invert())?;
                Some((member, numerator_slope * normalizer))
            })
            .collect::<Option<Vec<_>>>()?;
        super::interpolate(&h_points)?
    };

    Some((
        Polynomial::from_coeffs(g_coeffs),
        Polynomial::from_coeffs(h_coeffs),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::min_ident_chars, reason = "test code")]

    use core::iter;

    use ff::PrimeField as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::collections::multiset;

    /// $(p - 1) / 2$ as `pow_vartime` limbs, computed from field constants.
    fn half_order() -> [u64; 4] {
        let half = -Fp::ONE * Fp::TWO_INV;
        let repr = half.to_repr();
        let mut limbs = [0u64; 4];
        for (limb, bytes) in limbs.iter_mut().zip(repr.as_ref().chunks(8)) {
            *limb = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        limbs
    }

    /// Euler-criterion quadratic character: $1$, $-1$, or $0$.
    fn chi(x: Fp) -> Fp {
        x.pow_vartime(half_order())
    }

    #[test]
    fn the_non_residue_constant_satisfies_the_euler_criterion() {
        assert_eq!(chi(QUADRATIC_NON_RESIDUE), -Fp::ONE);
    }

    #[test]
    fn small_cubic_non_residues_are_quadratic_residues() {
        assert_eq!(chi(Fp::from(2)), Fp::ONE);
        assert_eq!(chi(Fp::from(3)), Fp::ONE);
    }

    #[test]
    fn classification_matches_the_legendre_symbol() {
        let rng = &mut StdRng::seed_from_u64(21);
        for _ in 0..64 {
            let x = Fp::random(&mut *rng);
            let offset = Fp::random(&mut *rng);
            let (bit, root) = classify(x, offset);
            assert_eq!(bit, chi(x + offset) != -Fp::ONE);
            let class = if bit { Fp::ONE } else { QUADRATIC_NON_RESIDUE };
            assert_eq!(root.square(), class * (x + offset));
        }
    }

    #[test]
    fn the_exceptional_value_is_pinned_to_the_residue_side() {
        let rng = &mut StdRng::seed_from_u64(22);
        let offset = Fp::random(&mut *rng);
        assert_eq!(classify(-offset, offset), (true, Fp::ZERO));
    }

    #[test]
    fn splits_are_exhaustive_and_disjoint() {
        let rng = &mut StdRng::seed_from_u64(30);
        let offset = Fp::random(&mut *rng);
        let members: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(64)
            .collect();

        let (residue, non_residue) = split(members.iter().copied(), offset);
        assert_eq!(residue.len() + non_residue.len(), members.len());
        for &(member, root) in &residue {
            assert_ne!(chi(member + offset), -Fp::ONE);
            assert_eq!(root.square(), member + offset);
        }
        for &(member, root) in &non_residue {
            assert_eq!(chi(member + offset), -Fp::ONE);
            assert_eq!(root.square(), QUADRATIC_NON_RESIDUE * (member + offset));
        }
    }

    /// Collects a polynomial's coefficients with the sparse capacity padding
    /// trimmed; the zero polynomial densifies to `[0]`.
    fn dense(poly: &Polynomial) -> Vec<Fp> {
        let mut coeffs = Vec::from_iter(poly.iter_coeffs());
        let last_nonzero = coeffs.iter().rposition(|coeff| coeff != &Fp::ZERO);
        coeffs.truncate(last_nonzero.map_or(1, |idx| idx + 1));
        coeffs
    }

    /// Verifies $g^2 - \mathsf{class}\cdot(X + R) = q \cdot h$ coefficient by
    /// coefficient, since exact division through `factor` silently drops any
    /// remainder.
    fn verify_certificate(members: &[Fp], offset: Fp, side: bool, g: &Polynomial, h: &Polynomial) {
        let class = if side { Fp::ONE } else { QUADRATIC_NON_RESIDUE };

        let g_coeffs = dense(g);
        let mut expected = Vec::new();
        arithmetic::poly_mul(&g_coeffs, &g_coeffs, &mut expected);
        if expected.len() < 2 {
            expected.resize(2, Fp::ZERO);
        }
        expected[0] -= class * offset;
        expected[1] -= class;

        let bucket = arithmetic::poly_with_roots(members);
        let mut product = Vec::new();
        arithmetic::poly_mul(&bucket, &dense(h), &mut product);
        while product.len() < expected.len() {
            product.push(Fp::ZERO);
        }
        while expected.len() < product.len() {
            expected.push(Fp::ZERO);
        }
        assert_eq!(product, expected);
    }

    /// Classification points drawn onto one side of the offset by rejection
    /// sampling.
    fn side_points(rng: &mut StdRng, offset: Fp, side: bool, count: usize) -> Vec<(Fp, Fp)> {
        iter::repeat_with(|| Fp::random(&mut *rng))
            .filter_map(|x| {
                let (bit, root) = classify(x, offset);
                (bit == side).then_some((x, root))
            })
            .take(count)
            .collect()
    }

    fn point_members(points: &[(Fp, Fp)]) -> Vec<Fp> {
        points.iter().map(|&(member, _)| member).collect()
    }

    #[test]
    fn decompositions_hold_for_single_members_on_both_sides() {
        let rng = &mut StdRng::seed_from_u64(23);
        for side in [true, false] {
            let offset = Fp::random(&mut *rng);
            let points = side_points(rng, offset, side, 1);
            let (g, h) = decomposition(&points, offset, side).unwrap();
            verify_certificate(&point_members(&points), offset, side, &g, &h);
        }
    }

    #[test]
    fn decompositions_hold_for_two_members_on_both_sides() {
        let rng = &mut StdRng::seed_from_u64(24);
        for side in [true, false] {
            let offset = Fp::random(&mut *rng);
            let points = side_points(rng, offset, side, 2);
            let (g, h) = decomposition(&points, offset, side).unwrap();
            verify_certificate(&point_members(&points), offset, side, &g, &h);
        }
    }

    #[test]
    fn decompositions_hold_for_the_empty_side() {
        let rng = &mut StdRng::seed_from_u64(25);
        for side in [true, false] {
            let offset = Fp::random(&mut *rng);
            let (g, h) = decomposition(&[], offset, side).unwrap();
            verify_certificate(&[], offset, side, &g, &h);
        }
    }

    #[test]
    fn decompositions_hold_at_the_maximum_bucket_size() {
        let rng = &mut StdRng::seed_from_u64(26);
        let offset = Fp::random(&mut *rng);
        let points = side_points(rng, offset, true, MAX_BUCKET_SIZE);
        let (g, h) = decomposition(&points, offset, true).unwrap();
        let members = point_members(&points);

        // Degree bounds: g < B and h <= B - 2, both under the 8192
        // coefficient cap enforced by `Polynomial::from_coeffs`.
        assert!(dense(&g).len() <= MAX_BUCKET_SIZE, "g exceeds B");
        assert!(dense(&h).len() < MAX_BUCKET_SIZE, "h exceeds B - 2");

        // The full coefficient compare is quadratic in B; evaluation at
        // random points verifies the identity in linear time instead.
        let bucket = multiset::encode(members.iter().copied());
        for _ in 0..4 {
            let z = Fp::random(&mut *rng);
            assert_eq!(
                g.eval(z).square() - (z + offset),
                bucket.eval(z) * h.eval(z),
            );
        }
    }

    #[test]
    fn split_and_decomposition_certify_both_sides_of_a_mixed_set() {
        let rng = &mut StdRng::seed_from_u64(27);
        let offset = Fp::random(&mut *rng);
        let members: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(32)
            .collect();

        let (residue, non_residue) = split(members.iter().copied(), offset);
        let (g_r, h_r) = decomposition(&residue, offset, true).unwrap();
        verify_certificate(&point_members(&residue), offset, true, &g_r, &h_r);
        let (g_n, h_n) = decomposition(&non_residue, offset, false).unwrap();
        verify_certificate(&point_members(&non_residue), offset, false, &g_n, &h_n);
    }

    #[test]
    fn repeated_members_leave_no_valid_decomposition() {
        let rng = &mut StdRng::seed_from_u64(29);
        let offset = Fp::random(&mut *rng);
        let mut points = side_points(rng, offset, true, 3);
        points.push(points[0]);
        assert!(
            decomposition(&points, offset, true).is_none(),
            "repeated members decomposed"
        );
    }
}
