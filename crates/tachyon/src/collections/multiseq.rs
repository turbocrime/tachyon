//! # Multisequence
//!
//! A multisequence may contain any number of unique or repeated nonzero members
//! at each nonzero index. Conceptually, it is a multiset of `(index, member)`
//! tuples.
//!
//! ## Irreducible encoding
//!
//! Construct a single-member multisequence of member $m$ at index
//! $i$ as the polynomial
//!
//! $$
//!   F_{i,m}(X) = (iX + m)^3 - c
//! $$
//!
//! where $c = 2$ is selected because it is the smallest cubic non-residue.
//!
//! Since $(iX + m)^3 \neq c$ the encoding is irreducible.
//!
//! ## Product composition
//!
//! Construct a larger multisequence as the product of smaller multisequences.
//!
//! $$
//!   S(X) = \prod_{(i,m) \in S}{F_{i,m}(X)}
//! $$
//!
//! Combined multisequences will maintain input multiplicity. The inputs may be
//! contiguous, disjoint, or overlapping.
//!
//! ## Quotient decomposition
//!
//! Since a union is a product of irreducible factors, we may demonstrate
//! correct division to confirm membership.
//!
//! $$
//!   \begin{aligned}
//!
//!   Q \uplus R &= S
//!       &\quad \iff &\quad
//!   &R &= S \setminus Q
//!
//!   \\ \\
//!
//!   Q(X) \cdot R(X) &= S(X)
//!       &\quad \iff &\quad
//!   &R(X) &= \frac{S(X)}{Q(X)}
//!
//!   \end{aligned}
//! $$
//!
//! Sequences $Q$ and $R$ combine to produce $S$, or, subsequence $R$ is
//! extracted from $S$ by complement $Q$. Select a challenge and evaluate.
//!
//! ## Injectivity
//!
//! Single-member encodings collide when the ratio of their linear terms is a
//! cube root of unity.
//!
//! Precisely, if
//!
//! $$
//!   \frac{i_1X + m_1}{i_2X + m_2} \in \{1, \zeta, \zeta^2\}
//! $$
//!
//! then $(i_1, m_1)$ cannot be distinguished from $(i_2, m_2)$ in a
//! multisequence.
//!
//! Specifying $i_\mathsf{max}$ below $\lfloor\sqrt{p/3}\rfloor$ is sufficient
//! to prevent collisions.

#![allow(clippy::min_ident_chars, reason = "just for fun")]

extern crate alloc;

use core::{iter, num::NonZero};

use ff::Field as _;
use pasta_curves::Fp;
use ragu::Polynomial;

use super::poly_mul;

const TWO: [u64; 4] = [2, 0, 0, 0];
const THREE: [u64; 4] = [3, 0, 0, 0];

#[must_use]
fn encode_single(i: Fp, m: Fp) -> Polynomial {
    // writing out expanded coefficients for $F(X) = (iX + m)^3 - \zeta$ is
    // cheaper than constructing a linear $f(X) = iX + m$ and then cubing it.
    Polynomial::from_coeffs(
        [
            m.pow(THREE) - Fp::from_raw(TWO),
            Fp::from_raw(THREE) * i * m.square(),
            Fp::from_raw(THREE) * i.square() * m,
            i.pow(THREE),
        ]
        .to_vec(),
    )
}

#[must_use]
fn direct_eval_single(i: Fp, m: Fp, x: Fp) -> Fp {
    ((i * x) + m).pow(THREE) - Fp::from_raw(TWO)
}

/// Encode the provided members consecutively.
pub(crate) fn encode(start_idx: NonZero<u64>, members: impl IntoIterator<Item = Fp>) -> Polynomial {
    let i_m = iter::successors(Some(start_idx), |idx| idx.checked_add(1))
        .map(|idx| Fp::from(idx.get()))
        .zip(members);

    i_m.fold(
        Polynomial::from_coeffs([Fp::ONE].to_vec()),
        |acc, (i, m)| poly_mul(&acc, &encode_single(i, m)),
    )
}

/// Evaluate the multisequence without building the polynomial.
pub(crate) fn direct_eval(
    start_idx: NonZero<u64>,
    members: impl IntoIterator<Item = Fp>,
    x: Fp,
) -> Fp {
    let i_m = iter::successors(Some(start_idx), |idx| idx.checked_add(1))
        .map(|idx| Fp::from(idx.get()))
        .zip(members);

    i_m.fold(Fp::ONE, |acc, (i, m)| acc * direct_eval_single(i, m, x))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::iter;

    use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};

    use super::*;

    #[test]
    fn member_encoding_matches_manual_evaluation() {
        let rng = &mut StdRng::seed_from_u64(3);
        for _ in 0..8 {
            let idx = NonZero::new(u64::from(rng.random_range(1..u32::MAX))).expect("nonzero");
            let member = Fp::random(&mut *rng);
            let x = Fp::random(&mut *rng);
            assert_eq!(
                encode_single(Fp::from(idx.get()), member).eval(x),
                direct_eval(idx, [member], x)
            );
        }
    }

    #[test]
    fn member_encoding_matches_manual_construction() {
        let rng = &mut StdRng::seed_from_u64(6);
        let idx = NonZero::new(u64::from(rng.random_range(1..u32::MAX))).expect("nonzero");
        let member = Fp::random(&mut *rng);
        let x = Fp::random(&mut *rng);

        let manual_poly = {
            let m_ix = Polynomial::from_coeffs([member, Fp::from(idx.get())].to_vec());

            let m_ix_cube = poly_mul(&poly_mul(&m_ix, &m_ix), &m_ix);

            {
                let mut coeffs = Vec::from_iter(m_ix_cube.iter_coeffs());
                coeffs[0] -= Fp::from_raw(TWO);
                Polynomial::from_coeffs(coeffs)
            }
        };

        assert_eq!(
            encode_single(Fp::from(idx.get()), member).eval(x),
            manual_poly.eval(x)
        );
    }

    #[test]
    fn sequence_evaluation_matches_the_encoding() {
        let rng = &mut StdRng::seed_from_u64(12);
        for len in 0..6 {
            let start_idx =
                NonZero::new(1 + u64::from(rng.random_range(0..u32::MAX))).expect("nonzero");
            let members: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
                .take(len)
                .collect();
            let x = Fp::random(&mut *rng);
            assert_eq!(
                direct_eval(start_idx, members.iter().copied(), x),
                encode(start_idx, members).eval(x)
            );
        }
    }
}
