extern crate alloc;

use alloc::vec::Vec;
use core::{num::NonZero, ops::Mul};

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use crate::{nullifier::Nullifier, primitives::EpochIndex};

fn poly_mul(input_a: &Polynomial, input_b: &Polynomial) -> Polynomial {
    use ragu_arithmetic as arithmetic;

    let trim = |coeffs: &mut Vec<Fp>| {
        if let Some(last_nonzero_idx) = coeffs.iter().rposition(|co| co != &Fp::ZERO) {
            coeffs.truncate(last_nonzero_idx + 1);
        }
    };

    let mut a_coeffs = Vec::from_iter(input_a.iter_coeffs());
    let mut b_coeffs = Vec::from_iter(input_b.iter_coeffs());

    trim(&mut a_coeffs);
    trim(&mut b_coeffs);

    let mut out_coeffs = Vec::new();

    arithmetic::poly_mul(&a_coeffs, &b_coeffs, &mut out_coeffs);

    trim(&mut out_coeffs);

    Polynomial::from_coeffs(out_coeffs)
}

/// Pedersen commitment to a nullifier sequence.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence: the product of its members'
/// encodings, one per member.
///
/// Each member carries its own epoch, so the polynomial determines its
/// members and their positions, as documented in [`multisequence`]. It does
/// not constrain the shape of the sequence, so claims like contiguity or one
/// member per epoch are provenance facts of the headers carrying particular
/// commitments.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfSeqPoly(Polynomial);

impl NfSeqPoly {
    /// Build the sequence polynomial for one contiguous run: the members of
    /// the consecutive epochs starting at `epoch_start`.
    #[must_use]
    pub fn new(epoch_start: EpochIndex, nfs: &[Nullifier]) -> Self {
        #[expect(clippy::expect_used, reason = "one plus an epoch is nonzero")]
        let idx = u64::from(epoch_start.0)
            .checked_add(1)
            .and_then(NonZero::new)
            .expect("offset index is nonzero");
        Self(multisequence::encode_sequence(
            idx,
            nfs.iter().copied().map(Fp::from),
        ))
    }

    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit())
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl Default for NfSeqPoly {
    fn default() -> Self {
        Self(Polynomial::from_coeffs(alloc::vec![Fp::ONE]))
    }
}

impl Mul for NfSeqPoly {
    type Output = Self;

    /// Multiset union: the product of two sequences' member multisets.
    ///
    /// # Panics
    ///
    /// If the product exceeds the polynomial coefficient cap.
    fn mul(self, rhs: Self) -> Self {
        Self(poly_mul(&self.0, &rhs.0))
    }
}

pub(crate) mod multisequence {
    //! Polynomial encoding of multisequences.
    //!
    //! A multisequence is a multiset in which the members are encodings of
    //! `(member, index)` tuples. A multisequence may contain one or more
    //! members at arbitrary indicies.
    //!
    //! We may encode a single-member multisequence of the member $m$ at the
    //! nonzero index $i$ with the polynomial
    //!
    //! $$
    //!   F_{i,m}(X) = (iX + m)^3 - \zeta
    //! $$
    //!
    //! where $\zeta$ is `Fp::ZETA`, a primitive cube root of unity.
    //!
    //! These `(member, index)` encodings are irreducible, because they are
    //! cubed and then combined with $- \zeta$ which is not a cube.
    //!
    //! A larger multisequence is constructed as the product of smaller
    //! multisequences, like a multiset union.
    //!
    //! $$
    //!   F_{i,m}(X) = \prod_{i,m} (iX + m)^3 - \zeta
    //! $$
    //!
    //! Combined multisequences will maintain input multiplicity. The inputs may
    //! be contiguous, disjoint, or overlapping.
    //!
    //!
    //! # Membership testing
    //!
    //! Since a union is a product, division is a membership test.
    //!
    //! $$
    //!   Q \uplus R = S
    //!   \qquad \implies \qquad
    //!   Q(X) \cdot R(X) = S(X)
    //! $$
    //!
    //! Sequences $Q$ and $R$ combine into $S$, or,
    //!
    //! $$
    //!   R = S \setminus Q
    //!   \qquad \implies \qquad
    //!   R(X) = \frac{S(X)}{Q(X)}
    //! $$
    //!
    //! $R$ is extracted from $S$ by complement $Q$.
    //!
    //! # Injectivity
    //!
    //! Two cubes agree only when the ratios of their respective linear terms
    //! are a cube root of unity.
    //!
    //! So a collision between $(m_1,i_1)$ and $(m_2,i_2)$ requires one of
    //!
    //! $$
    //! \begin{aligned}
    //!  (m_1, i_1) &= (m_2 \zeta, i_2 \zeta) \\
    //!  \text{or} \\
    //!  (m_1, i_1) &= (m_2 \zeta^2, i_2 \zeta^2)
    //! \end{aligned}
    //! $$
    //!
    //! Neither is satisfiable for $i \in [1, 2^{32}]$ because $\zeta i \bmod p$
    //! and $\zeta^2 i \bmod p$ both stay above $2^{220}$.

    #![allow(clippy::min_ident_chars, reason = "just for fun")]

    extern crate alloc;

    use core::num::NonZero;

    use ff::{Field as _, WithSmallOrderMulGroup as _};
    use pasta_curves::Fp;
    use ragu::Polynomial;

    use super::poly_mul;

    /// For `Fp::from_raw` or `Fp::pow`
    const THREE: [u64; 4] = [3, 0, 0, 0];

    /// Encode a single-member sequence.
    #[must_use]
    fn encode_single(numeric_idx: NonZero<u64>, member: Fp) -> Polynomial {
        let idx = Fp::from(numeric_idx.get());

        // writing out expanded coefficients for $F(X) = (iX + m)^3 - \zeta$ is
        // cheaper than constructing a linear $f(X) = iX + m$ and then cubing it
        Polynomial::from_coeffs(
            [
                member.pow(THREE) - Fp::ZETA,
                Fp::from_raw(THREE) * idx * member.square(),
                Fp::from_raw(THREE) * idx.square() * member,
                idx.pow(THREE),
            ]
            .to_vec(),
        )
    }

    /// Encode the provided members consecutively.
    pub(crate) fn encode_sequence(
        start_idx: NonZero<u64>,
        members: impl IntoIterator<Item = Fp>,
    ) -> Polynomial {
        let mut i = start_idx;
        let mut seq = Polynomial::from_coeffs([Fp::ONE].to_vec());

        for m in members {
            seq = poly_mul(&seq, &encode_single(i, m));
            i = {
                #[expect(clippy::expect_used, reason = "idx below u32::MAX")]
                i.checked_add(1).expect("idx below u32::MAX")
            };
        }

        seq
    }

    /// Evaluate a single-member sequence at $x$.
    #[must_use]
    fn direct_eval_single(i: Fp, m: Fp, x: Fp) -> Fp {
        ((i * x) + m).pow(THREE) - Fp::ZETA
    }

    /// Evaluate the consecutive members at $x$, without building the
    /// polynomial.
    ///
    /// The product of the members' evaluations is the sequence's evaluation.
    pub(crate) fn direct_eval_sequence(
        start_idx: NonZero<u64>,
        members: impl IntoIterator<Item = Fp>,
        x: Fp,
    ) -> Fp {
        let mut idx = start_idx;
        let mut seq_eval = Fp::ONE;

        for m in members {
            let i = Fp::from(idx.get());
            seq_eval *= direct_eval_single(i, m, x);
            idx = {
                #[expect(clippy::expect_used, reason = "idx below u32::MAX")]
                idx.checked_add(1).expect("idx below u32::MAX")
            };
        }

        seq_eval
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
                    encode_single(idx, member).eval(x),
                    direct_eval_single(Fp::from(idx.get()), member, x)
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
                // build the simple inner
                let m_ix = Polynomial::from_coeffs([member, Fp::from(idx.get())].to_vec());

                // cube it
                let m_ix_cube = poly_mul(&poly_mul(&m_ix, &m_ix), &m_ix);

                // subtract the constant term
                {
                    let mut coeffs = Vec::from_iter(m_ix_cube.iter_coeffs());
                    coeffs[0] -= Fp::ZETA;
                    Polynomial::from_coeffs(coeffs)
                }
            };

            assert_eq!(encode_single(idx, member).eval(x), manual_poly.eval(x));
        }

        /// Evaluating a sequence directly agrees with evaluating its encoding,
        /// so both paths walk the same indices.
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
                    direct_eval_sequence(start_idx, members.iter().copied(), x),
                    encode_sequence(start_idx, members).eval(x)
                );
            }
        }
    }
}
