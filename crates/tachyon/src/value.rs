//! Value commitments and related types.
//!
//! A value commitment hides the value transferred in an action:
//! `cv = [v]V + [rcv]R` where `rcv` is the [`CommitmentTrapdoor`].

use core::{iter, ops, ops::Neg as _};

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use lazy_static::lazy_static;
use pasta_curves::{
    Ep, EpAffine, Fq, arithmetic::CurveExt as _, group::prime::PrimeCurveAffine as _, pallas,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::SecretFq;

/// Hash-to-curve domain for value commitment generators $\mathcal{V}$ and
/// $\mathcal{R}$. Shared with Orchard to reuse `reddsa::orchard::Binding` —
/// same generators, same basepoint, same binding signature verification.
const VALUE_COMMITMENT_DOMAIN: &str = "z.cash:Orchard-cv";

lazy_static! {
    /// Generator $\mathcal{V}$ for value commitments.
    static ref VALUE_COMMIT_V: pallas::Point =
        pallas::Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"v");

    /// Generator $\mathcal{R}$ for value commitments and binding signatures.
    static ref VALUE_COMMIT_R: pallas::Point =
        pallas::Point::hash_to_curve(VALUE_COMMITMENT_DOMAIN)(b"r");
}

/// Value commitment trapdoor $\mathsf{rcv}$ — the randomness in a
/// Pedersen commitment.
///
/// Each action gets a fresh trapdoor:
/// $\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$.
///
/// The binding signing key is the scalar sum of trapdoors:
/// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$
/// ($\mathbb{F}_q$, Pallas scalar field).
///
/// ## Type representation
///
/// An $\mathbb{F}_q$ element (Pallas scalar field, 32 bytes). Lives
/// in the scalar field because $\mathsf{rcv}$ is used as a scalar in
/// point multiplication $[\mathsf{rcv}]\,\mathcal{R}$.
#[derive(AsRef, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct CommitmentTrapdoor(#[as_ref(forward)] pub(super) SecretFq);

impl CommitmentTrapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fq::random(rng).into())
    }

    /// Commit to a value with this trapdoor.
    ///
    /// $$\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
    ///
    /// Positive $v$ for spends (balance contributed), negative for
    /// outputs (balance exhausted).
    #[must_use]
    pub fn commit(&self, raw_value: i64) -> Commitment {
        assert_ne!(
            self.as_ref(),
            &Fq::ZERO,
            "commitment trapdoor should not be zero"
        );

        let value_abs: Fq = Fq::from(raw_value.unsigned_abs());
        let value_fq = if raw_value >= 0 {
            value_abs
        } else {
            value_abs.neg()
        };

        let committed: EpAffine = {
            let commit_value: Ep = *VALUE_COMMIT_V * value_fq;
            let commit_trapdoor: Ep = *VALUE_COMMIT_R * self.as_ref();
            (commit_value + commit_trapdoor).into()
        };

        Commitment(committed)
    }
}

/// A value commitment for a Tachyon action.
///
/// Commits to the value being transferred in an action without
/// revealing it. This is a Pedersen commitment (curve point) used in
/// value balance verification.
///
/// $$\mathsf{cv} = [v]\,\mathcal{V} + [\mathsf{rcv}]\,\mathcal{R}$$
///
/// where $v$ is the value, $\mathsf{rcv}$ is the randomness
/// ([`CommitmentTrapdoor`]), and $\mathcal{V}$, $\mathcal{R}$ are
/// generator points hashed-to-curve under the Orchard `cv` domain
/// (§5.4.8.3).
///
/// ## Type representation
///
/// An EpAffine (Pallas affine curve point, 32 compressed bytes).
#[derive(Clone, Copy, Debug, Default, From, Into, PartialEq, TotalEq)]
pub struct Commitment(EpAffine);

impl Commitment {
    /// Create the value balance commitment
    /// $\text{ValueCommit}_0(\mathsf{v\_{balance}})$.
    ///
    /// $$\text{ValueCommit}_0(v) = [v]\,\mathcal{V} + [0]\,\mathcal{R}
    ///   = [v]\,\mathcal{V}$$
    ///
    /// This is a **deterministic** commitment with zero randomness.
    /// Used by validators to derive the binding verification key:
    ///
    /// $$\mathsf{bvk} = \left(\bigoplus_i \mathsf{cv}_i\right)
    ///   \ominus \text{ValueCommit}_0(\mathsf{v\_{balance}})$$
    #[must_use]
    pub fn balance(value: i64) -> Self {
        let value_abs: Fq = Fq::from(value.unsigned_abs());
        let value_fq = if value >= 0 {
            value_abs
        } else {
            value_abs.neg()
        };
        Self((*VALUE_COMMIT_V * value_fq).into())
    }
}

impl ops::Add for Commitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 + rhs.0).into())
    }
}

impl ops::Sub for Commitment {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self((self.0 - rhs.0).into())
    }
}

impl iter::Sum for Commitment {
    /// $\bigoplus_i \mathsf{cv}_i$ — point addition over all value
    /// commitments. Identity element is the point at infinity.
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(EpAffine::identity()), |acc, cv| acc + cv)
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    /// balance(0) must be the identity point — the V-component cancels
    /// and the R-component has zero scalar.
    #[test]
    fn balance_zero_is_identity() {
        assert_eq!(Commitment::balance(0), Commitment(EpAffine::identity()));
    }

    /// The binding property: `cv_a + cv_b - balance(a+b) = [rcv_a + rcv_b]R`.
    /// The V-components cancel, leaving only the R-component.
    #[test]
    fn commit_homomorphic_binding_property() {
        let rng = &mut StdRng::seed_from_u64(0);
        let rcv_a = CommitmentTrapdoor::random(rng);
        let scalar_a = rcv_a.as_ref();
        let cv_a = rcv_a.commit(100);
        let rcv_b = CommitmentTrapdoor::random(rng);
        let scalar_b = rcv_b.as_ref();
        let cv_b = rcv_b.commit(200);

        let remainder = cv_a + cv_b - Commitment::balance(300);

        let rcv_sum = scalar_a + scalar_b;
        let expected: EpAffine = (*VALUE_COMMIT_R * rcv_sum).into();

        assert_eq!(remainder, Commitment(expected));
    }

    #[test]
    fn debug_value_trapdoor_redacts_scalar() {
        let rcv = CommitmentTrapdoor(Fq::from(0xFACEu64).into());
        assert_eq!(
            alloc::format!("{rcv:?}"),
            "CommitmentTrapdoor(SecretFq(..))"
        );
    }
}
