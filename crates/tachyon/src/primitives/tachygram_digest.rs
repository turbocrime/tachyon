use ff::{Field as _, PrimeField as _};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{constants::TACHYGRAM_DIGEST_DOMAIN, primitives::Tachygram};

/// Hash a single tachygram into the accumulation domain.
///
/// The resulting field element serves as a root in the accumulator
/// polynomial: `tg_poly(X) = ∏(X - digest_tachygram(tgᵢ))`.
///
/// # Panics
///
/// Panics if the Poseidon hash is zero (probability ~2⁻²⁵⁵).
#[must_use]
pub fn digest_tachygram(tg: Tachygram) -> Fp {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let domain = Fp::from_u128(u128::from_le_bytes(*TACHYGRAM_DIGEST_DOMAIN));
    let hash = Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([domain, Fp::from(tg)]);
    assert!(!hash.is_zero_vartime(), "Poseidon hash was zero");
    hash
}

#[cfg(test)]
mod tests {
    use pasta_curves::Fp;

    use super::*;

    /// Different tachygrams produce different digests.
    #[test]
    fn distinct_tachygrams_distinct_digests() {
        let tg_a = Tachygram::from(Fp::from(42u64));
        let tg_b = Tachygram::from(Fp::from(99u64));

        assert_ne!(digest_tachygram(tg_a), digest_tachygram(tg_b));
    }

    /// Same tachygram produces the same digest.
    #[test]
    fn digest_deterministic() {
        let tg = Tachygram::from(Fp::from(42u64));
        assert_eq!(digest_tachygram(tg), digest_tachygram(tg));
    }
}
