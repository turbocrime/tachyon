//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives an
//! [`ActionRandomizer`].

use core::marker::PhantomData;

use derive_more::{AsRef, Debug};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{note, primitives::Effect, secret::SecretFq};

/// Per-action entropy $\theta$ chosen by the signer (e.g. hardware wallet).
///
/// 32 bytes of randomness combined with a note commitment to
/// deterministically derive $\alpha$ via
/// [`randomizer`](Self::randomizer).
/// The signer picks $\theta$ once; any device with $\theta$ and the
/// note can independently reconstruct $\alpha$.
///
/// This separation enables **hardware wallet signing without proof
/// construction**: the hardware wallet holds $\mathsf{ask}$ and $\theta$,
/// signs with $\mathsf{rsk} = \mathsf{ask} + \alpha$, and a separate
/// (possibly untrusted) device constructs the proof later using $\theta$
/// and $\mathsf{cm}$ to recover $\alpha$
/// ("Tachyaction at a Distance", Bowe 2025).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
pub struct ActionEntropy(#[debug(skip)] pub(crate) [u8; 32]);

impl ActionEntropy {
    /// Parse action entropy from 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Sample fresh per-action entropy.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let entropy = Self(bytes);
        bytes.zeroize();
        entropy
    }

    /// Derive the action randomizer $\alpha$ for effect `E`.
    ///
    /// Uses distinct BLAKE2b personalizations for spend vs output to
    /// ensure the two randomizers are independent.
    #[must_use]
    pub fn randomizer<E: Effect>(&self, cm: &note::Commitment) -> ActionRandomizer<E> {
        ActionRandomizer(E::derive_alpha(self, cm).into(), PhantomData)
    }
}

mod sealed {
    use crate::primitives::Effect;

    pub trait RandomizerState: Copy {}
    impl<T: Effect> RandomizerState for T {}
}

/// Per-action randomizer $\alpha$, parameterized by effect state.
///
/// - [`ActionRandomizer<Spend>`]: $\mathsf{rsk} = \mathsf{ask} + \alpha$,
///   $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
/// - [`ActionRandomizer<Output>`]: $\mathsf{rsk} = \alpha$.
#[derive(AsRef, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ActionRandomizer<S: sealed::RandomizerState>(
    #[as_ref(forward)] SecretFq,
    PhantomData<S>,
);

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{note, primitives::effect};

    /// Distinct BLAKE2b personalizations must yield distinct alpha scalars
    /// for the same (theta, cm).
    #[test]
    fn spend_and_output_randomizers_differ() {
        let mut rng = StdRng::seed_from_u64(100);
        let theta = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::from(Fp::random(&mut rng));

        let spend_alpha = theta.randomizer::<effect::Spend>(&cm);
        let output_alpha = theta.randomizer::<effect::Output>(&cm);

        assert_ne!(spend_alpha.as_ref(), output_alpha.as_ref());
    }

    #[test]
    fn randomizer_deterministic() {
        let mut rng = StdRng::seed_from_u64(101);
        let theta_a = ActionEntropy::random(&mut rng);
        let theta_b = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::from(Fp::random(&mut rng));

        // Deterministic: same theta twice
        let first = theta_a.randomizer::<effect::Spend>(&cm);
        let second = theta_a.randomizer::<effect::Spend>(&cm);
        assert_eq!(first.as_ref(), second.as_ref());

        // Sensitive: different theta
        let other = theta_b.randomizer::<effect::Spend>(&cm);
        assert_ne!(first.as_ref(), other.as_ref());
    }

    #[test]
    fn debug_entropy_redacts_bytes() {
        let theta = ActionEntropy::from_bytes([0xAB; 32]);
        assert_eq!(alloc::format!("{theta:?}"), "ActionEntropy(..)");
    }

    #[test]
    fn debug_randomizer_redacts_scalar() {
        let mut rng = StdRng::seed_from_u64(200);
        let theta = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::from(Fp::random(&mut rng));
        let alpha = theta.randomizer::<effect::Spend>(&cm);
        assert_eq!(
            alloc::format!("{alpha:?}"),
            "ActionRandomizer(SecretFq(..), PhantomData<zcash_tachyon::primitives::effect::Spend>)"
        );
    }
}
