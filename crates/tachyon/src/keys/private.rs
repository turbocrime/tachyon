//! Private (signing) keys.

use core::marker::PhantomData;

use derive_more::{AsRef, Debug, From};
use ff::{Field as _, FromUniformBytes as _, PrimeField as _};
use group::GroupEncoding as _;
use pasta_curves::{EpAffine, Fp, Fq};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    note::{NullifierKey, PaymentKey},
    proof, public,
};
use crate::{
    action, bundle,
    digest::blake2b,
    entropy::ActionRandomizer,
    primitives::{Effect, effect},
    reddsa,
    secret::{self, SecretFq},
    value,
};

/// A Tachyon spending key — raw 32-byte entropy.
///
/// The root key from which all other keys are derived. This key must
/// be kept secret as it provides full spending authority.
///
/// Matches Orchard's representation: raw `[u8; 32]` (not a field element),
/// preserving the full 256-bit key space.
///
/// Derives child keys via purpose-specific methods:
/// - [`derive_auth_private`](Self::derive_auth_private) →
///   [`SpendAuthorizingKey`] (`ask`)
/// - [`derive_nullifier_private`](Self::derive_nullifier_private) →
///   [`NullifierKey`] (`nk`)
/// - [`derive_payment_key`](Self::derive_payment_key) → [`PaymentKey`] (`pk`)
/// - [`derive_proof_private`](Self::derive_proof_private) →
///   [`ProofAuthorizingKey`] (`ak` + `nk`)
#[derive(Clone, Debug, From, Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey(#[debug(skip)] [u8; 32]);

impl SpendingKey {
    /// Create a new spending key from 32 bytes of random data.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);
        let key = Self(rand_bytes);
        rand_bytes.zeroize();
        key
    }

    /// Derive $\mathsf{ask}$ from $\mathsf{sk}$ with RedPallas sign
    /// normalization.
    ///
    /// # Key derivation (Orchard §4.2.3)
    ///
    /// $$\mathsf{ask} = \text{ToScalar}\bigl(\text{PRF}^{\text{expand}}_
    /// {\mathsf{sk}}([0\text{x}21])\bigr)$$
    ///
    /// BLAKE2b-512 of $(\mathsf{sk} \| \texttt{0x21})$, reduced to
    /// $\mathbb{F}_q$ via `from_uniform_bytes`.
    ///
    /// # Sign normalization (§5.4.7.1)
    ///
    /// RedPallas requires $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ to
    /// have $\tilde{y} = 0$.  Pallas point compression (§5.4.9.7) encodes
    /// $\tilde{y}$ in bit 255 (byte 31, bit 7) of the 32-byte
    /// representation.  If $\tilde{y}(\mathsf{ak}) = 1$, we negate
    /// $\mathsf{ask}$: $[-\mathsf{ask}]\,\mathcal{G} =
    /// -[\mathsf{ask}]\,\mathcal{G}$ flips the y-coordinate sign.
    ///
    /// The reddsa::ActionAuth basepoint $\mathcal{G}$ is hash-derived
    /// (`hash_to_curve("z.cash:Orchard")(b"G")`) and sealed inside
    /// reddsa's `private::Sealed` trait, so we must construct a
    /// `SigningKey` (which internally computes $[\mathsf{ask}]\,\mathcal{G}$)
    /// to obtain $\mathsf{ak}$ and inspect its encoding.
    #[must_use]
    pub fn derive_auth_private(&self) -> SpendAuthorizingKey {
        // Derive ask scalar from sk via PRF (Orchard §4.2.3).
        let mut ask = Fq::from_uniform_bytes(&blake2b::prf_expand_ask(&self.0));

        // Sign normalization (§5.4.7.1): ak must have tilde_y = 0.
        // Compute ak = [ask]G via reddsa (basepoint is sealed) and check
        // the y-sign bit (byte 31, bit 7 of the compressed encoding).
        // TODO: reddsa round-trip leaves unwiped transients
        #[expect(
            clippy::expect_used,
            reason = "PRF-derived scalars are valid signing keys"
        )]
        let mut sk = reddsa::SigningKey::<reddsa::ActionAuth>::try_from(ask.to_repr())
            .expect("PRF-derived ask should be a valid RedPallas scalar");
        let ak: [u8; 32] = reddsa::VerificationKey::from(&sk).into();
        secret::wipe_reddsa_sk(&mut sk);
        if ak[31] >> 7u8 == 1u8 {
            ask = -ask;
        }

        // Store the sign-normalized scalar.
        SpendAuthorizingKey::from(ask)
    }

    /// Derive `nk` from `sk`.
    ///
    /// `nk = ToBase(PRF^expand_sk([0x22]))` — BLAKE2b-512 reduced to Fp.
    #[must_use]
    pub fn derive_nullifier_private(&self) -> NullifierKey {
        NullifierKey::from(Fp::from_uniform_bytes(&blake2b::prf_expand_nk(&self.0)))
    }

    /// Derive the payment key $\mathsf{pk}$ from $\mathsf{sk}$.
    ///
    /// $$\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
    /// \mathsf{nk})$$
    ///
    /// Derives `ak` and `nk` from `sk`, then computes `pk` via Poseidon.
    /// This binds `pk` to both spending authority and nullifier derivation,
    /// so `cm` (which contains `pk`) transitively pins the full proof
    /// authorizing key to the accumulator.
    #[must_use]
    pub fn derive_payment_key(&self) -> PaymentKey {
        PaymentKey::derive(
            &self.derive_auth_private().derive_auth_public(),
            &self.derive_nullifier_private(),
        )
    }

    /// Derive the proof authorizing key (`ak` + `nk`) for delegated proof
    /// construction.
    ///
    /// Combines [`derive_auth_private`](Self::derive_auth_private)
    /// → [`SpendAuthorizingKey::derive_auth_public`] with
    /// [`derive_nullifier_private`](Self::derive_nullifier_private).
    #[must_use]
    pub fn derive_proof_private(&self) -> proof::ProofAuthorizingKey {
        proof::ProofAuthorizingKey {
            ak: self.derive_auth_private().derive_auth_public(),
            nk: self.derive_nullifier_private(),
        }
    }
}

/// The spend authorizing key `ask` — a long-lived signing key derived
/// from [`SpendingKey`].
///
/// Corresponds to the "spend authorizing key" in Orchard (§4.2.3).
/// Only used for spend actions — output actions do not require `ask`.
///
/// `ask` **cannot sign directly**. It must first be randomized into a
/// per-action [`ActionSigningKey<Spend>`] (`rsk`) via
/// [`derive_action_private`](Self::derive_action_private), which can then
/// sign. Per-action randomization ensures each `rk` is unlinkable to
/// `ak`, so observers cannot correlate actions to the same spending
/// authority.
///
/// `ask` derives [`SpendValidatingKey`](super::proof::SpendValidatingKey)
/// (`ak`) via [`derive_auth_public`](Self::derive_auth_public) — the
/// circuit witness that validates spend authorization.
#[derive(Clone, Debug, From, Zeroize, ZeroizeOnDrop)]
#[from(Fq)]
pub struct SpendAuthorizingKey(SecretFq);

impl SpendAuthorizingKey {
    /// Derive the spend validating (public) key: `ak = [ask]G`.
    #[must_use]
    pub fn derive_auth_public(&self) -> proof::SpendValidatingKey {
        // TODO: reddsa round-trip leaves unwiped transients
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let mut ask = reddsa::SigningKey::<reddsa::ActionAuth>::try_from(self.0.as_ref().to_repr())
            .expect("scalar should be a valid key");

        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        let ak = reddsa::VerificationKey::from(&ask);
        secret::wipe_reddsa_sk(&mut ask);

        let ak_point =
            EpAffine::from_bytes(&ak.into()).expect("verification key is a valid curve point");
        proof::SpendValidatingKey(ak_point.into())
    }

    /// Derive the per-action private (signing) key: $\mathsf{rsk} =
    /// \mathsf{ask} + \alpha$.
    ///
    /// Only accepts [`ActionRandomizer<Spend>`] — passing an output
    /// randomizer is a compile error.
    #[must_use]
    pub fn derive_action_private(
        &self,
        alpha: &ActionRandomizer<effect::Spend>,
    ) -> ActionSigningKey<effect::Spend> {
        // TODO: reddsa round-trip leaves unwiped transients
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let mut ask = reddsa::SigningKey::<reddsa::ActionAuth>::try_from(self.0.as_ref().to_repr())
            .expect("scalar should be a valid key");

        // reddsa performs the per-action randomization rsk = ask + alpha.
        let mut rsk = ask.randomize(alpha.as_ref());
        secret::wipe_reddsa_sk(&mut ask);

        let rsk_scalar = SecretFq::from(
            Fq::from_repr(rsk.into()).expect("randomized signing key has a canonical scalar"),
        );
        secret::wipe_reddsa_sk(&mut rsk);

        ActionSigningKey(rsk_scalar, PhantomData)
    }
}

/// The per-action signing key `rsk` — ephemeral, parameterized by effect.
///
/// - [`ActionSigningKey<Spend>`]: $\mathsf{rsk} = \mathsf{ask} + \alpha$ —
///   derived from [`SpendAuthorizingKey::derive_action_private`]
/// - [`ActionSigningKey<Output>`]: $\mathsf{rsk} = \alpha$ — derived from
///   [`ActionRandomizer<Output>`]
///
/// Both variants sign via [`sign`](Self::sign) and derive `rk` via
/// [`derive_action_public`](Self::derive_action_public).
#[derive(AsRef, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ActionSigningKey<E: Effect>(#[as_ref(forward)] SecretFq, PhantomData<E>);

impl<E: Effect> ActionSigningKey<E> {
    /// Sign a transaction sighash with this action key.
    pub fn sign<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        sighash: &[u8; 32],
    ) -> action::Signature {
        // TODO: reddsa round-trip leaves unwiped transients
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let mut rsk = reddsa::SigningKey::<reddsa::ActionAuth>::try_from(self.0.as_ref().to_repr())
            .expect("scalar should be a valid key");

        let sig = rsk.sign(rng, sighash);
        secret::wipe_reddsa_sk(&mut rsk);
        action::Signature(sig)
    }

    /// Derive the per-action verification (public) key: `rk = [rsk]G`.
    #[must_use]
    pub fn derive_action_public(&self) -> public::ActionVerificationKey {
        // TODO: reddsa round-trip leaves unwiped transients
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let mut rsk = reddsa::SigningKey::<reddsa::ActionAuth>::try_from(self.0.as_ref().to_repr())
            .expect("scalar should be a valid key");

        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        let vk = reddsa::VerificationKey::from(&rsk);
        secret::wipe_reddsa_sk(&mut rsk);
        let point =
            EpAffine::from_bytes(&vk.into()).expect("verification key is a valid curve point");
        public::ActionVerificationKey::from(point)
    }
}

impl ActionSigningKey<effect::Output> {
    /// Create a new output action signing key from an output randomizer.
    ///
    /// For output actions the randomizer is the signing key: $\mathsf{rsk} =
    /// \alpha$.
    #[must_use]
    pub fn new(alpha: &ActionRandomizer<effect::Output>) -> Self {
        Self((*alpha.as_ref()).into(), PhantomData)
    }
}

/// BindingAuth signing key $\mathsf{bsk}$ — the scalar sum of all value
/// commitment trapdoors in a bundle.
///
/// $$\mathsf{bsk} := \boxplus_i \mathsf{rcv}_i$$
///
/// (sum in $\mathbb{F}_q$, the Pallas scalar field)
///
/// The binding signature proves knowledge of $\mathsf{bsk}$, which is
/// an opening of the Pedersen commitment $\mathsf{bvk}$ to value 0.
/// By the **binding property** of the commitment scheme, it is
/// infeasible to find another opening to a different value — so value
/// balance is enforced.
///
/// ## Sighash
///
/// Both action signatures and the binding signature sign the same
/// transaction-level sighash. The sighash incorporates the bundle
/// commitment (and commitments from other pools). The stamp is
/// excluded from the bundle commitment because it is stripped during
/// aggregation.
#[derive(AsRef, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct BindingSigningKey(#[as_ref(forward)] SecretFq);

impl BindingSigningKey {
    /// Sign a transaction sighash with this binding key.
    pub fn sign<RNG: RngCore + CryptoRng>(
        &self,
        rng: &mut RNG,
        sighash: &[u8; 32],
    ) -> bundle::Signature {
        // TODO: reddsa round-trip leaves unwiped transients
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let mut bsk = reddsa::SigningKey::<reddsa::BindingAuth>::try_from(self.as_ref().to_repr())
            .expect("scalar should be a valid key");

        let sig = bsk.sign(rng, sighash);
        secret::wipe_reddsa_sk(&mut bsk);
        bundle::Signature(sig)
    }

    /// Derive the binding verification (public) key:
    /// $\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$.
    #[must_use]
    pub fn derive_binding_public(&self) -> public::BindingVerificationKey {
        // TODO: reddsa round-trip leaves unwiped transients
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let mut bsk = reddsa::SigningKey::<reddsa::BindingAuth>::try_from(self.as_ref().to_repr())
            .expect("scalar should be a valid key");

        let vk = reddsa::VerificationKey::<reddsa::BindingAuth>::from(&bsk);
        secret::wipe_reddsa_sk(&mut bsk);
        let point =
            EpAffine::from_bytes(&vk.into()).expect("verification key is a valid curve point");

        public::BindingVerificationKey::from(point)
    }

    /// Construct from borrowed value commitment trapdoors without materializing
    /// a vector of copied trapdoor scalars.
    pub(crate) fn from_trapdoors<'source>(
        trapdoors: impl IntoIterator<Item = &'source value::CommitmentTrapdoor>,
    ) -> Self {
        let mut sum = SecretFq::from(Fq::ZERO);
        for trapdoor in trapdoors {
            sum += trapdoor.0.clone();
        }
        Self(sum)
    }
}

impl From<&[value::CommitmentTrapdoor]> for BindingSigningKey {
    /// BindingAuth signing key is the scalar sum of all value commitment
    /// trapdoors.
    fn from(trapdoors: &[value::CommitmentTrapdoor]) -> Self {
        Self::from_trapdoors(trapdoors)
    }
}
