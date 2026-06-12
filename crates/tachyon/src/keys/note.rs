//! Note-related keys: NullifierKey, NoteMasterKey, PaymentKey.

use core::{array, fmt};

use ff::PrimeField as _;
use pasta_curves::Fp;

use super::proof::SpendValidatingKey;
use crate::{
    constants::EPOCH_MAX,
    digest::{mimc, poseidon},
    note::{self, Nullifier},
    primitives::EpochIndex,
};

/// A Tachyon nullifier deriving key.
///
/// Tachyon simplifies Orchard's nullifier construction
/// ("Tachyaction at a Distance", Bowe 2025): a per-note keyset
/// $[\mathsf{mk}_0, \ldots, \mathsf{mk}_{n-1}]$, each $\mathsf{mk}_i =
/// \text{Poseidon}(\Psi, \mathsf{nk}, i)$; the leading keys key the
/// multi-key MiMC cipher and the last key is the input salt $\mathsf{mk}_s$,
/// so the nullifier for an epoch is
///
/// $$\mathsf{nf}_e = E_{\mathsf{mk}}(\mathsf{mk}_s + e)$$
///
/// where $\Psi$ is the note's nullifier trapdoor and $e$ the epoch-id.
///
/// `nk` alone does NOT confer spend authority; combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// and nullifier derivation without signing capability.
#[derive(Clone, Copy)]
pub struct NullifierKey(pub(super) Fp);

impl NullifierKey {
    /// Derive a note's master-key seed from its nullifier trapdoor `psi`.
    #[must_use]
    pub fn derive_note_private(&self, psi: &note::NullifierTrapdoor) -> NoteMasterKey {
        NoteMasterKey(array::from_fn(|i| {
            poseidon::nf_master(
                psi.0,
                self.0,
                Fp::from(
                    #[expect(clippy::expect_used, reason = "fits usize")]
                    u64::try_from(i).expect("fits usize"),
                ),
            )
        }))
    }
}

/// Per-note master secret: the MiMC keyset.
///
/// Derived on the user device as $\mathsf{mk}_i = \text{Poseidon}(\Psi,
/// \mathsf{nk}, i)$ for $i = 0, \ldots, n-1$. The leading keys key the
/// multi-key MiMC cipher and the last is the input salt; the nullifier for
/// epoch $e$ is $\mathsf{nf}_e = E_{\mathsf{mk}}(\mathsf{mk}_s + e)$,
/// multi-key MiMC in evaluation mode on inputs never known to an adversary
/// (only consecutive input differences are).
///
/// ## Delegation: value windows only
///
/// Delegation operates on value windows only; there is no key-material
/// delegation API, and the wallet is the sole prover of derivation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteMasterKey([Fp; Self::LENGTH]);

impl NoteMasterKey {
    /// The number of Fp elements in the key.
    pub const LENGTH: usize = 3;

    /// Derive the nullifier for the given epoch: `nf = E_mk(mk_s + epoch)`.
    #[must_use]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        assert!(epoch.0 <= EPOCH_MAX, "epoch exceeds epoch space");
        Nullifier::from(mimc::nullifier(self.0, Fp::from(epoch)))
    }
}

impl From<NoteMasterKey> for [Fp; NoteMasterKey::LENGTH] {
    fn from(mk: NoteMasterKey) -> Self {
        mk.0
    }
}

/// A Tachyon payment key — static per-spending-key recipient identifier.
///
/// Replaces Orchard's diversified transmission key $\mathsf{pk_d}$ and
/// the entire diversified address system. Tachyon removes the diversifier
/// $d$ because payment addresses are removed from the on-chain protocol
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// > "The transmission key $\mathsf{pk_d}$ is substituted with a payment
/// > key $\mathsf{pk}$."
///
/// ## Derivation
///
/// Derived from the proof authorizing key components:
///
/// $$\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
/// \mathsf{nk})$$
///
/// where $\mathsf{ak}_x$ is the x-coordinate of the spend validating key.
/// This binds `pk` to both `ak` and `nk`, so the note commitment `cm`
/// (which contains `pk`) transitively pins the full proof authorizing key.
/// Wrong `nk` produces wrong `pk`, wrong `cm`, and accumulator inclusion
/// fails.
///
/// Every note from the same spending key shares the same `pk`. There is
/// no per-note diversification — unlinkability is the wallet layer's
/// responsibility, not the core protocol's.
///
/// ## Usage
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band via higher-level protocols (ZIP 321 payment
/// requests, ZIP 324 URI encapsulated payments).
#[derive(Clone, Copy)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct PaymentKey(pub(crate) Fp);

impl PaymentKey {
    /// Derive the payment key from `ak` and `nk`:
    /// $\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
    /// \mathsf{nk})$.
    #[must_use]
    pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
        let ak_bytes: [u8; 32] = ak.0.into();
        let ak_fp = Fp::from_repr(ak_bytes).expect("ak bytes should be a valid Fp");
        Self(poseidon::payment_key(ak_fp, nk.0))
    }
}

impl fmt::Debug for NullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NullifierKey").finish_non_exhaustive()
    }
}

impl fmt::Debug for NoteMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteMasterKey").finish_non_exhaustive()
    }
}

impl fmt::Debug for PaymentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::primitives::EpochIndex;

    #[test]
    fn derive_note_private_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk1 = nk.derive_note_private(&psi);
        let mk2 = nk.derive_note_private(&psi);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn different_psi_different_mk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = note::NullifierTrapdoor::random(rng);
        let psi2 = note::NullifierTrapdoor::random(rng);
        let mk1 = nk.derive_note_private(&psi1);
        let mk2 = nk.derive_note_private(&psi2);
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = nk.derive_note_private(&psi);
        assert_ne!(
            mk.derive_nullifier(EpochIndex(0u32)),
            mk.derive_nullifier(EpochIndex(1u32)),
        );
    }
}
