//! ## Key Hierarchy
//!
//! Tachyon simplifies the key hierarchy compared to Orchard by removing
//! key diversification, viewing keys, and payment addresses from the core
//! protocol. These capabilities are handled by higher-level wallet software
//! through out-of-band payment protocols.
//!
//! ```mermaid
//! flowchart TB
//!     sk[SpendingKey]
//!     ask[SpendAuthorizingKey ask]
//!     ak[SpendValidatingKey ak]
//!     nk[NullifierKey nk]
//!     pk[PaymentKey pk]
//!     rk[ActionVerificationKey rk]
//!     sig["sig (action::Signature)"]
//!     pak[ProofAuthorizingKey]
//!     sighash["sighash &amp;[u8; 32]"]
//!     sk --> ask & nk
//!     ask --> ak
//!     theta["ActionEntropy theta"] -- "randomizer::&lt;Spend&gt;" --> spend_alpha["ActionRandomizer&lt;Spend&gt;"]
//!     theta -- "randomizer::&lt;Output&gt;" --> output_alpha["ActionRandomizer&lt;Output&gt;"]
//!     ask -- "derive_action_private(alpha)" --> spend_rsk["ActionSigningKey&lt;Spend&gt;"]
//!     output_alpha -- "new" --> output_rsk["ActionSigningKey&lt;Output&gt;"]
//!     ak -- "+alpha" --> rk
//!     spend_rsk -- "derive_action_public()" --> rk
//!     output_rsk -- "derive_action_public()" --> rk
//!     spend_rsk -- "sign(sighash)" --> sig
//!     output_rsk -- "sign(sighash)" --> sig
//!     ak & nk --> pak
//!     ak & nk -->|"Poseidon"| pk
//! ```
//!
//! ### Private keys ([`private`])
//!
//! - `sk`: Root spending key (full authority)
//! - `ask`: Authorizes spends (long-lived, cannot sign directly)
//! - `bsk = Σrcvᵢ`: Binding signing key (per-bundle)
//!
//! ### Public keys ([`public`])
//!
//! - `ak`: Public counterpart of `ask` (long-lived, cannot verify action sigs)
//! - `rk = ak + [alpha]G`: Per-action verification key (can verify, public)
//! - `bvk`: Binding verification key (derived from value commitments)
//!
//! ### Note keys ([`note`])
//!
//! - `nk`: Observes when funds are spent (nullifier derivation)
//! - `pk = Poseidon(domain, ak_x, nk)`: Derived from `pak`, binds spending
//!   authority and nullifier key to the note commitment
//!
//! ### Proof keys ([`proof`])
//!
//! - `pak`: `ak` + `nk` (proof authorizing key): Authorizes proof construction
//!   without spend authority
//!
//! ## Nullifier Derivation
//!
//! Nullifiers are derived via a GGM tree PRF instantiated from Poseidon:
//!
//! $$\mathsf{mk} = \text{KDF}(\psi, \mathsf{nk})$$
//! $$\mathsf{nf} = F_{\mathsf{mk}}(\text{flavor})$$
//!
//! where $\psi$ is the note's nullifier trapdoor, $\mathsf{nk}$ is the
//! nullifier key, and flavor is the epoch-id.
//!
//! The master root key $\mathsf{mk}$ supports oblivious sync delegation:
//! prefix keys $\Psi_t$ permit evaluating the PRF only for epochs
//! $e \leq t$, enabling range-restricted delegation without revealing
//! spend capability.

pub mod private;
pub mod public;

mod ggm;
mod note;
mod proof;

// Re-exports: public API surface.
pub use ggm::{
    GGM_CHUNK_MASK, GGM_CHUNK_SIZE, GGM_MAX_INDEX, GGM_TREE_ARITY, GGM_TREE_DEPTH, NoteMasterKey,
    NotePrefixedKey, cover_candidates,
};
pub use note::{NullifierKey, PaymentKey};
pub use proof::{ProofAuthorizingKey, SpendValidatingKey};

#[cfg(test)]
mod tests {
    use ff::{Field as _, PrimeField as _};
    use group::GroupEncoding as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        entropy::ActionEntropy,
        keys::{NullifierKey, PaymentKey, private},
        note::{self, Note},
        primitives::effect,
    };

    /// ask, nk, pk derived from the same sk must all be different.
    /// pk derives from (ak, nk) via Poseidon, not directly from sk.
    #[test]
    fn child_keys_independent() {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ak = sk.derive_auth_private().derive_auth_public();
        let nk = sk.derive_nullifier_private();
        let pk = sk.derive_payment_key();

        let ak_bytes: [u8; 32] = ak.as_ref().to_bytes();
        assert_ne!(ak_bytes, nk.as_ref().to_repr());
        assert_ne!(nk.as_ref().to_repr(), pk.as_ref().to_repr());

        let pak = sk.derive_proof_private();
        assert_eq!(pak.derive_payment_key().as_ref(), pk.as_ref());
    }

    /// pk must bind to nk: varying nk (with ak fixed) must produce a
    /// different pk. This is what makes the note commitment transitively
    /// pin the full proof authorizing key.
    #[test]
    fn payment_key_binds_nk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::random(rng);
        let ak = sk.derive_auth_private().derive_auth_public();
        let nk = sk.derive_nullifier_private();
        let pk = PaymentKey::derive(&ak, &nk);

        let nk_other = NullifierKey::from(*nk.as_ref() + Fp::ONE);
        let pk_other = PaymentKey::derive(&ak, &nk_other);
        assert_ne!(pk.as_ref(), pk_other.as_ref());
    }

    /// rsk.derive_action_public() must equal ak.derive_action_public(alpha) for
    /// the same alpha. This is the core consistency property between signer
    /// and prover sides of the randomized key derivation.
    #[test]
    fn rsk_public_equals_ak_derive_action_public() {
        let rng = &mut StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let ak = ask.derive_auth_public();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::try_from(1000u64).unwrap(),
            psi: note::NullifierTrapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let theta = ActionEntropy::random(rng);
        let alpha = theta.randomizer::<effect::Spend>(&note.commitment());
        let rsk = ask.derive_action_private(&alpha);

        assert_eq!(rsk.derive_action_public(), ak.derive_action_public(&alpha));
    }

    #[test]
    fn debug_spending_key_redacts_bytes() {
        let sk = private::SpendingKey::from([0xAB; 32]);
        assert_eq!(alloc::format!("{sk:?}"), "SpendingKey(..)");
    }

    #[test]
    fn debug_nullifier_key_redacts_value() {
        let nk = NullifierKey::from(Fp::from(0xDEADu64));
        assert_eq!(alloc::format!("{nk:?}"), "NullifierKey(SecretFp(..))");
    }
}
