//! Nullifiers and nullifier operations.

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::Fp;
use rand_core::CryptoRng;

use crate::primitives::Tachygram;

/// A Tachyon nullifier.
///
/// Derived from the note's master key as one squeeze of the sponge keyed on
/// $\mathsf{mk}$ and the epoch's group start. Published when a note is spent.
///
/// Unlike Orchard, Tachyon nullifiers:
/// - Don't need collision resistance (no faerie gold defense)
/// - Have an epoch component for sync delegation
/// - Are prunable by validators after a window of blocks
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
#[from(Fp, Tachygram)]
#[into(Fp, Tachygram)]
pub struct Nullifier(Tachygram);

/// Nullifier trapdoor ($\psi$), per-note randomness for nullifier derivation.
///
/// Used to derive the note's master key.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Trapdoor(#[debug(skip)] Fp);

impl Trapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_nullifier_trapdoor_redacts_value() {
        let psi = Trapdoor::from(Fp::from(0xCAFEu64));
        let dbg = alloc::format!("{psi:?}");
        assert!(dbg.contains("Trapdoor"), "must name the type");
        assert!(!dbg.contains("CAFE"), "must not leak field element");
        assert!(!dbg.contains("51966"), "must not leak decimal value");
    }
}
