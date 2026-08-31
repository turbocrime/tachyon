//! Per-note master key for nullifier derivation.

use derive_more::{Debug, Eq as TotalEq, Into, PartialEq};
use pasta_curves::Fp;
use ragu_arithmetic::PoseidonPermutation as _;
use ragu_pasta::PoseidonFp;

use crate::{digest::poseidon, nullifier::Nullifier, primitives::EpochIndex};

/// Per-note master key.
///
/// Derived by the user device from [`NullifierKey`](super::NullifierKey) and
/// the note's $\psi$ trapdoor, and the only key material a nullifier
/// derivation needs. Epochs are derived `PoseidonFp::RATE` at a time from
/// one sponge keyed on the group's start epoch.
#[derive(Clone, Copy, Debug, Into, PartialEq, TotalEq)]
pub struct NoteMasterKey(#[debug(skip)] pub(crate) Fp);

impl NoteMasterKey {
    /// Derive the nullifier for a single epoch.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "the remainder indexes an array of exactly PoseidonFp::RATE \
                  entries"
    )]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        let offset = epoch.0 as usize % PoseidonFp::RATE;
        self.derive_group(EpochIndex(epoch.0 - offset as u32))[offset]
    }

    /// Derive one sponge group: the nullifiers for
    /// `[epoch_start, … + PoseidonFp::RATE)`. `epoch_start` must be
    /// group-aligned.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::integer_division_remainder_used,
        reason = "the group width is a small constant"
    )]
    pub fn derive_group(&self, epoch_start: EpochIndex) -> [Nullifier; PoseidonFp::RATE] {
        debug_assert_eq!(
            epoch_start.0 % PoseidonFp::RATE as u32,
            0,
            "epoch_start must be group-aligned"
        );
        poseidon::nullifier_group(self.0, Fp::from(epoch_start)).map(Nullifier::from)
    }
}
