//! Per-note master key for nullifier derivation.

use core::array;

use derive_more::{Debug, Eq as TotalEq, Into, PartialEq};
use pasta_curves::Fp;

use crate::{
    digest::poseidon::{self, NF_DERIVATION_GROUP},
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    primitives::{EpochGroup, EpochIndex},
};

/// Per-note master key.
///
/// Derived by the user device from [`NullifierKey`](super::NullifierKey) and
/// the note's $\psi$ trapdoor, and the only key material a nullifier
/// derivation needs. Epochs are derived `NF_DERIVATION_GROUP` at a time from
/// one sponge keyed on the group index
/// $w = \lfloor e / \mathsf{NF\_DERIVATION\_GROUP} \rfloor$.
///
/// `mk` grants derivation over the whole epoch space; a delegate receives
/// proven value windows.
#[derive(Clone, Copy, Debug, Into, PartialEq, TotalEq)]
pub struct NoteMasterKey(#[debug(skip)] pub(crate) Fp);

impl NoteMasterKey {
    /// Derive the nullifier for a single epoch.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "the remainder indexes an array of exactly NF_DERIVATION_GROUP \
                  entries"
    )]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        let squeezed = poseidon::nullifier_group(self.0, EpochGroup::from(epoch));
        Nullifier::from(squeezed[epoch.0 as usize % NF_DERIVATION_GROUP])
    }

    /// Derive one derivation window: the nullifiers for
    /// `[group.start_epoch(), … + NF_DERIVATION_WIDTH)`.
    ///
    /// Group alignment makes the sponge count a compile-time constant inside
    /// [`NfDerive`](crate::stamp::proof::delegation::NfDerive):
    /// `NF_DERIVATION_WIDTH / NF_DERIVATION_GROUP` permutations.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "both widths are small powers of two and divide exactly"
    )]
    pub fn derive_window(&self, group: EpochGroup) -> [Nullifier; NF_DERIVATION_WIDTH] {
        let groups: [[Fp; NF_DERIVATION_GROUP]; NF_DERIVATION_WIDTH / NF_DERIVATION_GROUP] =
            array::from_fn(|offset| {
                poseidon::nullifier_group(self.0, EpochGroup(group.0 + offset as u32))
            });
        array::from_fn(|slot| {
            Nullifier::from(groups[slot / NF_DERIVATION_GROUP][slot % NF_DERIVATION_GROUP])
        })
    }
}
