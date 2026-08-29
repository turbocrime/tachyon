extern crate alloc;

use alloc::vec::Vec;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::Fp;

use super::Anchor;
use crate::{collections, digest::poseidon};

/// One split's discriminating value $R$, separating members by the
/// quadratic character of $x + R$.
///
/// Canonical values are minted by the builder's replay convention:
/// $R_\mathsf{new} = H(\mathsf{anchor}, R_\mathsf{prev})$ at the moment the
/// split fires, with $R_\mathsf{prev}$ zero at a bucket's first split. Any
/// discriminant yields sound evidence (classification is deterministic and
/// cannot unmake membership); the convention makes independently built
/// evidence identical.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(pub Fp);

impl QrDiscriminant {
    /// The unwritten slot value.
    pub const ZERO: Self = Self(Fp::ZERO);

    /// Mints the next discriminant from the momentary anchor and this one.
    #[must_use]
    pub fn next(self, anchor: Anchor) -> Self {
        Self(poseidon::qr_discriminant_next(Fp::from(anchor), self.0))
    }

    /// The side of this discriminant that `value` falls on: `true` iff
    /// $\mathsf{value} + R$ is a square or zero.
    #[must_use]
    pub fn side(self, value: Fp) -> bool {
        collections::qr::classify(value, self.0).0
    }
}

/// A bucket's QR profile: the side taken at each split, folded from $1$ by
/// double-and-add, $b' = 2b + \mathsf{bit}$. Self-delimiting — distinct
/// (depth, bits) pairs yield distinct literals.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrProfile(pub u64);

impl QrProfile {
    /// Depth zero: the root bucket, before any split.
    pub const ROOT: Self = Self(1);

    /// The number of splits the profile delimits.
    #[must_use]
    pub fn depth(self) -> usize {
        self.bits().len()
    }

    /// The per-split side bits, outermost split first.
    #[must_use]
    pub fn bits(self) -> Vec<bool> {
        assert!(self.0 >= 1, "a profile is at least the root literal");
        let mut bits = Vec::new();
        let mut value = self.0;
        while value > 1 {
            bits.push(value & 1 == 1);
            value >>= 1;
        }
        bits.reverse();
        bits
    }

    /// The profile of the child extending this one by `bit`.
    #[must_use]
    pub fn child(self, bit: bool) -> Self {
        Self(self.0 * 2 + u64::from(bit))
    }
}

impl From<QrProfile> for Fp {
    fn from(profile: QrProfile) -> Self {
        Self::from(profile.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_profile_has_depth_zero() {
        assert_eq!(QrProfile::ROOT.depth(), 0);
        assert_eq!(QrProfile::ROOT.bits(), Vec::<bool>::new());
    }

    #[test]
    fn children_extend_the_profile_in_order() {
        let profile = QrProfile::ROOT.child(true).child(false).child(true);
        assert_eq!(profile.0, 0b1101);
        assert_eq!(profile.depth(), 3);
        assert_eq!(profile.bits(), [true, false, true]);
    }

    #[test]
    fn distinct_split_histories_yield_distinct_literals() {
        let deep_zeroes = QrProfile::ROOT.child(false).child(false);
        let shallow_zero = QrProfile::ROOT.child(false);
        assert_ne!(deep_zeroes, shallow_zero);
        assert_ne!(deep_zeroes, QrProfile::ROOT);
    }

    #[test]
    fn minting_mixes_the_anchor_and_the_previous_discriminant() {
        let anchor = Anchor::default();
        let first = QrDiscriminant::ZERO.next(anchor);
        let second = first.next(anchor);
        assert_ne!(first, QrDiscriminant::ZERO, "mint must move off zero");
        assert_ne!(first, second, "same anchor must still advance the chain");
    }
}
