extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use super::Anchor;
use crate::{
    collections::{multiset, qr},
    digest::poseidon,
};

/// One depth's discriminant $R_j$, with $R_1 = H(\mathsf{terminal})$ and
/// $R_{j+1} = H(R_j)$. Every discriminant postdates the epoch's tachygrams.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(pub Fp);

impl QrDiscriminant {
    /// The epoch's first discriminant.
    #[must_use]
    pub fn of(terminal: Anchor) -> Self {
        Self(poseidon::qr_discriminant(Fp::from(terminal)))
    }

    /// The next depth's discriminant.
    #[must_use]
    pub fn next(self) -> Self {
        Self(poseidon::qr_discriminant(self.0))
    }
}

/// Witness polynomial for one side of a profile's path (discriminants encoded
/// as roots).
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrFilterPoly(Polynomial);

impl QrFilterPoly {
    /// Deterministic (untrapdoored) commitment to the filter.
    #[must_use]
    pub fn commit(&self) -> QrFilterCommit {
        QrFilterCommit(self.0.commit())
    }

    /// Evaluate the filter at a given point.
    #[must_use]
    pub fn eval(&self, at: Fp) -> Fp {
        self.0.eval(at)
    }
}

impl FromIterator<QrDiscriminant> for QrFilterPoly {
    fn from_iter<I: IntoIterator<Item = QrDiscriminant>>(iter: I) -> Self {
        Self(multiset::encode(iter.into_iter().map(Fp::from)))
    }
}

/// Pedersen commitment to one side of a profile's path.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrFilterCommit(Eq);

impl QrFilterCommit {
    /// The commitment to the empty filter.
    #[must_use]
    pub fn empty() -> Self {
        Self(multiset::encode(iter::empty()).commit())
    }
}

/// Witness polynomial interpolating one class's roots: $g(x_i) = y_i$ with
/// $y_i^2 = c\,(x_i + s)$ at that class's multiplier $c$ and shift $s$.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrInterpolantPoly(Polynomial);

impl QrInterpolantPoly {
    /// Deterministic (untrapdoored) commitment to the interpolant.
    #[must_use]
    pub fn commit(&self) -> QrInterpolantCommit {
        QrInterpolantCommit(self.0.commit())
    }

    /// Evaluate the interpolant at a given point.
    #[must_use]
    pub fn eval(&self, at: Fp) -> Fp {
        self.0.eval(at)
    }
}

/// Pedersen commitment to a class interpolant.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrInterpolantCommit(Eq);

/// Witness polynomial for one class decomposition's quotient: $h$ in $g^2 -
/// c\,(X + s) = q\,h$.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrQuotientPoly(Polynomial);

impl QrQuotientPoly {
    /// Deterministic (untrapdoored) commitment to the quotient.
    #[must_use]
    pub fn commit(&self) -> QrQuotientCommit {
        QrQuotientCommit(self.0.commit())
    }

    /// Evaluate the quotient at a given point.
    #[must_use]
    pub fn eval(&self, at: Fp) -> Fp {
        self.0.eval(at)
    }
}

/// Pedersen commitment to a class-decomposition quotient.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrQuotientCommit(Eq);

/// A QR profile: the number of splits taken and the side taken at each.
///
/// `bits` holds one side per bit, so a profile descends at most `u64::BITS`
/// times; within that bound two paths never share an encoding.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq, PartialOrd, Ord)]
pub struct QrProfile {
    /// The number of splits taken.
    pub depth: u64,
    /// The side taken at each split, outermost first from the high end.
    pub bits: u64,
}

impl QrProfile {
    /// The depth-zero profile.
    pub const ROOT: Self = Self { depth: 0, bits: 0 };

    /// The child profile on side `bit`, the residue side when set.
    ///
    /// # Panics
    ///
    /// Panics when `bits` has no bit left, at depth `u64::BITS`.
    #[must_use]
    pub fn descend(self, bit: bool) -> Self {
        assert!(
            self.depth < u64::from(u64::BITS),
            "profile has no bit left for another side"
        );
        Self {
            depth: self.depth + 1,
            bits: (self.bits << 1) | u64::from(bit),
        }
    }

    /// The side taken at each split, outermost split first.
    #[must_use]
    pub fn path(self) -> Vec<bool> {
        (0..self.depth)
            .map(|split| (self.bits >> (self.depth - 1 - split)) & 1 == 1)
            .collect()
    }

    /// The path's discriminants sorted by the side taken at each.
    #[must_use]
    pub fn discriminants_by_side(
        self,
        terminal: Anchor,
    ) -> (Vec<QrDiscriminant>, Vec<QrDiscriminant>) {
        let mut residue = Vec::new();
        let mut non_residue = Vec::new();
        let mut discriminant = QrDiscriminant::of(terminal);
        for bit in self.path() {
            if bit {
                residue.push(discriminant);
            } else {
                non_residue.push(discriminant);
            }
            discriminant = discriminant.next();
        }
        (residue, non_residue)
    }

    /// The class decomposition of `value` over one side of this path's
    /// discriminants, with `value` as the shift. `side` is the residue side
    /// when set.
    ///
    /// Returns `None` when `value` does not take `side` at every one of them.
    #[must_use]
    pub fn class_decomposition(
        self,
        terminal: Anchor,
        side: bool,
        value: Fp,
    ) -> Option<(QrInterpolantPoly, QrQuotientPoly)> {
        let (residue, non_residue) = self.discriminants_by_side(terminal);
        let points: Vec<(Fp, Fp)> = if side { residue } else { non_residue }
            .into_iter()
            .map(|discriminant| {
                let at = Fp::from(discriminant);
                (at, qr::classify(value, at).1)
            })
            .collect();
        let (interpolant, quotient) =
            qr::decomposition(&points, qr::class_multiplier(side), value)?;
        Some((interpolant.into(), quotient.into()))
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;

    use super::*;

    #[test]
    fn the_root_profile_has_no_bits() {
        assert_eq!(QrProfile::ROOT.depth, 0);
        assert_eq!(QrProfile::ROOT.path(), Vec::<bool>::new());
    }

    #[test]
    fn the_path_replays_the_splits_outermost_first() {
        let profile = QrProfile::ROOT.descend(false).descend(false).descend(true);
        assert_eq!(profile.depth, 3);
        assert_eq!(profile.path(), [false, false, true]);
        assert_eq!(profile.bits, 1);
    }

    #[test]
    fn distinct_split_histories_yield_distinct_profiles() {
        let deep_zeroes = QrProfile::ROOT.descend(false).descend(false);
        let shallow_zero = QrProfile::ROOT.descend(false);
        assert_ne!(deep_zeroes, shallow_zero);
        assert_ne!(deep_zeroes, QrProfile::ROOT);
    }

    #[test]
    #[should_panic(expected = "profile has no bit left for another side")]
    fn descending_past_the_register_panics() {
        let mut profile = QrProfile::ROOT;
        for _ in 0..=u64::BITS {
            profile = profile.descend(true);
        }
    }

    #[test]
    fn the_register_holds_its_full_width() {
        let mut profile = QrProfile::ROOT;
        for _ in 0..u64::BITS {
            profile = profile.descend(true);
        }
        assert_eq!(profile.depth, u64::from(u64::BITS));
        assert_eq!(profile.bits, u64::MAX);
        assert_eq!(profile.path(), [true; 64]);
    }

    #[test]
    fn the_discriminants_follow_the_path() {
        let terminal = Anchor::default();
        let first = QrDiscriminant::of(terminal);
        let second = first.next();
        assert_ne!(first, second);

        let (residue, non_residue) = QrProfile::ROOT
            .descend(true)
            .descend(false)
            .discriminants_by_side(terminal);
        assert_eq!(residue, [first]);
        assert_eq!(non_residue, [second]);

        let (root_residue, root_non_residue) = QrProfile::ROOT.discriminants_by_side(terminal);
        assert!(root_residue.is_empty() && root_non_residue.is_empty());
    }

    #[test]
    fn the_discriminant_derives_from_the_terminal_alone() {
        let terminal = Anchor::default();
        let first = QrDiscriminant::of(terminal);
        let again = QrDiscriminant::of(terminal);
        assert_eq!(first, again);
        assert_ne!(first.0, Fp::ZERO, "derivation must move off zero");
    }
}
