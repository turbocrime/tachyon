use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq};
use ff::Field as _;
use group::{Curve as _, Group as _};
use pasta_curves::Fp;

use super::{EpochIndex, TachygramSetCommit};
use crate::{digest::poseidon, serialization};

/// Errors that can occur when advancing an anchor.
#[derive(Debug, Display, Error)]
pub enum AnchorError {
    /// The provided tachygram set is empty.
    #[display("next stamp cannot be empty")]
    ZeroStamp,
    /// The provided epoch index is zero.
    #[display("next epoch cannot be zero")]
    ZeroEpoch,
}

/// Running anchor over the consensus state.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Anchor(pub Fp);

impl Anchor {
    /// Advance the anchor to the next stamp in the present epoch.
    ///
    /// The present epoch index may be zero, within the genesis epoch.
    ///
    /// # Errors
    ///
    /// Fails with `AnchorError::ZeroStamp` if `stamp_commit` is the identity
    /// point.
    pub fn next_stamp(
        self,
        present_epoch: EpochIndex,
        stamp_commit: &TachygramSetCommit,
    ) -> Result<Self, AnchorError> {
        if bool::from(stamp_commit.as_ref().is_identity()) {
            Err(AnchorError::ZeroStamp)
        } else {
            Ok(Self(poseidon::anchor_next_stamp(
                self.0,
                present_epoch.into(),
                stamp_commit.as_ref().to_affine(),
            )))
        }
    }

    /// Advance the anchor to the next epoch boundary.
    ///
    /// # Errors
    ///
    /// Fails with `AnchorError::ZeroEpoch` if `next_epoch` is zero, since there
    /// is no valid anchor before the genesis epoch boundary
    /// [`Anchor::default`].
    pub fn next_epoch(self, next_epoch: EpochIndex) -> Result<Self, AnchorError> {
        if next_epoch == EpochIndex(0) {
            Err(AnchorError::ZeroEpoch)
        } else {
            Ok(Self(poseidon::anchor_next_epoch(self.0, next_epoch.into())))
        }
    }

    /// Read a 32-byte anchor.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        serialization::read_fp(&mut reader).map(Self)
    }

    /// Write a 32-byte anchor.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_fp(&mut writer, &self.0)
    }
}

impl Default for Anchor {
    /// The genesis epoch boundary, for epoch zero.
    fn default() -> Self {
        Self(poseidon::anchor_next_epoch(Fp::ZERO, Fp::ZERO))
    }
}

#[cfg(test)]
mod tests {
    use pasta_curves::Eq;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{Tachygram, TachygramSetPoly};

    const EPOCH: EpochIndex = EpochIndex(7);

    /// Folding the same stamps in the same order yields the same anchor.
    #[test]
    fn next_stamp_is_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

        let run_one = Anchor::default()
            .next_stamp(EPOCH, &first)
            .expect("valid step")
            .next_stamp(EPOCH, &second)
            .expect("valid step");
        let run_two = Anchor::default()
            .next_stamp(EPOCH, &first)
            .expect("valid step")
            .next_stamp(EPOCH, &second)
            .expect("valid step");
        assert_eq!(run_one, run_two);
    }

    /// Two distinct stamp commits absorb to distinct anchors.
    #[test]
    fn distinct_stamps_distinct_anchors() {
        let rng = &mut StdRng::seed_from_u64(0);
        let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

        assert_ne!(
            Anchor::default()
                .next_stamp(EPOCH, &first)
                .expect("valid step"),
            Anchor::default()
                .next_stamp(EPOCH, &second)
                .expect("valid step"),
        );
    }

    /// Order matters: absorbing the same stamps in different orders diverges.
    #[test]
    fn order_matters() {
        let rng = &mut StdRng::seed_from_u64(0);
        let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

        let forward = Anchor::default()
            .next_stamp(EPOCH, &first)
            .expect("valid step")
            .next_stamp(EPOCH, &second)
            .expect("valid step");
        let reverse = Anchor::default()
            .next_stamp(EPOCH, &second)
            .expect("valid step")
            .next_stamp(EPOCH, &first)
            .expect("valid step");
        assert_ne!(forward, reverse);
    }

    /// Every link binds its epoch: the same tick in two epochs diverges.
    #[test]
    fn epoch_distinguishes_ticks() {
        let rng = &mut StdRng::seed_from_u64(0);
        let stamp = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let start = Anchor::default();

        assert_ne!(
            start.next_stamp(EpochIndex(1), &stamp).expect("valid step"),
            start.next_stamp(EpochIndex(2), &stamp).expect("valid step"),
        );
        assert_ne!(
            start.next_epoch(EpochIndex(1)).expect("valid step"),
            start.next_epoch(EpochIndex(2)).expect("valid step"),
        );
    }

    /// The boundary lift is domain-separated from stamp absorption, so a
    /// boundary anchor is unreachable by any chain link.
    #[test]
    fn next_epoch_distinct_from_next_stamp() {
        let rng = &mut StdRng::seed_from_u64(0);
        let stamp = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let via_epoch = Anchor::default().next_epoch(EPOCH);
        let via_stamp = Anchor::default().next_stamp(EPOCH, &stamp);
        assert_ne!(
            via_epoch.expect("valid step"),
            via_stamp.expect("valid step")
        );
    }

    /// The identity commitment has no Poseidon absorption, so it cannot
    /// advance the anchor.
    #[test]
    fn next_stamp_rejects_the_identity_commitment() {
        let identity = TachygramSetCommit::from(Eq::identity());

        let Err(AnchorError::ZeroStamp) = Anchor::default().next_stamp(EPOCH, &identity) else {
            panic!("identity commitment advanced the anchor");
        };
    }

    /// No boundary crosses into epoch zero; genesis rests there already.
    #[test]
    fn next_epoch_rejects_epoch_zero() {
        let Err(AnchorError::ZeroEpoch) = Anchor::default().next_epoch(EpochIndex(0)) else {
            panic!("epoch zero was crossed into");
        };

        assert_eq!(
            Anchor::default(),
            Anchor(poseidon::anchor_next_epoch(Fp::ZERO, Fp::ZERO)),
            "genesis remains the epoch-zero link"
        );
    }
}
