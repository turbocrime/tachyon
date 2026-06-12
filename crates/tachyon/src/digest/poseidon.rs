//! Tachyon Poseidon digests.
//!
//! Each named function provides one protocol-defined hash.

// TODO(#39): replace halo2_poseidon with Ragu Poseidon params

use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{EpAffine, EqAffine, Fp, arithmetic::Coordinates};

use crate::EpochIndex;

fn hash<const L: usize>(input: [Fp; L]) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(input)
}

const ACTION_DIGEST_DOMAIN: &[u8; 16] = b"Tachyon-ActionDg";

/// Derives an action digest from action fields.
pub(crate) fn action_digest(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*ACTION_DIGEST_DOMAIN)),
        *cv.x(),
        *cv.y(),
        *rk.x(),
        *rk.y(),
    ])
}

const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Derives a payment key from a spend validating key and nullifier key.
#[must_use]
pub(crate) fn payment_key(ak: Fp, nk: Fp) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN)),
        ak,
        nk,
    ])
}

const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-CmDerive";

/// Derives a note commitment from note fields.
#[must_use]
pub(crate) fn note_commitment(rcm: Fp, pk: Fp, value: u64, psi: Fp) -> Fp {
    hash::<5>([
        Fp::from_u128(u128::from_le_bytes(*NOTE_COMMITMENT_DOMAIN)),
        rcm,
        pk,
        Fp::from(value),
        psi,
    ])
}

const NULLIFIER_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-NfMaster";

/// Derives a master key element from note trapdoor and wallet nullifier key.
#[must_use]
pub(crate) fn nf_master(psi: Fp, nk: Fp, index: Fp) -> Fp {
    hash::<4>([
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_MASTER_DOMAIN)),
        psi,
        nk,
        index,
    ])
}

const ANCHOR_STAMP_DOMAIN: &[u8; 16] = b"Tachyon-StampFld";

/// Advances the anchor by absorbing one stamp's tachygram-set commitment.
#[must_use]
pub(crate) fn anchor_stamp_step(anchor_prev: Fp, tgs: Coordinates<EqAffine>) -> Fp {
    let (x, y) = (tgs.x().to_repr(), tgs.y().to_repr());

    #[expect(clippy::expect_used, reason = "constant size decomposition")]
    let (x_lo, x_hi, y_lo, y_hi) = (
        Fp::from_u128(u128::from_le_bytes(x[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(x[16..].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[..16].try_into().expect("16 bytes"))),
        Fp::from_u128(u128::from_le_bytes(y[16..].try_into().expect("16 bytes"))),
    );

    hash::<6>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_STAMP_DOMAIN)),
        anchor_prev,
        x_lo,
        x_hi,
        y_lo,
        y_hi,
    ])
}

const ANCHOR_EMPTY_DOMAIN: &[u8; 16] = b"Tachyon-EmptyBlk";

/// Advances the anchor through one block that contains zero stamps.
#[must_use]
pub(crate) fn anchor_empty_step(anchor_prev: Fp) -> Fp {
    hash::<2>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_EMPTY_DOMAIN)),
        anchor_prev,
    ])
}

const ANCHOR_EPOCH_DOMAIN: &[u8; 16] = b"Tachyon-EpochStp";

/// Advances the terminal anchor of an epoch into a new epoch's initial state.
#[must_use]
pub(crate) fn anchor_epoch_step(anchor_prev: Fp, new_epoch: EpochIndex) -> Fp {
    hash::<3>([
        Fp::from_u128(u128::from_le_bytes(*ANCHOR_EPOCH_DOMAIN)),
        anchor_prev,
        Fp::from(new_epoch),
    ])
}
