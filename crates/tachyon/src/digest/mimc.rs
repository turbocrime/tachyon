use ff::PrimeField as _;
use pasta_curves::Fp;
use zcash_mimc::tachyon::TachyonP5R64;

const NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Derives a note's nullifier for an epoch under its MiMC master key.
#[must_use]
pub(crate) fn nullifier(mk: Fp, epoch: Fp) -> Fp {
    zcash_mimc::encrypt_with::<TachyonP5R64, Fp, 5, 64>(
        &[mk],
        Fp::from_u128(u128::from_le_bytes(*NULLIFIER_DOMAIN)) + epoch,
    )
}
