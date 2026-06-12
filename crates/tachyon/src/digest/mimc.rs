use pasta_curves::Fp;
use zcash_mimc::{Spec as _, tachyon::TachyonP5R64};

use crate::keys::NoteMasterKey;

/// Derives a note's nullifier for an epoch under its multi-key MiMC keyset
/// and per-note input salt: `nf = E_mk(mk_s + epoch)`.
///
/// `keyset` is the cyclic §5.2 key schedule `[mk_0, …, mk_{κ-1}]`; the
/// salted input keeps cipher plaintexts unknown to any adversary (only
/// consecutive input *differences* are known), the model
/// [`TachyonP5R64`]'s round count is stated against.
#[must_use]
pub(crate) fn nullifier(salt: Fp, round_keys: [Fp; NoteMasterKey::ROUND_KEYS], epoch: Fp) -> Fp {
    zcash_mimc::encrypt_with::<TachyonP5R64, Fp, 5, 64>(&round_keys, salt + epoch)
}

/// The per-round state trace of one epoch's nullifier derivation: the `R`
/// cipher states [`zcash_mimc::state_sequence`] produces for the salted input
/// `mk_s + epoch`. These are the round cells of that epoch's trace row (the
/// salted input itself is not stored), and the [`nullifier`] should be the
/// final element plus the whitening key.
#[must_use]
pub(crate) fn nullifier_state_sequence(
    salt: Fp,
    round_keys: [Fp; NoteMasterKey::ROUND_KEYS],
    epoch: Fp,
) -> ([Fp; TachyonP5R64::ROUNDS], Fp) {
    let state_sequence =
        zcash_mimc::state_sequence::<TachyonP5R64, Fp, 5, 64>(&round_keys, salt + epoch);

    #[expect(
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "sequence length matches expected"
    )]
    let nullifier = state_sequence[TachyonP5R64::ROUNDS - 1]
        + round_keys[TachyonP5R64::ROUNDS % round_keys.len()];

    (state_sequence, nullifier)
}
