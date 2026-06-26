//! Utilities for preparing step witnesses.
//!
//! Each function builds the off-circuit witness tuple consumed by a single
//! [`Step`](ragu::Step) in the Ragu PCD tree. The caller assembles the inputs
//! — key material, expanded traces, consensus state, certified PCDs — and the
//! function returns the step's [`Witness`](ragu::Step::Witness) ready to thread
//! through [`PROOF_SYSTEM`](crate::stamp::proof::PROOF_SYSTEM).`fuse`.
//! Functions are named after the step they prepare a witness for.
//!
//! All key material is passed in as a parameter; none of these functions run
//! key derivation or the expansion cipher/FFT themselves. The expensive
//! [`NoteMasterKey::derive_expanded`](crate::keys::NoteMasterKey::derive_expanded)
//! and [`NoteMasterKey::derive_expanded_trace`](crate::keys::NoteMasterKey::derive_expanded_trace)
//! should be called once by the wallet and the results reused across steps.

use alloc::vec::Vec;
use core::array;

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Polynomial, Step};

use crate::{
    ExpandedKeyPoly,
    constants::NF_EMITTERS,
    digest::poseidon,
    keys::{ExpandedKey, NoteMasterKey},
    note::Nullifier,
    primitives::{
        Anchor, EpochIndex, ExpKeySpectrumPoly, NfEmitterPoly, NfEmittersDigest, NfSeqPoly,
        TachygramSetPoly,
    },
    relations::quotient::{
        self, LIFT_SPLITS, RoundBoundaryQuotients, accumulator_recurrence, weight_recurrence,
    },
    stamp::proof::{
        delegation::{NfMasterExpand, NullifierDerivationStep},
        pool::VerifyUnspent,
        spendable::SpendableInit,
    },
};

/// Prepare the witness for [`NfMasterExpand`] for one half:
/// `(trace T, round/boundary quotients, half-key poly, decimation quotient,
/// half)`.
///
/// The caller supplies this half's expansion products — `spectrum` (the trace
/// `T`) and `half_keys` (the half's `EK_HALF` keys) — produced by
/// [`NoteMasterKey::derive_expanded_trace`](crate::keys::NoteMasterKey::derive_expanded_trace)
/// with the matching `half`. `mk` is passed in for the round-key lookups the
/// quotient builders use. `base = half · EK_HALF` is the cipher-input window
/// origin. This function only builds the quotients the in-circuit relations
/// open against; it does not re-run the expansion cipher or any FFT.
#[must_use]
pub fn nf_master_expand<'key>(
    mk: &'key NoteMasterKey,
    spectrum: &'key ExpKeySpectrumPoly,
    half_keys: &'key [Fp; ExpandedKey::EK_HALF],
    half: usize,
) -> <NfMasterExpand as Step>::Witness<'key> {
    let key_poly = ExpandedKey::half_key_poly(half_keys);
    #[expect(clippy::as_conversions, reason = "constant size")]
    let base = Fp::from((half * ExpandedKey::EK_HALF) as u64);
    let (round, boundary, decimation_quotient) = quotient::expansion_quotients(
        spectrum.0.coefficients(),
        *mk,
        key_poly.0.coefficients(),
        base,
    );
    #[expect(clippy::as_conversions, reason = "half is 0 or 1")]
    (
        spectrum.clone(),
        RoundBoundaryQuotients { round, boundary },
        key_poly,
        decimation_quotient,
        Fp::from(half as u64),
    )
}

/// Prepare the witness for [`NullifierDerivationStep`]:
/// `(A, B, T_j, quotients_j, E_0)`.
///
/// `key_a`/`key_b` are the even/odd half-key polys (from
/// [`ExpandedKey::half_key_poly`](crate::keys::ExpandedKey::half_key_poly));
/// the full interleaved `keyset` supplies the 256-key schedule the round
/// quotients are built against. `polys` are the caller-supplied derivation
/// polynomials `T_j` (the per-emitter IFFTs, produced once and reused across
/// steps); `mk` supplies the per-poly salts (a cheap sponge) the boundary
/// quotients bind against. `creation_epoch` (`E_0`) is the offset origin (later
/// pinned by `SpendableInit`).
#[must_use]
pub fn nullifier_derivation<'key>(
    keyset: &'key ExpandedKey,
    key_a: ExpandedKeyPoly,
    key_b: ExpandedKeyPoly,
    mk: &'key NoteMasterKey,
    polys: &'key [NfEmitterPoly; NF_EMITTERS],
    creation_epoch: EpochIndex,
) -> <NullifierDerivationStep as Step>::Witness<'key> {
    let salts = mk.query_salts();
    // k_0 = K(1) = A(1) = the even-position-0 key.
    let first_key = keyset.round_key(0);

    #[expect(clippy::indexing_slicing, reason = "todo")]
    let quotients: [RoundBoundaryQuotients<_>; NF_EMITTERS] = array::from_fn(|i| {
        RoundBoundaryQuotients {
            round: quotient::nf_emitter_round_quotient(polys[i].0.coefficients(), &keyset.0),
            boundary: quotient::nf_emitter_boundary_quotient(
                polys[i].0.coefficients(),
                salts.0[i],
                first_key,
            ),
        }
    });
    (key_a, key_b, polys.clone(), quotients, creation_epoch)
}

/// Prepare the witness for [`SpendableInit`]:
/// `(pre_epoch_anchor, pre_cm_anchor, creation_set, polys)`.
///
/// `polys` are the caller-supplied derivation polynomials `T_j` (the
/// per-emitter IFFTs, produced once and reused across steps). The set poly
/// and the two anchors are consensus state the caller reconstructs.
#[must_use]
pub fn spendable_init(
    polys: &[NfEmitterPoly; NF_EMITTERS],
    pre_epoch_anchor: Anchor,
    pre_cm_anchor: Anchor,
    creation_set: TachygramSetPoly,
) -> <SpendableInit as Step>::Witness<'_> {
    (pre_epoch_anchor, pre_cm_anchor, creation_set, polys.clone())
}

/// Prepare the witness for [`VerifyUnspent`]:
/// `(elapsed_poly, tip_poly, range_poly, T_j, weights, accumulator,
/// weight_quotients, accumulator_quotient)`.
///
/// The lift witness is the most complex: it reconstructs the sync-tested
/// polynomial `q = elapsed ++ [present_nf]` over `[start, present]`, then
/// builds the per-poly geometric weights `w_j`, the exclusive-prefix
/// accumulator `A`, and their recurrence quotients for the lift challenge
/// `β = Poseidon(derivation_digest, commit(q), start, end)`. `polys` are the
/// caller-supplied derivation polynomials `T_j` (the per-emitter IFFTs,
/// produced once and reused across steps); `mk` supplies the ratios/shift (a
/// cheap sponge); `digest` is the certified derivation transcript digest the
/// caller reads off the certified derivation PCD header.
#[must_use]
pub fn verify_unspent<'key>(
    polys: &'key [NfEmitterPoly; NF_EMITTERS],
    mk: &'key NoteMasterKey,
    digest: NfEmittersDigest,
    range_nfs: &'key [Nullifier],
    start: EpochIndex,
    present: EpochIndex,
) -> <VerifyUnspent as Step>::Witness<'key> {
    use group::Curve as _;
    use pasta_curves::{Eq, arithmetic::CurveAffine as _};

    // The ratios and shift are re-derived from mk (they match the certified
    // derivation header's by the derivation step's soundness).
    let (ratios, shift) = mk.query_weights();

    // Tested values q over [start, present]: query nullifiers at offsets.
    let split = range_nfs.len() - 1;
    let (elapsed_nfs, tip_nfs) = range_nfs.split_at(split);
    let elapsed = NfSeqPoly::from(elapsed_nfs);
    let tip = NfSeqPoly::from(tip_nfs);
    let range_poly = NfSeqPoly::from(range_nfs);

    // Lift challenge β over the certified digest, commit(q), and range.
    let range_coords = Eq::from(range_poly.commit())
        .to_affine()
        .coordinates()
        .expect("range commitment is not identity");
    let beta = poseidon::lift_challenge(digest.0, range_coords, start, present.next());

    // Per-poly geometric weights w_j (split) and quotients; the
    // exclusive-prefix accumulator A (split) and its recurrence quotient.
    let (weights, weight_quotients): (Vec<_>, Vec<_>) = ratios
        .0
        .map(|ratio| weight_recurrence(ratio * beta, shift.0))
        .into_iter()
        .unzip();
    let weights_arr: [[Polynomial; LIFT_SPLITS]; NF_EMITTERS] =
        weights.try_into().unwrap_or_else(|extra: Vec<_>| {
            unreachable!("NF_EMITTERS is {NF_EMITTERS}, got {}", extra.len())
        });
    let weight_quotients_arr: [Polynomial; NF_EMITTERS] =
        weight_quotients.try_into().unwrap_or_else(|extra: Vec<_>| {
            unreachable!("NF_EMITTERS is {NF_EMITTERS}, got {}", extra.len())
        });
    let (accumulator, accumulator_quotient) =
        accumulator_recurrence(polys, &ratios.0, shift.0, beta);

    (
        elapsed,
        tip,
        range_poly,
        polys.clone(),
        weights_arr,
        accumulator,
        weight_quotients_arr,
        accumulator_quotient,
    )
}
