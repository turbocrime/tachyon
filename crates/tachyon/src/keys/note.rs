//! Note-related keys: NullifierKey, NoteMasterKey, PaymentKey.

extern crate alloc;

use alloc::vec::Vec;
use core::{array, fmt, iter};

use ff::PrimeField as _;
use pasta_curves::{Fp, arithmetic::CurveAffine as _};
use ragu::Polynomial;

use super::proof::SpendValidatingKey;
use crate::{
    NfSeqPoly, NullifierEraTrace,
    constants::{EPOCH_MAX, ERA_EPOCHS},
    digest::{mimc, poseidon},
    note::{self, Nullifier},
    primitives::{EpochIndex, NullifierEra},
};

/// A Tachyon nullifier deriving key.
///
/// Tachyon simplifies Orchard's nullifier construction
/// ("Tachyaction at a Distance", Bowe 2025): a per-note keyset
/// $[\mathsf{mk}_0, \ldots, \mathsf{mk}_{n-1}]$, each $\mathsf{mk}_i =
/// \text{Poseidon}(\Psi, \mathsf{nk}, i)$; the leading keys key the
/// multi-key MiMC cipher and the last key is the input salt $\mathsf{mk}_s$,
/// so the nullifier for an epoch is
///
/// $$\mathsf{nf}_e = E_{\mathsf{mk}}(\mathsf{mk}_s + e)$$
///
/// where $\Psi$ is the note's nullifier trapdoor and $e$ the epoch-id.
///
/// `nk` alone does NOT confer spend authority; combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// and nullifier derivation without signing capability.
#[derive(Clone, Copy)]
pub struct NullifierKey(pub(super) Fp);

impl NullifierKey {
    /// Derive a note's master-key seed from its nullifier trapdoor `psi`.
    #[must_use]
    pub fn derive_note_private(&self, psi: &note::NullifierTrapdoor) -> NoteMasterKey {
        NoteMasterKey(array::from_fn(|i| {
            poseidon::nf_master(
                psi.0,
                self.0,
                Fp::from(
                    #[expect(clippy::expect_used, reason = "fits usize")]
                    u64::try_from(i).expect("fits usize"),
                ),
            )
        }))
    }
}

/// Per-note master secret: the MiMC keyset.
///
/// Derived on the user device as $\mathsf{mk}_i = \text{Poseidon}(\Psi,
/// \mathsf{nk}, i)$ for $i = 0, \ldots, n-1$. The leading keys key the
/// multi-key MiMC cipher and the last is the input salt; the nullifier for
/// epoch $e$ is $\mathsf{nf}_e = E_{\mathsf{mk}}(\mathsf{mk}_s + e)$,
/// multi-key MiMC in evaluation mode on inputs never known to an adversary
/// (only consecutive input differences are).
///
/// ## Delegation: value windows only
///
/// Delegation operates on value windows only; there is no key-material
/// delegation API, and the wallet is the sole prover of derivation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteMasterKey(pub(crate) [Fp; Self::KEY_LENGTH]);

impl NoteMasterKey {
    /// The length of the key in bytes.
    pub const KEY_BYTES: usize = Self::KEY_LENGTH * size_of::<Fp>();
    /// The number of Fp elements in the key.
    pub const KEY_LENGTH: usize = 3;
    /// The number of Fp elements used as round keys.
    pub const ROUND_KEYS: usize = Self::KEY_LENGTH - 1;

    /// Derive the nullifier for the given epoch: `nf = E_mk(mk_s + epoch)`.
    #[must_use]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        assert!(epoch.0 <= EPOCH_MAX, "epoch exceeds epoch space");
        let [round_keys @ .., salt] = self.0;
        Nullifier::from(mimc::nullifier(salt, round_keys, Fp::from(epoch)))
    }

    /// The round keys.
    #[must_use]
    pub const fn round_keys(&self) -> [Fp; Self::ROUND_KEYS] {
        let [round_keys @ .., _salt] = self.0;
        round_keys
    }

    /// The round key at the given index.
    #[must_use]
    pub const fn round_key(&self, index: usize) -> Fp {
        #[expect(clippy::integer_division_remainder_used, reason = "modulo index")]
        self.0[index % Self::ROUND_KEYS]
    }

    /// The salt.
    #[must_use]
    pub const fn salt(&self) -> Fp {
        let [_round_keys @ .., salt] = self.0;
        salt
    }

    /// Derive the nullifier era for the window `[start, start + ERA_EPOCHS)`:
    /// the row-major cell matrix whose rows are each epoch's MiMC round-state
    /// sequence (one cell per cipher round, the salted input `mk_s + epoch` not
    /// stored) plus the nullifier sequence it produces (each row's final state
    /// plus the whitening key), as a pre-FFT [`NullifierEra`]. One cipher pass,
    /// no transform; interpolate to a proof witness with
    /// [`NullifierEra::into_trace`].
    #[must_use]
    pub fn derive_era(&self, start: EpochIndex) -> NullifierEra {
        let [round_keys @ .., salt] = self.0;

        let epochs =
            iter::successors(Some(start), |prev: &EpochIndex| Some(prev.next())).take(ERA_EPOCHS);

        let (states, outputs): (Vec<_>, Vec<_>) = epochs
            .map(|epoch| mimc::nullifier_state_sequence(salt, round_keys, epoch.into()))
            .unzip();

        let nullifiers: Vec<Nullifier> = outputs.into_iter().map(Nullifier::from).collect();

        #[expect(clippy::expect_used, reason = "correct length")]
        NullifierEra::new(
            states.concat(),
            &nullifiers.try_into().expect("correct length"),
        )
    }

    /// Compute the prover-derived era witness components a caller does not
    /// already hold: the round, boundary, and sumcheck quotients and the
    /// reduction `G`, for the given `trace`, era `start`, and committed output
    /// `range`. The caller assembles the witness from these plus what it knows
    /// (`start`, `trace`, `range`). The round and boundary quotients are honest
    /// for this keyset; `pos`, `G`, and `Q_s` follow `range`, so a forgery test
    /// can pass a tampered sequence to isolate the conversion check. The
    /// trace's coset evaluation is computed once and shared across the
    /// three builders.
    // TODO(#139): name pending; this is the era prover's quotient/reduction
    // pass, candidate to graduate from the test fixture to non-test code.
    #[must_use]
    pub fn era_quotients(
        &self,
        trace: &NullifierEraTrace,
        start: EpochIndex,
        range: &NfSeqPoly,
    ) -> (
        [Polynomial; quotient_utils::ROUND_QUOTIENT_SPLITS],
        Polynomial,
        Polynomial,
        Polynomial,
    ) {
        let trace_coeffs = trace.coefficients();
        let trace_ext = quotient_utils::coset_evaluations(trace_coeffs, quotient_utils::EXTENDED);
        let round_quotient = quotient_utils::era_round_quotient(&trace_ext, *self);
        let boundary_quotient = quotient_utils::era_boundary_quotient(
            &trace_ext,
            self.salt() + Fp::from(start),
            self.round_key(0),
        );

        // The reduction position, from the two committed polynomials.
        let trace_commit: ragu::Commitment = trace.commit().into();
        let range_commit: ragu::Commitment = range.commit().into();

        let reduction_pos = {
            let trace_coords = (*trace_commit.inner())
                .coordinates()
                .expect("era trace commitment is not identity");
            let range_coords = (*range_commit.inner())
                .coordinates()
                .expect("era range commitment is not identity");
            poseidon::era_reduction(trace_coords, range_coords)
        };
        let (reduction, sumcheck_quotient) =
            quotient_utils::era_reduction(&trace_ext, trace_coeffs, reduction_pos);

        (
            round_quotient,
            boundary_quotient,
            sumcheck_quotient,
            reduction,
        )
    }
}

impl From<NoteMasterKey> for [u8; NoteMasterKey::KEY_BYTES] {
    fn from(mk: NoteMasterKey) -> Self {
        let mut out = [0u8; NoteMasterKey::KEY_BYTES];
        for (chunk, key_part) in out.chunks_mut(size_of::<Fp>()).zip(mk.0) {
            chunk.copy_from_slice(&key_part.to_repr());
        }
        out
    }
}

/// A Tachyon payment key — static per-spending-key recipient identifier.
///
/// Replaces Orchard's diversified transmission key $\mathsf{pk_d}$ and
/// the entire diversified address system. Tachyon removes the diversifier
/// $d$ because payment addresses are removed from the on-chain protocol
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// > "The transmission key $\mathsf{pk_d}$ is substituted with a payment
/// > key $\mathsf{pk}$."
///
/// ## Derivation
///
/// Derived from the proof authorizing key components:
///
/// $$\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
/// \mathsf{nk})$$
///
/// where $\mathsf{ak}_x$ is the x-coordinate of the spend validating key.
/// This binds `pk` to both `ak` and `nk`, so the note commitment `cm`
/// (which contains `pk`) transitively pins the full proof authorizing key.
/// Wrong `nk` produces wrong `pk`, wrong `cm`, and accumulator inclusion
/// fails.
///
/// Every note from the same spending key shares the same `pk`. There is
/// no per-note diversification — unlinkability is the wallet layer's
/// responsibility, not the core protocol's.
///
/// ## Usage
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band via higher-level protocols (ZIP 321 payment
/// requests, ZIP 324 URI encapsulated payments).
#[derive(Clone, Copy)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct PaymentKey(pub(crate) Fp);

impl PaymentKey {
    /// Derive the payment key from `ak` and `nk`:
    /// $\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
    /// \mathsf{nk})$.
    #[must_use]
    pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
        let ak_bytes: [u8; 32] = ak.0.into();
        let ak_fp = Fp::from_repr(ak_bytes).expect("ak bytes should be a valid Fp");
        Self(poseidon::payment_key(ak_fp, nk.0))
    }
}

impl fmt::Debug for NullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NullifierKey").finish_non_exhaustive()
    }
}

impl fmt::Debug for NoteMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteMasterKey").finish_non_exhaustive()
    }
}

impl fmt::Debug for PaymentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentKey").finish_non_exhaustive()
    }
}

#[expect(clippy::indexing_slicing, reason = "for internal use")]
mod quotient_utils {
    use alloc::{vec, vec::Vec};
    use core::array;

    use ff::{Field as _, PrimeField as _};
    use lazy_static::lazy_static;
    use pasta_curves::Fp;
    use ragu::{Domain, Polynomial};
    use zcash_mimc::{Spec as _, tachyon::TachyonP5R64};

    use super::NoteMasterKey;
    use crate::{NullifierEraTrace, constants::ERA_EPOCHS};

    /// Committed splits of the masked-quintic transition quotient (degree
    /// `5·8191 + 128` over an 8192-capacity commitment).
    pub(super) const ROUND_QUOTIENT_SPLITS: usize = 5;

    /// Extended (coset) evaluation domain size for the degree-5 round numerator
    /// (degree `5·8191 + 128 < EXTENDED`); also the size of the shared trace
    /// evaluation `trace_ext`.
    pub(super) const EXTENDED: usize = 1 << 16;

    /// Reduced (coset) evaluation domain size for the linear boundary and
    /// reduction numerators (degree `< REDUCED`), half the extended domain.
    const REDUCED: usize = 1 << 15;

    /// Row step: the extended-to-trace size ratio. `T(gX)` on the extended
    /// coset is `trace_ext` rotated by this, since ω_trace =
    /// ω_ext^ROW_STEP.
    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "exact power-of-two domain-size ratio"
    )]
    const ROW_STEP: usize = EXTENDED / NullifierEraTrace::TRACE_SIZE;

    /// Decimation stride: the extended-to-reduced size ratio. The reduced-coset
    /// evaluations are every REDUCE_STRIDE-th extended one, since
    /// ω_reduced = ω_ext^REDUCE_STRIDE.
    #[expect(
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "exact power-of-two domain-size ratio"
    )]
    const REDUCE_STRIDE: usize = EXTENDED / REDUCED;

    /// Coset shift for every evaluation domain in this module.
    const COSET: Fp = Fp::MULTIPLICATIVE_GENERATOR;

    /// Length of an era-stride spread: coefficient `k` of a
    /// `TRACE_COLUMNS`-term polynomial lands at degree `k·ERA_EPOCHS`.
    const SPREAD_LEN: usize = (NullifierEraTrace::TRACE_COLUMNS - 1) * ERA_EPOCHS + 1;

    lazy_static! {
        /// Output-cell mask `M(X) = X^ERA − column_root^OUTPUT_CELL` evaluated on
        /// the extended coset. Keyset-independent, so it is built once.
        static ref MASK_EXT: Vec<Fp> = {
            let column_root = Domain::new(NullifierEraTrace::TRACE_COLUMNS.ilog2()).omega();
            let mut mask = vec![Fp::ZERO; ERA_EPOCHS + 1];
            mask[0] = -column_root.pow_vartime(
                #[expect(clippy::as_conversions, reason = "constant conversion")]
                [(NullifierEraTrace::TRACE_COLUMNS - 1) as u64],
            );
            mask[ERA_EPOCHS] = Fp::ONE;
            coset_evaluations(&mask, EXTENDED)
        };

        /// Boundary complement `E(X) = Σ X^(ERA·m)` evaluated on the reduced
        /// coset. Keyset-independent, so it is built once.
        static ref COMPLEMENT_EXT: Vec<Fp> = coset_evaluations(
            &spread_by_era(&[Fp::ONE; NullifierEraTrace::TRACE_COLUMNS]),
            REDUCED,
        );

        /// Reduced-coset evaluations of the row-power interpolants, the cached
        /// basis that folds round 0 into the boundary without a per-call FFT.
        /// `ROW_POWER_EXT[j]` is the coset evaluation of the row-subgroup
        /// interpolant of `row^j`. The round-0 target `(a + row)^POW` (with
        /// `a = mk_s + start + k_0`) expands by the binomial theorem into
        /// `Σ_j C(POW, j) · a^{POW−j} · row^j`; since ifft and coset_evaluations
        /// are linear, its coset evaluation is this keyset-independent basis
        /// combined with per-call scalars (see `era_boundary_quotient`).
        /// Keyset-independent, so it is built once.
        static ref ROW_POWER_EXT: Vec<Vec<Fp>> = (0..=TachyonP5R64::POW)
            .map(|power| {
                #[expect(clippy::as_conversions, reason = "row index conversion")]
                let mut samples: Vec<Fp> =
                    (0..ERA_EPOCHS as u64).map(|row| Fp::from(row).pow_vartime([power])).collect();
                Domain::new(ERA_EPOCHS.ilog2()).ifft(&mut samples);
                coset_evaluations(&samples, REDUCED)
            })
            .collect();

        /// Extended-coset evaluations of the round offset's constants part: the
        /// `CONSTANTS[col + 1]` contribution of `offset[col]` alone (the row-wrap
        /// column zeroed), with no key material. The keyset-independent half of
        /// the cached `offset_ext` basis (see `era_round_quotient`). Built once.
        static ref OFFSET_CONST_EXT: Vec<Fp> = offset_basis_ext(
            &TachyonP5R64::CONSTANTS
                .iter()
                .skip(1)
                .copied()
                .chain([Fp::ZERO])
                .collect::<Vec<Fp>>(),
        );

        /// Extended-coset evaluations of the round offset's per-key selector
        /// bases, one per round-key residue class. `OFFSET_KEY_EXT[r]` is `1` at
        /// every column whose offset adds `round_key(r)` (i.e.
        /// `(col + 1) % ROUND_KEYS == r`, the row-wrap column excepted) and `0`
        /// elsewhere -- pure structure, no key material. The per-call combine
        /// scales each by `round_key(r)` (see `era_round_quotient`). Built once.
        static ref OFFSET_KEY_EXT: Vec<Vec<Fp>> = (0..NoteMasterKey::ROUND_KEYS)
            .map(|residue| {
                #[expect(
                    clippy::integer_division_remainder_used,
                    reason = "round-key residue class"
                )]
                let selector: Vec<Fp> = (0..NullifierEraTrace::TRACE_COLUMNS)
                    .map(|col| {
                        if col + 1 < NullifierEraTrace::TRACE_COLUMNS
                            && (col + 1) % NoteMasterKey::ROUND_KEYS == residue
                        {
                            Fp::ONE
                        } else {
                            Fp::ZERO
                        }
                    })
                    .collect();
                offset_basis_ext(&selector)
            })
            .collect();
    }

    /// Apply the keyset-independent offset transform to per-column `values`:
    /// interpolate over the column subgroup, spread by the era stride, and
    /// evaluate on the extended coset. Linear, so it builds each cached
    /// `offset_ext` basis (see `era_round_quotient`).
    fn offset_basis_ext(values: &[Fp]) -> Vec<Fp> {
        let mut coeffs = values.to_vec();
        Domain::new(NullifierEraTrace::TRACE_COLUMNS.ilog2()).ifft(&mut coeffs);
        coset_evaluations(&spread_by_era(&coeffs), EXTENDED)
    }

    /// The challenge-free masked-quintic transition quotient `Q_round`, as
    /// [`ROUND_QUOTIENT_SPLITS`](ROUND_QUOTIENT_SPLITS) adjacent
    /// splits. Builds the round numerator `mask·(T(gX) − (T + offset)^5)` on a
    /// coset of the extended domain and divides by `Z_D`.
    pub(super) fn era_round_quotient(
        trace_ext: &[Fp],
        keyset: NoteMasterKey,
    ) -> [Polynomial; ROUND_QUOTIENT_SPLITS] {
        // Per-column offset `round_key(col + 1) + CONSTANTS[col + 1]`, evaluated
        // on the extended coset. The transition out of column `col` produces
        // round `col + 1` (cell `col` is round `col`'s output, with the salted
        // input held outside the trace and pinned by the boundary), so column
        // `col` carries round `col + 1`'s offset; the row-wrap column is zeroed.
        //
        // The offset is affine in the round keys and ifft/spread/coset_evaluations
        // are linear, so its coset evaluation needs no per-call FFT: it is the
        // cached keyset-independent basis (OFFSET_CONST_EXT, OFFSET_KEY_EXT)
        // combined with the per-call `round_key(r)` scalars, bit-identical by
        // field linearity. The keys enter only in this combine, never the cache.
        let offset_ext: Vec<Fp> = {
            let const_ext: &[Fp] = &OFFSET_CONST_EXT;
            let key_ext: &[Vec<Fp>] = &OFFSET_KEY_EXT;
            (0..EXTENDED)
                .map(|point| {
                    let mut value = const_ext[point];
                    for (residue, basis) in key_ext.iter().enumerate() {
                        value += keyset.round_key(residue) * basis[point];
                    }
                    value
                })
                .collect()
        };

        // The output-cell mask is keyset-independent: built once (see MASK_EXT).
        let mask_ext: &[Fp] = &MASK_EXT;

        let quotient = coset_quotient(EXTENDED, |point| {
            let cipher_in = trace_ext[point] + offset_ext[point];
            // T(gX) is trace_ext rotated cyclically by ROW_STEP.
            #[expect(clippy::integer_division_remainder_used, reason = "cyclic rotation")]
            let shifted = trace_ext[(point + ROW_STEP) % EXTENDED];
            mask_ext[point] * (shifted - cipher_in.square().square() * cipher_in)
        });
        assert!(
            quotient.len() <= ROUND_QUOTIENT_SPLITS * NullifierEraTrace::TRACE_SIZE,
            "round quotient exceeds the split budget",
        );
        array::from_fn(|split| {
            let lo = split * NullifierEraTrace::TRACE_SIZE;
            let hi = ((split + 1) * NullifierEraTrace::TRACE_SIZE).min(quotient.len());
            Polynomial::from_coeffs(if lo < hi { &quotient[lo..hi] } else { &[] })
        })
    }

    /// The challenge-free boundary quotient `Q_boundary` (one split): builds
    /// `complement·(T − target)` on the reduced coset and divides by `Z_D`,
    /// where `target` interpolates each row's round-0 output. Round 0 is
    /// folded into the boundary here: `base = mk_s + start` makes the
    /// cipher input `base + row` for row-start cell `row`, and `first_key =
    /// k_0` (with `c_0 = 0`) maps that input through round 0's S-box,
    /// pinning each first-column cell to `(a + row)^POW` for `a = base +
    /// first_key`.
    ///
    /// The target's coset evaluation needs no per-call FFT: `(a + row)^POW`
    /// expands by the binomial theorem to `Σ_j C(POW, j) · a^{POW−j} · row^j`,
    /// so it is the cached row-power basis [`ROW_POWER_EXT`] combined with the
    /// per-call scalars `C(POW, j) · a^{POW−j}`. This matches the values the
    /// step pins via `enforce_first_column_values`.
    pub(super) fn era_boundary_quotient(trace_ext: &[Fp], base: Fp, first_key: Fp) -> Polynomial {
        // `C(5, j)` for `j = 0..=5`.
        const BINOMIAL: [u64; 6] = [1, 5, 10, 10, 5, 1];
        const {
            assert!(
                TachyonP5R64::POW == 5,
                "boundary binomial coefficients assume the x^5 S-box"
            );
        }

        // The complement `E(X) = Σ X^(ERA·m)` and the row-power basis are both
        // keyset-independent: built once (see COMPLEMENT_EXT, ROW_POWER_EXT).
        let complement_ext: &[Fp] = &COMPLEMENT_EXT;
        let row_power_ext: &[Vec<Fp>] = &ROW_POWER_EXT;

        // Per-call scalars `scale[j] = C(5, j) · a^{5−j}` for `a = base + k_0`.
        let alpha = base + first_key;
        let mut scale = [Fp::ZERO; BINOMIAL.len()];
        let mut alpha_power = Fp::ONE;
        for (degree, coefficient) in BINOMIAL.iter().enumerate().rev() {
            scale[degree] = Fp::from(*coefficient) * alpha_power;
            alpha_power *= alpha;
        }

        let quotient = coset_quotient(REDUCED, |point| {
            let target = scale
                .iter()
                .zip(row_power_ext.iter())
                .fold(Fp::ZERO, |acc, (weight, basis)| {
                    acc + *weight * basis[point]
                });
            complement_ext[point] * (trace_at_reduced(trace_ext, point) - target)
        });
        assert!(
            quotient.len() <= NullifierEraTrace::TRACE_SIZE,
            "boundary quotient exceeds one split"
        );
        Polynomial::from_coeffs(&quotient)
    }

    /// The converter reduction `G = T·w mod Z_D` and its sumcheck-link quotient
    /// `Q_s` (one split), built from the reduction position: `w` interpolates
    /// `pos^r` at the row output cells, `G` is their pointwise product reduced
    /// onto `D`, and `Q_s = (T·w − G)/Z_D`.
    pub(super) fn era_reduction(
        trace_ext: &[Fp],
        trace_coeffs: &[Fp],
        pos: Fp,
    ) -> (Polynomial, Polynomial) {
        let domain = Domain::new(NullifierEraTrace::TRACE_SIZE.ilog2());
        let mut trace_evals = trace_coeffs.to_vec();
        domain.fft(&mut trace_evals);

        let mut weight_evals = vec![Fp::ZERO; NullifierEraTrace::TRACE_SIZE];
        let mut power = Fp::ONE;
        for row in 0..ERA_EPOCHS {
            weight_evals
                [row * NullifierEraTrace::TRACE_COLUMNS + (NullifierEraTrace::TRACE_COLUMNS - 1)] =
                power;
            power *= pos;
        }

        let mut reduction_coeffs: Vec<Fp> = trace_evals
            .iter()
            .zip(weight_evals.iter())
            .map(|(trace_eval, weight_eval)| *trace_eval * *weight_eval)
            .collect();
        domain.ifft(&mut reduction_coeffs);
        let reduction = Polynomial::from_coeffs(&reduction_coeffs);

        let mut weight_coeffs = weight_evals;
        domain.ifft(&mut weight_coeffs);

        let weight_ext = coset_evaluations(&weight_coeffs, REDUCED);
        let reduction_ext = coset_evaluations(&reduction_coeffs, REDUCED);

        let quotient = coset_quotient(REDUCED, |point| {
            trace_at_reduced(trace_ext, point) * weight_ext[point] - reduction_ext[point]
        });
        assert!(
            quotient.len() <= NullifierEraTrace::TRACE_SIZE,
            "sumcheck quotient exceeds one split"
        );
        (reduction, Polynomial::from_coeffs(&quotient))
    }

    /// Trace value on the reduced coset, decimated from the shared extended
    /// evaluation `trace_ext`.
    fn trace_at_reduced(trace_ext: &[Fp], point: usize) -> Fp {
        trace_ext[point * REDUCE_STRIDE]
    }

    /// Spread `coeffs` by the era stride: place coefficient `k` at degree
    /// `k·ERA_EPOCHS`, zero elsewhere. `coeffs.len()` must not exceed
    /// `TRACE_COLUMNS`.
    fn spread_by_era(coeffs: &[Fp]) -> Vec<Fp> {
        let mut spread = vec![Fp::ZERO; SPREAD_LEN];
        for (column, &coeff) in coeffs.iter().enumerate() {
            spread[column * ERA_EPOCHS] = coeff;
        }
        spread
    }

    /// Multiply coefficient `k` by `base^k` in place, mapping `p(X)` to
    /// `p(base·X)`.
    fn scale_by_powers(coeffs: &mut [Fp], base: Fp) {
        let mut power = Fp::ONE;
        for coeff in coeffs.iter_mut() {
            *coeff *= power;
            power *= base;
        }
    }

    /// Build a numerator from its coset evaluations `numerator(point)` over the
    /// `size`-point coset domain, then divide by `Z_D` (asserting exact
    /// division).
    fn coset_quotient(size: usize, numerator: impl Fn(usize) -> Fp) -> Vec<Fp> {
        let evaluations: Vec<Fp> = (0..size).map(numerator).collect();
        era_quotient_coeffs(&coset_coefficients(evaluations))
    }

    /// Evaluations of `coeffs` on the coset `COSET · ⟨size-th root⟩`.
    pub(super) fn coset_evaluations(coeffs: &[Fp], size: usize) -> Vec<Fp> {
        assert!(
            coeffs.len() <= size,
            "numerator piece exceeds the coset domain"
        );
        let mut values = vec![Fp::ZERO; size];
        values[..coeffs.len()].copy_from_slice(coeffs);
        scale_by_powers(&mut values[..coeffs.len()], COSET);
        Domain::new(size.ilog2()).fft(&mut values);
        values
    }

    /// Coefficients from coset evaluations (inverse of [`coset_evaluations`]),
    /// trailing zeros trimmed. The domain size is the input length.
    fn coset_coefficients(mut values: Vec<Fp>) -> Vec<Fp> {
        Domain::new(values.len().ilog2()).ifft(&mut values);
        scale_by_powers(&mut values, COSET.invert().expect("coset shift is nonzero"));
        while values.last() == Some(&Fp::ZERO) {
            values.pop();
        }
        values
    }

    /// Exact division by `X^domain − 1`: returns `(quotient, remainder)` with
    /// `len(remainder) <= domain`, in `O(len)`.
    fn divide_by_vanishing(poly: &[Fp], domain: usize) -> (Vec<Fp>, Vec<Fp>) {
        if poly.len() <= domain {
            return (Vec::new(), poly.to_vec());
        }
        let mut remainder = poly.to_vec();
        let mut quotient = vec![Fp::ZERO; poly.len() - domain];
        for degree in (domain..poly.len()).rev() {
            let coeff = remainder[degree];
            quotient[degree - domain] += coeff;
            remainder[degree - domain] += coeff;
            remainder[degree] = Fp::ZERO;
        }
        remainder.truncate(domain);
        (quotient, remainder)
    }

    /// Divide an era numerator by `Z_D` and assert exact divisibility (a
    /// nonzero remainder means the trace violates the constraint),
    /// returning the quotient coefficients.
    fn era_quotient_coeffs(numerator: &[Fp]) -> Vec<Fp> {
        let (quotient, remainder) = divide_by_vanishing(numerator, NullifierEraTrace::TRACE_SIZE);
        assert!(
            remainder.iter().all(|coeff| *coeff == Fp::ZERO),
            "era numerator is not divisible by Z_D: the trace violates a constraint",
        );
        quotient
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::primitives::EpochIndex;

    #[test]
    fn derive_note_private_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk1 = nk.derive_note_private(&psi);
        let mk2 = nk.derive_note_private(&psi);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn different_psi_different_mk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = note::NullifierTrapdoor::random(rng);
        let psi2 = note::NullifierTrapdoor::random(rng);
        let mk1 = nk.derive_note_private(&psi1);
        let mk2 = nk.derive_note_private(&psi2);
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = note::NullifierTrapdoor::random(rng);
        let mk = nk.derive_note_private(&psi);
        assert_ne!(
            mk.derive_nullifier(EpochIndex(0u32)),
            mk.derive_nullifier(EpochIndex(1u32)),
        );
    }
}
