extern crate alloc;

use alloc::vec::Vec;

use pasta_curves::{EqAffine, Fp};
use ragu::{Commitment, Domain, Polynomial};
use zcash_mimc::{Spec as _, tachyon::TachyonP5R64};

use crate::{constants::ERA_EPOCHS, note::Nullifier};

/// The pre-FFT nullifier era: the row-major cell matrix plus its nullifiers.
///
/// The cells are the trace's evaluation form over the era domain (each row an
/// epoch's MiMC round-state sequence, one cell per cipher round), and the
/// nullifier sequence is what those rows derive. Built by
/// [`NoteMasterKey::derive_era`](crate::keys::NoteMasterKey::derive_era) from
/// one cipher pass, with no transform: callers that only need the sequence read
/// [`nullifiers`](Self::nullifiers) and skip the FFT; callers building a proof
/// interpolate it into the witness-format [`NullifierEraTrace`] with
/// [`into_trace`](Self::into_trace).
#[derive(Clone, Debug)]
pub struct NullifierEra {
    cells: Vec<Fp>,
    nullifiers: [Nullifier; ERA_EPOCHS],
}

impl NullifierEra {
    /// Wrap a prebuilt cell matrix (evaluations over the era domain) and the
    /// nullifier sequence its rows derive.
    #[must_use]
    pub(crate) fn new(cells: Vec<Fp>, nullifiers: &[Nullifier; ERA_EPOCHS]) -> Self {
        assert_eq!(
            cells.len(),
            NullifierEraTrace::TRACE_SIZE,
            "cells length mismatch"
        );
        Self {
            cells,
            nullifiers: *nullifiers,
        }
    }

    /// The era's nullifier sequence, derived without interpolation.
    #[must_use]
    pub const fn nullifiers(&self) -> &[Nullifier; ERA_EPOCHS] {
        &self.nullifiers
    }

    /// Interpolate the cells into the committed witness-format trace
    /// ([`Domain::ifft`]).
    #[must_use]
    pub fn into_trace(self) -> NullifierEraTrace {
        NullifierEraTrace::from_evaluations(self.cells)
    }
}

/// Pedersen commitment to a nullifier era derivation trace $T$.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NullifierEraTraceCommit(Commitment);

/// Witness polynomial for a nullifier era derivation trace $T$.
///
/// The row-major matrix whose rows are the per-epoch MiMC round-state sequences
/// (one cell per cipher round), interpolated over the era evaluation domain
/// into the committed coefficient form the witness needs. Produced from a
/// [`NullifierEra`] via [`NullifierEra::into_trace`].
#[derive(Clone, Debug)]
pub struct NullifierEraTrace(Polynomial);

impl NullifierEraTrace {
    /// Columns per trace row: one state per cipher round.
    pub const TRACE_COLUMNS: usize = TachyonP5R64::ROUNDS;
    /// The era trace size: the row-major cell matrix over the evaluation domain
    pub const TRACE_SIZE: usize = Self::TRACE_COLUMNS * ERA_EPOCHS;

    /// Interpolate `cells` (the trace's evaluations over the era domain `D`)
    /// into the committed coefficient form. `cells.len()` must be a power of
    /// two (the domain size).
    #[must_use]
    fn from_evaluations(mut cells: Vec<Fp>) -> Self {
        assert_eq!(cells.len(), Self::TRACE_SIZE, "cells length mismatch");
        Domain::new(cells.len().ilog2()).ifft(&mut cells);
        Self(Polynomial::from_coeffs(&cells))
    }

    /// Deterministic (untrapdoored) commitment to the trace polynomial.
    #[must_use]
    pub fn commit(&self) -> NullifierEraTraceCommit {
        NullifierEraTraceCommit(self.0.commit())
    }

    /// The trace's coefficients, for off-circuit witness preparation (the
    /// prover evaluates the trace on the extended coset to build its
    /// quotients).
    #[must_use]
    pub fn coefficients(&self) -> &[Fp] {
        self.0.coefficients()
    }
}

impl From<NullifierEraTrace> for Polynomial {
    fn from(trace: NullifierEraTrace) -> Self {
        trace.0
    }
}

impl From<NullifierEraTraceCommit> for Commitment {
    fn from(commit: NullifierEraTraceCommit) -> Self {
        commit.0
    }
}

impl From<NullifierEraTraceCommit> for EqAffine {
    fn from(commit: NullifierEraTraceCommit) -> Self {
        *commit.0.inner()
    }
}
