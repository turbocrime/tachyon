//! # zcash_mimc
//!
//! The MiMC block cipher (additive construction, exponent $x^5$) over prime
//! fields, per [eprint 2016/492] §2.1/§5.1: for $i \in 0 \ldots r-1$,
//! $x \gets (x + k_{i \bmod \kappa} + c_i)^5$; the ciphertext is the final
//! $x + k_{r \bmod \kappa}$, with $c_0 = 0$ and a cyclic schedule of
//! $\kappa$ keys (§5.2; $\kappa = 1$ adds the same key every round).
//! Forward direction only: no inverse cipher is provided.
//!
//! Instances are described by a [`Spec`]: a pure-data trait carrying the
//! S-box exponent `P`, the round count `R`, and the pinned round-constant
//! table, all compile-time constants. Each shipped instantiation lives in
//! its own module: the Tachyon instantiation is [`tachyon::TachyonP5R64`],
//! consumed through the single generic construction [`encrypt_with`].
//!
//! [eprint 2016/492]: https://eprint.iacr.org/2016/492

#![no_std]
#![allow(
    clippy::indexing_slicing,
    clippy::integer_division_remainder_used,
    reason = "do not care"
)]

#[cfg(test)]
extern crate alloc;

use ff::PrimeField;

pub mod tachyon;

/// The type used to hold permutation state.
pub type State<F, const T: usize> = [F; T];

/// A specification for a MiMC instance over a prime field: `R` rounds of the
/// monomial S-box $x \mapsto x^P$ under a pinned constant schedule.
///
/// A `Spec` is pure data, entirely in compile-time constants; golden vectors
/// pin the `Spec`, and constructions ([`encrypt_with`]) derive the behavior
/// from it.
pub trait Spec<F: PrimeField, const P: u64, const R: usize> {
    /// The number of rounds.
    const ROUNDS: usize = R;

    /// The round-constant schedule, with $c_0 = 0$, pinned as literals from
    /// an independent reference implementation (a test re-derives the chain
    /// and cross-checks the table).
    const CONSTANTS: &'static [F; R];

    /// The S-box exponent: each round computes $x \mapsto x^P$.
    ///
    /// $\gcd(P, p - 1) = 1$ is required for the round function to be a
    /// permutation, which MiMC-$p$/$p$ use requires.
    const POW: u64 = P;
}

/// One MiMC round, the construction's S-box: $x \mapsto (x + \text{key} +
/// \text{constant})^P$.
///
/// The S-box is the single `pow_vartime` raising to the public exponent `P`, so
/// any `P` is supported (the variable-time exponentiation leaks only `P`, which
/// is public, never the secret base). This is the single source of the
/// per-round step: both [`encrypt_with`] and [`state_sequence`] are built on
/// it.
#[must_use]
pub fn round<F: PrimeField, const P: u64>(state: F, key: F, constant: F) -> F {
    (state + key + constant).pow_vartime([P])
}

/// The per-round pre-whitening state sequence for `R` rounds under the cyclic
/// key schedule. The caller's `input` state (before round 0) is not included.
///
/// Shares its per-round step with [`encrypt_with`] via [`round`], so the two
/// never diverge: `encrypt_with` is this sequence's final element plus the
/// whitening key.
#[must_use]
pub fn state_sequence<S, F: PrimeField, const P: u64, const R: usize>(
    keys: &[F],
    input: F,
) -> [F; R]
where
    S: Spec<F, P, R>,
{
    assert!(!keys.is_empty(), "key schedule must be non-empty");
    let mut states = [input; R];
    let mut state = input;
    for ((i, constant), slot) in S::CONSTANTS.iter().enumerate().zip(states.iter_mut()) {
        #[expect(
            clippy::unreachable,
            clippy::integer_division_remainder_used,
            reason = "mod length is in bounds"
        )]
        let round_key = keys.get(i % keys.len()).unwrap_or_else(|| unreachable!());

        state = round::<F, P>(state, *round_key, *constant);
        *slot = state;
    }
    states
}

/// MiMC-$p$/$p$ encryption under the cyclic key schedule `keys`.
///
/// One [`round`] per constant, each adding $k_{i \bmod \kappa}$, with final
/// whitening by the next key in the cycle ($k_{r \bmod \kappa}$). For a
/// single key this is the §2.1 cipher; for several it is the §5.2 larger-key
/// variant. Plain field arithmetic over the pinned compile-time constant
/// table, with a compile-time-fixed iteration count and no allocation.
#[must_use]
pub fn encrypt_with<S, F: PrimeField, const P: u64, const R: usize>(keys: &[F], input: F) -> F
where
    S: Spec<F, P, R>,
{
    assert!(!keys.is_empty(), "key schedule must be non-empty");
    let after_rounds = S::CONSTANTS
        .iter()
        .enumerate()
        .fold(input, |state, (i, constant)| {
            #[expect(
                clippy::unreachable,
                clippy::integer_division_remainder_used,
                reason = "mod length is in bounds"
            )]
            let round_key = keys
                .get(i % keys.len())
                .unwrap_or_else(|| unreachable!("index mod length is in bounds"));

            round::<F, P>(state, *round_key, *constant)
        });

    // After `R` rounds the cyclic schedule's next key is the whitening key.
    #[expect(
        clippy::unreachable,
        clippy::integer_division_remainder_used,
        reason = "mod length is in bounds"
    )]
    let whitening = keys
        .get(R % keys.len())
        .unwrap_or_else(|| unreachable!("index mod length is in bounds"));

    after_rounds + whitening
}

#[cfg(test)]
mod tests;
