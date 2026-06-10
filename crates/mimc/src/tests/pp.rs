//! MiMC-p/p cipher tests over the [`TachyonP5R64`] instantiation.

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};

use super::{PERSONALIZATION, SAMPLES, inverse_exponent};
use crate::{Spec as _, encrypt_with, tachyon::TachyonP5R64};

/// `c_1` from the Python reference.
const EXPECTED_C1: Fp = Fp::from_raw([
    0xab71_a1f8_c93a_9d47,
    0x2ab1_a7c0_c80b_eb1c,
    0x1b15_535d_dcba_6422,
    0x074c_f4d2_38ee_9f54,
]);

/// `c_5` from the Python reference.
const EXPECTED_C5: Fp = Fp::from_raw([
    0x7c7c_dd4f_ae01_4c89,
    0x03bc_9cd9_e9a7_7339,
    0x86fd_6a01_11ff_ea18,
    0x0656_9ee5_8ffc_018c,
]);

/// `c_63`, the last constant, from the Python reference.
const EXPECTED_C63: Fp = Fp::from_raw([
    0xaeb9_9562_349d_d47e,
    0x64d9_5138_37ba_ffdd,
    0x4e04_63f8_6e8a_8f9a,
    0x1d59_97c4_5b43_1f6a,
]);

#[test]
fn pinned_round_constants_match_python_reference() {
    let constants = TachyonP5R64::CONSTANTS;
    assert_eq!(
        constants[1], EXPECTED_C1,
        "c_1 drifted from the Python reference"
    );
    assert_eq!(
        constants[5], EXPECTED_C5,
        "c_5 drifted from the Python reference"
    );
    assert_eq!(
        constants[63], EXPECTED_C63,
        "c_63 drifted from the Python reference"
    );
}

#[test]
fn encrypt_matches_pinned_vectors_at_tachyon_rounds() {
    // (key, input, ciphertext) triples at r = 64: the spec evaluated with the
    // canonical x^5 S-box, independent of `encrypt_with`'s unrolled round.
    let vectors = [
        (
            Fp::ZERO,
            Fp::ZERO,
            Fp::from_raw([
                0x4925_60af_f4d3_efee,
                0x97f0_09fb_5bc0_877e,
                0x9871_c51d_0328_efa7,
                0x1ec1_45f7_c6ac_ba28,
            ]),
        ),
        (
            Fp::from_raw([
                0x0000_0000_0000_0001,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
            Fp::from_raw([
                0x0000_0000_0000_0002,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
            Fp::from_raw([
                0x4e8f_a67e_9e5e_db86,
                0x67bc_e69d_e91a_a116,
                0xb38f_6a18_bfab_a469,
                0x1b63_6523_a3d3_b4fe,
            ]),
        ),
        (
            -Fp::ONE,
            -Fp::from(2u64),
            Fp::from_raw([
                0x72b1_2441_1a45_1350,
                0x717a_3d99_8879_fa51,
                0x658f_9a74_cb15_a118,
                0x2c51_053d_b014_d6c0,
            ]),
        ),
    ];

    for (key, input, expected) in vectors {
        assert_eq!(
            encrypt_with::<TachyonP5R64, Fp, 5, 64>(&[key], input),
            expected,
            "r=64 vector mismatch"
        );
    }
}

#[test]
fn cyclic_keys_match_pinned_vectors() {
    // keys [1, 2], x = 3 at r = 64: round i uses k_{i mod 2}, whitening is
    // k_{64 mod 2} = k_0.
    let expected_two = Fp::from_raw([
        0x8c1e_86c8_9383_7d0e,
        0x66b8_b238_84c0_9f7e,
        0x7ae5_936a_00d6_b3cb,
        0x16d5_6191_a52b_ad4e,
    ]);
    assert_eq!(
        encrypt_with::<TachyonP5R64, Fp, 5, 64>(
            &[
                Fp::from_raw([
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                Fp::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            ],
            Fp::from_raw([
                0x0000_0000_0000_0003,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
        ),
        expected_two,
        "kappa=2 vector mismatch"
    );

    // keys [1, 2, 3], x = 4 at r = 64: whitening is k_{64 mod 3} = k_1.
    let expected_three = Fp::from_raw([
        0xc054_c6cc_5217_902a,
        0xca78_a4c2_adb0_36e1,
        0xc19d_6ea6_afe0_05a0,
        0x20de_f51c_dea0_896b,
    ]);
    assert_eq!(
        encrypt_with::<TachyonP5R64, Fp, 5, 64>(
            &[
                Fp::from_raw([
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                Fp::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                Fp::from_raw([
                    0x0000_0000_0000_0003,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            ],
            Fp::from_raw([
                0x0000_0000_0000_0004,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
        ),
        expected_three,
        "kappa=3 vector mismatch"
    );
}

#[test]
fn pow5_is_a_permutation() {
    let inverse_five = inverse_exponent(5);
    let rng = &mut StdRng::seed_from_u64(0);
    for _ in 0..SAMPLES {
        let element = Fp::random(&mut *rng);
        let image = element.square().square().mul(&element);
        assert_eq!(
            image.pow(inverse_five),
            element,
            "x^5 then x^(5^-1 mod p-1) must be the identity"
        );
    }
}

#[test]
fn round_constant_schedule_hygiene() {
    let constants = TachyonP5R64::CONSTANTS;
    assert_eq!(
        constants.len(),
        TachyonP5R64::ROUNDS,
        "schedule length must equal ROUNDS"
    );
    assert_eq!(constants[0], Fp::ZERO, "c_0 must be zero");

    let mut reprs: Vec<[u8; 32]> = constants.iter().map(Fp::to_repr).collect();
    reprs.sort_unstable();
    reprs.dedup();
    assert_eq!(
        reprs.len(),
        TachyonP5R64::ROUNDS,
        "round constants must be pairwise distinct"
    );
}

#[test]
fn pinned_table_matches_blake2b_chain() {
    assert_eq!(
        TachyonP5R64::CONSTANTS.as_slice(),
        super::derive_chain(PERSONALIZATION, TachyonP5R64::ROUNDS).as_slice(),
        "pinned table must equal the Blake2b chain"
    );
}

#[test]
fn distinct_keys_give_distinct_ciphertexts() {
    let rng = &mut StdRng::seed_from_u64(0);
    let input = Fp::random(&mut *rng);
    for _ in 0..SAMPLES {
        let key_a = Fp::random(&mut *rng);
        let key_b = Fp::random(&mut *rng);
        assert_ne!(key_a, key_b, "rng produced a key collision");
        assert_ne!(
            encrypt_with::<TachyonP5R64, Fp, 5, 64>(&[key_a], input),
            encrypt_with::<TachyonP5R64, Fp, 5, 64>(&[key_b], input),
            "distinct keys must give distinct ciphertexts"
        );
    }
}
