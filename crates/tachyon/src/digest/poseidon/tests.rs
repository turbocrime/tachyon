use core::str;

use ragu::primitives::{
    Simulator,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{curve::Projective as _, field::Field as _};

use super::*;

// All expected values were computed with standalone Python integer arithmetic
// (no ragu or udon code). Read ragu at 70fb72e8 with
// `git show 70fb72e8:qa/params/reference/pallas-t5.txt` (SHA-256
// 703f71fd3138e969a74090594fb264c31982623949ec7236c64e92d588942ee1).
// Parse the 64 rows of 5 hexadecimal integers in `Round constants for GF(p)`
// and the 5 rows under `MDS matrix` (not the inverse), in file order, with
// int(h, 16). Use p =
// 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001.
// For each zero-indexed round r, in order:
//   a[i] = (s[i] + rc[r][i]) % p
//   b[i] = pow(a[i], 5, p) if i == 0 or r < 4 or r >= 60 else a[i]
//   s[i] = sum(mds[i][j] * b[j] for j in range(5)) % p
// The raw input below is the integer tuple (1, 2, 3, 4, 5) in lane order
// 0 through 4. Both the raw output and the digest vectors encode each lane
// as x.to_bytes(32, 'little').hex(), without reversing the lane order.
//
// For the digests, take tags from book/src/domain-separators.md: start at
// (0, 0, 0, 0, int.from_bytes(tag.ljust(16, b'\0'), 'little')), where tag
// is ASCII. Add each consecutive chunk of up to four preimage words to rate
// lanes 0 through 3 modulo p, then permute. Preserve untouched lanes; do not
// pad, encode a length, or append an extra chunk to a full block. Read lane 0
// (all four rate lanes in order for the nullifier group). Point fixtures use
// G = (-1, 2) and 2G = (41/16, -299/64) in Fp, from the affine doubling
// formula. For AnchorSt use the affine bridge coordinates in
// book/src/proof-tree.md.
fn from_le_hex(hex: &str) -> Fp {
    assert_eq!(hex.len(), 64);
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    let bytes = array::from_fn(|i| {
        let digits = str::from_utf8(&pairs[i]).expect("ASCII hex pair");
        u8::from_str_radix(digits, 16).expect("valid hex pair")
    });
    Fp::from_bytes(bytes).expect("canonical field encoding")
}

#[test]
fn width_five_permutation_known_answer() {
    let input = [1, 2, 3, 4, 5].map(Fp::from);
    let expected = [
        "f687fff86787c7286ea90da8b5cd9e9fdcd7554f7d4a306d1e54ff10fea8953e",
        "b687f1dc59592a51fc8c7d452492e4af2cbbcf3a77b8959a2cc7396e851bd323",
        "f9a80203d270f4e6ebf79c6085cd6fbb0a35e1282ac02ee632b5a2fb0853010f",
        "9b570a934ef260ac0df1c57328fe8074ad6869111391fd3bb12d03349fce2833",
        "8161f7b530facbce7f3722b25f837642e80f9a0550d3b9253db3b4255e30ab08",
    ]
    .map(from_le_hex);

    let mut actual = [Fp::ZERO; 5];
    Simulator::<Fp>::simulate(input, |dr, witness| {
        let values = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), witness.as_ref().map(|words| words[i]))
        })?;
        let state = SpongeState::from_elements(values);
        let mut sponge = Sponge::resume(state, &PoseidonFp);
        // The permutation routine is private. Buffering a zero and saving the
        // state runs exactly one permutation without changing its input lanes.
        let zero = Element::zero(dr);
        sponge.absorb(dr, &zero)?;
        let permuted = sponge.save_state(dr).expect("zero is buffered");
        for (slot, lane) in actual.iter_mut().zip(permuted.into_elements().iter()) {
            *slot = *lane.value().take();
        }
        Ok(())
    })
    .expect("raw permutation simulation");
    assert_eq!(actual, expected);
}

#[test]
fn feemax_blind_known_answer() {
    let [pk, psi, rcm] = [1, 2, 3].map(Fp::from);
    assert_eq!(
        feemax_blind(pk, psi, rcm),
        from_le_hex("00aeb3a8e849b323f7c58cee4432fb96b597b4c91032d25c95d7f2e20e39d011")
    );
}

#[test]
fn fee_digest_known_answer() {
    assert_eq!(
        fee_digest(EpAffine::generator(), 3, Fp::from(4)),
        from_le_hex("f289e99bd3d7f0b73b6cd0132e10431c9b507dc3833142809d7e6b4400c2fe1f")
    );
}

#[test]
fn action_digest_known_answer() {
    let cv = EpAffine::generator();
    let rk = cv.to_projective().double().to_affine();
    assert_eq!(
        action_digest(cv, rk, (Fp::from(3), Fp::from(5))),
        from_le_hex("9e00f4d2fc91102ebc5fb9b43bede6a1efc0935dc9444452c84355f1c2f80a17")
    );
}

#[test]
fn payment_key_known_answer() {
    assert_eq!(
        payment_key(EpAffine::generator(), Fp::from(3)),
        from_le_hex("5073ee2bf2ee3cd8222695270084a03a109cc58fde4ee85b6fd9a836924e030f")
    );
}

#[test]
fn note_commitment_known_answer() {
    let [rcm, pk, psi] = [1, 2, 4].map(Fp::from);
    assert_eq!(
        note_commitment(rcm, pk, 3, psi),
        from_le_hex("50179fd42b6d87421f1f487da795e88538bdda88ca3baa8edf4e0da13fb4ec1f")
    );
}

#[test]
fn pad_tachygram_known_answer() {
    let [rcm, pk, psi] = [1, 2, 4].map(Fp::from);
    assert_eq!(
        pad_tachygram(rcm, pk, 3, psi),
        from_le_hex("27bc88ed527a35a3a21b20ec669a4d05aaa71c375520f51cc9201a704150db21")
    );
}

#[test]
fn nf_master_known_answer() {
    let [psi, nk] = [1, 2].map(Fp::from);
    let native = nf_master(psi, nk);
    assert_eq!(
        native,
        from_le_hex("ccb4b30d418b900649e2d50c502cb3b0f2c71ca833829f23ca56d2d595fbfc3e")
    );

    let mut simulated = Fp::ZERO;
    Simulator::<Fp>::simulate((psi, nk), |dr, witness| {
        let psi_element = Element::alloc(dr, &mut (), witness.as_ref().map(|&(x, _)| x))?;
        let nk_element = Element::alloc(dr, &mut (), witness.as_ref().map(|&(_, x)| x))?;
        simulated = *circuit::nf_master(dr, &psi_element, &nk_element)?
            .value()
            .take();
        Ok(())
    })
    .expect("master key simulation");
    assert_eq!(simulated, native);
}

#[test]
fn alpha_spend_known_answer() {
    let [theta, cm] = [1, 2].map(Fp::from);
    assert_eq!(
        alpha_spend(theta, cm),
        from_le_hex("55bed2bd1617a3c629938c8db6f6b39b3923e711921d849db131e368d08bcd0d")
    );
}

#[test]
fn alpha_output_known_answer() {
    let [theta, cm] = [1, 2].map(Fp::from);
    assert_eq!(
        alpha_output(theta, cm),
        from_le_hex("99b0e381ce904f368b7196f175f77e2b007be719ca80b031473ab24030540523")
    );
}

#[test]
fn nullifier_group_known_answer() {
    let [mk, epoch_start] = [1, 8].map(Fp::from);
    assert_eq!(
        nullifier_group(mk, epoch_start),
        [
            "dc40686635e985b2d1ab96fbbb84041b41038e0b9fe6ebed9eaa077f38be2429",
            "5e54d33809d5d50d7c6542c5e81d1112194d26d69eaa4df6d6b9cde23924db2a",
            "71db780a0bf5c76086fb2a681a09ce847dd887cca640b9855b45d61139a7ad11",
            "55fe8b0be746fdee0f1ffecf6c2518ce9fb2c6f48e0c37621ed9222a31cfa338",
        ]
        .map(from_le_hex)
    );
}

#[test]
fn anchor_next_stamp_known_answer() {
    let [prev, epoch] = [1, 2].map(Fp::from);
    assert_eq!(
        anchor_next_stamp(prev, epoch, EpAffine::generator()),
        from_le_hex("b3bf76f865ffd41180ce7572150a5e1630f272a49b7901463e790c08aaf3a936")
    );
}

#[test]
fn anchor_next_epoch_known_answer() {
    let [prev, epoch] = [1, 2].map(Fp::from);
    assert_eq!(
        anchor_next_epoch(prev, epoch),
        from_le_hex("5cbdfaf30a8af4d28ebfc2f06bad14ae8e9281ded70715f72b13cc10fafa0618")
    );
}

#[test]
fn evidence_tree_leaf_known_answer() {
    let [epoch, start, next, disc, depth, bits] = [1, 2, 3, 4, 5, 6].map(Fp::from);
    let contents = EpAffine::generator();
    let native = evidence_tree_leaf(epoch, start, next, disc, depth, bits, contents);
    assert_eq!(
        native,
        from_le_hex("239d06e4a63df82e638848f086e22cc0d3cdd0d5de80fbb2658324f247b0a022")
    );

    let (x, y) = contents
        .coordinates()
        .expect("generator is not the identity");
    let mut simulated = Fp::ZERO;
    Simulator::<Fp>::simulate(
        [epoch, start, next, disc, depth, bits, x, y],
        |dr, witness| {
            let [
                epoch_element,
                a_start,
                a_next,
                discriminant,
                profile_depth,
                profile_bits,
                bridge_x,
                bridge_y,
            ] = [0, 1, 2, 3, 4, 5, 6, 7]
                .map(|i| Element::alloc(dr, &mut (), witness.as_ref().map(|words| words[i])));
            let digest = circuit::evidence_tree_leaf(
                dr,
                &epoch_element?,
                &a_start?,
                &a_next?,
                &discriminant?,
                (&profile_depth?, &profile_bits?),
                &[bridge_x?, bridge_y?],
            )?;
            simulated = *digest.value().take();
            Ok(())
        },
    )
    .expect("evidence leaf simulation");
    assert_eq!(simulated, native);
}

#[test]
fn evidence_tree_node_known_answer() {
    let children = [1, 2, 3, 4].map(Fp::from);
    let native = evidence_tree_node(children);
    assert_eq!(
        native,
        from_le_hex("5ccb22c3c900f126d41dc966a65cb9a74b26fe655b781fe7038ce8d8b0653e29")
    );

    let mut simulated = Fp::ZERO;
    Simulator::<Fp>::simulate(children, |dr, witness| {
        let [first, second, third, fourth] = [0, 1, 2, 3]
            .map(|i| Element::alloc(dr, &mut (), witness.as_ref().map(|words| words[i])));
        simulated = *circuit::evidence_tree_node(dr, &[first?, second?, third?, fourth?])?
            .value()
            .take();
        Ok(())
    })
    .expect("evidence node simulation");
    assert_eq!(simulated, native);
}
