//! QR epoch-evidence tests: the tree builder, the consumer lift, and the
//! rejection surfaces.

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::iter;

use ff::Field as _;
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, Tachygram,
    constants::EPOCH_SIZE,
    nullifier::Nullifier,
    stamp::proof::{PROOF_SYSTEM, pool, qr},
    witness,
};

use crate::fixtures::{PoolSim, QrLeaf, build_qr_tree_pcds};

fn random_tgs<RNG: CryptoRng>(rng: &mut RNG, count: usize) -> Vec<Tachygram> {
    iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
        .take(count)
        .collect()
}

/// A pool whose epoch 1 carries the worked trace: 4 stamps, 26 tachygrams.
fn worked_pool<RNG: CryptoRng>(rng: &mut RNG) -> (PoolSim, Vec<Vec<Tachygram>>) {
    let mut pool = PoolSim::genesis_with(vec![random_tgs(rng, 3)]);
    pool.advance(EPOCH_SIZE - 1, |_| vec![]);

    let trace: Vec<Vec<Tachygram>> = [6, 7, 7, 6]
        .into_iter()
        .map(|count| random_tgs(rng, count))
        .collect();
    pool.mine(vec![trace[0].clone(), trace[1].clone()]);
    pool.mine(vec![trace[2].clone()]);
    pool.mine(vec![trace[3].clone()]);
    (pool, trace)
}

const CAP: usize = 8;

/// The tick entering epoch 1: an [`ArbitraryUnspent`](pool::ArbitraryUnspent)
/// whose tip is `(epoch 1, nf)` at the epoch's opening sentinel.
fn tick_into_epoch_one<RNG: CryptoRng>(
    rng: &mut RNG,
    pool: &PoolSim,
    nf: Nullifier,
) -> ragu::Pcd<pool::ArbitraryUnspent> {
    let epoch_zero_terminal = pool.block(BlockHeight(EPOCH_SIZE - 1)).anchor();
    let nf_prev = Nullifier::from(Fp::random(&mut *rng));
    let (tick, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(
                ((), ()),
                epoch_zero_terminal,
                EpochIndex(0),
                nf_prev,
                nf,
            ),
        )
        .expect("EndEpochUnspentSeed");
    tick
}

fn leaf_for(leaves: &[QrLeaf], value: Fp) -> &QrLeaf {
    leaves
        .iter()
        .find(|leaf| leaf.matches(value))
        .expect("every value has exactly one leaf")
}

#[test]
fn the_epoch_tree_splits_at_the_cap_and_covers_every_tachygram() {
    let rng = &mut StdRng::seed_from_u64(40);
    let (pool, trace) = worked_pool(rng);

    let leaves = build_qr_tree_pcds(rng, &pool, EpochIndex(1), CAP);
    assert!(leaves.len() > 1, "26 tachygrams at cap 8 must split");

    let sntl = pool.block(BlockHeight(EPOCH_SIZE)).prev;
    let endpoint = pool.anchor();
    let mut covered: Vec<Tachygram> = Vec::new();
    for leaf in &leaves {
        let (epoch, leaf_sntl, last_anchor, _discriminants, _profile, _commit) = leaf.header();
        assert_eq!(epoch, EpochIndex(1));
        assert_eq!(leaf_sntl, sntl, "every leaf spans from the sentinel");
        assert_eq!(last_anchor, endpoint, "every leaf spans to the endpoint");
        assert!(leaf.members.len() <= CAP, "leaf exceeds the cap");
        for &member in &leaf.members {
            assert!(leaf.matches(Fp::from(member)), "misfiled member");
        }
        assert!(
            PROOF_SYSTEM
                .verify(&leaf.pcd, StdRng::seed_from_u64(0))
                .expect("verify runs"),
            "leaf proof must verify"
        );
        covered.extend(leaf.members.iter().copied());
    }

    let mut published: Vec<Tachygram> = trace.into_iter().flatten().collect();
    published.sort();
    covered.sort();
    assert_eq!(covered, published, "the leaves partition the epoch exactly");
}

#[test]
fn an_absent_nullifier_lifts_across_the_whole_epoch() {
    let rng = &mut StdRng::seed_from_u64(41);
    let (pool, _trace) = worked_pool(rng);
    let leaves = build_qr_tree_pcds(rng, &pool, EpochIndex(1), CAP);

    let nf = Nullifier::from(Fp::random(&mut *rng));
    let tick = tick_into_epoch_one(rng, &pool, nf);
    let leaf = leaf_for(&leaves, Fp::from(nf));

    let (lifted, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentLift,
            witness::qr_unspent_lift((*tick.data(), leaf.header()), &leaf.members),
            tick,
            leaf.pcd.clone(),
        )
        .expect("QrUnspentLift");

    let (_prev, _start, _elapsed, (epoch_last, nf_last), anchor_last) = *lifted.data();
    assert_eq!(epoch_last, EpochIndex(1));
    assert_eq!(nf_last, nf);
    assert_eq!(
        anchor_last,
        pool.anchor(),
        "the lift advances to the bucket endpoint"
    );
}

#[test]
fn the_lift_composes_with_the_next_boundary_tick() {
    let rng = &mut StdRng::seed_from_u64(47);
    let (pool, _trace) = worked_pool(rng);
    let leaves = build_qr_tree_pcds(rng, &pool, EpochIndex(1), CAP);

    let nf_prev = Nullifier::from(Fp::random(&mut *rng));
    let nf = Nullifier::from(Fp::random(&mut *rng));
    let nf_next = Nullifier::from(Fp::random(&mut *rng));

    let epoch_zero_terminal = pool.block(BlockHeight(EPOCH_SIZE - 1)).anchor();
    let (tick_in, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(
                ((), ()),
                epoch_zero_terminal,
                EpochIndex(0),
                nf_prev,
                nf,
            ),
        )
        .expect("EndEpochUnspentSeed");

    let leaf = leaf_for(&leaves, Fp::from(nf));
    let (lifted, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentLift,
            witness::qr_unspent_lift((*tick_in.data(), leaf.header()), &leaf.members),
            tick_in,
            leaf.pcd.clone(),
        )
        .expect("QrUnspentLift");

    // The lift's output anchor is the bucket endpoint, which is exactly the
    // next boundary tick's `anchor_prev` — the fuse seam that closes the
    // evidence's endpoint (item 7's spine obligation).
    let (tick_out, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(((), ()), pool.anchor(), EpochIndex(1), nf, nf_next),
        )
        .expect("EndEpochUnspentSeed");

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse(
                (*lifted.data(), *tick_out.data()),
                &[nf_prev, nf],
                &[nf, nf_next],
            ),
            lifted,
            tick_out,
        )
        .expect("UnspentFuse");

    let (anchor_prev, (epoch_start, nf_start), _elapsed, (epoch_last, nf_last), _anchor_last) =
        *fused.data();
    assert_eq!(anchor_prev, epoch_zero_terminal);
    assert_eq!((epoch_start, nf_start), (EpochIndex(0), nf_prev));
    assert_eq!((epoch_last, nf_last), (EpochIndex(2), nf_next));
}

#[test]
fn a_published_nullifier_cannot_lift() {
    let rng = &mut StdRng::seed_from_u64(42);
    let (pool, trace) = worked_pool(rng);
    let leaves = build_qr_tree_pcds(rng, &pool, EpochIndex(1), CAP);

    let published = trace[0][0];
    let nf = Nullifier::from(published);
    let tick = tick_into_epoch_one(rng, &pool, nf);
    let leaf = leaf_for(&leaves, Fp::from(published));
    assert!(leaf.members.contains(&published), "leaf holds its member");

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentLift,
            witness::qr_unspent_lift((*tick.data(), leaf.header()), &leaf.members),
            tick,
            leaf.pcd.clone(),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrUnspentLift: found nullifier in the bucket"
    );
}

#[test]
fn a_lineage_elsewhere_cannot_consume_the_evidence() {
    let rng = &mut StdRng::seed_from_u64(43);
    let (pool, _trace) = worked_pool(rng);
    let leaves = build_qr_tree_pcds(rng, &pool, EpochIndex(1), CAP);

    let nf = Nullifier::from(Fp::random(&mut *rng));
    // A tick from the wrong anchor: its output sentinel differs from the
    // evidence's.
    let nf_prev = Nullifier::from(Fp::random(&mut *rng));
    let (tick, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(
                ((), ()),
                Anchor::default(),
                EpochIndex(0),
                nf_prev,
                nf,
            ),
        )
        .expect("EndEpochUnspentSeed");
    let leaf = leaf_for(&leaves, Fp::from(nf));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentLift,
            witness::qr_unspent_lift((*tick.data(), leaf.header()), &leaf.members),
            tick,
            leaf.pcd.clone(),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrUnspentLift: lineage does not end at the bucket's sentinel"
    );
}

#[test]
fn an_omitted_value_cannot_be_absorbed() {
    let rng = &mut StdRng::seed_from_u64(44);
    let (pool, trace) = worked_pool(rng);

    let sntl = pool.block(BlockHeight(EPOCH_SIZE)).prev;
    let (seed, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrBucketSeed,
            witness::qr_bucket_seed(((), ()), EpochIndex(1), sntl),
        )
        .expect("QrBucketSeed");

    let mut absorb = witness::qr_bucket_absorb((*seed.data(), ()), &[], &trace[0]);
    // Drop one value from the scalar list; the witnessed set polynomial
    // still holds it.
    absorb.3[0].0 = Fp::ZERO;

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketAbsorb,
            absorb,
            seed,
            ragu::Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrBucketAbsorb: scalar values do not multiply to the set polynomial"
    );
}

#[test]
fn a_misclassified_value_cannot_be_absorbed() {
    let rng = &mut StdRng::seed_from_u64(45);
    let (pool, _trace) = worked_pool(rng);
    let leaves = build_qr_tree_pcds(rng, &pool, EpochIndex(1), CAP);

    // A split leaf has at least one active discriminant to lie against.
    let leaf = leaves
        .iter()
        .find(|leaf| leaf.header().4.depth() > 0)
        .expect("the worked trace splits");
    let incoming = random_tgs(rng, 1);

    let mut absorb = witness::qr_bucket_absorb((leaf.header(), ()), &leaf.members, &incoming);
    // Flip the value's claimed side at the first split.
    absorb.3[0].1[0].1 = !absorb.3[0].1[0].1;

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketAbsorb,
            absorb,
            leaf.pcd.clone(),
            ragu::Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrBucketAbsorb: root does not match the claimed class"
    );
}

#[test]
fn swapped_decomposition_sides_are_rejected() {
    let rng = &mut StdRng::seed_from_u64(46);
    let (pool, _trace) = worked_pool(rng);
    let leaves = build_qr_tree_pcds(rng, &pool, EpochIndex(1), CAP);

    let leaf = leaves
        .iter()
        .find(|leaf| leaf.members.len() > 1)
        .expect("a populated leaf exists");

    let honest = witness::qr_bucket_left_decomp((leaf.header(), ()), &leaf.members);
    let swapped = (honest.0, honest.2, honest.1, honest.4, honest.3);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketLeftDecomp,
            swapped,
            leaf.pcd.clone(),
            ragu::Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrBucketLeftDecomp: residue side fails its decomposition"
    );
}
