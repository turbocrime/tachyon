//! QR epoch evidence: the partition of an epoch's tachygrams, its filters, and
//! the `ArbitraryUnspent` lineage born from one bucket.

extern crate alloc;

use alloc::{string::ToString as _, vec::Vec};
use core::{array, iter};

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrDiscriminant, QrFilterPoly, QrProfile, Tachygram,
    TachygramSetPoly,
    nullifier::Nullifier,
    stamp::proof::{PROOF_SYSTEM, qr, summary},
    witness,
};

use crate::fixtures::{
    PoolSim, QrIntakeEntry, build_qr_filter_pcd, build_qr_partition, build_summary_pcd,
    qr_profile_of, random_block, seal_qr_intake, seed_qr_stamp_intake, split_qr_intake,
};

#[test]
fn qr_summary_intake_init_starts_a_root_from_a_summary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 6] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (_, _, anchor_last, acc_commit) = *summary.data();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    assert_eq!(
        *root.data(),
        (
            epoch,
            terminal,
            start,
            anchor_last,
            QrProfile::ROOT,
            QrDiscriminant::of(terminal),
            acc_commit
        ),
        "a root intake carries the summary's span and contents at depth zero"
    );
}

#[test]
fn qr_stamp_intake_seed_roots_an_intake_on_one_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::genesis_with(random_block(rng, 3, 1));
    let block = pool.block(BlockHeight(0));
    let terminal = block.anchor();
    let entry = block.stamps.first().expect("one stamp");
    let (anchor_prev, members, commit, anchor_last) = entry.clone();

    let stamp_root = seed_qr_stamp_intake(rng, &pool, entry, terminal);
    assert_eq!(
        *stamp_root.pcd.data(),
        (
            EpochIndex(0),
            terminal,
            anchor_prev,
            anchor_last,
            QrProfile::ROOT,
            QrDiscriminant::of(terminal),
            commit
        ),
        "the seed folds the stamp into its anchor and roots at depth zero"
    );
    assert_eq!(stamp_root.members, members);

    let (summary, _) = build_summary_pcd(rng, &pool, (anchor_prev, anchor_last));
    let (summary_root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    assert_eq!(
        *stamp_root.pcd.data(),
        *summary_root.data(),
        "a stamp-rooted intake matches the summary route over the same stamp"
    );
}

#[test]
fn qr_stamp_intake_seed_rejects_an_empty_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor_prev = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let err = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), anchor_prev, EpochIndex(3), terminal, &[]),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "invalid anchor step");
}

#[test]
fn qr_stamp_rooted_intakes_merge_and_seal_with_summary_rooted_ones() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 3, 2));
    pool.mine(random_block(rng, 3, 1));
    let terminal = pool.block(BlockHeight(1)).anchor();
    let joint = pool.block(BlockHeight(0)).anchor();

    // Six members open the span as one summary; the last stamp joins it rooted
    // on its own.
    let summary_rooted = build_qr_partition(rng, &pool, (Anchor::default(), joint), terminal, 6, 0)
        .into_iter()
        .next()
        .expect("one root");
    let stamp_rooted = seed_qr_stamp_intake(
        rng,
        &pool,
        pool.block(BlockHeight(1))
            .stamps
            .first()
            .expect("one stamp"),
        terminal,
    );

    let members: Vec<Tachygram> = summary_rooted
        .members
        .iter()
        .chain(&stamp_rooted.members)
        .copied()
        .collect();
    let witness = witness::qr_intake_merge(
        (*summary_rooted.pcd.data(), *stamp_rooted.pcd.data()),
        &summary_rooted.members,
        &stamp_rooted.members,
    );
    let (merged, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeMerge,
            witness,
            summary_rooted.pcd,
            stamp_rooted.pcd,
        )
        .expect("QrIntakeMerge");
    let contents = members
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    assert_eq!(
        *merged.data(),
        (
            EpochIndex(0),
            terminal,
            Anchor::default(),
            terminal,
            QrProfile::ROOT,
            QrDiscriminant::of(terminal),
            contents
        ),
        "the merge joins a summary-rooted span onto a stamp-rooted one"
    );

    let bucket = seal_qr_intake(
        rng,
        QrIntakeEntry {
            pcd: merged,
            members,
        },
        Anchor::from(Fp::ZERO),
    );
    assert_eq!(
        *bucket.pcd.data(),
        (
            EpochIndex(0),
            terminal,
            Anchor::default(),
            QrProfile::ROOT,
            QrDiscriminant::of(terminal),
            contents
        ),
        "the joined span runs the epoch's opening anchor to its terminal"
    );
}

#[test]
fn qr_intake_split_partitions_the_contents_by_class() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let discriminant = QrDiscriminant::of(terminal);
    let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0);
    assert!(
        !residue.is_empty() && !non_residue.is_empty(),
        "twelve random members reach both classes"
    );

    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    assert_eq!(
        *split.data(),
        (
            epoch,
            terminal,
            start,
            start
                .next_stamp(
                    epoch,
                    &members
                        .iter()
                        .copied()
                        .collect::<TachygramSetPoly>()
                        .commit()
                )
                .unwrap(),
            QrProfile::ROOT,
            discriminant,
            residue
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            non_residue
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit()
        ),
        "the split emits each class as its own set, span and profile unchanged"
    );
}

#[test]
fn qr_intake_split_rejects_a_forged_partition() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 8] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let (contents, residue, _non_residue) = witness::qr_intake_split((*root.data(), ()), &members);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (contents, residue.clone(), residue),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeSplit: the sides do not partition the contents"
    );
}

#[test]
fn qr_intake_split_rejects_the_exceptional_value_on_the_non_residue_side() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::of(terminal);
    let exceptional = Tachygram::from(-Fp::from(discriminant));
    let members: Vec<Tachygram> = iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
        .take(8)
        .chain([exceptional])
        .collect();

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    // Moving one member across the partition leaves the product intact, so
    // only the opening at -R separates the two filings.
    let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) =
        members.iter().copied().partition(|&member| {
            member != exceptional && qr::classify(Fp::from(member), Fp::from(discriminant)).0
        });
    let (contents, ..) = witness::qr_intake_split((*root.data(), ()), &members);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (
                contents,
                residue.iter().copied().collect(),
                non_residue.iter().copied().collect(),
            ),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeSplit: exceptional value claimed the non-residue class"
    );
}

#[test]
fn qr_side_descend_carries_each_side_one_level_down() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (_, _, _, end, ..) = *root.data();
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    let discriminant = QrDiscriminant::of(terminal);
    for side in [true, false] {
        let side_members: Vec<Tachygram> = members
            .iter()
            .copied()
            .filter(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0 == side)
            .collect();
        let (child, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*split.data(), ()), &members, side),
                split.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSideDescend");
        assert_eq!(
            *child.data(),
            (
                epoch,
                terminal,
                start,
                end,
                QrProfile::ROOT.descend(side),
                discriminant.next(),
                side_members
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit()
            ),
            "a descent keeps the span and takes the next discriminant"
        );
    }
}

#[test]
fn qr_side_descend_rejects_a_foreign_side() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    let (_, non_residue_side, ..) = witness::qr_side_descend((*split.data(), ()), &members, false);
    let (_, _, interpolant, quotient) =
        witness::qr_side_descend((*split.data(), ()), &members, true);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            (true, non_residue_side, interpolant, quotient),
            split,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSideDescend: side does not match the selected child"
    );
}

#[test]
fn qr_side_descend_rejects_a_foreign_interpolant() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    let (bit, side_contents, _interpolant, quotient) =
        witness::qr_side_descend((*split.data(), ()), &members, true);
    let (_, _, foreign_interpolant, _) =
        witness::qr_side_descend((*split.data(), ()), &members, false);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            (bit, side_contents, foreign_interpolant, quotient),
            split,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSideDescend: the side fails the residue class decomposition"
    );
}

#[test]
fn qr_side_descend_rejects_a_foreign_interpolant_on_the_non_residue_side() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    let (bit, side_contents, _interpolant, quotient) =
        witness::qr_side_descend((*split.data(), ()), &members, false);
    let (_, _, foreign_interpolant, _) =
        witness::qr_side_descend((*split.data(), ()), &members, true);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            (bit, side_contents, foreign_interpolant, quotient),
            split,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSideDescend: the side fails the non-residue class decomposition"
    );
}

#[test]
fn qr_side_descend_refuses_a_full_register() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let members: [Tachygram; 2] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), terminal),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let mut intake = QrIntakeEntry {
        pcd: root,
        members: members.to_vec(),
    };
    for _ in 0..u64::BITS {
        let (residue, _non_residue) = split_qr_intake(rng, intake);
        intake = residue;
    }
    let (.., profile, _discriminant, _contents) = *intake.pcd.data();
    assert_eq!(
        profile,
        QrProfile {
            depth: u64::from(u64::BITS),
            bits: u64::MAX
        },
        "sixty-four residue sides fill the register"
    );

    let split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            intake.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");
    let descend_witness = witness::qr_side_descend((*sides.data(), ()), &intake.members, true);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            descend_witness,
            sides,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSideDescend: profile has no bit left for another side"
    );
}

#[test]
fn qr_intake_merge_joins_two_spans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (_, _, junction, _) = *left_summary.data();
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), junction, epoch, &right_members),
        )
        .expect("SummarySeed");
    let (_, _, end, _) = *right_summary.data();

    let (left, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*left_summary.data(), ()), terminal),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), terminal),
            right_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let (merged, ()) = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .expect("QrIntakeMerge");

    let union = left_members
        .iter()
        .chain(&right_members)
        .copied()
        .collect::<TachygramSetPoly>();
    assert_eq!(
        *merged.data(),
        (
            epoch,
            terminal,
            start,
            end,
            QrProfile::ROOT,
            QrDiscriminant::of(terminal),
            union.commit()
        ),
        "the merge spans both inputs and holds their union"
    );
}

#[test]
fn qr_intake_merge_rejects_a_gap() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let left_start = Anchor::from(Fp::random(&mut *rng));
    let right_start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), left_start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), right_start, epoch, &right_members),
        )
        .expect("SummarySeed");

    let (left, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*left_summary.data(), ()), terminal),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), terminal),
            right_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeMerge: right input does not continue the left span"
    );
}

#[test]
fn qr_intake_merge_rejects_different_profiles() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (_, _, junction, _) = *left_summary.data();
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), junction, epoch, &right_members),
        )
        .expect("SummarySeed");

    let (left_root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*left_summary.data(), ()), terminal),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), terminal),
            right_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*left_root.data(), ()), &left_members),
            left_root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");
    let (deeper, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*split.data(), ()), &left_members, true),
            split,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSideDescend");

    let discriminant = QrDiscriminant::of(terminal);
    let deeper_members: Vec<Tachygram> = left_members
        .iter()
        .copied()
        .filter(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0)
        .collect();
    let witness = witness::qr_intake_merge(
        (*deeper.data(), *right.data()),
        &deeper_members,
        &right_members,
    );
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, deeper, right)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeMerge: inputs sit at different depths"
    );
}

#[test]
fn qr_split_alone_leaves_both_children_over_one_span() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let terminal = pool.block(pool.height()).anchor();

    // Eight members fit one polynomial, so the span opens as a single intake.
    let routed = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 8, 1);

    assert_eq!(routed.len(), 2, "one layer leaves one intake per side");
    for intake in &routed {
        let (_, _, start, end, profile, ..) = *intake.pcd.data();
        assert_eq!(profile.depth, 1);
        assert_eq!(start, Anchor::default());
        assert_eq!(end, terminal, "both children keep their parent's span");
    }
}

#[test]
fn qr_partition_covers_the_epoch_by_profile() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let published: Vec<Tachygram> = (0..=3)
        .flat_map(|height| pool.block(BlockHeight(height)).tachygrams())
        .flatten()
        .collect();

    // The epoch's twenty-four members fit one polynomial, so each profile ends
    // up as a single intake over the whole span.
    let routed = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 24, 2);

    assert_eq!(routed.len(), 4, "two layers leave one intake per profile");
    let mut profiles: Vec<u64> = routed
        .iter()
        .map(|intake| {
            let (_, _, start, end, profile, ..) = *intake.pcd.data();
            assert_eq!(profile.depth, 2);
            assert_eq!(start, Anchor::default());
            assert_eq!(end, terminal, "every intake spans the whole epoch");
            profile.bits
        })
        .collect();
    profiles.sort_unstable();
    assert_eq!(profiles, [0, 1, 2, 3], "the intakes are the four profiles");

    let mut covered: Vec<Tachygram> = Vec::new();
    for intake in &routed {
        let (_, _, _, _, profile, _, contents) = *intake.pcd.data();
        assert_eq!(
            contents,
            intake
                .members
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            "an intake's header commits exactly the members it holds"
        );
        for &member in &intake.members {
            let mut discriminant = QrDiscriminant::of(terminal);
            for &side in &profile.path() {
                assert_eq!(
                    qr::classify(Fp::from(member), Fp::from(discriminant)).0,
                    side,
                    "a member's class at every level is its intake's path"
                );
                discriminant = discriminant.next();
            }
        }
        covered.extend(intake.members.iter().copied());
    }

    let sorted = |mut tgs: Vec<Tachygram>| {
        tgs.sort_unstable_by_key(|&tg| Fp::from(tg).to_repr());
        tgs
    };
    assert_eq!(
        sorted(covered),
        sorted(published),
        "the intakes partition the epoch's published tachygrams"
    );
}

/// A span past what one polynomial holds leaves each profile as a run of
/// adjacent intakes rather than a single one.
#[test]
fn qr_partition_chunks_a_span_past_the_polynomial_capacity() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let published: Vec<Tachygram> = (0..=3)
        .flat_map(|height| pool.block(BlockHeight(height)).tachygrams())
        .flatten()
        .collect();
    let capacity = 11;

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        terminal,
        capacity,
        1,
    );

    assert!(
        routed.len() > 2,
        "no intake holds more than the capacity, so twenty-four members need three"
    );
    let mut covered: Vec<Tachygram> = Vec::new();
    for side in [true, false] {
        let run: Vec<&QrIntakeEntry> = routed
            .iter()
            .filter(|intake| intake.pcd.data().4 == QrProfile::ROOT.descend(side))
            .collect();
        let first = run.first().expect("each side carries an intake");
        assert_eq!(
            first.pcd.data().2,
            Anchor::default(),
            "the side's run opens at the span's start"
        );
        let mut cursor = first.pcd.data().3;
        for pair in run.windows(2) {
            assert_eq!(
                pair[1].pcd.data().2,
                cursor,
                "the side's intakes cover adjacent spans"
            );
            assert!(
                pair[0].members.len() + pair[1].members.len() > capacity,
                "neighbours merge as far as the capacity allows"
            );
            cursor = pair[1].pcd.data().3;
        }
        assert_eq!(cursor, terminal, "the side's run closes at the span's end");
        for intake in run {
            covered.extend(intake.members.iter().copied());
        }
    }

    let sorted = |mut tgs: Vec<Tachygram>| {
        tgs.sort_unstable_by_key(|&tg| Fp::from(tg).to_repr());
        tgs
    };
    assert_eq!(
        sorted(covered),
        sorted(published),
        "the runs still partition the epoch's published tachygrams"
    );
}

#[test]
fn qr_intakes_at_one_profile_merge_across_adjacent_spans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let terminal = pool.block(pool.height()).anchor();

    // A four-member capacity chunks the eight-member span into two roots.
    let roots = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 4, 0);
    assert_eq!(roots.len(), 2, "one root per capacity-sized run");

    let mut blocks = roots.into_iter();
    let left = blocks.next().expect("left root");
    let right = blocks.next().expect("right root");
    let (left_residue, _left_non_residue) = split_qr_intake(rng, left);
    let (right_residue, _right_non_residue) = split_qr_intake(rng, right);

    let witness = witness::qr_intake_merge(
        (*left_residue.pcd.data(), *right_residue.pcd.data()),
        &left_residue.members,
        &right_residue.members,
    );
    let (merged, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeMerge,
            witness,
            left_residue.pcd,
            right_residue.pcd,
        )
        .expect("QrIntakeMerge");

    let (_, _, start, end, profile, ..) = *merged.data();
    assert_eq!(profile, QrProfile::ROOT.descend(true));
    assert_eq!(start, Anchor::default());
    assert_eq!(end, terminal, "the merged residue bucket spans both runs");
}

#[test]
fn qr_filter_descend_records_the_path_by_side() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let profile = QrProfile::ROOT.descend(true).descend(false).descend(true);

    let filter = build_qr_filter_pcd(rng, epoch, terminal, profile);
    let (residue, non_residue) = profile.discriminants_by_side(terminal);
    let next = QrDiscriminant::of(terminal).next().next().next();

    assert_eq!(
        *filter.data(),
        (
            epoch,
            terminal,
            profile,
            next,
            residue.iter().copied().collect::<QrFilterPoly>().commit(),
            non_residue
                .iter()
                .copied()
                .collect::<QrFilterPoly>()
                .commit()
        ),
        "each side's filter holds the discriminants the path took that way"
    );
    assert_eq!(residue.len(), 2);
    assert_eq!(non_residue.len(), 1);
}

#[test]
fn qr_filter_descend_rejects_a_forged_extension() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let terminal = Anchor::from(Fp::random(&mut *rng));

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrFilterSeed,
            witness::qr_filter_seed(((), ()), epoch, terminal),
        )
        .expect("QrFilterSeed");

    let (bit, side_filter, _extended) = witness::qr_filter_descend((*seeded.data(), ()), true);
    let foreign = iter::once(QrDiscriminant::of(terminal).next()).collect::<QrFilterPoly>();
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrFilterDescend,
            (bit, side_filter, foreign),
            seeded,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrFilterDescend: extended filter does not record this discriminant"
    );
}

#[test]
fn qr_filter_descend_refuses_a_full_register() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let full = QrProfile {
        depth: u64::from(u64::BITS),
        bits: u64::MAX,
    };

    let filter = build_qr_filter_pcd(rng, epoch, terminal, full);
    let (_, _, profile, ..) = *filter.data();
    assert_eq!(profile, full, "sixty-four residue sides fill the register");

    let witness = witness::qr_filter_descend((*filter.data(), ()), true);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrFilterDescend,
            witness,
            filter,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrFilterDescend: profile has no bit left for another side"
    );
}

#[test]
fn qr_bucket_seal_seals_a_fully_routed_intake() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();

    let routed = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 24, 2);
    let intake = routed.into_iter().next().expect("one intake");
    let (epoch, _, start, _, profile, discriminant, contents) = *intake.pcd.data();
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    assert_eq!(
        *bucket.pcd.data(),
        (epoch, terminal, start, profile, discriminant, contents),
        "sealing keeps every field and drops the redundant end"
    );
    assert_eq!(
        start,
        Anchor::default(),
        "epoch zero's opening anchor is the general rule at prev_last = 0"
    );
}

#[test]
fn qr_bucket_seal_rejects_an_intake_short_of_the_epoch_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    // Opening the span past the epoch's first stamp leaves it rooted on a stamp
    // anchor, which the epoch domain cannot produce. The span reaches its
    // terminal, so only the boundary check can fail.
    let terminal = pool.block(BlockHeight(2)).anchor();
    let start = pool.block(BlockHeight(0)).anchor();

    let routed = build_qr_partition(rng, &pool, (start, terminal), terminal, 12, 1);
    let intake = routed.into_iter().next().expect("one intake");
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), Anchor::from(Fp::ZERO));
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness,
            intake.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrBucketSeal: intake does not begin at the epoch boundary"
    );
}

#[test]
fn qr_bucket_seal_rejects_an_intake_short_of_its_terminal() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();

    // A six-member capacity chunks the epoch into four roots. The first opens at
    // the epoch boundary but stops well short of the terminal.
    let routed = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 6, 0);
    let intake = routed.into_iter().next().expect("one intake");
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), Anchor::from(Fp::ZERO));
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness,
            intake.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrBucketSeal: intake does not reach its terminal"
    );
}

#[test]
fn qr_unspent_init_clears_an_absent_nullifier_against_its_bucket() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let epoch = BlockHeight(0).epoch();
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let routed = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 24, 2);
    let profile = qr_profile_of(Fp::from(nf), terminal, 2);
    let intake = routed
        .into_iter()
        .find(|intake| intake.pcd.data().4 == profile)
        .expect("one intake carries the nullifier's own profile");
    assert!(
        !intake
            .members
            .iter()
            .any(|&member| Fp::from(member) == Fp::from(nf)),
        "a fresh nullifier is absent from the epoch"
    );
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    let filter = build_qr_filter_pcd(rng, epoch, terminal, profile);
    let (claim, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrResidueAttest,
            witness::qr_residue_attest((*filter.data(), ()), nf),
            filter,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrResidueAttest");
    let witness = witness::qr_unspent_init((*claim.data(), *bucket.pcd.data()), &bucket.members);
    let (unspent, ()) = PROOF_SYSTEM
        .fuse(rng, qr::QrUnspentInit, witness, claim, bucket.pcd)
        .expect("QrUnspentInit");

    let (anchor_prev, first, elapsed, last, anchor_last) = *unspent.data();
    assert_eq!(
        anchor_prev,
        Anchor::default(),
        "the segment opens where the partition's span does"
    );
    assert_eq!(anchor_last, terminal, "and closes at the epoch's terminal");
    assert_eq!(first, (epoch, nf));
    assert_eq!(last, (epoch, nf));
    assert_eq!(elapsed, NfSeqPoly::new(epoch, &[nf]).commit());
}

#[test]
fn qr_unspent_init_rejects_a_published_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let epoch = BlockHeight(0).epoch();

    let routed = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 24, 2);
    let intake = routed
        .into_iter()
        .find(|intake| !intake.members.is_empty())
        .expect("some intake holds a member");
    let published = *intake.members.first().expect("a member");
    let nf = Nullifier::from(Fp::from(published));
    let (_, _, _, _, profile, ..) = *intake.pcd.data();
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    let filter = build_qr_filter_pcd(rng, epoch, terminal, profile);
    let (claim, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrResidueAttest,
            witness::qr_residue_attest((*filter.data(), ()), nf),
            filter,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrResidueAttest");
    let witness = witness::qr_unspent_init((*claim.data(), *bucket.pcd.data()), &bucket.members);
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrUnspentInit, witness, claim, bucket.pcd)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrUnspentInit: found nullifier in the bucket"
    );
}

#[test]
fn qr_unspent_init_rejects_a_foreign_bucket() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let epoch = BlockHeight(0).epoch();
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let routed = build_qr_partition(rng, &pool, (Anchor::default(), terminal), terminal, 24, 2);
    let profile = qr_profile_of(Fp::from(nf), terminal, 2);
    let foreign = routed
        .into_iter()
        .find(|intake| intake.pcd.data().4 != profile)
        .expect("three intakes carry another profile");
    let bucket = seal_qr_intake(rng, foreign, Anchor::from(Fp::ZERO));

    let filter = build_qr_filter_pcd(rng, epoch, terminal, profile);
    let (claim, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrResidueAttest,
            witness::qr_residue_attest((*filter.data(), ()), nf),
            filter,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrResidueAttest");
    let witness = witness::qr_unspent_init((*claim.data(), *bucket.pcd.data()), &bucket.members);
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrUnspentInit, witness, claim, bucket.pcd)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrUnspentInit: claim and bucket sit at different profiles"
    );
}

#[test]
fn qr_residue_attest_rejects_a_foreign_interpolant() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let terminal = Anchor::from(Fp::random(&mut *rng));
    let nf = Nullifier::from(Fp::random(&mut *rng));
    let profile = qr_profile_of(Fp::from(nf), terminal, 3);

    let filter = build_qr_filter_pcd(rng, epoch, terminal, profile);
    let (_, residue_filter, _interpolant, quotient, elapsed_seq) =
        witness::qr_residue_attest((*filter.data(), ()), nf);

    // A decomposition exists only along the value's own path, so the forgery
    // has to come from another nullifier's attestation.
    let foreign = Nullifier::from(Fp::random(&mut *rng));
    let foreign_filter = build_qr_filter_pcd(
        rng,
        epoch,
        terminal,
        qr_profile_of(Fp::from(foreign), terminal, 3),
    );
    let (_, _, foreign_interpolant, ..) =
        witness::qr_residue_attest((*foreign_filter.data(), ()), foreign);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrResidueAttest,
            (
                nf,
                residue_filter,
                foreign_interpolant,
                quotient,
                elapsed_seq,
            ),
            filter,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrResidueAttest: nullifier fails the residue side of this profile"
    );
}
