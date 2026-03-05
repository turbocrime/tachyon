//! Poseidon hash primitives for Tachyon.
//!
//! All Poseidon usage routes through this module to ensure consistent
//! parameters: P128Pow5T3 (width 3, rate 2, Pow5 S-box, 128-bit security).

use ff::Field as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{Fp, Fq};

/// GGM tree depth — 32-bit epochs cover ~4 billion values.
pub(crate) const GGM_TREE_DEPTH: usize = 32;

/// Poseidon hash of two field elements: `H(a, b)`.
pub(crate) fn hash_2(a: Fp, b: Fp) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

/// Poseidon hash of four field elements: `H(a, b, c, d)`.
pub(crate) fn hash_4(a: Fp, b: Fp, c: Fp, d: Fp) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([a, b, c, d])
}

/// GGM tree PRF: walk all 32 bits of `leaf` from root `key`.
///
/// Traverses MSB-first (bit 31 → bit 0) so that left subtrees cover
/// lower-numbered leaves, enabling contiguous-range prefix delegation.
pub(crate) fn ggm_evaluate(key: Fp, leaf: u32) -> Fp {
    ggm_walk(key, leaf, GGM_TREE_DEPTH, 0)
}

/// Descend `depth` left-child (zero-bit) levels from `root`.
///
/// Returns the intermediate node covering epochs `0..2^(32 - depth)`.
pub(crate) fn ggm_prefix_node(root: Fp, depth: usize) -> Fp {
    assert!(depth <= GGM_TREE_DEPTH);
    let mut node = root;
    for _ in 0..depth {
        node = hash_2(node, Fp::ZERO);
    }
    node
}

/// Continue a GGM walk from an intermediate node at `start_depth`.
///
/// Walks bits `(31 - start_depth)` down to `0` of `leaf`.
pub(crate) fn ggm_evaluate_from(node: Fp, leaf: u32, start_depth: usize) -> Fp {
    ggm_walk(node, leaf, GGM_TREE_DEPTH, start_depth)
}

/// Internal: walk bits of `leaf` from `start_depth` to `total_depth`,
/// MSB-first.
fn ggm_walk(mut node: Fp, leaf: u32, total_depth: usize, start_depth: usize) -> Fp {
    assert!(start_depth <= total_depth);
    for i in start_depth..total_depth {
        let bit_pos = total_depth - 1 - i;
        let bit = ((leaf >> bit_pos) & 1) as u64;
        node = hash_2(node, Fp::from(bit));
    }
    node
}

/// Reinterpret `Fq` bytes as `Fp` (auto-reduces mod p).
pub(crate) fn fq_to_fp(fq: Fq) -> Fp {
    use ff::PrimeField as _;
    let bytes = fq.to_repr();
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
    }
    Fp::from_raw(limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_2_deterministic() {
        let a = Fp::from(42u64);
        let b = Fp::from(99u64);
        assert_eq!(hash_2(a, b), hash_2(a, b));
    }

    #[test]
    fn hash_2_not_commutative() {
        let a = Fp::from(1u64);
        let b = Fp::from(2u64);
        assert_ne!(hash_2(a, b), hash_2(b, a));
    }

    #[test]
    fn ggm_distinct_leaves() {
        let key = Fp::from(123u64);
        assert_ne!(ggm_evaluate(key, 0), ggm_evaluate(key, 1));
    }

    #[test]
    fn ggm_distinct_keys() {
        assert_ne!(
            ggm_evaluate(Fp::from(1u64), 42),
            ggm_evaluate(Fp::from(2u64), 42),
        );
    }

    /// Full-depth prefix node equals direct evaluation of leaf 0.
    #[test]
    fn prefix_full_depth_equals_leaf_zero() {
        let key = Fp::from(77u64);
        assert_eq!(ggm_prefix_node(key, GGM_TREE_DEPTH), ggm_evaluate(key, 0));
    }

    /// Prefix node + suffix evaluation equals direct evaluation for
    /// leaves covered by the prefix subtree.
    #[test]
    fn prefix_then_suffix_equals_direct() {
        let key = Fp::from(77u64);
        // The prefix node at depth d covers leaves 0..2^(32-d).
        // Test that evaluating from the prefix gives the same result
        // as full evaluation for covered leaves.
        for depth in [0, 1, 8, 16, 31, 32] {
            let prefix = ggm_prefix_node(key, depth);
            // leaf 0 is always in the left subtree
            let result = ggm_evaluate_from(prefix, 0, depth);
            assert_eq!(
                result,
                ggm_evaluate(key, 0),
                "mismatch at depth {depth}"
            );
        }
    }
}
