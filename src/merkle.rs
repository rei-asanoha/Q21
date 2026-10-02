//! Merkle tree.
//!
//! Two differences from Bitcoin, both deliberate.
//!
//! **The odd node is not duplicated.** Bitcoin duplicates the last digest when
//! a level has an odd number of elements. That trick produced `CVE-2012-2459`:
//! two different transaction lists could give the same root, which made it
//! possible to craft an invalid block that nodes permanently marked as
//! rejected, blocking the matching valid block. Q21 promotes the odd node
//! unchanged to the next level up.
//!
//! **Leaves and branches have distinct tags.** Without that separation, an
//! attacker can present an internal node as a leaf and build a second
//! preimage. The problem has been known for a long time; we settle it at
//! design time rather than downstream.

use crate::hash::{tagged_hash, tagged_hash_parts, tags, Hash256};

/// Hash of a leaf.
pub fn leaf_hash(data: &[u8]) -> Hash256 {
    tagged_hash(tags::MERKLE_LEAF, data)
}

/// Hash of an internal node, from its two children.
pub fn branch_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    tagged_hash_parts(tags::MERKLE_BRANCH, &[left.as_bytes(), right.as_bytes()])
}

/// Merkle root of a list of leaf hashes.
///
/// An empty tree returns `Hash256::ZERO`. A one-leaf tree returns that leaf.
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256::ZERO;
    }
    let mut level: Vec<Hash256> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(branch_hash(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            // Odd count: promote, do not duplicate.
            next.push(level[i]);
        }
        level = next;
    }
    level[0]
}

/// Element of an inclusion proof: a sibling hash and its side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Hash256,
    /// True if the sibling is to the right of the current node.
    pub sibling_on_right: bool,
}

/// Builds the inclusion proof of the leaf at index `index`.
pub fn merkle_proof(leaves: &[Hash256], index: usize) -> Option<Vec<ProofStep>> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    let mut level: Vec<Hash256> = leaves.to_vec();
    let mut pos = index;

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            if i == pos || i + 1 == pos {
                let on_right = pos == i;
                proof.push(ProofStep {
                    sibling: if on_right { level[i + 1] } else { level[i] },
                    sibling_on_right: on_right,
                });
                pos = next.len();
            }
            next.push(branch_hash(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            if i == pos {
                // Promoted node: it moves up alone, without a proof step.
                pos = next.len();
            }
            next.push(level[i]);
        }
        level = next;
    }
    Some(proof)
}

/// Checks that a leaf does belong to the tree with root `root`.
pub fn verify_proof(leaf: &Hash256, proof: &[ProofStep], root: &Hash256) -> bool {
    let mut current = *leaf;
    for step in proof {
        current = if step.sibling_on_right {
            branch_hash(&current, &step.sibling)
        } else {
            branch_hash(&step.sibling, &current)
        };
    }
    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash256> {
        (0..n)
            .map(|i| leaf_hash(format!("transaction {i}").as_bytes()))
            .collect()
    }

    #[test]
    fn empty_tree_and_single_leaf_tree() {
        assert_eq!(merkle_root(&[]), Hash256::ZERO);
        let one = leaves(1);
        assert_eq!(merkle_root(&one), one[0]);
    }

    #[test]
    fn root_changes_if_a_leaf_changes() {
        let a = leaves(7);
        let mut b = a.clone();
        b[3] = leaf_hash(b"something else");
        assert_ne!(merkle_root(&a), merkle_root(&b));
    }

    #[test]
    fn leaf_order_matters() {
        let a = leaves(4);
        let mut b = a.clone();
        b.swap(0, 1);
        assert_ne!(merkle_root(&a), merkle_root(&b));
    }

    /// The test that expresses `CVE-2012-2459`.
    ///
    /// With Bitcoin's duplication, a 3-leaf tree [A,B,C] and a 4-leaf tree
    /// [A,B,C,C] give the same root. Here, they do not.
    #[test]
    fn duplicating_the_odd_node_does_not_collide() {
        let three = leaves(3);
        let mut four = three.clone();
        four.push(three[2]);
        assert_ne!(
            merkle_root(&three),
            merkle_root(&four),
            "CVE-2012-2459 style collision"
        );
    }

    #[test]
    fn a_leaf_cannot_pass_for_a_branch() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        let branch = branch_hash(&a, &b);
        let mut concat = Vec::new();
        concat.extend_from_slice(a.as_bytes());
        concat.extend_from_slice(b.as_bytes());
        assert_ne!(branch, leaf_hash(&concat));
    }

    #[test]
    fn proofs_are_valid_for_all_sizes() {
        for n in 1..=33usize {
            let f = leaves(n);
            let root = merkle_root(&f);
            for i in 0..n {
                let p = merkle_proof(&f, i).expect("missing proof");
                assert!(verify_proof(&f[i], &p, &root), "invalid proof: n={n} i={i}");
            }
        }
    }

    #[test]
    fn forged_proof_is_rejected() {
        let f = leaves(8);
        let root = merkle_root(&f);
        let p = merkle_proof(&f, 3).unwrap();
        assert!(!verify_proof(&leaf_hash(b"made-up leaf"), &p, &root));
    }

    #[test]
    fn index_out_of_bounds() {
        assert_eq!(merkle_proof(&leaves(4), 4), None);
    }
}
