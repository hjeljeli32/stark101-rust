use crate::finite_fields::MyField;
use crate::utils::concat_slices;
use ark_ff::{BigInteger, PrimeField};
use rs_merkle::algorithms::Sha256;
use rs_merkle::{Hasher, MerkleTree};

pub fn create_merkle_tree(data: &Vec<MyField>) -> MerkleTree<Sha256> {
    let leaves: Vec<[u8; 32]> = data
        .iter()
        .map(|eval| Sha256::hash(&eval.into_bigint().to_bytes_le()))
        .collect();
    MerkleTree::<Sha256>::from_leaves(&leaves)
}

// Verifies that a decommitment matches with authentication path included in a Merkle proof
pub fn verify_decommitment(
    leaf_id: usize,
    leaf_data: MyField,
    authentication_path: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    let mut leaf_id = leaf_id;
    let content_hash = Sha256::hash(&leaf_data.into_bigint().to_bytes_le());
    let mut hash = content_hash;
    for i in 0..authentication_path.len() {
        if leaf_id & 1 == 1 {
            hash = Sha256::hash(&concat_slices(&authentication_path[i], &hash).as_slice());
        } else {
            hash = Sha256::hash(&concat_slices(&hash, &authentication_path[i]).as_slice());
        }
        leaf_id = leaf_id >> 1;
    }
    hash == root
}
