use crate::finite_fields::MyField;
use crate::utils::concatenate_arrays;
use ark_ff::{BigInteger, PrimeField};
use rs_merkle::algorithms::Sha256;
use rs_merkle::Hasher;

// Verifies that a decommitment matches with authentication path included in a Merkle proof 
pub fn verify_decommitment(
    leaf_id: usize,
    leaf_data: MyField,
    authentication_path: &[[u8; 32]],
    root: [u8; 32]
) -> bool {
    let mut leaf_id = leaf_id;
    let content_hash = Sha256::hash(&leaf_data.into_bigint().to_bytes_le());
    let mut hash = content_hash;
    for i in 0..authentication_path.len() {
        if leaf_id & 1 == 1 {
            hash = Sha256::hash(&concatenate_arrays(&authentication_path[i], &hash));
        } else {
            hash = Sha256::hash(&concatenate_arrays(&hash, &authentication_path[i]));
        }
        leaf_id = leaf_id >> 1;
    }
    hash == root
}