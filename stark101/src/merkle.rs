use crate::finite_fields::MyField;
use ark_ff::{BigInteger, PrimeField};
use rs_merkle::algorithms::Sha256;
use rs_merkle::Hasher;

// Concatenates two arrays of 32 bytes
pub fn concatenate_arrays(arr1: &[u8; 32], arr2: &[u8; 32]) -> [u8; 64] {
    let mut result = [0u8; 64]; 
    result[..32].copy_from_slice(arr1); 
    result[32..].copy_from_slice(arr2); 
    result
}

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