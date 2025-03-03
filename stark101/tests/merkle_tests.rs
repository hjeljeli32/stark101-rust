use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::{test_rng, rand::Rng};
use rs_merkle::{MerkleTree, algorithms::Sha256};
use rs_merkle::Hasher;
use hex::encode;
use stark101::finite_fields::MyField;
use stark101::merkle::*;

#[test]
fn test_create_tree_with_2_leaves() {
    let leaves = [
        Sha256::hash(&MyField::from(1).into_bigint().to_bytes_le()),  // H(0100000000000000)
        Sha256::hash(&MyField::from(2).into_bigint().to_bytes_le()),  // H(0200000000000000)
    ];
    // H0 = 7c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b8
    // H1 = d86e8112f3c4c4442126f8e9f44f16867da487f29052bf91b810457db34209a4
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = merkle_tree.root().unwrap();
    assert_eq!(
        encode(root), 
        "c06b7afada32b8e5e3e62b0a563e632f68dcef97d8dd39de5c1b3fe4132aaea1", 
        "root is not matching!"
    );
}

#[test]
fn test_create_tree_with_4_leaves() {
    let leaves = [
        Sha256::hash(&MyField::from(1).into_bigint().to_bytes_le()),  // H(0100000000000000)
        Sha256::hash(&MyField::from(2).into_bigint().to_bytes_le()),  // H(0200000000000000)
        Sha256::hash(&MyField::from(3).into_bigint().to_bytes_le()),  // H(0300000000000000)
        Sha256::hash(&MyField::from(4).into_bigint().to_bytes_le()),  // H(0400000000000000)
    ];
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    // H00 = 7c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b8
    // H01 = d86e8112f3c4c4442126f8e9f44f16867da487f29052bf91b810457db34209a4
    // H10 = 35be322d094f9d154a8aba4733b8497f180353bd7ae7b0a15f90b586b549f28b
    // H11 = f0a0278e4372459cca6159cd5e71cfee638302a7b9ca9b05c34181ac0a65ac5d
    // H0 = c06b7afada32b8e5e3e62b0a563e632f68dcef97d8dd39de5c1b3fe4132aaea1
    // H1 = 3b95ab12601f8fa42464588a735ac0ffda59c8c49e79712770229adf2b9e6ada
    let root = merkle_tree.root().unwrap();
    assert_eq!(
        encode(root), 
        "8a977dd50bf34d05d66ca85bcc0c2684482c9c3284720c3d1037af248f3c572f", 
        "root is not matching!"
    );
}

#[test]
fn test_get_authentication_path() {
    let leaves = [
        Sha256::hash(&MyField::from(1).into_bigint().to_bytes_le()),
        Sha256::hash(&MyField::from(2).into_bigint().to_bytes_le()),
        Sha256::hash(&MyField::from(3).into_bigint().to_bytes_le()),
        Sha256::hash(&MyField::from(4).into_bigint().to_bytes_le()),
    ];
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let proof = merkle_tree.proof(&[1]); // proof for 2nd element
    let authentication_path = proof.proof_hashes();
    assert_eq!(authentication_path.len(), 2, "length of authentication path is wrong");
    assert_eq!(
        encode(authentication_path[0]), 
        "7c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b8", 
        "1st hash of authentication path is not matching!"
    );
    assert_eq!(
        encode(authentication_path[1]), 
        "3b95ab12601f8fa42464588a735ac0ffda59c8c49e79712770229adf2b9e6ada", 
        "2nd hash of authentication path is not matching!"
    );
}

#[test]
fn test_verify_decommitment() {
    let leaves = [
        Sha256::hash(&MyField::from(1).into_bigint().to_bytes_le()),
        Sha256::hash(&MyField::from(2).into_bigint().to_bytes_le()),
        Sha256::hash(&MyField::from(3).into_bigint().to_bytes_le()),
        Sha256::hash(&MyField::from(4).into_bigint().to_bytes_le()),
    ];
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = merkle_tree.root().unwrap();
    let proof2 = merkle_tree.proof(&[1]); // proof for 2nd element
    assert!(
        verify_decommitment(1, MyField::from(2), proof2.proof_hashes(), root), 
        "verification of decommitment failed"
    );
    let proof3 = merkle_tree.proof(&[2]); // proof for 3rd element
    assert!(
        verify_decommitment(2, MyField::from(3), proof3.proof_hashes(), root), 
        "verification of decommitment failed"
    );
}

#[test]
fn test_verify_decommitment_random() {
    let rng = &mut test_rng();
    for i in 1..=15 {
        let data_length = 1<<i;
        let data: Vec<MyField> = (0..data_length).map(|_| MyField::rand(rng)).collect();
        let leaves: Vec<[u8; 32]> = data
            .iter()
            .map(|x| Sha256::hash(&x.into_bigint().to_bytes_le()))
            .collect();
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = merkle_tree.root().unwrap();
        let leaf_id = rng.gen_range(0..data_length);
        let proof = merkle_tree.proof(&[leaf_id]);
        assert!(
            verify_decommitment(leaf_id, data[leaf_id], proof.proof_hashes(), root), 
            "verification of decommitment failed with length: {}",
            data_length
        );
    
    }
}

