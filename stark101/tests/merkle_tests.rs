use ark_ff::UniformRand;
use ark_std::{rand::Rng, test_rng};
use hex::encode;
use stark101::finite_fields::MyField;
use stark101::merkle::*;

#[test]
fn test_create_tree_with_2_leaves() {
    let data = vec![MyField::from(1), MyField::from(2)];
    let merkle_tree = create_merkle_tree(&data);
    // H0 = H(0100000000000000) = 7c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b8
    // H1 = H(0200000000000000) = d86e8112f3c4c4442126f8e9f44f16867da487f29052bf91b810457db34209a4
    let root = merkle_tree.root().unwrap();
    assert_eq!(
        encode(root),
        "c06b7afada32b8e5e3e62b0a563e632f68dcef97d8dd39de5c1b3fe4132aaea1",
        "root is not matching!"
    );
}

#[test]
fn test_create_tree_with_4_leaves() {
    let data = vec![
        MyField::from(1),
        MyField::from(2),
        MyField::from(3),
        MyField::from(4),
    ];
    let merkle_tree = create_merkle_tree(&data);
    // H00 = H(0100000000000000) = 7c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b8
    // H01 = H(0200000000000000) = d86e8112f3c4c4442126f8e9f44f16867da487f29052bf91b810457db34209a4
    // H10 = H(0300000000000000) = 35be322d094f9d154a8aba4733b8497f180353bd7ae7b0a15f90b586b549f28b
    // H11 = H(0400000000000000) = f0a0278e4372459cca6159cd5e71cfee638302a7b9ca9b05c34181ac0a65ac5d
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
    let data = vec![
        MyField::from(1),
        MyField::from(2),
        MyField::from(3),
        MyField::from(4),
    ];
    let merkle_tree = create_merkle_tree(&data);
    let authentication_path = get_authentication_path(&merkle_tree, 1); // authentication-path of 2nd element
    assert_eq!(
        authentication_path.len(),
        2,
        "length of authentication path is wrong"
    );
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
    let data = vec![
        MyField::from(1),
        MyField::from(2),
        MyField::from(3),
        MyField::from(4),
    ];
    let merkle_tree = create_merkle_tree(&data);
    let root = merkle_tree.root().unwrap();
    let authentication_path2 = get_authentication_path(&merkle_tree, 1); // authentication-path of 2nd element
    assert!(
        verify_decommitment(1, MyField::from(2), &authentication_path2, root),
        "verification of decommitment of 2nd element failed"
    );
    let authentication_path3 = get_authentication_path(&merkle_tree, 2); // authentication-path of 3rd element
    assert!(
        verify_decommitment(2, MyField::from(3), &authentication_path3, root),
        "verification of decommitment of 3rd element failed"
    );
}

#[test]
fn test_verify_decommitment_random() {
    let rng = &mut test_rng();
    for i in 1..=15 {
        let data_length = 1 << i;
        let data: Vec<MyField> = (0..data_length).map(|_| MyField::rand(rng)).collect();
        let merkle_tree = create_merkle_tree(&data);
        let root = merkle_tree.root().unwrap();
        let leaf_id = rng.gen_range(0..data_length);
        let authentication_path = get_authentication_path(&merkle_tree, leaf_id);
        assert!(
            verify_decommitment(leaf_id, data[leaf_id], &authentication_path, root),
            "verification of decommitment failed with length: {}",
            data_length
        );
    }
}
