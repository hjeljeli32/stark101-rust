use ark_ff::{FftField, Field};

use crate::common::{
    channel::{
        parse_received_field_element, parse_received_int, parse_sent_authentication_path,
        parse_sent_field_element, parse_sent_root, Member,
    },
    finite_fields::MyField,
    fri::check_decommittment_on_query,
};
use std::time::Instant;

pub fn run(proof: Vec<Member>) -> bool {
    println!("Executing verifier...");
    let start = Instant::now();

    // check length
    assert_eq!(proof.len(), 170, "Length of proof must be 170");

    // Create a Group of size 8192
    let h = MyField::GENERATOR.pow(&(vec![3221225472_u64 / 8192]));
    let mut H = vec![MyField::ONE];
    for i in 1..8192 {
        H.push(H[i - 1] * h);
    }
    // Construct eval domain
    let w = MyField::GENERATOR;
    let eval_domain: Vec<MyField> = H.iter().map(|x| w * x).collect();

    let f_merkle_root = parse_sent_root(&proof[0]); // member 0
    let mut alphas: Vec<MyField> = vec![];
    for i in 0..3 {
        alphas.push(parse_received_field_element(&proof[1 + i])); // members [1,3]
    }
    let CP_merkle_root = parse_sent_root(&proof[4]); // member 4

    let mut betas = vec![];
    let mut fri_polys_merkle_roots = vec![CP_merkle_root];
    for i in 0..10 {
        betas.push(parse_received_field_element(&proof[5 + 2 * i])); // members 5, 7, .. 23
        fri_polys_merkle_roots.push(parse_sent_root(&proof[5 + 2 * i + 1])); // members 6, 8, .. 24
    }
    let fri_constant_poly_commit = parse_sent_field_element(&proof[25]); // member 25

    // Prover Decommitted on a Set of 3 Queries
    // We verify the data's consistency for each Query
    for query in 0..3 {
        let id = parse_received_int(&proof[26 + 48 * query]) as usize; //members 26, 74, 122

        let f_id = parse_sent_field_element(&proof[27 + 48 * query]); // members 27, 75, 123
        let authentication_path_f_id = parse_sent_authentication_path(&proof[28 + 48 * query]); // members 28, 76, 124
        let f_g_id = parse_sent_field_element(&proof[29 + 48 * query]); // members 29, 77, 125
        let authentication_path_f_g_id = parse_sent_authentication_path(&proof[30 + 48 * query]); // members 30, 78, 126
        let f_g2_id = parse_sent_field_element(&proof[31 + 48 * query]); // members 31, 79, 127
        let authentication_path_f_g2_id = parse_sent_authentication_path(&proof[32 + 48 * query]); // members 32, 80, 128

        let mut fri_poly_id = vec![];
        let mut authentication_path_fri_poly_id = vec![];
        let mut fri_poly_sibling = vec![];
        let mut authentication_path_fri_poly_sibling = vec![];
        for i in 0..10 {
            fri_poly_id.push(parse_sent_field_element(&proof[33 + 4 * i + 48 * query])); // members (33, 37, .. 69), (81, 85, .. 117), (129, 133, .. 165)
            authentication_path_fri_poly_id.push(parse_sent_authentication_path(
                &proof[33 + 4 * i + 1 + 48 * query],
            )); // members (34, 38, .., 70), (82, 86, .. 118), (130, 131, .. 166)
            fri_poly_sibling.push(parse_sent_field_element(
                &proof[33 + 4 * i + 2 + 48 * query],
            )); // members (35, 39, .. 71), (83, 87, .. 119), (131, 132, .. 167)
            authentication_path_fri_poly_sibling.push(parse_sent_authentication_path(
                &proof[33 + 4 * i + 3 + 48 * query],
            )); // members (36, 40, .., 72), (84, 88, .. 120), (132, 133, .. 168)
        }
        let fri_constant_poly_decommit = parse_sent_field_element(&proof[73 + 48 * query]); // members 73, 121, 169
        assert_eq!(
            fri_constant_poly_commit, fri_constant_poly_decommit,
            "Constant polynomial should be the same between commit and decommit"
        );
        // Add the constant poly to check the consistency of last FRI layer
        fri_poly_id.push(fri_constant_poly_decommit);

        check_decommittment_on_query(
            &eval_domain,
            f_merkle_root,
            &betas,
            &fri_polys_merkle_roots,
            id,
            f_id,
            &authentication_path_f_id,
            f_g_id,
            &authentication_path_f_g_id,
            f_g2_id,
            &authentication_path_f_g2_id,
            &fri_poly_id,
            &authentication_path_fri_poly_id,
            &fri_poly_sibling,
            &authentication_path_fri_poly_sibling,
        );
    }

    println!("Verification took: {:?}", start.elapsed());
    true
}
