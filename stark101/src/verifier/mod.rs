use crate::common::{
    channel::{parse_received_field_element, parse_sent_root, Member},
    finite_fields::MyField,
};
use std::time::Instant;

pub fn run(proof: Vec<Member>) -> bool {
    println!("Executing verifier...");
    let start = Instant::now();

    // check length
    assert_eq!(proof.len(), 170, "length of proof must be 170!");

    let f_merkle_root = parse_sent_root(&proof[0]);
    let mut alphas: Vec<MyField> = vec![];
    for i in 0..3 {
        alphas.push(parse_received_field_element(&proof[i + 1]));
    }

    println!("Verification took: {:?}", start.elapsed());
    true
}
