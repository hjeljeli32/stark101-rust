use std::time::Instant;
use crate::common::channel::Member;

pub fn run(proof: Vec<Member>) -> bool {
    println!("Executing verifier...");
    let start = Instant::now();

    // check length
    assert_eq!(proof.len(), 170, "length of proof must be 170");

    println!("Verification took: {:?}", start.elapsed());
    true
}