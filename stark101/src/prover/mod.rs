pub mod part1;
pub mod part2;
pub mod part3;
pub mod part4;

use crate::common::channel::Member;
use std::time::Instant;

pub fn run() -> Vec<Member> {
    println!("Executing prover...");
    let start = Instant::now();

    let (g, eval_domain, f, f_eval, f_merkle, mut channel) = part1::run();
    println!("✅ Part1 took: {:?}", start.elapsed());
    let start = Instant::now();
    assert_eq!(channel.proof.len(), 1, "length of proof must be 1");

    let (CP, CP_eval, CP_merkle) = part2::run(g, &eval_domain, &f, &mut channel);
    println!("✅ Part2 took: {:?}", start.elapsed());
    let start = Instant::now();
    assert_eq!(channel.proof.len(), 5, "length of proof must be 5");

    let (fri_layers, fri_merkles) =
        part3::run(&eval_domain, &CP, &CP_eval, &CP_merkle, &mut channel);
    println!("✅ Part3 took: {:?}", start.elapsed());
    let start = Instant::now();
    assert_eq!(channel.proof.len(), 26, "length of proof must be 26");

    part4::run(f_eval, f_merkle, fri_layers, fri_merkles, &mut channel);
    println!("✅ Part4 took: {:?}", start.elapsed());
    assert_eq!(channel.proof.len(), 170, "length of proof must be 170");

    channel.proof
}
