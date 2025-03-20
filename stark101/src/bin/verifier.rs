use serde_json;
use stark101::common::channel::Member;
use stark101::verifier;
use std::fs::File;
use std::io::Read;

fn main() {
    let mut file = File::open("proofs/proof.json").expect("Failed to open file");
    let mut json_str = String::new();
    file.read_to_string(&mut json_str)
        .expect("Failed to read file");

    let proof: Vec<Member> = serde_json::from_str(&json_str).expect("Failed to parse JSON");
    println!("✅ Proof loaded successfully");

    let result = verifier::run(proof);
    match result {
        true => println!("✅ Proof verified successfully"),
        false => println!("Proof Verification failed"),
    }
}
