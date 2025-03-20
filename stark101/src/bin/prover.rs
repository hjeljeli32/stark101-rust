use serde_json;
use stark101::prover;
use std::fs::File;
use std::io::Write;

fn main() {
    let proof = prover::run();

    // Convert to pretty JSON
    let json = serde_json::to_string_pretty(&proof).expect("Failed to serialize proof");

    // Save to file
    let mut file = File::create("proofs/proof.json").expect("Failed to create file");
    file.write_all(json.as_bytes())
        .expect("Failed to write to file");
    println!("✅ Proof saved successfully");
}
