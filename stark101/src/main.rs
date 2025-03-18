use stark101::{prover, verifier};

fn main() {
    let proof = prover::run();

    let result = verifier::run(proof);
}
