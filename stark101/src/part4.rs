use ark_poly::univariate::DensePolynomial;
use rs_merkle::{algorithms::Sha256, MerkleTree};
use stark101::{channel::Channel, finite_fields::MyField};

pub fn run_part4(
    f_eval: Vec<MyField>,
    f_merkle: MerkleTree<Sha256>,
    fri_polys: Vec<DensePolynomial<MyField>>,
    fri_domains: Vec<Vec<MyField>>,
    fri_layers: Vec<Vec<MyField>>,
    fri_merkles: Vec<MerkleTree<Sha256>>,
    channel: &mut Channel,
) {
    println!("Executing part 4...");
}
