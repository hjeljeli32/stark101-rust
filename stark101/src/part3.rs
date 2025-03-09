use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use rs_merkle::{algorithms::Sha256, MerkleTree};
use stark101::finite_fields::MyField;

pub fn run_part3(
    eval_domain: Vec<MyField>,
    CP: DensePolynomial<MyField>,
    CP_eval: Vec<MyField>,
    CP_merkle: MerkleTree<Sha256>,
) {
    println!("Executing part 3...");
    // FRI folding
    // Compute subsequent FRI domain 
    let half_domain_size = eval_domain.len() / 2;
    assert_eq!(
        eval_domain[100].pow(&(vec![2])),
        eval_domain[half_domain_size + 100].pow(&(vec![2]))
    );
}
