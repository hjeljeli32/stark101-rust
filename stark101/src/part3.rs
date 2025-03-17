use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use rs_merkle::{algorithms::Sha256, MerkleTree};
use stark101::{channel::Channel, finite_fields::MyField, fri::generate_fri_commitments};

pub fn run_part3(
    eval_domain: Vec<MyField>,
    CP: DensePolynomial<MyField>,
    CP_eval: Vec<MyField>,
    CP_merkle: MerkleTree<Sha256>,
    channel: &mut Channel,
) -> (
    Vec<Vec<MyField>>,
    Vec<MerkleTree<Sha256>>,
) {
    println!("Executing part 3...");

    // FRI folding
    // Compute subsequent FRI domain
    let half_domain_size = eval_domain.len() / 2;
    assert_eq!(
        eval_domain[100].pow(&(vec![2])),
        eval_domain[half_domain_size + 100].pow(&(vec![2]))
    );
    // Generate FRI commitments
    let (fri_polys, _, fri_layers, fri_merkles) =
        generate_fri_commitments(&CP, &eval_domain, &CP_eval, &CP_merkle, channel);
    assert_eq!(fri_layers.len(), 11, "Expected number of FRI layers is 11");
    assert_eq!(
        fri_layers.last().unwrap().len(),
        8,
        "Expected last layer to contain exactly 8 elements"
    );
    assert!(
        fri_layers
            .last()
            .unwrap()
            .iter()
            .all(|&x| x == MyField::from(1150958405)),
        "Expected last layer to be constant"
    );
    assert_eq!(
        fri_polys.last().unwrap().degree(),
        0,
        "Expacted last polynomial to be constant (degree 0)"
    );
    (fri_layers, fri_merkles)
}
