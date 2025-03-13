use crate::{channel::Channel, finite_fields::MyField, merkle::create_merkle_tree};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use rs_merkle::{algorithms::Sha256, MerkleTree};

// Computes the subsequent FRI domain by taking the first half of the current FRI domain (dropping the second half),
// and squaring each of its elements.
pub fn compute_next_fri_domain(fri_domain: &Vec<MyField>) -> Vec<MyField> {
    let next_fri_domain_len = fri_domain.len() / 2;
    fri_domain[..next_fri_domain_len]
        .iter()
        .map(|x| x.pow(&(vec![2])))
        .collect()
}

// Computes subsequent FRI polynomial by
// 1. Getting a random field element
// 2. Multiplying the odd coefficients of the previous polynomial by
// 3. Summing together consecutive pairs (even-odd) of coefficients.
pub fn compute_next_fri_polynomial(
    poly: &DensePolynomial<MyField>,
    beta: MyField,
) -> DensePolynomial<MyField> {
    let even_coeffs: Vec<MyField> = poly.coeffs.iter().step_by(2).cloned().collect();
    let odd_coeffs: Vec<MyField> = poly.coeffs.iter().skip(1).step_by(2).cloned().collect();
    let even = DensePolynomial::<MyField> {
        coeffs: even_coeffs,
    };
    let odd = DensePolynomial::<MyField> { coeffs: odd_coeffs };
    &even + (&odd * beta)
}

// Computes next FRI layer by taking a polynomial, a domain, and a field element and returns the next polynomial,
// the next domain, and the evaluation of this next polynomial on this next domain.
pub fn compute_next_fri_layer(
    poly: &DensePolynomial<MyField>,
    domain: &Vec<MyField>,
    beta: MyField,
) -> (DensePolynomial<MyField>, Vec<MyField>, Vec<MyField>) {
    let next_poly = compute_next_fri_polynomial(poly, beta);
    let next_domain = compute_next_fri_domain(domain);
    let next_layer = next_domain
        .iter()
        .map(|point| next_poly.evaluate(&point))
        .collect();
    (next_poly, next_domain, next_layer)
}

// Computes the FRI polynomials, the FRI domains, the FRI layers and the FRI Merkle trees
// The method contains a loop, in each iteration of which we extend these four lists, using the last element in each.
// The iteration should stop once the last FRI polynomial is of degree 0, that is - when the last FRI polynomial is just
// a constant.
pub fn generate_fri_commitments(
    poly: &DensePolynomial<MyField>,
    poly_domain: &Vec<MyField>,
    poly_eval: &Vec<MyField>,
    poly_merkle: &MerkleTree<Sha256>,
    channel: &mut Channel,
) -> (
    Vec<DensePolynomial<MyField>>,
    Vec<Vec<MyField>>,
    Vec<Vec<MyField>>,
    Vec<MerkleTree<Sha256>>,
) {
    let mut fri_polys = vec![poly.clone()];
    let mut fri_domains = vec![poly_domain.clone()];
    let mut fri_layers = vec![poly_eval.clone()];
    let mut fri_merkles = vec![poly_merkle.clone()];
    while fri_polys.last().unwrap().degree() > 0 {
        let beta = channel.receive_random_field_element();
        let (next_poly, next_domain, next_layer) =
            compute_next_fri_layer(fri_polys.last().unwrap(), fri_domains.last().unwrap(), beta);
        fri_polys.push(next_poly);
        fri_domains.push(next_domain);
        fri_layers.push(next_layer);
        fri_merkles.push(create_merkle_tree(&fri_layers.last().unwrap()));
        channel.send(&fri_merkles.last().unwrap().root().unwrap().to_vec());
    }
    channel.send(
        &fri_polys.last().unwrap().coeffs[0]
            .into_bigint()
            .to_bytes_le(),
    );
    (fri_polys, fri_domains, fri_layers, fri_merkles)
}
