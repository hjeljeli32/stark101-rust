use crate::finite_fields::MyField;
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial};

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
