use crate::finite_fields::MyField;
use ark_poly::polynomial::univariate::*;
use ark_std::{Zero, test_rng};
use ark_poly::DenseUVPolynomial;

/// Generates a random polynomial of certain degree
pub fn random_polynomial(degree: usize) -> DensePolynomial::<MyField> {
    let rng = &mut test_rng();
    DensePolynomial::<MyField>::rand(degree, rng)
}

/// Interpolates a polynomial from given evaluations at points using Lagrange interpolation.
pub fn interpolate_polynomial(x_points: Vec<MyField>, y_points: Vec<MyField>) -> DensePolynomial<MyField> {
    let n = x_points.len();
    let mut result = DensePolynomial::zero();

    // Loop through all the points (x, y) where x is the point and y is the evaluation
    for i in 0..n {
        // Compute Lagrange basis polynomial L_i(x)
        let mut lagrange_basis = DensePolynomial {coeffs: vec![MyField::from(1)]};

        for j in 0..n {
            if i != j {
                // (x - x_j) / (x_i - x_j)
                let numerator = DensePolynomial {coeffs: vec![-x_points[j], MyField::from(1)]};
                let denominator = DensePolynomial {coeffs: vec![x_points[i] - x_points[j]]};
 
                // Multiply the numerator and denominator (i.e., (x - x_j) / (x_i - x_j))
                lagrange_basis = lagrange_basis * &numerator / &denominator;
            }
        }

        // Multiply L_i(x) by y_i and add it to the result
        let scaled_lagrange_basis = lagrange_basis * y_points[i];
        result = result + &scaled_lagrange_basis;
    }

    result
}

/// Raises a polynomial to a power
pub fn pow(base: &DensePolynomial::<MyField>, exp: u64) -> DensePolynomial::<MyField> {
    let mut result = DensePolynomial::<MyField> { coeffs: vec![MyField::from(1)] };
    let mut base = base.clone();
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = &result * &base;
        }
        base = &base * &base;
        exp /= 2;
    }

    result
}

/// Computes the composition of two polynomials
pub fn compose_polynomials(f: &DensePolynomial::<MyField>, g: &DensePolynomial::<MyField>) -> DensePolynomial::<MyField>{
    let f_coeffs = f.coeffs();
    let mut result = DensePolynomial::<MyField> { coeffs: vec![f_coeffs[0]] };
    for (i, coeff) in f_coeffs.iter().enumerate().skip(1) {
        result = result + &(pow(g, i as u64) * *coeff);
    } 
    result
}