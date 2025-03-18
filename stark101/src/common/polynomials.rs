use crate::common::finite_fields::MyField;
use ark_ff::Field;
use ark_poly::polynomial::univariate::*;
use ark_poly::DenseUVPolynomial;
use ark_std::{test_rng, Zero};

/// Generates a random polynomial of certain degree
pub fn random_polynomial(degree: usize) -> DensePolynomial<MyField> {
    let rng = &mut test_rng();
    DensePolynomial::<MyField>::rand(degree, rng)
}

/// Calculates lagrange polynomials corresponding to given points
fn calculate_lagrange_polynomials(x_points: &Vec<MyField>) -> Vec<DensePolynomial<MyField>> {
    let n = x_points.len();
    let mut lagrange_polys = vec![];

    // Computes monomials and their product
    let mut monomials = vec![];
    let mut product = DensePolynomial {
        coeffs: vec![MyField::ONE],
    };
    for x in x_points {
        monomials.push(DensePolynomial {
            coeffs: vec![-*x, MyField::from(1)],
        });
        product = product * monomials.last().unwrap();
    }

    // Computes Lagrange polynomials
    for i in 0..n {
        let numerator = &product
            / DensePolynomial {
                coeffs: vec![-x_points[i], MyField::from(1)],
            };
        let mut denominator = MyField::ONE;
        for j in 0..n {
            if i != j {
                denominator *= x_points[i] - x_points[j];
            }
        }
        lagrange_polys.push(&numerator * denominator.inverse().unwrap());
    }
    lagrange_polys
}

/// Interpolates a polynomial from given evaluations at points using Lagrange interpolation.
pub fn interpolate_polynomial(
    x_points: &Vec<MyField>,
    y_points: &Vec<MyField>,
) -> DensePolynomial<MyField> {
    let n = x_points.len();
    let mut result = DensePolynomial::zero();
    let lagrange_polys = calculate_lagrange_polynomials(&x_points);

    for i in 0..n {
        // Multiply L_i(x) by y_i and add it to the result
        result = result + &(&lagrange_polys[i] * y_points[i]);
    }
    result
}

/// Raises a polynomial to a power
pub fn pow(base: &DensePolynomial<MyField>, exp: u64) -> DensePolynomial<MyField> {
    let mut result = DensePolynomial::<MyField> {
        coeffs: vec![MyField::from(1)],
    };
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
pub fn compose_polynomials(
    f: &DensePolynomial<MyField>,
    g: &DensePolynomial<MyField>,
) -> DensePolynomial<MyField> {
    let f_coeffs = f.coeffs();
    let mut result = DensePolynomial::<MyField> {
        coeffs: vec![f_coeffs[0]],
    };
    for (i, coeff) in f_coeffs.iter().enumerate().skip(1) {
        result = result + &(pow(g, i as u64) * *coeff);
    }
    result
}
