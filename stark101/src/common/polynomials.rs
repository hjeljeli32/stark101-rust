use crate::common::finite_fields::MyField;
use ark_ff::Field;
use ark_poly::polynomial::univariate::*;
use ark_poly::DenseUVPolynomial;
use ark_std::{test_rng, Zero};
use rayon::prelude::*;

/// Generates a random polynomial of certain degree
pub fn random_polynomial(degree: usize) -> DensePolynomial<MyField> {
    let rng = &mut test_rng();
    DensePolynomial::<MyField>::rand(degree, rng)
}

/// Calculates lagrange polynomials corresponding to given points
fn calculate_lagrange_polynomials(x_points: &Vec<MyField>) -> Vec<DensePolynomial<MyField>> {
    let n = x_points.len();

    // Computes monomials and their product
    let monomials = x_points.par_iter().map(|x| DensePolynomial {
        coeffs: vec![-*x, MyField::from(1)],
    });
    let product = monomials.clone().into_par_iter().reduce(
        || DensePolynomial {
            coeffs: vec![MyField::ONE],
        },
        |product, monomial| product * monomial,
    );

    // Computes Lagrange polynomials
    let lagrange_polys = (0..n)
        .into_par_iter()
        .map(|i| {
            let numerator = &product
                / DensePolynomial {
                    coeffs: vec![-x_points[i], MyField::from(1)],
                };
            let denominator = (0..n)
                .filter(|&j| j != i)
                .collect::<Vec<_>>() // Collect into Vec to enable parallel iteration
                .into_par_iter()
                .map(|j| x_points[i] - x_points[j])
                .reduce(|| MyField::ONE, |val, denominator| denominator * val);
            &numerator * denominator.inverse().unwrap()
        })
        .collect();

    lagrange_polys
}

/// Interpolates a polynomial from given evaluations at points using Lagrange interpolation.
pub fn interpolate_polynomial(
    x_points: &Vec<MyField>,
    y_points: &Vec<MyField>,
) -> DensePolynomial<MyField> {
    let n = x_points.len();
    let lagrange_polys = calculate_lagrange_polynomials(&x_points);

    let result = (0..n)
        .into_par_iter()
        .map(|i| &lagrange_polys[i] * y_points[i])
        .reduce(|| DensePolynomial::zero(), |result, value| result + &value);
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

    let mut g_power = DensePolynomial::<MyField> {
        coeffs: vec![MyField::from(1)],
    }; // Initialize g^0 = 1

    for (_, coeff) in f_coeffs.iter().enumerate().skip(1) {
        // Update g^i by multiplying the previous g^i by g
        g_power = g_power.clone() * g;

        // Add the current term (g^i * coeff) to the result
        result = result + &(g_power.clone() * *coeff);
    }
    result
}
