use ark_ff::{AdditiveGroup, FftField, Field};
use ark_poly::polynomial::univariate::*;
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_std::{rand::Rng, test_rng, UniformRand};
use stark101::common::{finite_fields::MyField, polynomials::*};
use std::collections::HashSet;

#[test]
fn test_rand_poly_degree() {
    let mut rng = ark_std::test_rng();
    for i in 0..100 {
        assert_eq!(random_polynomial(&mut rng, i).degree(), i, "degree is wrong");
    }
}

#[test]
fn test_add_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![MyField::ONE, MyField::from(2), MyField::from(3)],
    }; // 1 + 2*x + 3*x^2
    let poly2 = DensePolynomial {
        coeffs: vec![MyField::from(4), MyField::from(5), MyField::from(6)],
    }; // 4 + 5*x + 6*x^2
    let poly3 = &poly1 + &poly2;
    assert_eq!(
        poly3.coeffs,
        vec![MyField::from(5), MyField::from(7), MyField::from(9)]
    ); // 5 + 7x + 9*x^2
}

#[test]
fn test_mul_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![MyField::ONE, MyField::ONE],
    }; // 1 + x
    let poly2 = DensePolynomial {
        coeffs: vec![MyField::ONE, MyField::ONE],
    }; // 1 + x
    let poly3 = &poly1 * &poly2;
    assert_eq!(
        poly3.coeffs,
        vec![MyField::ONE, MyField::from(2), MyField::ONE]
    ); // 1 + 2x + x^2
}

#[test]
fn test_div_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![MyField::from(-1), MyField::ZERO, MyField::ONE],
    }; // -1 + x^2
    let poly2 = DensePolynomial {
        coeffs: vec![MyField::from(-1), MyField::ONE],
    }; // -1 + x
    let poly3 = &poly1 / &poly2;
    assert_eq!(poly3.coeffs, vec![MyField::ONE, MyField::ONE]); // 1 + x
}

#[test]
fn test_divide_with_q_r_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![
            MyField::from(4),
            MyField::from(-5),
            MyField::ZERO,
            MyField::ZERO,
            MyField::ZERO,
            MyField::ZERO,
            MyField::ZERO,
            MyField::ZERO,
            MyField::ZERO,
            MyField::ONE,
        ],
    }; // 4 - 5x + x^9
    let poly2 = DensePolynomial {
        coeffs: vec![MyField::ONE, MyField::ZERO, MyField::ONE],
    }; // 1 + x^2
    let (q, r) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&poly1).into(), &(&poly2).into()).unwrap();
    assert_eq!(
        q.coeffs,
        vec![
            MyField::ZERO,
            MyField::from(-1),
            MyField::ZERO,
            MyField::ONE,
            MyField::ZERO,
            MyField::from(-1),
            MyField::ZERO,
            MyField::ONE
        ]
    ); // -x + x^3 - x^5 + x^7
    assert_eq!(r.coeffs, vec![MyField::from(4), MyField::from(-4)]); // 4 - 4x
}

#[test]
fn test_divide_with_q_r_rand_polys() {
    let rng = &mut test_rng();
    for _ in 0..20 {
        let degree_a = rng.gen_range(0..=50);
        let degree_b = rng.gen_range(0..=50);
        let a = DensePolynomial::<MyField>::rand(degree_a, rng);
        let b = DensePolynomial::<MyField>::rand(degree_b, rng);
        let (q, r) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&a).into(), &(&b).into()).unwrap();
        let d = &r + &q * &b;
        let degree_r = r.degree();
        assert!(
            degree_r < degree_b || (degree_r == 0 && degree_b == 0),
            "Polynomial r must have a smaller degree than polynomial b (r: {}, b: {})",
            degree_r,
            degree_b
        );
        assert_eq!(
            d, a,
            "Polynomial d: {:?} must be equal to a: {:?}",
            d.coeffs, a.coeffs
        )
    }
}

#[test]
fn test_prod_polys() {
    let g = MyField::GENERATOR.pow(&(vec![3221225472_u64 / 1024]));

    let mut coefficients = vec![MyField::from(-1)];
    coefficients.extend(vec![MyField::ZERO; 1023]);
    coefficients.push(MyField::ONE);
    let expected_product = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^1024

    let mut product = DensePolynomial {
        coeffs: vec![MyField::ONE],
    }; // start product with polynomial 1
    for i in 0..1024 {
        let gi = g.pow(&[i]); // g^i, exponentiation with a scalar field
        let term = DensePolynomial {
            coeffs: vec![-gi, MyField::ONE],
        }; // (X - g^i) as (1, -gi)
        product = product * term; // Multiply with the accumulated product
    }
    assert_eq!(
        product, expected_product,
        "Polynomial product: {:?} must be equal to expected_product: {:?}",
        product.coeffs, expected_product.coeffs
    )
}

#[test]
fn test_eval_poly() {
    let poly = DensePolynomial {
        coeffs: vec![MyField::ZERO, MyField::ONE, MyField::ONE],
    }; // x + x^2
    assert_eq!(poly.evaluate(&MyField::from(5)), MyField::from(30));
}

#[test]
fn test_poly_interpolation() {
    let x_vals = vec![
        MyField::from(0u64),
        MyField::from(1u64),
        MyField::from(2u64),
    ];
    let y_vals = vec![
        MyField::from(0u64), // f(0)
        MyField::from(1u64), // f(1)
        MyField::from(8u64), // f(2)
    ];
    let poly = interpolate_polynomial(&x_vals, &y_vals);
    let expected_poly = DensePolynomial {
        coeffs: vec![MyField::ZERO, MyField::from(-2), MyField::from(3)],
    }; // -2x + 3x^2
    assert_eq!(
        poly, expected_poly,
        "Interpolated poly: {:?} must be equal to expected_poly: {:?}",
        poly.coeffs, expected_poly.coeffs
    );
}

#[test]
fn test_rand_poly_interpolation() {
    let rng = &mut test_rng();
    for _ in 0..10 {
        let degree = rng.gen_range(0..=100);
        let poly = DensePolynomial::<MyField>::rand(degree, rng);
        let mut x_vals: HashSet<MyField> = HashSet::new();
        while x_vals.len() < degree + 1 {
            x_vals.insert(MyField::rand(rng));
        }
        let x_vals: Vec<MyField> = x_vals.into_iter().collect();
        let y_vals: Vec<MyField> = x_vals.iter().map(|x| poly.evaluate(x)).collect();
        let interpolated_poly = interpolate_polynomial(&x_vals, &y_vals);
        assert_eq!(
            interpolated_poly, poly,
            "Interpolated poly: {:?} must be equal to poly: {:?}",
            interpolated_poly.coeffs, poly.coeffs
        );
    }
}

#[test]
fn test_pow_poly() {
    let f = DensePolynomial {
        coeffs: vec![MyField::ONE, MyField::ONE],
    }; // 1 + x
    let f_pow_2 = pow(&f, 2);
    let f_pow_3 = pow(&f, 3);
    let f_pow_2_expected = DensePolynomial {
        coeffs: vec![MyField::ONE, MyField::from(2), MyField::ONE],
    }; // 1 + 2x + x^2
    let f_pow_3_expected = DensePolynomial {
        coeffs: vec![
            MyField::ONE,
            MyField::from(3),
            MyField::from(3),
            MyField::ONE,
        ],
    }; // 1 + 3x + 3x^2 + x^3
    assert_eq!(f_pow_2, f_pow_2_expected);
    assert_eq!(f_pow_3, f_pow_3_expected);
}

#[test]
fn test_compose_polys() {
    let f = DensePolynomial {
        coeffs: vec![MyField::ZERO, MyField::ONE, MyField::ONE],
    }; // x + x^2
    let g = DensePolynomial {
        coeffs: vec![MyField::ONE, MyField::ONE],
    }; // 1 + x
    let f_g = compose_polynomials(&f, &g);
    let f_g_expected = DensePolynomial {
        coeffs: vec![MyField::from(2), MyField::from(3), MyField::ONE],
    }; // 2 + 3x + x^2
    assert_eq!(
        f_g, f_g_expected,
        "Composed poly: {:?} must be equal to poly: {:?}",
        f_g.coeffs, f_g_expected.coeffs
    );
}
