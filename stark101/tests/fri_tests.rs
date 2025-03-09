use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_std::{test_rng, UniformRand};
use stark101::{finite_fields::MyField, fri::*};

#[test]
fn test_next_fri_domain() {
    let rng = &mut test_rng();
    let fri_domain: Vec<MyField> = (0..8192).map(|_| MyField::rand(rng)).collect();
    let next_fri_domain = compute_next_fri_domain(&fri_domain);
    assert_eq!(
        next_fri_domain.len(),
        4096,
        "length of next fri_domain is wrong"
    );
    for i in 0..4096 {
        assert_eq!(
            next_fri_domain[i],
            fri_domain[i].pow(&(vec![2])),
            "element number {} of next fri_domain is wrong",
            i
        );
    }
}

#[test]
fn test_compute_next_fri_polynomial() {
    let poly = DensePolynomial {
        coeffs: vec![
            MyField::ONE,
            MyField::from(2),
            MyField::from(3),
            MyField::from(4),
        ],
    }; // 1 + 2*x + 3*x^2 + 4*x^3
    let beta = MyField::from(5);
    let next_poly = compute_next_fri_polynomial(&poly, beta);
    let expected_next_poly = DensePolynomial {
        coeffs: vec![MyField::from(11), MyField::from(23)],
    }; // 11 + 23*x
    assert_eq!(next_poly, expected_next_poly);
}

#[test]
fn test_compute_next_fri_layer() {
    let poly = DensePolynomial {
        coeffs: vec![
            MyField::ONE,
            MyField::from(2),
            MyField::from(3),
            MyField::from(4),
        ],
    }; // 1 + 2*x + 3*x^2 + 4*x^3
    let beta = MyField::from(5);
    let domain = vec![
        MyField::ONE,
        MyField::from(2),
        MyField::from(3),
        MyField::from(4),
    ];
    let (next_poly, next_domain, next_layer) = compute_next_fri_layer(&poly, &domain, beta);
    let expected_next_poly = DensePolynomial {
        coeffs: vec![MyField::from(11), MyField::from(23)],
    }; // 11 + 23*x
    let expected_next_domain = vec![MyField::from(1), MyField::from(4)];
    let expected_next_layer = vec![MyField::from(34), MyField::from(103)];
    assert_eq!(next_poly, expected_next_poly, "next_poly does not match");
    assert_eq!(
        next_domain, expected_next_domain,
        "next_domain does not match"
    );
    assert_eq!(next_layer, expected_next_layer, "next_layer does not match");
}
