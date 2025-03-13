use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_std::{test_rng, UniformRand};
use stark101::{channel::Channel, finite_fields::MyField, fri::*, merkle::create_merkle_tree};

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

#[test]
fn test_generate_fri_commitments() {
    let poly = DensePolynomial {
        coeffs: vec![
            MyField::ONE,
            MyField::from(2),
            MyField::from(3),
            MyField::from(4),
        ],
    }; // 1 + 2*x + 3*x^2 + 4*x^3
    let poly_domain = vec![
        MyField::ONE,
        MyField::from(2),
        MyField::from(3),
        MyField::from(4),
    ];
    let poly_eval: Vec<MyField> = poly_domain
        .iter()
        .map(|point| poly.evaluate(&point))
        .collect();
    let poly_merkle = create_merkle_tree(&poly_eval);
    let mut channel = Channel::new();
    // we first send some data otherwise if we receive directly random field element it will be equal to 0
    let data = [01u8; 32];
    channel.send(&data.to_vec());
    let (fri_polys, fri_domains, fri_layers, fri_merkles) =
        generate_fri_commitments(&poly, &poly_domain, &poly_eval, &poly_merkle, &mut channel);
    // test fri_polys
    assert_eq!(fri_polys.len(), 3);
    assert_eq!(fri_polys[0], poly);
    assert_eq!(
        fri_polys[1],
        DensePolynomial {
            coeffs: vec![MyField::from(807540146), MyField::from(1615080293)]
        }
    );
    assert_eq!(
        fri_polys[2],
        DensePolynomial {
            coeffs: vec![MyField::from(1461010691)]
        }
    );
    // test fri_domains
    assert_eq!(fri_domains.len(), 3);
    assert_eq!(fri_domains[0], poly_domain);
    assert_eq!(fri_domains[1], vec![MyField::from(1), MyField::from(4)]);
    assert_eq!(fri_domains[2], vec![MyField::from(1)]);
    // test fri_layers
    assert_eq!(fri_layers.len(), 3);
    assert_eq!(fri_layers[0], poly_eval);
    assert_eq!(
        fri_layers[1],
        vec![MyField::from(2422620439_u32), MyField::from(825410372)]
    );
    assert_eq!(fri_layers[2], vec![MyField::from(1461010691)]);
    // test fri_merkles
    assert_eq!(fri_merkles.len(), 3);
    assert_eq!(fri_merkles[0].root(), poly_merkle.root());
    assert_eq!(
        fri_merkles[1].root(),
        create_merkle_tree(&vec![
            MyField::from(2422620439_u32),
            MyField::from(825410372)
        ])
        .root()
    );
    assert_eq!(
        fri_merkles[2].root(),
        create_merkle_tree(&vec![MyField::from(1461010691)]).root()
    );
    // test channel's proof
    assert_eq!(channel.proof.len(), 6);
}
