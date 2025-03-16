use std::vec;

use ark_ff::{BigInteger, FftField, Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_std::{test_rng, UniformRand};
use hex::decode;
use stark101::{
    channel::{Channel, Member, Type},
    finite_fields::MyField,
    fri::*,
    merkle::{create_merkle_tree, get_authentication_path, verify_decommitment},
};

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

#[test]
fn test_decommit_on_fri_layers() {
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
    let (_, _, fri_layers, fri_merkles) =
        generate_fri_commitments(&poly, &poly_domain, &poly_eval, &poly_merkle, &mut channel);
    decommit_on_fri_layers(1, fri_layers, fri_merkles, &mut channel);
    assert_eq!(channel.proof.len(), 15, "proof must contain 15 elements"); // 9 sending added by decommit_on_fri_layers
    assert_eq!(
        channel.proof[6],
        Member::new(Type::Send, (49_u64).to_le_bytes().to_vec())
    ); // decommit of id of 1st merkle
    assert_eq!(
        channel.proof[7],
        Member::new(
            Type::Send,
            decode("a111f275cc2e7588000001d300a31e76336d15b9d314cd1a1d8f3d3556975eed") // H(0a00000000000000)
                .unwrap()
                .iter()
                .chain(
                    decode("84a9bfa2c0c8ab01fd85ecfa9f7bb7da20822b54ca1cb5c03d5f9f122491ffe2") // H(H(8e00000000000000), H(3901000000000000))
                        .unwrap()
                        .iter()
                )
                .copied()
                .collect()
        )
    ); // decommit of authentication path of id of 1st merkle
    assert_eq!(
        channel.proof[8],
        Member::new(Type::Send, (313_u64).to_le_bytes().to_vec())
    ); // decommit of sibling id of 1st merkle
    assert_eq!(
        channel.proof[9],
        Member::new(
            Type::Send,
            decode("0c8b964f5ed84d78c6473e73f5d9307e453cd813c44a012f1b39c1c0262a56d3") // H(8e00000000000000)
                .unwrap()
                .iter()
                .chain(
                    decode("a3de3569dba30b2dbfd4aeffd9b95912536ac0b7d2d55cb6033c6e776ac10dd6") // H(H(0a00000000000000), H(3100000000000000))
                        .unwrap()
                        .iter()
                )
                .copied()
                .collect()
        )
    ); // decommit of authentication path of sibling id of 1st merkle
    assert_eq!(
        channel.proof[10],
        Member::new(Type::Send, (825410372_u64).to_le_bytes().to_vec())
    ); // decommit of id of 2nd merkle
    assert_eq!(
        channel.proof[11],
        Member::new(
            Type::Send,
            decode("4f304a3a93ff3cceb6181215f9da922481a7473d8508f9cbaeddb5c318fc7039") // H(1741669000000000)
                .unwrap()
        )
    ); // decommit of authentication path of id of 2nd merkle
    assert_eq!(
        channel.proof[12],
        Member::new(Type::Send, (2422620439_u64).to_le_bytes().to_vec())
    ); // decommit of sibling id of 2nd merkle
    assert_eq!(
        channel.proof[13],
        Member::new(
            Type::Send,
            decode("2ffef4ff8b90f8a3f2beae33f39b3f356b6f0587593c9d12a77de88fcac62583") // H(44c3323100000000)
                .unwrap()
        )
    ); // decommit of authentication path of sibling id of 2nd merkle
    assert_eq!(
        channel.proof[14],
        Member::new(Type::Send, (1461010691_u64).to_le_bytes().to_vec())
    ); // decommit of last element (constant polynomial)
}

#[test]
fn test_decommit_on_query() {
    let f = DensePolynomial {
        coeffs: vec![
            MyField::ONE,
            MyField::from(2),
            MyField::from(3),
            MyField::from(4),
        ],
    }; // 1 + 2*x + 3*x^2 + 4*x^3
       // Create a Group of size 4
    let g = MyField::GENERATOR.pow(&(vec![3221225472_u64 / 4]));
    let mut G = vec![MyField::ONE];
    for i in 1..4 {
        G.push(G[i - 1] * g);
    }
    // Create a Group of size 32
    let h = MyField::GENERATOR.pow(&(vec![3221225472_u64 / 32]));
    let mut H = vec![MyField::ONE];
    for i in 1..32 {
        H.push(H[i - 1] * h);
    }
    // Construct eval domain
    let w = MyField::GENERATOR;
    let eval_domain: Vec<MyField> = H.iter().map(|x| w * x).collect();
    // Evaluate on the Coset
    let f_eval: Vec<MyField> = eval_domain.iter().map(|point| f.evaluate(&point)).collect();
    // Commit f_eval on merkle tree
    let f_merkle = create_merkle_tree(&f_eval);
    // Send root of f_merkle
    let mut channel = Channel::new();
    let root = f_merkle.root().unwrap();
    channel.send(&root.to_vec());
    // set query index
    let id = 2;
    decommit_on_query(id, &f_eval, &f_merkle, &mut channel);
    // test length of proof
    assert_eq!(channel.proof.len(), 7, "proof must contain 7 elements");
    // test f(x) and its authentication path
    let f_x = f.evaluate(&(w * h.pow(&(vec![2]))));
    assert_eq!(
        channel.proof[1],
        Member::new(Type::Send, f_x.into_bigint().to_bytes_le()),
        "test of f(x) failed"
    );
    let authentication_path_f_x: Vec<[u8; 32]> = channel.proof[2]
        .data
        .chunks_exact(32)
        .map(|chunk| <[u8; 32]>::try_from(chunk).unwrap())
        .collect();
    assert!(
        verify_decommitment(2, f_x, &authentication_path_f_x, root),
        "verification of authentication path of f(x) failed"
    );
    // test f(gx) and its authentication path
    let f_gx = f.evaluate(&(w * h.pow(&(vec![2+8]))));
    assert_eq!(
        channel.proof[3],
        Member::new(Type::Send, f_gx.into_bigint().to_bytes_le()),
        "test of f(gx) failed"
    );
    let authentication_path_f_gx: Vec<[u8; 32]> = channel.proof[4]
        .data
        .chunks_exact(32)
        .map(|chunk| <[u8; 32]>::try_from(chunk).unwrap())
        .collect();
    assert!(
        verify_decommitment(2+8, f_gx, &authentication_path_f_gx, root),
        "verification of authentication path of f(gx) failed"
    );
    // test f(g^2x) and its authentication path
    let f_g2x = f.evaluate(&(w * h.pow(&(vec![2+16]))));
    assert_eq!(
        channel.proof[5],
        Member::new(Type::Send, f_g2x.into_bigint().to_bytes_le()),
        "test of f(gx) failed"
    );
    let authentication_path_f_g2x: Vec<[u8; 32]> = channel.proof[6]
        .data
        .chunks_exact(32)
        .map(|chunk| <[u8; 32]>::try_from(chunk).unwrap())
        .collect();
    assert!(
        verify_decommitment(2+16, f_g2x, &authentication_path_f_g2x, root),
        "verification of authentication path of f(gx) failed"
    );
}
