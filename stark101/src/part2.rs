use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    Polynomial,
};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use stark101::{
    channel::Channel,
    finite_fields::MyField,
    polynomials::{compose_polynomials, pow},
};

pub fn run_part2(
    g: MyField,
    eval_domain: &Vec<MyField>,
    f: DensePolynomial<MyField>,
    channel: &mut Channel,
) -> (DensePolynomial<MyField>, Vec<MyField>, MerkleTree<Sha256>) {
    println!("Executing part 2...");

    // Rational Functions (That are in Fact Polynomials)
    // The first constraint
    let numer0 = &f
        - &DensePolynomial {
            coeffs: vec![MyField::ONE],
        };
    let denom0 = DensePolynomial {
        coeffs: vec![-MyField::ONE, MyField::ONE],
    }; // x-1
    let (p0, r0) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&numer0).into(), &(&denom0).into()).unwrap();
    assert_eq!(
        r0,
        DensePolynomial { coeffs: vec![] },
        "numer0 should be divisble by x-1"
    );
    assert_eq!(
        p0.evaluate(&MyField::from(2718)),
        MyField::from(2509888982_u32)
    );
    // The second constraint
    let numer1 = &f
        - &DensePolynomial {
            coeffs: vec![MyField::from(2338775057_u32)],
        };
    let denom1 = DensePolynomial {
        coeffs: vec![-g.pow(&(vec![1022])), MyField::ONE],
    }; // x - g**1022
    let (p1, r1) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&numer1).into(), &(&denom1).into()).unwrap();
    assert_eq!(
        r1,
        DensePolynomial { coeffs: vec![] },
        "numer1 should be divisible by x-g**1022"
    );
    assert_eq!(
        p1.evaluate(&MyField::from(5772)),
        MyField::from(232961446_u32)
    );
    // The third constraint
    let t20 = DensePolynomial {
        coeffs: vec![MyField::ZERO, g.pow(&(vec![2]))],
    }; // g**2 x
    let t21 = DensePolynomial {
        coeffs: vec![MyField::ZERO, g],
    }; // g x
    let numer2 =
        &compose_polynomials(&f, &t20) - &pow(&compose_polynomials(&f, &t21), 2) - &pow(&f, 2);
    assert_eq!(numer2.evaluate(&g.pow(&(vec![1020]))), MyField::ZERO);
    assert_ne!(numer2.evaluate(&g.pow(&(vec![1021]))), MyField::ZERO);
    let mut t22_coeffs = vec![MyField::from(-1)];
    t22_coeffs.extend(vec![MyField::ZERO; 1023]);
    t22_coeffs.push(MyField::ONE);
    let t22 = DensePolynomial { coeffs: t22_coeffs }; // x^1024 - 1
    let t23 = DensePolynomial {
        coeffs: vec![-g.pow(&(vec![1021])), MyField::ONE],
    }; // x - g**1021
    let t24 = DensePolynomial {
        coeffs: vec![-g.pow(&(vec![1022])), MyField::ONE],
    }; // x - g**1022
    let t25 = DensePolynomial {
        coeffs: vec![-g.pow(&(vec![1023])), MyField::ONE],
    }; // x - g**1023
    let (denom2, _) = DenseOrSparsePolynomial::divide_with_q_and_r(
        &(&t22).into(),
        &(&(&t23 * &t24 * &t25)).into(),
    )
    .unwrap();
    let (p2, r2) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&numer2).into(), &(&denom2).into()).unwrap();
    assert_eq!(
        r2,
        DensePolynomial { coeffs: vec![] },
        "numer2 should be divisible by (x**1024 - 1) / ((x - g**1021) * (x - g**1022) * (x - g**1023))"
    );
    assert_eq!(
        p2.evaluate(&MyField::from(31415)),
        MyField::from(2090051528_u32)
    );
    // Composition polynomial
    let alpha0 = channel.receive_random_field_element();
    let alpha1 = channel.receive_random_field_element();
    let alpha2 = channel.receive_random_field_element();
    let CP = &p0 * alpha0 + &p1 * alpha1 + &p2 * alpha2;
    assert_eq!(CP.degree(), 1023, "The degree of CP must be 1023");
    // Evaluate on the Coset
    let CP_eval: Vec<MyField> = eval_domain
        .iter()
        .map(|point| CP.evaluate(&point))
        .collect();
    // Commitment
    let leaves: Vec<[u8; 32]> = CP_eval
        .iter()
        .map(|eval| Sha256::hash(&eval.into_bigint().to_bytes_le()))
        .collect();
    let CP_merkle = MerkleTree::<Sha256>::from_leaves(&leaves);
    // send on Channel
    channel.send(CP_merkle.root().unwrap());

    (CP, CP_eval, CP_merkle)
}
