use super::super::common::{
    channel::*, finite_fields::MyField, merkle::create_merkle_tree, polynomials::*,
};
use ark_ff::{FftField, Field};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use rs_merkle::{algorithms::Sha256, MerkleTree};

pub fn run() -> (
    MyField,
    Vec<MyField>,
    DensePolynomial<MyField>,
    Vec<MyField>,
    MerkleTree<Sha256>,
    Channel,
) {
    println!("Executing part 1...");

    // FibonacciSq Trace
    let mut a = vec![MyField::from(1), MyField::from(3141592)];
    for i in 2..1023 {
        a.push(a[i - 2] * a[i - 2] + a[i - 1] * a[i - 1]);
    }
    assert!(
        a.len() == 1023,
        "The trace must consist of exactly 1023 elements."
    );
    assert!(
        a[1022] == MyField::from(2338775057u64),
        "Wrong last element!"
    );

    // Thinking of polynomials
    // Create a Group of size 1024
    let g = MyField::GENERATOR.pow(&(vec![3221225472_u64 / 1024]));
    let mut G = vec![MyField::ONE];
    for i in 1..1024 {
        G.push(G[i - 1] * g);
    }
    assert!(
        g.pow(&(vec![1024])) == MyField::ONE,
        "The generator g is of wrong order"
    );
    assert!(G[1023] * g == MyField::ONE, "Wrong last element!");
    // Interpolate the polynomial
    let f = interpolate_polynomial(&G[..1023].to_vec(), &a);
    assert!(
        f.evaluate(&MyField::from(2)) == MyField::from(1302089273),
        "Evaluation at point 2 is wrong!"
    );

    // Evaluating on a Larger Domain
    // The trace, viewed as evaluations of a polynomial f on G , can now be extended by evaluating over a
    // larger domain, thereby creating a Reed-Solomon error correction code.
    // Create a Group of size 8192
    let h = MyField::GENERATOR.pow(&(vec![3221225472_u64 / 8192]));
    let mut H = vec![MyField::ONE];
    for i in 1..8192 {
        H.push(H[i - 1] * h);
    }
    assert!(
        h.pow(&(vec![8192])) == MyField::ONE,
        "The generator h is of wrong order"
    );
    assert!(H[8191] * h == MyField::ONE, "Wrong last element!");
    // Construct eval domain
    let w = MyField::GENERATOR;
    let w_inv = w.inverse().unwrap();
    let eval_domain: Vec<MyField> = H.iter().map(|x| w * x).collect();
    for i in 0..8192 {
        assert!(
            ((w_inv * eval_domain[1]).pow(&(vec![i]))) * w == eval_domain[i as usize],
            "element of eval_domain is wrong!"
        );
    }
    // Evaluate on the Coset
    let f_eval: Vec<MyField> = eval_domain.iter().map(|point| f.evaluate(&point)).collect();
    assert!(
        f_eval[0] == MyField::from(576067152),
        "Wrong first element of f_eval!"
    );
    assert!(
        f_eval[8191] == MyField::from(1076821037),
        "Wrong last element of f_eval!"
    );

    // Commitments
    // We will use Sha256-based Merkle Trees as our commitment scheme
    let f_merkle = create_merkle_tree(&f_eval);
    // Channel
    let mut channel = Channel::new();
    channel.send(&f_merkle.root().unwrap().to_vec());

    (g, eval_domain, f, f_eval, f_merkle, channel)
}
