use std::iter::zip;

use crate::common::{
    channel::Channel,
    finite_fields::MyField,
    merkle::{create_merkle_tree, get_authentication_path},
};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use rs_merkle::{algorithms::Sha256, MerkleTree};

use super::merkle::verify_decommitment;

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

// Computes the FRI polynomials, the FRI domains, the FRI layers and the FRI Merkle trees
// The method contains a loop, in each iteration of which we extend these four lists, using the last element in each.
// The iteration should stop once the last FRI polynomial is of degree 0, that is - when the last FRI polynomial is just
// a constant.
pub fn generate_fri_commitments(
    poly: &DensePolynomial<MyField>,
    poly_domain: &Vec<MyField>,
    poly_eval: &Vec<MyField>,
    poly_merkle: &MerkleTree<Sha256>,
    channel: &mut Channel,
) -> (
    Vec<DensePolynomial<MyField>>,
    Vec<Vec<MyField>>,
    Vec<Vec<MyField>>,
    Vec<MerkleTree<Sha256>>,
) {
    let mut fri_polys = vec![poly.clone()];
    let mut fri_domains = vec![poly_domain.clone()];
    let mut fri_layers = vec![poly_eval.clone()];
    let mut fri_merkles = vec![poly_merkle.clone()];
    while fri_polys.last().unwrap().degree() > 0 {
        let beta = channel.receive_random_field_element();
        let (next_poly, next_domain, next_layer) =
            compute_next_fri_layer(fri_polys.last().unwrap(), fri_domains.last().unwrap(), beta);
        fri_polys.push(next_poly);
        fri_domains.push(next_domain);
        fri_layers.push(next_layer);
        fri_merkles.push(create_merkle_tree(&fri_layers.last().unwrap()));
        channel.send(&fri_merkles.last().unwrap().root().unwrap().to_vec());
    }
    channel.send(
        &fri_polys.last().unwrap().coeffs[0]
            .into_bigint()
            .to_bytes_le(),
    );
    (fri_polys, fri_domains, fri_layers, fri_merkles)
}

// Decommits on FRI layers given an index by sending the following data
// 1. The element of the FRI layer at the given index (using fri_layers).
// 2. Its authentication path (using the corresponding Merkle tree from fri_merkles).
// 3. The element's FRI sibling
// 4. The authentication path of the element's sibling (using the same merkle tree).
pub fn decommit_on_fri_layers(
    id: usize,
    fri_layers: &Vec<Vec<MyField>>,
    fri_merkles: &Vec<MerkleTree<Sha256>>,
    channel: &mut Channel,
) {
    for (layer, merkle) in zip(
        &fri_layers[..fri_layers.len() - 1],
        &fri_merkles[..fri_merkles.len() - 1],
    ) {
        let id = id % layer.len();
        let sibling_id = (id + layer.len() / 2) % layer.len();
        channel.send(&layer[id].into_bigint().to_bytes_le()); // The element from the current layer
        channel.send(
            &get_authentication_path(&merkle, id)
                .iter()
                .flat_map(|arr| arr.to_vec())
                .collect(),
        ); // The authentication path for this element
        channel.send(&layer[sibling_id].into_bigint().to_bytes_le()); // The element's sibling in the current layer
        channel.send(
            &get_authentication_path(&merkle, sibling_id)
                .iter()
                .flat_map(|arr| arr.to_vec())
                .collect(),
        ); // The authentication path for the sibling element
    }
    channel.send(&fri_layers.last().unwrap()[0].into_bigint().to_bytes_le()); // The last element (constant polynomial)
}

// Decommits on the Trace polynomial by sending the following data
// The value f(x) with its authentication path.
// The value f(gx) with its authentication path.
// The value f(g^2x) with its authentication path.
// Finally, decommits on FRI layers
pub fn decommit_on_query(
    id: usize,
    f_eval: &Vec<MyField>,
    f_merkle: &MerkleTree<Sha256>,
    fri_layers: &Vec<Vec<MyField>>,
    fri_merkles: &Vec<MerkleTree<Sha256>>,
    channel: &mut Channel,
) -> () {
    assert!(id + 16 < f_eval.len());
    channel.send(&f_eval[id].into_bigint().to_bytes_le()); // f(x)
    channel.send(
        &get_authentication_path(&f_merkle, id)
            .iter()
            .flat_map(|arr| arr.to_vec())
            .collect(),
    ); // authentication path of f(x)
    channel.send(&f_eval[id + 8].into_bigint().to_bytes_le()); // f(gx)
    channel.send(
        &get_authentication_path(&f_merkle, id + 8)
            .iter()
            .flat_map(|arr| arr.to_vec())
            .collect(),
    ); // authentication path of f(gx)
    channel.send(&f_eval[id + 16].into_bigint().to_bytes_le()); // f(g^2x)
    channel.send(
        &get_authentication_path(&f_merkle, id + 16)
            .iter()
            .flat_map(|arr| arr.to_vec())
            .collect(),
    ); // authentication path of f(g^2x)
    decommit_on_fri_layers(id, fri_layers, fri_merkles, channel);
}

pub fn check_decommittment_on_fri_layers(
    eval_domain: &Vec<MyField>,
    betas: &Vec<MyField>,
    fri_polys_merkle_roots: &Vec<[u8; 32]>,
    id: usize,
    fri_poly_id: &Vec<MyField>,
    authentication_path_fri_poly_id: &Vec<Vec<[u8; 32]>>,
    fri_poly_sibling: &Vec<MyField>,
    authentication_path_fri_poly_sibling: &Vec<Vec<[u8; 32]>>,
) {
    let layer_nb = fri_poly_id.len() - 1;
    let mut layer_len = 8 * 1 << layer_nb;
    let mut fri_domain = eval_domain.clone();
    for i in 0..layer_nb {
        let id = id % layer_len;
        let sibling_id = (id + (layer_len / 2)) % layer_len;
        assert!(
            verify_decommitment(
                id,
                fri_poly_id[i],
                &authentication_path_fri_poly_id[i],
                fri_polys_merkle_roots[i]
            ),
            "check of decommitment of id of round {} in fri_poly failed",
            i
        );
        assert!(
            verify_decommitment(
                sibling_id,
                fri_poly_sibling[i],
                &authentication_path_fri_poly_sibling[i],
                fri_polys_merkle_roots[i]
            ),
            "check of decommitment of sibling of round {} in fri_poly failed",
            i
        );
        let sum = (fri_poly_id[i] + fri_poly_sibling[i]) / MyField::from(2);
        let diff = (fri_poly_id[i] - fri_poly_sibling[i]) / (MyField::from(2) * fri_domain[id]);
        assert_eq!(
            sum + (diff * betas[i]),
            fri_poly_id[i + 1],
            "Evaluations of FRI poly at layer {} do not satisfy the recurrence relation",
            i
        );

        layer_len /= 2;
        fri_domain = compute_next_fri_domain(&fri_domain);
    }
}

// Checks the consistency of decomitted data with committed data
pub fn check_decommittment_on_query(
    eval_domain: &Vec<MyField>,
    f_merkle_root: [u8; 32],
    betas: &Vec<MyField>,
    fri_polys_merkle_roots: &Vec<[u8; 32]>,
    id: usize,
    f_id: MyField,
    authentication_path_f_id: &Vec<[u8; 32]>,
    f_g_id: MyField,
    authentication_path_f_g_id: &Vec<[u8; 32]>,
    f_g2_id: MyField,
    authentication_path_f_g2_id: &Vec<[u8; 32]>,
    fri_poly_id: &Vec<MyField>,
    authentication_path_fri_poly_id: &Vec<Vec<[u8; 32]>>,
    fri_poly_sibling: &Vec<MyField>,
    authentication_path_fri_poly_sibling: &Vec<Vec<[u8; 32]>>,
) {
    assert!(
        verify_decommitment(id, f_id, authentication_path_f_id, f_merkle_root),
        "check of decommitment of id in f failed"
    );
    assert!(
        verify_decommitment(id + 8, f_g_id, authentication_path_f_g_id, f_merkle_root),
        "check of decommitment of g*id in f failed"
    );
    assert!(
        verify_decommitment(id + 16, f_g2_id, authentication_path_f_g2_id, f_merkle_root),
        "check of decommitment of g^2*id in f failed"
    );
    check_decommittment_on_fri_layers(
        eval_domain,
        betas,
        fri_polys_merkle_roots,
        id,
        fri_poly_id,
        authentication_path_fri_poly_id,
        fri_poly_sibling,
        authentication_path_fri_poly_sibling,
    );
}
