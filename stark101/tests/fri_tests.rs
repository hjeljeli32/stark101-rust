use ark_ff::Field;
// use ark_std::test_rng;
use ark_std::{test_rng, UniformRand};
use stark101::{finite_fields::MyField, fri::*};

#[test]
fn test_next_fri_domain() {
    let rng = &mut test_rng();
    let fri_domain: Vec<MyField> = (0..8192).map(|_| MyField::rand(rng)).collect();
    let next_fri_domain = compute_next_fri_domain(&fri_domain);
    assert_eq!(next_fri_domain.len(), 4096, "length of next fri_domain is wrong");
    for i in 0..4096 {
        assert_eq!(next_fri_domain[i], fri_domain[i].pow(&(vec![2])), "element number {} of next fri_domain is wrong", i);    
    }
}