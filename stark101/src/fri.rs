use crate::finite_fields::MyField;
use ark_ff::Field;

// Computes the subsequent FRI domain by taking the first half of the current FRI domain (dropping the second half), 
// and squaring each of its elements.
pub fn compute_next_fri_domain(fri_domain: &Vec<MyField>) -> Vec<MyField> {
    let next_fri_domain_len = fri_domain.len() / 2;
    fri_domain[..next_fri_domain_len]
        .iter()
        .map(|x| x.pow(&(vec![2])))
        .collect()
}
