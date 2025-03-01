use stark101::finite_fields::MyField;
use ark_ff::fields::Field;
use ark_std::{UniformRand, test_rng};

#[test]
fn test_field_modulus() {
    let modulus = MyField::from(3221225473u64);
    let zero = MyField::from(0u64);
    
    assert_eq!(modulus, zero, "modulus should be 0");
}

#[test]
fn test_field_identity_elements() {
    let zero = MyField::from(0u64);
    let one = MyField::from(1u64);

    assert_eq!(zero + one, one, "0 + 1 should be 1");
    assert_eq!(one * one, one, "1 * 1 should be 1");
}

#[test]
fn test_field_operations() {
    let a = MyField::from(7u64);
    let b = MyField::from(5u64);

    let sum = a + b;
    let product = a * b;
    let inverse_a = a.inverse().unwrap(); // Compute a⁻¹ mod p

    assert_eq!(sum, MyField::from(12u64), "Addition failed");
    assert_eq!(product, MyField::from(35u64), "Multiplication failed");
    assert_eq!(inverse_a * a, MyField::from(1u64), "Inverse computation failed");
}

#[test]
fn test_field_inversion() {
    for _ in 0..100 {
        let t = MyField::rand(&mut test_rng());
        let inverse_t = t.inverse().unwrap();

        assert_eq!(inverse_t * t, MyField::from(1u64), "Inverse computation failed");
    }
}

#[test]
fn test_field_division() {
    for _ in 0..100 {
        let t = MyField::rand(&mut test_rng());
        let inverse_t = MyField::from(1u64) / t; 

        assert_eq!(inverse_t, t.inverse().unwrap(), "Division and inverse are different"); 
        assert_eq!(inverse_t * t, MyField::from(1u64), "Inverse computation failed");
    }
}
