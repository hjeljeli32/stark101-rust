use ark_ff::{fields::Field, AdditiveGroup};
use ark_std::{test_rng, UniformRand};
use stark101::common::finite_fields::MyField;

#[test]
fn test_field_modulus() {
    let modulus = MyField::from(3221225473u64);
    let zero = MyField::ZERO;

    assert_eq!(modulus, zero, "modulus should be 0");
}

#[test]
fn test_field_identity_elements() {
    let zero = MyField::ZERO;
    let one = MyField::ONE;

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
    assert_eq!(inverse_a * a, MyField::ONE, "Inverse computation failed");
}

#[test]
fn test_field_inversion() {
    let mut rng = test_rng();
    for _ in 0..100 {
        let t = MyField::rand(&mut rng);
        let inverse_t = t.inverse().unwrap();

        assert_eq!(inverse_t * t, MyField::ONE, "Inverse computation failed");
    }
}

#[test]
fn test_field_division() {
    let mut rng = test_rng();
    for _ in 0..100 {
        let t = MyField::rand(&mut rng);
        let inverse_t = MyField::ONE / t;

        assert_eq!(
            inverse_t,
            t.inverse().unwrap(),
            "Division and inverse are different"
        );
        assert_eq!(inverse_t * t, MyField::ONE, "Inverse computation failed");
    }
}
