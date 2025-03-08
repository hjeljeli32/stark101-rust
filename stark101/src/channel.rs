use crate::{finite_fields::MyField, utils::concatenate_arrays};
use ark_ff::{BigInteger, PrimeField};
use hex::encode;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use rs_merkle::{algorithms::Sha256, Hasher};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Send,
    Receive,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Member {
    pub member_type: Type,
    pub data: Vec<u8>,
}

impl Member {
    pub fn new(member_type: Type, data: Vec<u8>) -> Self {
        Self { member_type, data }
    }
}

impl fmt::Display for Member {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded_data = encode(&self.data); // Apply encode to data
        write!(f, "{{{:?}:{}}}", self.member_type, encoded_data)
    }
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded_data = encode(&self.data); // Apply encode to data
        write!(f, "{{{:?}:{}}}", self.member_type, encoded_data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    pub state: [u8; 32],
    pub proof: Vec<Member>,
}

impl Channel {
    pub fn new() -> Self {
        Self {
            state: [0u8; 32],
            proof: vec![],
        }
    }

    pub fn send(&mut self, data: [u8; 32]) {
        self.state = Sha256::hash(&concatenate_arrays(&self.state, &data));
        self.proof.push(Member {
            member_type: Type::Send,
            data: data.to_vec(),
        });
    }

    pub fn receive_random_field_element(&mut self) -> MyField {
        let modulus: BigUint = MyField::MODULUS.into();
        let random_number = BigUint::from_bytes_be(&self.state) % modulus;
        let random_field_element = MyField::from(random_number.to_u64().unwrap());
        self.state = Sha256::hash(&self.state);
        self.proof.push(Member {
            member_type: Type::Receive,
            data: random_field_element.into_bigint().to_bytes_le().to_vec(),
        });
        random_field_element
    }
}
