use crate::common::{finite_fields::MyField, utils::concat_slices};
use ark_ff::{BigInteger, PrimeField};
use hex::{decode, encode};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use rs_merkle::{algorithms::Sha256, Hasher};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Send,
    Receive,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Member {
    pub member_type: Type,
    #[serde(serialize_with = "serialize_hex_array")]
    #[serde(deserialize_with = "deserialize_hex_array")]
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

fn serialize_hex_array<S>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let compact = encode(data); // Get hex-encoded string
    serializer.serialize_str(&compact)
}

fn deserialize_hex_array<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_string: String = String::deserialize(deserializer)?; // Deserialize as a regular string
    decode(&hex_string).map_err(serde::de::Error::custom) // Decode the hex string to Vec<u8>
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

    pub fn send(&mut self, data: &Vec<u8>) {
        self.state = Sha256::hash(&concat_slices(&self.state, &data.as_slice()).as_slice());
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

    pub fn receive_random_int(&mut self, min: u64, max: u64) -> u64 {
        let random_int = (min + BigUint::from_bytes_be(&self.state) % (max - min + 1))
            .to_u64()
            .unwrap();
        self.state = Sha256::hash(&self.state);
        self.proof.push(Member {
            member_type: Type::Receive,
            data: random_int.to_le_bytes().to_vec(),
        });
        random_int
    }
}

pub fn parse_sent_root(member: &Member) -> [u8; 32] {
    assert_eq!(member.member_type, Type::Send, "Type must be Send");
    let root: [u8; 32] = match member.data.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Data must have exactly 32 bytes"),
    };

    root
}

pub fn parse_received_field_element(member: &Member) -> MyField {
    assert_eq!(member.member_type, Type::Receive, "Type must be Receive");
    let bytes: [u8; 8] = match member.data.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Data must have exactly 8 bytes"),
    };

    MyField::from(u64::from_le_bytes(bytes))
}
