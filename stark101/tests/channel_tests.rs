use ark_ff::{BigInteger, PrimeField};
use hex::encode;
use stark101::{channel::*, finite_fields::MyField};

#[test]
fn test_new_channel() {
    let channel = Channel::new();
    assert_eq!(
        encode(channel.state),
        "0000000000000000000000000000000000000000000000000000000000000000",
        "state must be composed of 0 bytes"
    );
    assert_eq!(channel.proof, vec![], "proof must be empty vector");
}

#[test]
fn test_send() {
    let mut channel = Channel::new();
    let data = [01u8; 32];
    channel.send(data);
    assert_eq!(
        encode(channel.state),
        "5c85955f709283ecce2b74f1b1552918819f390911816e7bb466805a38ab87f3",
        "state is wrong"
    );
    assert_eq!(
        channel.proof,
        vec![Member::new(Type::Send, data.to_vec())],
        "proof is wrong"
    );
}

#[test]
fn test_receive_random_field_elements() {
    let mut channel = Channel::new();
    // we first send some data otherwise if we receive directly random field element it will be equal to 0
    let data = [01u8; 32];
    channel.send(data);
    // we receive a first random field element
    let _ = channel.receive_random_field_element();
    assert_eq!(
        encode(channel.state),
        "705ede9d42476fc3e5a978b042ce790a193678f46d19f47ec4ab46539c47b76d",
        "state is wrong"
    );
    assert_eq!(channel.proof.len(), 2, "proof should contain 2 members");
    assert_eq!(
        channel.proof[1],
        Member::new(
            Type::Receive,
            MyField::from(2014382809_u64)
                .into_bigint()
                .to_bytes_le()
                .to_vec()
        ),
        "first received field element is wrong"
    );
    // we receive a second random field element
    let _ = channel.receive_random_field_element();
    assert_eq!(
        encode(channel.state),
        "f6bca4ad35bf0e47f352f618eebbb6beb4d5398706ce39156e8f4c9fd8f50a46",
        "state is wrong"
    );
    assert_eq!(channel.proof.len(), 3, "proof should contain 3 members");
    assert_eq!(
        channel.proof[2],
        Member::new(
            Type::Receive,
            MyField::from(2889731371_u64)
                .into_bigint()
                .to_bytes_le()
                .to_vec()
        ),
        "second received field element is wrong"
    );
}
