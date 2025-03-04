use hex::encode;
use stark101::channel::*;

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
        "proof must be empty vector"
    );
}
