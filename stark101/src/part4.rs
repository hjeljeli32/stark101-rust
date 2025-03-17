use crate::{channel::Channel, finite_fields::MyField, fri::decommit_on_query};
use rs_merkle::{algorithms::Sha256, MerkleTree};

pub fn run_part4(
    f_eval: Vec<MyField>,
    f_merkle: MerkleTree<Sha256>,
    fri_layers: Vec<Vec<MyField>>,
    fri_merkles: Vec<MerkleTree<Sha256>>,
    channel: &mut Channel,
) {
    println!("Executing part 4...");

    // Decommit on a Set of Queries
    // Prover gets a set of random queries from the channel, i.e., indices between 0 to 8191, and decommits on each query.
    for _ in 0..3 {
        let id = channel.receive_random_int(0, 8191 - 16);
        decommit_on_query(
            id.try_into().unwrap(),
            &f_eval,
            &f_merkle,
            &fri_layers,
            &fri_merkles,
            channel,
        );
    }
}
