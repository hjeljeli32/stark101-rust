mod part1;

fn main() {
    let (a, g, G, h, H, f, f_eval, f_merkle, channel) = part1::run_part1();
    println!("proof: {:?}", channel.proof);
}
