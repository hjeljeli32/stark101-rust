mod part1;
mod part2;

fn main() {
    let (a, g, G, h, H, f, f_eval, f_merkle, channel) = part1::run_part1();
    println!("proof: {:?}", channel.proof);
    part2::run_part2(a, g, G, h, H, f, f_eval, f_merkle, channel);
}
