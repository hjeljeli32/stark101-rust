mod part1;
mod part2;

fn main() {
    let (g, eval_domain, f, mut channel) = part1::run_part1();
    println!("proof: {:?}", channel.proof);
    let (CP, CP_eval, CP_merkle) = part2::run_part2(g, eval_domain, f, &mut channel);
    println!("proof: {:?}", channel.proof);
}
