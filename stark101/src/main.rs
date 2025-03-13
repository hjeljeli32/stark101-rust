mod part1;
mod part2;
mod part3;

fn main() {
    let (g, eval_domain, f, mut channel) = part1::run_part1();
    println!("proof: {:?}", channel.proof);
    let (CP, CP_eval, CP_merkle) = part2::run_part2(g, &eval_domain, f, &mut channel);
    println!("proof: {:?}", channel.proof);
    let (fri_polys, fri_domains, fri_layers, fri_merkles) =
        part3::run_part3(eval_domain, CP, CP_eval, CP_merkle, &mut channel);
    println!("proof: {:?}", channel.proof);
}
