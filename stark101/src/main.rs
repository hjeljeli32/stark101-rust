mod part1;
mod part2;
mod part3;
mod part4;

fn main() {
    let (g, eval_domain, f, f_eval, f_merkle, mut channel) = part1::run_part1();
    assert_eq!(channel.proof.len(), 1, "length of proof must be 1");
    println!("proof: {:?}", channel.proof);
    let (CP, CP_eval, CP_merkle) = part2::run_part2(g, &eval_domain, f, &mut channel);
    assert_eq!(channel.proof.len(), 5, "length of proof must be 5");
    println!("proof: {:?}", channel.proof);
    let (fri_layers, fri_merkles) =
        part3::run_part3(eval_domain, CP, CP_eval, CP_merkle, &mut channel);
    assert_eq!(channel.proof.len(), 26, "length of proof must be 26");
    println!("proof: {:?}", channel.proof);
    part4::run_part4(f_eval, f_merkle, fri_layers, fri_merkles, &mut channel);
    assert_eq!(channel.proof.len(), 170, "length of proof must be 170");
    println!("proof: {:?}", channel.proof);
}
