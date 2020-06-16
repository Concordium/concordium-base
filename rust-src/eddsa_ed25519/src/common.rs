#[cfg(test)]
pub fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
    // length of the challenge
    let l = csprng.gen_range(0, 1000);
    let mut challenge_prefix = vec![0; l];
    for v in challenge_prefix.iter_mut() {
        *v = csprng.gen();
    }
    challenge_prefix
}
