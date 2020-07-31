use bulletproofs::range_proof::{prove_given_scalars as bulletprove, Generators, RangeProof};
use curve_arithmetic::{Curve, Value};
use elgamal::{
    cipher::{Cipher, Randomness as ElgamalRandomness},
    public::PublicKey,
};
use id::sigma_protocols::{com_eq::*, common::*};
use merlin::Transcript;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness as PedersenRandomness};
use random_oracle::*;

// First attempt implementing protocol genEncExpInfo documented in the
// Cryptoprim Bluepaper
#[allow(clippy::many_single_char_names)]
#[allow(dead_code)]
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
fn enc_exp<C: Curve, R: rand::Rng>(
    ro: RandomOracle,
    transcript: &mut Transcript,
    csprng: &mut R,
    cmm_key: &CommitmentKey<C>,
    pk: &PublicKey<C>,
    cipher_randomness: &[(Cipher<C>, ElgamalRandomness<C>)],
    value: &[Value<C>],
    generators: &Generators<C>,
    s: u8,
) -> Option<(
    ReplicateAdapter<ComEq<C, C>>,
    SigmaProof<ReplicateWitness<Witness<C>>>,
    RangeProof<C>,
)> {
    let (g, h) = (cmm_key.0, cmm_key.1);
    let pk_eg = pk.key;
    // let sigma_proofs = Vec::with_capacity(cipher.len());
    let mut sigma_protocols = Vec::with_capacity(value.len());
    let mut sigma_secrets = Vec::with_capacity(value.len());
    let xs: Vec<C::Scalar> = value.iter().map(|x| *x.as_ref()).collect();
    let rs: Vec<C::Scalar> = cipher_randomness.iter().map(|x| *(x.1.as_ref())).collect();
    for i in 0..value.len() {
        let x = xs[i];
        let r = rs[i];
        // let commitment =
        // Commitment(h.mul_by_scalar(&x).plus_point(&pk_eg.mul_by_scalar(&r)));
        let commitment = Commitment((cipher_randomness[i].0).1);
        let y = g.mul_by_scalar(&r);
        let cmm_key_comeq = CommitmentKey(pk_eg, h);
        let comeq = ComEq {
            commitment,
            y,
            cmm_key: cmm_key_comeq,
            g,
        };
        let secret_r = PedersenRandomness::<C>::new(x);
        let secret_a = Value::new(r);
        let comeq_secret = ComEqSecret {
            r: secret_r,
            a: secret_a,
        };
        sigma_protocols.push(comeq);
        sigma_secrets.push(comeq_secret);
        // sigma_proofs.push(sigma_proof);
        // let sigma_proof = prove(ro, &comeq, comeq_secret, csprng);
    }
    let sigma_protocol = ReplicateAdapter {
        protocols: sigma_protocols,
    };
    let sigma_proof = prove(ro, &sigma_protocol, sigma_secrets, csprng);
    let cmm_key_bulletproof = CommitmentKey(h, pk_eg);
    let bulletproof_randomness: Vec<PedersenRandomness<C>> = rs
        .iter()
        .map(|&x| PedersenRandomness::<C>::new(x))
        .collect();
    let bulletproof = bulletprove(
        transcript,
        csprng,
        s,
        value.len() as u8,
        &xs,
        generators,
        &cmm_key_bulletproof,
        &bulletproof_randomness,
    );
    match sigma_proof {
        Some(proof1) => match bulletproof {
            Some(proof2) => Some((sigma_protocol, proof1, proof2)),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::{Fr, G1};
    // use rand::{rngs::ThreadRng, Rng};
    use bulletproofs::range_proof::verify_efficient;
    use elgamal::{secret::SecretKey, value_to_chunks};
    use ff::PrimeField;
    use rand::*;

    type SomeCurve = G1;
    // Copied from common.rs in sigma_protocols since apparently it is not available
    pub fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
        // length of the challenge
        let l = csprng.gen_range(0, 1000);
        let mut challenge_prefix = vec![0; l];
        for v in challenge_prefix.iter_mut() {
            *v = csprng.gen();
        }
        challenge_prefix
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_enc_exp() {
        let mut csprng = thread_rng();
        let sk: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
        let pk = PublicKey::from(&sk);
        let x = Fr::from_str(
            "52435875175126190479447740508185965837690552500527637822603658699938581184512",
        )
        .unwrap();
        let xs = value_to_chunks::<G1>(&x, 4);
        let m = xs.len();
        let n = 32;
        let nm = n * m;
        // println!("{:?}", xs);

        let mut G_H = Vec::with_capacity(nm);

        for _i in 0..(nm) {
            let g = SomeCurve::generate(&mut csprng);
            let h = SomeCurve::generate(&mut csprng);
            G_H.push((g, h));
        }
        let gens = Generators { G_H };
        let g = pk.generator;
        let pk_eg = pk.key;
        let generator = SomeCurve::generate(&mut csprng);
        let enc_randomness =
            pk.encrypt_exponent_vec_rand_given_generator(&mut csprng, &xs.as_slice(), &generator);
        let mut commitments = Vec::with_capacity(enc_randomness.len());
        for i in 0..enc_randomness.len() {
            commitments.push(Commitment((enc_randomness[i].0).1));
        }
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        let mut transcript = Transcript::new(&[]);
        let cmm_key = CommitmentKey(g, generator);
        let cmm_key_bulletproof = CommitmentKey(generator, pk_eg);
        let (sigma_protocol, sigma_proof, bulletproof) = enc_exp(
            ro.split(),
            &mut transcript,
            &mut csprng,
            &cmm_key,
            &pk,
            &enc_randomness,
            &xs,
            &gens,
            n as u8,
        )
        .unwrap();

        assert!(verify(ro, &sigma_protocol, &sigma_proof));

        let mut transcript = Transcript::new(&[]);

        assert!(verify_efficient(
            &mut transcript,
            n as u8,
            &commitments,
            &bulletproof,
            &gens,
            &cmm_key_bulletproof
        )
        .is_ok());
    }
}
