use bulletproofs::range_proof::{prove_given_scalars as bulletprove, RangeProof, Generators};
use curve_arithmetic::{Curve, Value};
use elgamal::{
    cipher::{Cipher, Randomness as ElgamalRandomness},
    public::PublicKey,
    secret::SecretKey,
};
use id::sigma_protocols::{com_eq::*, common::*};
use pedersen_scheme::{Commitment, CommitmentKey, Randomness as PedersenRandomness};
use random_oracle::*;
use merlin::Transcript;

fn enc_exp<C: Curve, R: rand::Rng>(
    ro: RandomOracle,
    transcript: &mut Transcript,
    csprng: &mut R,
    cmm_key: &CommitmentKey<C>,
    pk: &PublicKey<C>,
    cipher: &[Cipher<C>],
    value: &[Value<C>],
    randomness: &[ElgamalRandomness<C>],
    generators: &Generators<C>,
    s: u8,
) -> Option<(SigmaProof<ReplicateWitness<Witness<C>>>, RangeProof<C>)> {
    let (g, h) = (cmm_key.0, cmm_key.1);
    let pk_eg = pk.key;
    // let sigma_proofs = Vec::with_capacity(cipher.len());
    let mut sigma_protocols = Vec::with_capacity(cipher.len());
    let mut sigma_secrets = Vec::with_capacity(cipher.len());
    let xs : Vec<C::Scalar>= value.iter().map(|x| *x.as_ref()).collect();
    let rs : Vec<C::Scalar>= randomness.iter().map(|x| *x.as_ref()).collect();
    for i in 0..cipher.len(){
        let x = xs[i];
        let r = rs[i];
        let commitment = Commitment(h.mul_by_scalar(&x).plus_point(&pk_eg.mul_by_scalar(&r)));
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
    let sigma_protocol = ReplicateAdapter{protocols: sigma_protocols};
    let sigma_proof = prove(ro, &sigma_protocol, sigma_secrets, csprng);
    let cmm_key_bulletproof = CommitmentKey(h, pk_eg);
    let bulletproof_randomness : Vec<PedersenRandomness<C>> = rs.iter().map(|&x| PedersenRandomness::<C>::new(x)).collect();
    let bulletproof = bulletprove(transcript, csprng, s, cipher.len() as u8, &xs, generators, &cmm_key_bulletproof, &bulletproof_randomness);
    match sigma_proof {
        Some(proof1) => match bulletproof {
            Some(proof2) => return Some((proof1, proof2)),
            _ => return None
        },
        _ => return None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::{G1, Fr};

    fn test_enc_exp(){
        ()
    }
}