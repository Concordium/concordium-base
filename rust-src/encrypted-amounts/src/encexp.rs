use crate::{dlogaggequal::*, enc_trans::*};
use bulletproofs::range_proof::{prove_given_scalars as bulletprove, Generators, RangeProof};
use curve_arithmetic::{multiexp, Curve, Value};
use elgamal::{
    cipher::{Cipher, Randomness as ElgamalRandomness},
    public::PublicKey,
};
use ff::Field;
use id::sigma_protocols::{
    aggregate_dlog::*,
    com_eq::{Witness as ComEqWitness, *},
    common::*,
    dlog::{Witness as DlogWitness, *},
};
use merlin::Transcript;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness as PedersenRandomness};
use random_oracle::*;

// For testing
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
    SigmaProof<ReplicateWitness<ComEqWitness<C>>>,
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

// First attempt implementing protocol genEncExpInfo documented in the
// Cryptoprim Bluepaper, maybe without bulletproof part.
#[allow(clippy::many_single_char_names)]
#[allow(dead_code)]
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
fn gen_enc_exp_info<C: Curve /* , R: rand::Rng */>(
    // ro: RandomOracle,
    // transcript: &mut Transcript,
    // csprng: &mut R,
    cmm_key: &CommitmentKey<C>,
    pk: &PublicKey<C>,
    cipher: &[Cipher<C>],
    /* generators: &Generators<C>,
     * s: u8, */
) -> Vec<ComEq<C, C>>
// RangeProof<C>>
{
    let (g, h) = (cmm_key.0, cmm_key.1);
    let pk_eg = pk.key;
    // let sigma_proofs = Vec::with_capacity(cipher.len());
    let mut sigma_protocols = Vec::with_capacity(cipher.len());
    for i in 0..cipher.len() {
        // let commitment =
        // Commitment(h.mul_by_scalar(&x).plus_point(&pk_eg.mul_by_scalar(&r)));
        let commitment = Commitment(cipher[i].1);
        // let y = g.mul_by_scalar(&r);
        let y = cipher[i].0;
        let cmm_key_comeq = CommitmentKey(pk_eg, h);
        let comeq = ComEq {
            commitment,
            y,
            cmm_key: cmm_key_comeq,
            g,
        };
        sigma_protocols.push(comeq);
        // sigma_proofs.push(sigma_proof);
        // let sigma_proof = prove(ro, &comeq, comeq_secret, csprng);
    }
    // let sigma_protocol = ReplicateAdapter {
    //     protocols: sigma_protocols,
    // };
    // let cmm_key_bulletproof = CommitmentKey(h, pk_eg);
    // let bulletproof_randomness: Vec<PedersenRandomness<C>> = rs
    //     .iter()
    //     .map(|&x| PedersenRandomness::<C>::new(x))
    //     .collect();
    // let bulletproof = bulletprove(
    //     transcript,
    //     csprng,
    //     s,
    //     value.len() as u8,
    //     &xs,
    //     generators,
    //     &cmm_key_bulletproof,
    //     &bulletproof_randomness,
    // );
    sigma_protocols
}

// Implementation of genEncTransProofInfo in the Cryptoprim Bluepaper
pub fn gen_enc_trans_proof_info<C: Curve>(
    pk_sender: &PublicKey<C>,
    pk_receiver: &PublicKey<C>,
    S: &Cipher<C>,
    A: &[Cipher<C>],
    S_prime: &[Cipher<C>],
    h: &C,
) -> EncTrans<C> {
    // let t = S.len();
    let sigma_1 = Dlog {
        public: pk_sender.key,
        coeff:  pk_sender.generator,
    };
    // let mut elg_dec_protocols = Vec::with_capacity(t);
    // for j in 0..t {
    let (e1, e2) = (S.0, S.1);
    let elg_dec = AggregateDlog {
        public: e2,
        coeff:  vec![e1, *h],
    };
    // elg_dec_protocols.push(elg_dec);
    // }
    let sigma_2 = elg_dec; //_protocols;
    let cmm_key = CommitmentKey(pk_sender.generator, *h);
    let sigma_3_protocols = gen_enc_exp_info(&cmm_key, pk_receiver, A);
    let sigma_4_protocols = gen_enc_exp_info(&cmm_key, pk_sender, S_prime);
    // sigma_3_4_protocols.append(&mut sigma_4_protocols);
    // let sigma_3_4 = ReplicateAdapter {
    //     protocols: sigma_3_4_protocols,
    // };

    // let sigma = AndAdapter {
    //     first: sigma_1,
    //     second: sigma_2
    // };
    // let sigma = AndAdapter {
    //     first: sigma,
    //     second: sigma_3_4
    // };
    EncTrans {
        dlog:    sigma_1,
        elg_dec: sigma_2,
        encexp1: sigma_3_protocols,
        encexp2: sigma_4_protocols,
    }

    // sigma
}

struct DlogEqual<C: Curve> {
    dlog1: Dlog<C>,
    dlog2: Dlog<C>,
}

impl<C: Curve> SigmaProtocol for DlogEqual<C> {
    type CommitMessage = (C, C);
    type ProtocolChallenge = C::Scalar;
    type ProverState = C::Scalar;
    type ProverWitness = DlogWitness<C>;
    type SecretData = DlogSecret<C>;

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        let ro1 = self.dlog1.public(ro);
        self.dlog2.public(ro1)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        // Ideally we want to do the below for the same randomness, but
        // that is not possible for the moment.
        // let (m1, s1) = self.dlog.first.commit_point(csprng)?;
        // let (m2, s2) = self.dlog.second.commit_point(csprng)?;
        // Some(((m1, m2), (s1, s2)))
        let rand_scalar = C::generate_non_zero_scalar(csprng);
        let randomized_point_1 = self.dlog1.coeff.mul_by_scalar(&rand_scalar);
        let randomized_point_2 = self.dlog2.coeff.mul_by_scalar(&rand_scalar);
        let commit = (randomized_point_1, randomized_point_2);
        Some((commit, rand_scalar))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        // let mut witness = *challenge;
        // witness.mul_assign(&secret.secret);
        // witness.add_assign(&state);
        // Some(DlogEqualWitness { witness })
        let w1 = self.dlog1.generate_witness(secret, state, &challenge)?; // The witnesses are the same, so does not matter which one
        Some(w1)
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let p1 = self.dlog1.extract_point(&challenge, &witness)?;
        let p2 = self.dlog2.extract_point(&challenge, &witness)?;
        Some((p1, p2))
    }

    // #[cfg(test)]
    // fn with_valid_data<R: rand::Rng>(
    //     data_size: usize,
    //     csprng: &mut R,
    //     f: impl FnOnce(Self, Self::SecretData, &mut R) -> (),
    // ) {
    //     ()
    // }
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
    use std::rc::Rc;

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
    fn test_gen_eq() {
        let mut csprng = thread_rng();
        let x = Fr::from_str("3").unwrap();
        let x_secret = Value::<G1>::new(x);
        let g1 = G1::generate(&mut csprng);
        let g2 = G1::generate(&mut csprng);
        let mut g1x = g1.mul_by_scalar(&x);
        let mut g2x = g2.mul_by_scalar(&x);
        let dlog1 = Dlog {
            public: g1x,
            coeff:  g1,
        };
        let dlog2 = Dlog {
            public: g2x,
            coeff:  g2,
        };
        let equal = DlogEqual { dlog1, dlog2 };
        let secret = DlogSecret { secret: x_secret };
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        let proof = prove(ro.split(), &equal, secret, &mut csprng).unwrap();
        assert!(verify(ro, &equal, &proof));
    }

    #[test]
    fn test_dlog_agg_eq() {
        let mut csprng = thread_rng();
        let x = Fr::from_str("3").unwrap();
        let x1 = Fr::from_str("5").unwrap();
        let x2 = Fr::from_str("7").unwrap();
        let y1 = Fr::from_str("70").unwrap();
        let y2 = Fr::from_str("75").unwrap();
        let g = G1::generate(&mut csprng);
        let g1 = G1::generate(&mut csprng);
        let h1 = G1::generate(&mut csprng);
        let f1 = G1::generate(&mut csprng);
        let g2 = G1::generate(&mut csprng);
        let h2 = G1::generate(&mut csprng);
        let f2 = G1::generate(&mut csprng);
        let mut gx = g.mul_by_scalar(&x);
        let dlog = Dlog {
            public: gx,
            coeff:  g,
        };
        let g1xh1x1f1y1 = multiexp(&[g1, h1, f1], &[x, x1, y1]);
        let g2xh2x2f2y2 = multiexp(&[g2, h2, f2], &[x, x2, y2]);
        let agg1 = AggregateDlog {
            public: g1xh1x1f1y1,
            coeff:  vec![g1, h1, f1],
        };
        let agg2 = AggregateDlog {
            public: g2xh2x2f2y2,
            coeff:  vec![g2, h2, f2],
        };
        let protocol = DlogAndAggregateDlogsEqual {
            dlog,
            aggregate_dlogs: vec![agg1, agg2],
        };
        let secret = (Rc::new(x), vec![vec![Rc::new(x1), Rc::new(y1)], vec![
            Rc::new(x2),
            Rc::new(y2),
        ]]);
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        let proof = prove(ro.split(), &protocol, secret, &mut csprng).unwrap();
        assert!(verify(ro, &protocol, &proof));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_enc_trans() {
        // Minus bulletproofs
        let mut csprng = thread_rng();
        let sk_sender: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
        let pk_sender = PublicKey::from(&sk_sender);
        let sk_receiver: SecretKey<G1> = SecretKey::generate(&pk_sender.generator, &mut csprng);
        let pk_receiver = PublicKey::from(&sk_receiver);
        let s = Fr::from_str(
            // Amount on account
            "52435875175126190479447740508185965837690552500527637822603658699938581184512",
        )
        .unwrap();
        let a = Fr::from_str(
            // Amount to send
            "22435875175126190479447740508185965837690552500527637822603658699938581184400",
        )
        .unwrap();
        // let a = Fr::from_str(
        //     // Amount to send
        //     "5",
        // )
        // .unwrap();
        let mut s_prime = s;
        s_prime.sub_assign(&a);
        let s_prime_chunks = value_to_chunks::<G1>(&s_prime, 4);
        let a_chunks = value_to_chunks::<G1>(&a, 4);
        println!("a = {:?}\n\n a_chunks = {:?}", a, a_chunks);
        // let s_chunks = value_to_chunks::<G1>(&a, 4);

        // let m = xs.len();
        // let n = 32;
        // let nm = n * m;
        // println!("{:?}", xs);

        // let mut G_H = Vec::with_capacity(nm);

        // for _i in 0..(nm) {
        //     let g = SomeCurve::generate(&mut csprng);
        //     let h = SomeCurve::generate(&mut csprng);
        //     G_H.push((g, h));
        // }
        // let gens = Generators { G_H };
        let g = pk_sender.generator;
        let pk_eg = pk_sender.key;
        let generator = SomeCurve::generate(&mut csprng); // h
        let A_enc_randomness = pk_receiver.encrypt_exponent_vec_rand_given_generator(
            &mut csprng,
            &a_chunks.as_slice(),
            &generator,
        );
        let (A, A_rand): (Vec<_>, Vec<_>) = A_enc_randomness.iter().cloned().unzip();
        let S_prime_enc_randomness = pk_sender.encrypt_exponent_vec_rand_given_generator(
            &mut csprng,
            &s_prime_chunks.as_slice(),
            &generator,
        );
        let (S_prime, S_prime_rand): (Vec<_>, Vec<_>) =
            S_prime_enc_randomness.iter().cloned().unzip();
        let s_value = Value::new(s);
        let S = pk_sender.encrypt_exponent_given_generator(&mut csprng, &s_value, &generator);
        // let (S_prime, S_prime_rand): (Vec<_>, Vec<_>) =
        // S_prime_enc_randomness.iter().cloned().unzip(); let mut commitments =
        // Vec::with_capacity(enc_randomness.len()); for i in 0..enc_randomness.
        // len() {     commitments.push(Commitment((enc_randomness[i].0).1));
        // }
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let ro = RandomOracle::domain(&challenge_prefix);
        // let mut transcript = Transcript::new(&[]);
        let cmm_key = CommitmentKey(g, generator);
        let protocol =
            gen_enc_trans_proof_info(&pk_sender, &pk_receiver, &S, &A, &S_prime, &generator);
        let A_rand_as_value: Vec<Value<_>> =
            A_rand.iter().map(|x| Value::new(*(x.as_ref()))).collect();
        let a_chunks_as_rand: Vec<PedersenRandomness<_>> = a_chunks
            .iter()
            .map(|x| PedersenRandomness::new(*(x.as_ref())))
            .collect();
        let S_prime_rand_as_value: Vec<Value<_>> = S_prime_rand
            .iter()
            .map(|x| Value::new(*(x.as_ref())))
            .collect();
        let s_prime_chunks_as_rand: Vec<PedersenRandomness<_>> = s_prime_chunks
            .iter()
            .map(|x| PedersenRandomness::new(*(x.as_ref())))
            .collect();
        let secret = EncTransSecret {
            dlog_secret:     Rc::new(sk_sender.scalar),
            agg_dlog_secret: vec![vec![Rc::new(s)]], // s is here
            r_a:             a_chunks_as_rand,
            a:               A_rand_as_value,
            r_s:             s_prime_chunks_as_rand,
            s:               S_prime_rand_as_value,
        };
        let proof = prove(ro.split(), &protocol, secret, &mut csprng).unwrap();
        println!("{:?}", verify(ro, &protocol, &proof));
        // let cmm_key_bulletproof = CommitmentKey(generator, pk_eg);
        // let (sigma_protocol, sigma_proof, bulletproof) = enc_exp(
        //     ro.split(),
        //     &mut transcript,
        //     &mut csprng,
        //     &cmm_key,
        //     &pk,
        //     &enc_randomness,
        //     &xs,
        //     &gens,
        //     n as u8,
        // )
        // .unwrap();

        // assert!(verify(ro, &sigma_protocol, &sigma_proof));

        // let mut transcript = Transcript::new(&[]);

        // assert!(verify_efficient(
        //     &mut transcript,
        //     n as u8,
        //     &commitments,
        //     &bulletproof,
        //     &gens,
        //     &cmm_key_bulletproof
        // )
        // .is_ok());
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
