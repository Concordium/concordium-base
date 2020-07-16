
use crate::sigma_protocols::common::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use random_oracle::{Challenge, RandomOracle};

pub struct ComLinSecret<C: Curve> {
    xs: Vec<Value<C>>,
    rs: Vec<Randomness<C>>,
    r: Randomness<C>
}

pub struct ComLin<C: Curve> {
    pub us:    Vec<C::Scalar>,
    pub cmms:    Vec<Commitment<C>>,
    pub cmm:    Commitment<C>,
    pub cmm_key: CommitmentKey<C>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Witness<C: Curve> {
    zs: Vec<C::Scalar>,
    ss: Vec<C::Scalar>,
    s: C::Scalar
}

impl<C: Curve> SigmaProtocol for ComLin<C>{
    type CommitMessage = (Vec<Commitment<C>>, Commitment<C>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = (Vec<Value<C>>, Vec<Randomness<C>>, Randomness<C>);
    type ProverWitness = Witness<C>;
    type SecretData = ComLinSecret<C>;

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        ro.extend_from(self.us.iter()).extend_from(self.cmms.iter()).append(&self.cmm).append(&self.cmm_key)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let n = self.cmms.len();
        let mut ais = Vec::with_capacity(n);
        let mut alphas : Vec<Value<C>> = Vec::with_capacity(n);
        let mut r_i_tildes = Vec::with_capacity(n);

        
        for _ in 0..n {
            let alpha = Value::generate_non_zero(csprng);
            let (a_i, r_i_tilde) = self.cmm_key.commit(&alpha, csprng);
            ais.push(a_i);
            alphas.push(alpha);
            r_i_tildes.push(r_i_tilde);
        }
        
        let mut sum_ui_alphai = C::Scalar::zero();
        for i in 0..alphas.len() {
            let mut ualpha = self.us[i];
            ualpha.mul_assign(&alphas[i]);
            sum_ui_alphai.add_assign(&ualpha);
        }
        let sum_ui_alphai : Value<C> = Value::new(sum_ui_alphai);
        let (a, r_tilde) = self.cmm_key.commit(&sum_ui_alphai, csprng);

        let cm = (ais, a);
        let ps = (alphas, r_i_tildes, r_tilde);
    
        Some((cm, ps))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let (alphas, r_i_tildes, r_tilde) = state;
        let n = alphas.len();
        let mut zs = Vec::with_capacity(n);
        let mut ss = Vec::with_capacity(n);
        let c = *challenge;
        for i in 0..n {
            let mut zi = c;
            zi.mul_assign(&secret.xs[i]);
            zi.negate();
            zi.add_assign(&alphas[i]);
            zs.push(zi);

            let mut si = c;
            si.mul_assign(&secret.rs[i]);
            si.negate();
            si.add_assign(&r_i_tildes[i]);
            ss.push(si);
        }
        let mut s = c;
        s.mul_assign(&secret.r);
        s.negate();
        s.add_assign(&r_tilde);
        let witness = Witness{zs, ss, s};
        Some(witness)
    }
    
    #[allow(non_snake_case)]
    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let zs = &witness.zs;
        let ss = &witness.ss;
        let s = witness.s;
        let c = *challenge;
        let n = zs.len();       
        let mut ais = Vec::with_capacity(n);
        let mut sum = C::Scalar::zero();
        let g = self.cmm_key.0;
        let h = self.cmm_key.1;
        for i in 0..n {
            let Ci = self.cmms[i].0;
            let ai = Commitment(multiexp(&[g, h, Ci], &[zs[i], ss[i], c]));
            ais.push(ai);
            let mut uizi = self.us[i];
            uizi.mul_assign(&zs[i]);
            sum.add_assign(&uizi);
        }
        let a = Commitment(multiexp(&[g, h, self.cmm.0], &[sum, s, c]));
        let cm = (ais, a);
        Some(cm)
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R) -> (),
    ){
        let n = _data_size;
        let cmm_key = CommitmentKey::generate(csprng);
        let mut xs = Vec::with_capacity(n);
        let mut rs = Vec::with_capacity(n);
        let mut us = Vec::with_capacity(n);
        let mut cmms = Vec::with_capacity(n);
        let r = Randomness::<C>::generate(csprng);
        let mut sum = C::Scalar::zero();
        for _ in 0..n{
            let xi = Value::<C>::generate(csprng); 
            let ri = Randomness::<C>::generate(csprng); 
            let ui = C::generate_scalar(csprng);
            let mut uixi = ui;
            uixi.mul_assign(&xi);
            sum.add_assign(&uixi);
            cmms.push(cmm_key.hide(&xi, &ri));
            xs.push(xi);
            rs.push(ri);
            us.push(ui);
        }
        let cmm = cmm_key.hide_worker(&sum, &r);
        let com_lin = ComLin{us, cmms, cmm, cmm_key};
        let secret = ComLinSecret{xs, rs, r};

        f(com_lin, secret, csprng)
    }
} 

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use pairing::bls12_381::{Fr, G1};
    // use pairing::bls12_381::G1;
    use rand::thread_rng;
    use merlin::Transcript;

    #[test]
    pub fn test_com_lin_correctness() {
        let mut csprng = thread_rng();
        for _ in 0..10 {
            ComLin::<G1>::with_valid_data(10, &mut csprng, |com_lin, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(ro.split(), &com_lin, secret, csprng).expect("Proving should succeed.");
                // println!("{}", verify(ro, &com_lin, &proof));
                assert!(verify(ro, &com_lin, &proof));
            })
        }
    }

    #[test]
    pub fn test_com_lin_soundness() {
        let mut csprng = thread_rng();
        for _ in 0..2 {
            let n = 6;
            ComLin::<G1>::with_valid_data(n, &mut csprng, |com_lin, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let proof =
                    prove(ro.split(), &com_lin, secret, csprng).expect("Proving should succeed.");
                assert!(verify(ro.split(), &com_lin, &proof));

                // Construct invalid parameters
                let wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));

                // Verify failure for invalid parameters
                assert!(!verify(wrong_ro, &com_lin, &proof));
                let mut wrong_cmm = com_lin;
                for i in 0..n {
                    let tmp = wrong_cmm.cmms[i];
                    let v = pedersen_scheme::Value::<G1>::generate(csprng);
                    wrong_cmm.cmms[i] = wrong_cmm.cmm_key.commit(&v, csprng).0;
                    assert!(!verify(ro.split(), &wrong_cmm, &proof));
                    wrong_cmm.cmms[i] = tmp;
                }

                {
                    let tmp = wrong_cmm.cmm;
                    let v = pedersen_scheme::Value::<G1>::generate(csprng);
                    wrong_cmm.cmm = wrong_cmm.cmm_key.commit(&v, csprng).0;
                    assert!(!verify(ro.split(), &wrong_cmm, &proof));
                    wrong_cmm.cmm = tmp;
                }

                wrong_cmm.cmm_key = pedersen_scheme::CommitmentKey::generate(csprng);

                assert!(!verify(ro.split(), &wrong_cmm, &proof))
            })
        }
    }
    
    #[test]
    pub fn test_linear_relation_of_chunks() {
        let rng = &mut thread_rng();
        let number = Fr::from_str("2738").unwrap();
        let x1 = Fr::from_str("2").unwrap();
        let x2 = Fr::from_str("11").unwrap();
        let x3 = Fr::from_str("10").unwrap();
        let u1 = Fr::from_str("1").unwrap();
        let u2 = Fr::from_str("16").unwrap();
        let u3 = Fr::from_str("256").unwrap();
        let mut term1 = x1;
        term1.mul_assign(&u1);
        let mut term2 = x2;
        term2.mul_assign(&u2);
        let mut term3 = x3;
        term3.mul_assign(&u3);
        let mut sum = term1;
        sum.add_assign(&term2);
        sum.add_assign(&term3);
        println!("{:?}", sum == number);
        let x1 = Value::<G1>::new(x1);
        let x2 = Value::<G1>::new(x2);
        let x3 = Value::<G1>::new(x3);
        let dummy = Value::<G1>::new(Fr::zero());
        let sum = Value::<G1>::new(sum);
        
        let g = G1::generate(rng);
        let h = G1::generate(rng);
        let r = Randomness::<G1>::generate(rng);
        let r1 = Randomness::<G1>::generate(rng);
        let r2 = Randomness::<G1>::generate(rng);
        let r3 = Randomness::<G1>::generate(rng);
        let r_dummy = Randomness::<G1>::generate(rng);
        let cmm_key = CommitmentKey(g,h);
        let C = cmm_key.hide(&sum, &r);
        let C1 = cmm_key.hide(&x1, &r1);
        let C2 = cmm_key.hide(&x2, &r2);
        let C3 = cmm_key.hide(&x3, &r3);
        let com_dummy = cmm_key.hide(&dummy, &r_dummy);
        let cmms = vec![C1, C2, C3];
        let cmms_dummy = vec![C1, C2, C3, com_dummy];
        let xs = vec![x1, x2, x3];
        let us = vec![u1, u2, u3];
        let rs = vec![r1, r2, r3];
        let mut rs_dummy = rs.clone();
        rs_dummy.push(r_dummy);
        let cmm = C;
        let com_lin = ComLin{us, cmms, cmm, cmm_key};
        let secret = ComLinSecret{xs, rs, r};
        let challenge_prefix = generate_challenge_prefix(rng);
        let ro = RandomOracle::domain(&challenge_prefix);
        let proof = prove(ro.split(), &com_lin, secret, rng).expect("Proving should succeed.");
        // println!("{}", verify(ro, &com_lin, &proof));
        assert!(verify(ro, &com_lin, &proof));
        let mut transcript = Transcript::new(&[]);
        let n = 4;
        let m = 4;
        let nm = 16;
        let mut G_H = Vec::with_capacity(nm);
        // xs.push(dummy);
        let v_vec = vec![2,11,10,0];
        for _i in 0..(nm) {
            let g = G1::generate(rng);
            let h = G1::generate(rng);
            G_H.push((g, h));
        }
        let gens = bulletproofs::range_proof::Generators{G_H};
        let proof = bulletproofs::range_proof::prove(
            &mut transcript,
            rng,
            n,
            m,
            &v_vec,
            &gens,
            &cmm_key,
            &rs_dummy,
        );
        let mut transcript = Transcript::new(&[]);
        assert!(bulletproofs::range_proof::verify_efficient(&mut transcript, n, &cmms_dummy, &proof.unwrap(), &gens, &cmm_key).is_ok());
    }
}