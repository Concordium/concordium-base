
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

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;
    use rand::thread_rng;

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
}