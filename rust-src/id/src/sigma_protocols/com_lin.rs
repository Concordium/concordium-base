
use crate::sigma_protocols::common::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{Curve};
use ff::Field;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use random_oracle::{Challenge, RandomOracle};

pub struct ComMultSecret<T: Curve> {

}

pub struct ComMult<C: Curve> {
    pub us:    Vec<C::Scalar>,
    pub cmms:    Vec<Commitment<C>>,
    pub cmm_key: CommitmentKey<C>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Witness<C: Curve> {
    zs: Vec<C::Scalar>,
    ss: Vec<C::Scalar>,
    s: C::Scalar
}

impl<C: Curve> SigmaProtocol for ComMult<C>{
    type CommitMessage = (Vec<Commitment<C>>, Commitment<C>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = (Vec<Randomness<C>>, Vec<Randomness<C>>, Randomness<C>);
    type ProverWitness = Witness<C>;
    type SecretData = ComMultSecret<C>;

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {

        let cm : Self::CommitMessage;
        let ps : Self::ProverState;
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
    
        Some((cm, ps))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {

    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {

    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(ComMult<C>, Self::SecretData, &mut R) -> (),
    ){
        ()
    }
} 
