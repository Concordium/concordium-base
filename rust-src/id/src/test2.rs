 use crate::types::*;

use sha2::{Digest, Sha512};

use curve_arithmetic::{Curve, Pairing};
use secret_sharing::secret_sharing::*;
use dodis_yampolskiy_prf::secret as prf;
use eddsa_ed25519::dlog_ed25519 as eddsa_dlog;
use elgamal::{cipher::Cipher, secret::SecretKey as DecryptionKey, public::PublicKey as EncryptionKey, message::Message as ElgamalMessage};
use pairing::Field;
use pedersen_scheme::{
    commitment::Commitment,
    randomness::Randomness,
    key::{CommitmentKey, CommitmentKey as PedersenKey},
    value as pedersen,
    value::Value,
};
//use ps_sig;
use rand::*;
use rand::thread_rng;
use sigma_protocols::{com_enc_eq, com_eq, com_eq_different_groups, com_eq_sig, com_mult};
use secret_sharing::{share};
use curve_arithmetic::bls12_381_instance::*;
use pairing::bls12_381::G1;

fn generate_ar_info<C: Curve> (n: usize) -> Vec<(DecryptionKey<C>, ArInfo<C>)>{
    let mut v : Vec<(DecryptionKey<C>,ArInfo<C>)> = Vec::with_capacity(n);
    let mut csprng = thread_rng();
    for i in 0..n{
        let ar_name = csprng.gen_ascii_chars().take(30).collect();
        let sk = DecryptionKey::generate(&mut csprng);
        let pk = EncryptionKey::from(&sk);
        v.push((sk, ArInfo{
            ar_name: ar_name,
            ar_public_key : pk, 
            ar_elgamal_generator : C::one_point(),
        }));
    }
    v
}
#[test]
pub fn test(){
    let mut csprng = thread_rng();
    let prf_key = prf::SecretKey::<G1>::generate(&mut csprng);
    let ar_info = generate_ar_info::<G1>(8);
    let mut ar_parameters: Vec<ArInfo<G1>> = Vec::with_capacity(8);
    let mut ar_dec_keys = Vec::with_capacity(8);
    for (sk, x) in ar_info.iter(){
        //assert!(i<8);
        ar_parameters.push(x.clone()); 
        ar_dec_keys.push(sk);
    }
    let ck = PedersenKey::<G1>::generate(&mut csprng);
    let v = compute_prf_key_data(&prf_key, &(ar_parameters, 5), &ck);
    for i in 0..8{
        let message = ar_dec_keys[i].decrypt(&v[i].encrypted_share);
        assert_eq!(<G1 as Curve>::one_point().mul_by_scalar(&v[i].share), message.0);
    }
    let sufficient_sample = sample(&mut csprng, &v, 5);
    let mut good_shares: Vec<(u64, <G1 as Curve>::Scalar)> = vec![];
    for sad in sufficient_sample { 
        good_shares.push((sad.share_number, sad.share.clone()));
    }
    assert_eq!(prf_key.0, reveal::<G1>(good_shares.iter().map(|x| x).collect()));

    let insufficient_sample = sample(&mut csprng, &v, 4);
    let mut bad_shares: Vec<(u64, <G1 as Curve>::Scalar)> = vec![];
    for sad in insufficient_sample {
          bad_shares.push((sad.share_number, sad.share.clone()));
      }
    assert_ne!(prf_key.0, reveal::<G1>(bad_shares.iter().map(|x| x).collect()));

    for item in v.iter(){
        assert!(ck.open(&Value(item.share), &item.randomness_cmm_to_share, &item.cmm_to_share));
    }

}

pub struct SingleArData<C:Curve>{
      ar_name: String,
      share: C::Scalar,
      share_number: u64,
      encrypted_share: Cipher<C>,
      encryption_randomness: C::Scalar,
      cmm_to_share: Commitment<C>,
      randomness_cmm_to_share: Randomness<C>
  }
  #[inline]
fn compute_prf_key_data<C:Curve> (prf_key: &prf::SecretKey<C>, ar_parameters: &(Vec<ArInfo<C>>, u64), commitment_key: &PedersenKey<C>)-> Vec<SingleArData<C>>{
      let n = ar_parameters.0.len() as u64;
      let t = ar_parameters.1;
      let mut csprng = thread_rng();
      let prf_key_scalar = prf_key.0;
      let (cmm_prf, cmm_prf_rand) = commitment_key.commit(&Value(prf_key_scalar), &mut csprng);
      let sharing_data = share::<C, ThreadRng>(&prf_key_scalar, n, t, &mut csprng);
      let mut cmm_sharing_coefficients:Vec<(u64, Commitment<C>)> = Vec::with_capacity(t as usize);
      cmm_sharing_coefficients.push((0, cmm_prf));
      let mut cmm_coeff_randomness: Vec<(u64, Randomness<C>)> = Vec::with_capacity(t as usize);
      cmm_coeff_randomness.push((0, cmm_prf_rand));
      for i in 1..(t as usize){
          let (cmm, rnd) = commitment_key.commit(&Value(sharing_data.coefficients[i as usize-1].1), &mut csprng);
          cmm_sharing_coefficients.push((i as u64, cmm));
          cmm_coeff_randomness.push((i as u64, rnd));
      }
      let mut ar_prf_data :Vec<SingleArData<C>> = Vec::with_capacity(n as usize);
      for i in 1..n+1 {
          let ar = &ar_parameters.0[(i as usize)-1];
          let pk = ar.ar_public_key;
          let share = sharing_data.shares[(i as usize)-1].1;
          assert_eq!(i as u64, sharing_data.shares[(i as usize)-1].0);
          let (cipher, rnd2) = pk.encrypt_exponent_rand(&mut csprng, &share);
          let (cmm, rnd) = commitment_to_share(i as u64, &cmm_sharing_coefficients, &cmm_coeff_randomness);
          let ar_data =
              SingleArData{
              ar_name: ar.ar_name.clone(),
              share: share,
              share_number: i as u64,
              encrypted_share: cipher,
              encryption_randomness: rnd2,
              cmm_to_share: cmm,
              randomness_cmm_to_share: rnd,
          };
          ar_prf_data.push(ar_data)
      }
      ar_prf_data

}

#[inline(always)]
fn commitment_to_share<C:Curve>(share_number: u64, coeff_commitments: &Vec<(u64,Commitment<C>)>, coeff_randomness: &Vec<(u64,Randomness<C>)>)
   -> (Commitment<C>,Randomness<C>){
      let deg = coeff_commitments.len()-1;
      let mut cmm_share_point : C = (coeff_commitments[0].1).0;
      let mut cmm_share_randomness_scalar : C::Scalar = (coeff_randomness[0].1).0;
      for i in 1..(deg+1) {
          let j_pow_i: C::Scalar = C::scalar_from_u64(share_number).unwrap().pow([i as u64]);
          let (s, Commitment(cmm_point)) = coeff_commitments[i]; 
          assert_eq!(s as usize, i);
          let a = cmm_point.mul_by_scalar(&j_pow_i);
          cmm_share_point = cmm_share_point.plus_point(&a);
          //let mut r = C::scalar_from_u64(coeff_randomness[i].0).unwrap();
          let mut r = (coeff_randomness[i].1).0;
          r.mul_assign(&j_pow_i);
          cmm_share_randomness_scalar.add_assign(&r);
      }
      let cmm = Commitment(cmm_share_point);
      let rnd = Randomness(cmm_share_randomness_scalar);
      (cmm,rnd)
}
