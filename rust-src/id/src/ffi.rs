use pedersen_scheme::key::CommitmentKey as PedersenKey;
use crate::types::*;
use curve_arithmetic::curve_arithmetic::*;
use pairing::bls12_381::{Bls12,G1};
use std::io::{Cursor, Read};
use libc::*;
use std::slice;
use crate::chain::{CDIVerificationError};
use crate::chain as chain;


use ffi_helpers::*;
use std::slice;
use libc::size_t;
use rand::thread_rng;
use failure::Error;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum AttributeKind {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

impl AttributeKind {
    pub fn size_of(&self) -> usize {
        match self {
            AttributeKind::U8(_) => 1,
            AttributeKind::U16(_) => 2,
            AttributeKind::U32(_) => 4,
            AttributeKind::U64(_) => 8,
        }
    }

    fn to_u64(&self) -> u64 {
        match self {
            AttributeKind::U8(x) => (*x as u64),
            AttributeKind::U16(x) => (*x as u64),
            AttributeKind::U32(x) => (*x as u64),
            AttributeKind::U64(x) => (*x as u64),
        }
    }
}

impl Attribute<<G1 as Curve>::Scalar> for AttributeKind {
    fn to_field_element(&self) -> <G1 as Curve>::Scalar {
        <G1 as Curve>::scalar_from_u64(self.to_u64()).unwrap()
    }

    fn to_bytes(&self) -> Box<[u8]> {
        match self {
            AttributeKind::U8(x) => {
                let mut buff = [0u8; 2];
                buff[0] = 1u8; 
                buff[1..].copy_from_slice(&x.to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U16(x) => {
                let mut buff = [0u8; 3];
                buff[0] = 2u8;
                buff[1..].copy_from_slice(&x.to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U32(x) => {
                let mut buff = [0u8; 5];
                buff[0] = 4u8;
                buff[1..].copy_from_slice(&x.to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U64(x) => {
                let mut buff = [0u8; 9];
                buff[0] = 8u8;
                buff[1..].copy_from_slice(&x.to_be_bytes());
                Box::new(buff)
            }
        }
    }

    fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        //let bytes = cur.get_ref();
        let mut size_buff = [0u8;1];
        cur.read_exact(&mut size_buff);
        match size_buff[0] {
            1 => {
                let mut buf = [0u8; 1];
                cur.read_exact(&mut buf);
                Some(AttributeKind::U8(u8::from_be_bytes(buf)))
            }
            2 => {
                let mut buf = [0u8; 2];
                cur.read_exact(&mut buf);
                Some(AttributeKind::U16(u16::from_be_bytes(buf)))
            }
            4 => {
                let mut buf = [0u8; 4];
                cur.read_exact(&mut buf);
                Some(AttributeKind::U32(u32::from_be_bytes(buf)))
            }
            8 => {
                let mut buf = [0u8; 8];
                cur.read_exact(&mut buf);
                Some(AttributeKind::U64(u64::from_be_bytes(buf)))
            }
            _ => None,
        }
    }
}


pub extern "C" fn verify_cdi(global_context_ptr: *const u8, global_context_len: size_t, ip_info_ptr: *const u8, ip_info_len: size_t, cdi_ptr: *const u8, cdi_len: size_t) -> int32_t {
    if global_context_ptr.is_null() {
        return -6;
    }
    if ip_info_ptr.is_null(){
        return -7
    }
    if cdi_ptr.is_null(){
        return -8
    }

    let global_context_bytes = unsafe { slice::from_raw_parts(global_context_ptr, global_context_len) };
    let ip_info_bytes = unsafe { slice::from_raw_parts(ip_info_ptr, ip_info_len) };
    let cdi_bytes = unsafe { slice::from_raw_parts(cdi_ptr, cdi_len) };
    
    match GlobalContext::<G1>::from_bytes(&mut Cursor::new(&global_context_bytes)){
        None => return -9,
        Some(gc) => {
            match IpInfo::<Bls12, G1>::from_bytes(&mut Cursor::new(&ip_info_bytes)){
                None => return -10,
                Some(ip_info) => match CredDeploymentInfo::<Bls12, G1, AttributeKind>::from_bytes(&mut Cursor::new(&cdi_bytes)){
                    None => return -11,
                    Some(cdi) => {
                        match  chain::verify_cdi::<Bls12, G1, AttributeKind>(&gc, ip_info, cdi){
                            Ok(()) => 1, //verification succeeded
                            Err(CDIVerificationError::RegId) => -1,
                            Err(CDIVerificationError::IdCredPub) => -2, 
                            Err(CDIVerificationError::Signature) => -3,
                            Err(CDIVerificationError::Dlog) => -4,
                            Err(CDIVerificationError::Policy) => -5
                        }
                    }
                }
            }
        }
    }
}

mod test{
  use std::fmt;
  use crate::{account_holder::*, identity_provider::*, types::*};
  use byteorder::{BigEndian, ReadBytesExt};
  use curve_arithmetic::{Curve, Pairing};
  use dodis_yampolskiy_prf::secret as prf;
  use eddsa_ed25519 as ed25519;
  use elgamal::{public::PublicKey, secret::SecretKey};
  use pairing::{
      bls12_381::{Bls12, Fr, FrRepr},
      PrimeField,
  };
  use ps_sig;
  use rand::*;
  use pedersen_scheme::key as pedersen_key;
  use std::io::Cursor;
  use super::*;

  type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;
  type ExampleCurve = <Bls12 as Pairing>::G_1;
    #[test]
  fn test_pipeline() {
      let mut csprng = thread_rng();

      let secret = ExampleCurve::generate_scalar(&mut csprng);
      let public = ExampleCurve::one_point().mul_by_scalar(&secret);
      let ah_info = CredentialHolderInfo::<ExampleCurve, ExampleCurve> {
          id_ah:   "ACCOUNT_HOLDER".to_owned(),
          id_cred: IdCredentials {
              id_cred_sec:    secret,
              id_cred_pub:    public,
              id_cred_pub_ip: public,
          },
      };

      let id_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(10, &mut csprng);
      let id_public_key = ps_sig::public::PublicKey::from(&id_secret_key);

      let ar_secret_key = SecretKey::generate(&mut csprng);
      let ar_public_key = PublicKey::from(&ar_secret_key);
      let ar_info = ArInfo {
          ar_name: "AR".to_owned(),
          ar_public_key,
          ar_elgamal_generator: PublicKey::generator(),
      };

      let ip_info = IpInfo {
          ip_identity: "ID".to_owned(),
          ip_verify_key: id_public_key,
          ar_info,
      };

      let prf_key = prf::SecretKey::generate(&mut csprng);

      let variant = 0;
      let expiry_date = 123123123;
      let alist = vec![AttributeKind::U8(55), AttributeKind::U64(313123333)];

      let aci = AccCredentialInfo {
          acc_holder_info: ah_info,
          prf_key,
          attributes: ExampleAttributeList {
              variant,
              expiry: expiry_date,
              alist,
              _phantom: Default::default(),
          },
      };

      let context = make_context_from_ip_info(ip_info.clone());
      let (pio, randomness) = generate_pio(&context, &aci);

      let sig_ok = verify_credentials(&pio, context, &id_secret_key);

      // First test, check that we have a valid signature.
      assert!(sig_ok.is_ok());

      let ip_sig = sig_ok.unwrap();
      let global_ctx = GlobalContext {
          dlog_base_chain:         ExampleCurve::one_point(),
          on_chain_commitment_key: pedersen_key::CommitmentKey::generate(1, &mut csprng),
      };

      let policy = Policy {
          variant,
          expiry: expiry_date,
          policy_vec: vec![(0, AttributeKind::U8(55))],
          _phantom: Default::default(),
      };

      let wrong_policy = Policy{
          variant,
          expiry: expiry_date,
          policy_vec: vec![(0, AttributeKind::U8(5))],
          _phantom: Default::default(),
      };

      let kp = ed25519::generate_keypair();
      let acc_data = AccountData {
          sign_key:   kp.secret,
          verify_key: kp.public,
      };

      let cdi = generate_cdi(
          &ip_info,
          &global_ctx,
          &aci,
          &pio,
          0,
          &ip_sig,
          &policy,
          &acc_data,
          &randomness,
      );


        let wrong_cdi = generate_cdi(
            &ip_info,
            &global_ctx,
            &aci,
            &pio,
            0,
            &ip_sig,
            &wrong_policy,
            &acc_data,
            &randomness,
        );


      let cdi_bytes = &*cdi.to_bytes();
      let cdi_bytes_len = cdi_bytes.len() as size_t;
      let ip_info_bytes = &*ip_info.to_bytes();
      let ip_info_bytes_len = ip_info_bytes.len() as size_t;
      let global_context_bytes =  &*global_ctx.to_bytes();
      let global_context_bytes_len = global_context_bytes.len() as size_t;

      let cdi_check = verify_cdi(global_context_bytes.as_ptr(), global_context_bytes_len,ip_info_bytes.as_ptr(), ip_info_bytes_len, cdi_bytes.as_ptr(), cdi_bytes_len);
      println!("cdi_check={}", cdi_check);
      assert_eq!(cdi_check, 1);
      let wrong_cdi_bytes = &*wrong_cdi.to_bytes();
      let wrong_cdi_bytes_len = wrong_cdi_bytes.len() as size_t;
      let wrong_cdi_check = verify_cdi(global_context_bytes.as_ptr(), global_context_bytes_len,ip_info_bytes.as_ptr(), ip_info_bytes_len, wrong_cdi_bytes.as_ptr(), wrong_cdi_bytes_len);
      assert_ne!(wrong_cdi_check, 1);

      
 }


}


macro_derive_from_bytes!(pedersen_key_from_bytes, PedersenKey<G1>, PedersenKey::from_bytes);
macro_derive_to_bytes!(pedersen_key_to_bytes, PedersenKey<G1>);
macro_free_ffi!(pedersen_key_free, PedersenKey<G1>);
macro_generate_commitment_key!(pedersen_key_gen, PedersenKey<G1>, PedersenKey::generate);

macro_derive_from_bytes!(ps_sig_key_from_bytes, ps_sig::PublicKey<Bls12>, ps_sig::PublicKey::from_bytes);
macro_derive_to_bytes!(ps_sig_key_to_bytes, ps_sig::PublicKey<Bls12>);
macro_free_ffi!(ps_sig_key_free, ps_sig::PublicKey<Bls12>);
macro_generate_commitment_key!(ps_sig_key_gen, ps_sig::PublicKey<Bls12>, ps_sig::PublicKey::arbitrary);

pub struct ElgamalGenerator(G1);

impl ElgamalGenerator{
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.curve_to_bytes()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let r = G1::bytes_to_curve(cur)?;
        Ok(ElgamalGenerator(r))
    }

    pub fn generate() -> Self {
        ElgamalGenerator(G1::generate(&mut thread_rng()))
    }
}

macro_derive_from_bytes!(elgamal_gen_from_bytes, ElgamalGenerator, ElgamalGenerator::from_bytes);
macro_derive_to_bytes!(elgamal_gen_to_bytes, ElgamalGenerator);
macro_free_ffi!(elgamal_gen_free, ElgamalGenerator);
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn elgamal_gen_gen() -> *const ElgamalGenerator {
    Box::into_raw(Box::new(ElgamalGenerator::generate()))
}



macro_derive_from_bytes!(elgamal_pub_key_from_bytes, elgamal::PublicKey<G1>, elgamal::PublicKey::from_bytes);
macro_derive_to_bytes!(elgamal_pub_key_to_bytes, elgamal::PublicKey<G1>);
macro_free_ffi!(elgamal_pub_key_free, elgamal::PublicKey<G1>);
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn elgamal_pub_key_gen() -> *const elgamal::PublicKey<G1> {
    let sk = elgamal::secret::SecretKey::generate(&mut thread_rng());
    Box::into_raw(Box::new(elgamal::PublicKey::from(&sk)))
}
