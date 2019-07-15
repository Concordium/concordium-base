use pedersen_scheme::key::CommitmentKey as PedersenKey;
use crate::types::*;
use curve_arithmetic::curve_arithmetic::*;
use pairing::bls12_381::{Bls12,G1};
use std::io::{Cursor, Read};

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
            AttributeKind::U8(_) => {
                let mut buff = [0u8; 2];
                buff.copy_from_slice(&(1 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U16(_) => {
                let mut buff = [0u8; 3];
                buff.copy_from_slice(&(2 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U32(_) => {
                let mut buff = [0u8; 5];
                buff.copy_from_slice(&(4 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
            AttributeKind::U64(_) => {
                let mut buff = [0u8; 9];
                buff.copy_from_slice(&(8 as u8).to_be_bytes());
                buff[1..].copy_from_slice(&self.to_u64().to_be_bytes());
                Box::new(buff)
            }
        }
    }

    fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let bytes = cur.get_ref();
        let size = bytes[0];
        match size {
            1 => {
                let mut buf = [0u8; 1];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U8(u8::from_be_bytes(buf)))
            }
            2 => {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U16(u16::from_be_bytes(buf)))
            }
            4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U32(u32::from_be_bytes(buf)))
            }
            8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[1..]);
                Some(AttributeKind::U64(u64::from_be_bytes(buf)))
            }
            _ => None,
        }
    }
}

/*
pub extern "C" fn verify_cdi(global_context_ptr: *const u8, ip_info_ptr: *const u8, cdi_ptr: *const u8) -> int32_t {
    if global_context_ptr.is_null() {
        return -3;
    }
    if ip_info_ptr.is_null(){
        return -4
    }
    if cdi_ptr.is_null(){
        return -5
    }

}

*/

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
