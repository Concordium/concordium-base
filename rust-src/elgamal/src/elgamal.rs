use libc::{uint8_t, size_t};
use std::slice;
use rayon::prelude::*;
use rayon::iter::IntoParallelRefIterator;
use crate::secret::*;
use crate::public::*;
use crate::message::*;
use crate::errors::*;
use crate::cipher::*;
use rand::*;
use bitvec::Bits;


use pairing::bls12_381::{G1 };
use pairing::CurveProjective;
use pairing::bls12_381::{Fr};
#[cfg(test)]
use pairing::bls12_381::{FrRepr};
#[cfg(test)]
use pairing::PrimeField;

//foreign function interface
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn new_secret_key() -> *mut SecretKey{
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(SecretKey::generate(&mut csprng)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn secret_key_free(ptr: *mut SecretKey) {
    if ptr.is_null() { return }
    unsafe { Box::from_raw(ptr); }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn public_key(ptr : *mut SecretKey) -> *mut PublicKey{
    let sk: &SecretKey = unsafe{
        assert!(!ptr.is_null());
        &* ptr
    };
    Box::into_raw(Box::new(PublicKey::from(sk)))
}
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn public_key_free(ptr: *mut PublicKey) {
    if ptr.is_null() { return }
    unsafe { Box::from_raw(ptr); }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn encrypt_u64(ptr : *mut PublicKey, e: u64, out: &mut [u8;6144]) {
    let pk: &PublicKey = unsafe {
        assert!(!ptr.is_null());
        &* ptr
    };
    let xs:Vec<[u8;96]> = encrypt_u64_bitwise(pk, e).iter().map(|x| x.to_bytes()).collect();
    for i in 0..64{
        for j in 0..96{
            out[j + (i * 96)] = xs[i][j];
            
        }
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn decrypt_u64(ptr: *mut SecretKey, cipher_bytes: *const uint8_t, len: size_t) -> u64{
    let cipher = unsafe {
        assert!(!cipher_bytes.is_null());
        slice::from_raw_parts(cipher_bytes, len as usize) 
    };
    let sk: &SecretKey = unsafe{
        assert!(!ptr.is_null());
        &* ptr
    };
    let  v:Vec<_> = cipher.par_chunks(96).map(|x| {let c = Cipher::from_bytes(x).unwrap();
                                                   let Message(m) = sk.decrypt(&c);
                                                   m}).collect();
    group_bits_to_u64(v.as_slice())
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn decrypt_u64_unsafe(ptr:*mut SecretKey, cipher_bytes: *const uint8_t, len: size_t) -> Result<u64, ElgamalError>{
       let cipher = unsafe {
          assert!(!cipher_bytes.is_null());
          slice::from_raw_parts(cipher_bytes, len as usize)
      };
      let sk: &SecretKey = unsafe{
          assert!(!ptr.is_null());
          &* ptr
      };
      let  v:Vec<_> = cipher.par_chunks(96).map(|x| {let c = Cipher::from_bytes_unchecked(x).unwrap();
                                                     let Message(m) = sk.decrypt(&c);
                                                     m}).collect();
      Ok(group_bits_to_u64(v.as_slice()))
}
    
pub fn encrypt_u64_bitwise(pk: &PublicKey, e:u64) -> Vec<Cipher>{
    let mut csprng = thread_rng();
    let mut er = vec![];
    for i in 0..64{
        er.push((e.get(i as u8), Fr::rand(&mut csprng)));
    }
    er.par_iter().map(|(x,y)| pk.hide_binary_exp(*y,*x)).collect()
}
//take an array of zero's and ones and returns a u64
pub fn group_bits_to_u64 (v: &[G1] ) -> u64{
    let mut r= 0u64;
    for i in 0..v.len(){
        r.set(i  as u8, v[i]==G1::one());
    }
    r
}



pub fn decrypt_u64_bitwise(sk:&SecretKey, v:&[Cipher])-> u64{
    let dr:Vec<G1> = v.par_iter().map(|x| {let Message(m) = sk.decrypt(&x); m}).collect();
    group_bits_to_u64(dr.as_slice())
}

#[test]
pub fn encrypt_decrypt(){
    let mut csprng = thread_rng();
    for _i in 1..100{
        let sk = SecretKey::generate(&mut csprng);
        let sk2 = sk.clone();
//        println!("SK={:x}", ByteBuf(&sk.to_bytes()));
        let pk = PublicKey::from(&sk);
        let pk2 = pk.clone();
 //       println!("PK={:x}", ByteBuf(&pk.to_bytes()));
        let m = Message::generate(&mut csprng);
 //       println!("M={:x}", ByteBuf(&m.to_bytes()));
        let c = pk.encrypt(&mut csprng, &m);
 //       println!("C={:x}", ByteBuf(&c.to_bytes()));
        let t = sk.decrypt(&c);
 //       println!("d={:x}", ByteBuf(&t.to_bytes()));
        assert_eq!(t, m);
        assert_eq!(pk, pk2);
        assert_eq!(sk, sk2);
      }
}

#[test]
pub fn encrypt_decrypt_exponent(){
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    let sk2 = sk.clone();
    let pk = PublicKey::from(&sk);
    let pk2 = pk.clone();
    for _i in 1..100{
        let n = u64::rand(&mut csprng);
        let e = Fr::from_repr(FrRepr::from(n % 1000)).unwrap();
        println!("e={}", e);
        let c = pk.encrypt_exponent(&mut csprng,&e);
        println!("C={:x}", ByteBuf(&c.to_bytes()));
        let e2 = sk.decrypt_exponent(&c);
        println!("e2={}", e2);
        assert_eq!(e,e2);
    }
    assert_eq!(sk, sk2);
    assert_eq!(pk, pk2);

}

#[test]
pub fn encrypt_decrypt_bitwise_vec(){
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    let sk2 = sk.clone();
    let pk = PublicKey::from(&sk);
    let pk2 =pk.clone();
    for _i in 1..100 {
        let n = u64::rand(&mut csprng);
        let c = encrypt_u64_bitwise(&pk, n);
        let n2 = decrypt_u64_bitwise(&sk, &c);
        assert_eq!(n,n2);
    }
    assert_eq!(sk, sk2);
    assert_eq!(pk, pk2);
}


#[test]
pub fn ff_encrypt_decrypt_u64(){
    let sk = new_secret_key();
    let pk = public_key(sk);
    let mut xs=[0u8;6144];
    let mut csprng = thread_rng();
    for _i in 1..100{
        let n = u64::rand(&mut csprng);
        println!("n={}", n);
        encrypt_u64(pk, n, &mut xs); 
        let m = decrypt_u64(sk, xs.as_ptr(), 6144);
        println!("m={}", m);
        assert_eq!(m,n);
    }
}

#[test]
pub fn ff_encrypt_decrypt_u64_unchecked(){
    let sk = new_secret_key();
    let pk = public_key(sk);
    let mut xs=[0u8;6144];
    let mut csprng = thread_rng();
    for _i in 1..100{
        let n = u64::rand(&mut csprng);
        println!("n={}", n);
        encrypt_u64(pk, n, &mut xs);
        let m = decrypt_u64_unsafe(sk, xs.as_ptr(), 6144).unwrap();
        println!("m={}", m);
        assert_eq!(m,n);
    }
}

// Still prototyping
#[allow(dead_code)]
struct ByteBuf<'a>(&'a [u8]);

impl<'a> std::fmt::LowerHex for ByteBuf<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for byte in self.0 {
            ( fmtr.write_fmt(format_args!("{:02x}", byte)))?;
        }
        Ok(())
    }
}
