use rayon::prelude::*;
use rayon::iter::IntoParallelRefIterator;
use crate::constants::*;
use crate::secret::*;
use crate::public::*;
use crate::message::*;
use crate::cipher::*;
use rand::*;
use std::fmt::LowerHex;
use bitvec::Bits;
use std::thread;
use std::time::Duration;


use pairing::bls12_381::{G1, G1Affine, FrRepr, Fr};
use pairing::{CurveProjective, CurveAffine,Field,PrimeField};

//returns the binary representation of a u64
//as an array of Fr::zero() and Fr::one()

pub fn u64_to_group_bits (e: &u64) -> Vec<bool>{
    //let  mut xs = [G1::zero();64];
    let mut xs = vec![];
    //let mut xs = [false ; 64];
    //let mut x = e.clone();
    for i in 0..64{
        xs.push(e.get(i as u8));
    }
    
   // for i in 0..64 {
   //     let y= x % 2;
   //     if y==1 {xs[i]= G1::one()} else {xs[i] = G1::zero()};
   //     x = x/2;
   // }
    xs
}

//take an array of zero's and ones and returns a u64
pub fn group_bits_to_u64 (v: &[G1] ) -> u64{
    let mut r= 0u64;
    let mut ind = 0;
    for i in 0..v.len(){
        r.set((i  as u8), v[i]==G1::one());
    //    let x:u64 = if v[i]==G1::one() {2u64.pow(i as u32)} else {0};
    //    r = r + x;
    }
    r
}

        
pub fn encrypt_bitwise(pk: &PublicKey, e: u64) -> Vec<Cipher> {
    let mut csprng = thread_rng();
    let er = u64_to_group_bits(&e);
    let cs = er.par_iter().map(|x| pk.encrypt_binary_exp(x)).collect();
    cs
}


pub fn decrypt_bitwise(sk:&SecretKey, v:&Vec<Cipher>)-> u64{
    //let er = sk.decrypt_exponent_vec(v);
    let dr:Vec<G1> = v.par_iter().map(|x| {let Message(m) = sk.decrypt(&x); m}).collect();
    group_bits_to_u64(&dr.as_slice())
    //let mut er = [G1::zero();64];
    //for i in 0..64{
    //    let Message(z) = sk.decrypt(&v[i]);
    //    er[i] = z;
   // }
    //let er:Vec<G1> = v.into_iter().map(|y| {let Message(z) =sk.decrypt(y); z}).collect();
    //group_bits_to_u64(&er)
}

/*
#[test]
pub fn bits(){
    let mut csprng = thread_rng();
    for _i in 1..100{
        let m = u64::rand(&mut csprng);
        let n  = group_bits_to_u64(&u64_to_group_bits(&m));
        println!("m={:?}, n={:?}", m, n);
        assert_eq!(m,n)
    }
}
*/
#[test]
pub fn encrypt_decrypt(){
    let mut csprng = thread_rng();
    for _i in 1..100{
        let sk = SecretKey::generate(&mut csprng);
//        println!("SK={:x}", ByteBuf(&sk.to_bytes()));
        let pk = PublicKey::from(&sk);
 //       println!("PK={:x}", ByteBuf(&pk.to_bytes()));
        let m = Message::generate(&mut csprng);
 //       println!("M={:x}", ByteBuf(&m.to_bytes()));
        let c = pk.encrypt(&mut csprng, &m);
 //       println!("C={:x}", ByteBuf(&c.to_bytes()));
        let t = sk.decrypt(&c);
 //       println!("d={:x}", ByteBuf(&t.to_bytes()));
        assert_eq!(t, m);
      }
}

#[test]
pub fn encrypt_decrypt_exponent(){
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    let pk = PublicKey::from(&sk);
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

}

#[test]
pub fn encrypt_decrypt_bitwise_vec(){
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    let pk = PublicKey::from(&sk);
    for _i in 1..100 {
        let n = u64::rand(&mut csprng);
        let c = encrypt_bitwise(&pk, n);
        let n2 = decrypt_bitwise(&sk, &c);
        assert_eq!(n,n2);
    }
}




struct ByteBuf<'a>(&'a [u8]);

impl<'a> std::fmt::LowerHex for ByteBuf<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for byte in self.0 {
            try!( fmtr.write_fmt(format_args!("{:02x}", byte)));
        }
        Ok(())
    }
}
