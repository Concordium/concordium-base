use rayon::prelude::*;
use rayon::iter::IntoParallelRefIterator;
use crate::constants::*;
use crate::secret::*;
use crate::public::*;
use crate::message::*;
use crate::cipher::*;
use rand::*;
use bitvec::Bits;


use pairing::bls12_381::{G1 };
use pairing::{CurveProjective};
#[cfg(test)]
use pairing::bls12_381::{FrRepr, Fr};
#[cfg(test)]
use pairing::PrimeField;

//returns the binary representation of a u64

pub fn u64_to_bits (e: &u64) -> Vec<bool>{
    let mut xs = vec![];
    for i in 0..64{
        xs.push(e.get(i as u8));
    }
    xs
}

//take an array of zero's and ones and returns a u64
pub fn group_bits_to_u64 (v: &[G1] ) -> u64{
    let mut r= 0u64;
    for i in 0..v.len(){
        r.set(i  as u8, v[i]==G1::one());
    }
    r
}

//encrypts a u64 bitwise, that is
// it turns the u64 into it's binary representation b0...bn 
// and encrypts the group elements g^b0...g^bn in parallel
pub fn encrypt_bitwise(pk: &PublicKey, e: u64) -> Vec<Cipher> {
    let er = u64_to_bits(&e);
    let cs = er.par_iter().map(|x| {let mut csprng = thread_rng(); pk.encrypt_binary_exp(&mut csprng, x)}).collect();
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
    for i in 1..100 {
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
