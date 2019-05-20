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
use pairing::{Field, CurveProjective};
use pairing::bls12_381::{Fr};
#[cfg(test)]
use pairing::bls12_381::{FrRepr};
#[cfg(test)]
use pairing::PrimeField;


pub fn encrypt_u64_bitwise(pk: &PublicKey, e:&u64) -> Vec<Cipher>{
    let mut csprng = thread_rng();
    let mut er = vec![];
    for i in 0..64{
        er.push((e.get(i as u8), Fr::rand(&mut csprng)));
    }
    er.par_iter().map(|(x,y)| pk.hide_binary_exp(*y,x)).collect()
}
//take an array of zero's and ones and returns a u64
pub fn group_bits_to_u64 (v: &[G1] ) -> u64{
    let mut r= 0u64;
    for i in 0..v.len(){
        r.set(i  as u8, v[i]==G1::one());
    }
    r
}



pub fn decrypt_bitwise(sk:&SecretKey, v:&Vec<Cipher>)-> u64{
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
        let c = encrypt_u64_bitwise(&pk, &n);
        let n2 = decrypt_bitwise(&sk, &c);
        assert_eq!(n,n2);
    }
    assert_eq!(sk, sk2);
    assert_eq!(pk, pk2);
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
