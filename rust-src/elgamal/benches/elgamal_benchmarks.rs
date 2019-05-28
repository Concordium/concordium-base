extern crate rand;
use rand::*;

#[macro_use]
extern crate criterion;

use criterion::Criterion;

extern crate elgamal;

use elgamal::elgamal::*;
use elgamal::public::*;
use elgamal::secret::*;

extern crate pairing;
use pairing::bls12_381::{G1};
use pairing::CurveProjective;
use pairing::CurveAffine;
use pairing::EncodedPoint;

pub fn encrypt_bitwise_bench(c: &mut Criterion){
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    let pk = PublicKey::from(&sk);
    let n = u64::rand(&mut csprng);
    c.bench_function("encryption bitwise", move |b| b.iter(|| encrypt_u64_bitwise(&pk, n)));
}

pub fn ff_encrypt_u64_bench(c: &mut Criterion){
      let sk = new_secret_key();
      let pk = public_key(sk);
      let mut xs=[0u8;6144];
      let mut csprng = thread_rng();
      let n = u64::rand(&mut csprng);
      c.bench_function("ff encrypt u64", move |b| b.iter(|| encrypt_u64(pk, n, &mut xs)));
}
pub fn into_projective_bench(c:&mut Criterion){
    let mut csprng = thread_rng();
    let g = G1::rand(&mut csprng); 
    let x = g.into_affine().into_compressed();
    c.bench_function("compressed into projective", move |b| b.iter(||G1::from(x.into_affine().unwrap())));
}
pub fn into_affine_bench(c:&mut Criterion){
    let mut csprng = thread_rng();
    let g = G1::rand(&mut csprng); 
    let x = g.into_affine().into_compressed();
    c.bench_function("compressed into affine", move |b| b.iter(|| x.into_affine_unchecked().unwrap()));
}
/*
pub fn cipher_from_bytes_bench(c: &mut Criterion){
    let mut csprng = thread_rng();
    let g = G1::rand(&mut csprng); 
    let h = G1::rand(&mut csprng); 
    let q = Cipher(g,h);
    let p = q.to_bytes();
    c.bench_function("cipher from bytes", move |b| b.iter(|| Cipher::from_bytes(&p)));


}
*/
pub fn ff_decrypt_u64_bench(c: &mut Criterion){
      let sk = new_secret_key();
      let pk = public_key(sk);
      let mut xs=[0u8;6144];
      let mut csprng = thread_rng();
      let n = u64::rand(&mut csprng);
      encrypt_u64(pk, n, &mut xs);
      c.bench_function("ff decrypt u64", move |b| b.iter(|| decrypt_u64(sk, xs.as_ptr(), 6144)));

}

pub fn ff_decrypt_u64_unchecked_bench(c: &mut Criterion){
      let sk = new_secret_key();
      let pk = public_key(sk);
      let mut xs=[0u8;6144];
      let mut csprng = thread_rng();
      let n = u64::rand(&mut csprng);
      encrypt_u64(pk, n, &mut xs);
      c.bench_function("ff decrypt u64 unsafe", move |b| b.iter(|| decrypt_u64_unsafe(sk, xs.as_ptr(), 6144)));

}


pub fn decrypt_bitwise_bench(c: &mut Criterion){
      let mut csprng = thread_rng();
      let sk = SecretKey::generate(&mut csprng);
      let pk = PublicKey::from(&sk);
      let n = u64::rand(&mut csprng);
      let p = encrypt_u64_bitwise(&pk, n);
      c.bench_function("decryption bitwise", move |b| b.iter(|| decrypt_u64_bitwise(&sk, &p)));
}




criterion_group!{
    name = elgamal_benches;
    config = Criterion::default();
    targets = 
        //encrypt_bitwise_bench,
        //decrypt_bitwise_bench,
        //ff_encrypt_u64_bench,
        //cipher_from_bytes_bench,
        //into_affine_bench,
        //into_projective_bench
        //ff_decrypt_u64_bench
        ff_decrypt_u64_unchecked_bench
}

criterion_main!(
    elgamal_benches);
