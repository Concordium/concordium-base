extern crate rand;
use rand::*;

#[macro_use]
extern crate criterion;

use criterion::BatchSize;
use criterion::Criterion;
use criterion::black_box;

extern crate elgamal;

use elgamal::elgamal::*;
use elgamal::public::*;
use elgamal::secret::*;


pub fn encrypt_bitwise_bench(c: &mut Criterion){
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    let pk = PublicKey::from(&sk);
    let n = u64::rand(&mut csprng);
    c.bench_function("encryption bitwise", move |b| b.iter(|| encrypt_bitwise(&pk, n)));
}


pub fn decrypt_bitwise_bench(c: &mut Criterion){
      let mut csprng = thread_rng();
      let sk = SecretKey::generate(&mut csprng);
      let pk = PublicKey::from(&sk);
      let n = u64::rand(&mut csprng);
      let p = encrypt_bitwise(&pk, n);
      c.bench_function("decryption bitwise", move |b| b.iter(|| decrypt_bitwise(&sk, &p)));
}


pub fn det(c:&mut Criterion){
      let mut csprng = thread_rng();
      let e = u64::rand(&mut csprng);
      c.bench_function("u64 to g bits", move |b| b.iter(|| u64_to_bits(&e)));
      //let er = u64_to_group_bits(&e);
      //let cs = er.par_iter().map(|x| pk.encrypt_binary_exp(x)).collect();
      //cs
}


criterion_group!{
    name = elgamal_benches;
    config = Criterion::default();
    targets = 
        encrypt_bitwise_bench,
        decrypt_bitwise_bench,
}

criterion_main!(
    elgamal_benches);
