extern crate clear_on_drop;
extern crate core;
extern crate failure;
extern crate pairing;
extern crate rand;
extern crate rand_core;
extern crate serde;

mod constants;
mod errors;
mod secret;
use pairing::CurveAffine;
use rand::*;
use secret::*;

fn main() {
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    println!("{:?}", sk);
    let r = sk.to_bytes();
    let sk2 = SecretKey::from_bytes(&r);
    println!("{:?}", sk2);
    for i in 1..10 {
        let m = sk.prf(i).unwrap();
        let o = m.into_compressed();
        let pr = o.as_ref();
        println!("{:?}", pr);
    }
    for i in 1..10 {
        let m = sk.prf(i).unwrap();
        let o = m.into_compressed();
        let pr = o.as_ref();
        println!("{:?}", pr);
    }
}
