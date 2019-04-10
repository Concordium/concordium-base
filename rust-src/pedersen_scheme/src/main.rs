extern crate pairing;
extern crate rand_core;
extern crate clear_on_drop;
extern crate rand;
extern crate failure;
extern crate core;

mod constants;
mod errors;
mod key;
use key::*;
use pairing::{CurveAffine};
use rand::*;



fn main() {
/*
   let mut csprng = thread_rng();
   let sk = SecretKey::generate(&mut csprng);  
   println!("{:?}", sk);
   let r = sk.to_bytes();
   let sk2 = SecretKey::from_bytes(&r);
   println!("{:?}", sk2);
   for i in 1..10{
    let m = sk.prf(i).unwrap();
    let o = m.into_compressed();
    let pr = o.as_ref();
    println!("{:?}", pr);
   }
   for i in 1..10{
      let m = sk.prf(i).unwrap();
      let o = m.into_compressed();
      let pr = o.as_ref();
      println!("{:?}", pr);
     }
     */

}
