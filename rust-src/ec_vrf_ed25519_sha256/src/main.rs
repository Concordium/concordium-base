use rand::*;
//extern crate std;
extern crate core;

extern crate clear_on_drop;
extern crate curve25519_dalek;
extern crate failure;
extern crate rand;
#[cfg(feature = "serde")]
extern crate serde;
extern crate sha2;

mod constants;
mod errors;
mod public;
mod secret;
mod proof;
mod ec_vrf_ed25519_sha256;
// Export everything public in ec_vrf_ed25519_sha256.rs
pub use crate::secret::*;
pub use crate::public::*;
use curve25519_dalek::edwards::*;
use curve25519_dalek::traits::{Identity, IsIdentity};
use ec_vrf_ed25519_sha256::*;

fn main(){
   //print!("{:?}", EdwardsPoint::identity());
   //let m = EdwardsPoint::identity().compress().decompress().expect("failed");
   //print!("{:?}", m);
   //let dc = CompressedEdwardsY::identity().decompress().expect("failed");
   //print!("{:?}",dc.is_identity()) ;
   //println!("");
   //print!("{}", EdwardsPoint::identity()==CompressedEdwardsY::identity().decompress().expect("failed")); 
   //println!("");
    let mut csprng = rand::thread_rng();
    let mut data = [0u8; 64];
    let mut sk_bytes = [0u8;32];
    let sk = SecretKey::generate(&mut csprng);
    let sk_bytes = sk.to_bytes();
    print!("SK: "); print_bytes(&sk.to_bytes());
    let pk = PublicKey::from(&sk);
    let pk_bytes = pk.to_bytes();
    print!("PK: "); print_bytes(&pk.to_bytes());

    for i in 0..100 {
        rand::thread_rng().fill_bytes(&mut data);
        print!("MSG: "); print_bytes(&data);
        let mut proof =  [0u8;80];
        ec_vrf_prove(&mut proof, &pk_bytes, &sk_bytes, data.as_ptr(), data.len()); 
        println!("{}", ec_vrf_verify(&pk_bytes, &proof, data.as_ptr(), data.len()));
        //let p = sk.prove(&pk, &data, &mut csprng).expect("Proof failed");
        //let h = p.to_hash();
        //print!("proof hash: "); print_bytes(&h);

        //let b = pk.verify(p, &data);
        //let z = PublicKey::verify_key(&pk.0.to_bytes());
        //println!("proof {}", if b {"Succeeded"} else {"failed"});
        //println!("verif key {}", z);
    }
}


fn print_bytes(b: &[u8]){
    for i in b {
        print!("{:02x}", i);
    }
    println!("");
}
