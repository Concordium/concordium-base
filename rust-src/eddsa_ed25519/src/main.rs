use rand::*;

mod eddsa_ed25519;

use eddsa_ed25519::*;
use ed25519_dalek::*;

fn main(){
    let mut csprng = rand::thread_rng();
    let mut data = [0u8; 64];
    let mut sk_bytes = [0u8;32];
    eddsa_priv_key(&mut sk_bytes);
    //let sk = SecretKey::generate(&mut csprng);
    //let sk_bytes = sk.to_bytes();
    print!("SK: "); print_bytes(&sk_bytes);
    //let pk = PublicKey::from(&sk);
    let mut pk_bytes = [0u8;32];
    eddsa_pub_key(&sk_bytes, &mut pk_bytes);
    //let pk_bytes = pk.to_bytes();
    print!("PK: "); print_bytes(&pk_bytes);
    print!("SK2: "); print_bytes(&sk_bytes);

    for i in 0..100 {
        rand::thread_rng().fill_bytes(&mut data);
        print!("MSG: "); print_bytes(&data);
        let mut signature =  [0u8;SIGNATURE_LENGTH];
        eddsa_sign(data.as_ptr(), data.len(),  &sk_bytes, &pk_bytes, &mut signature);
        println!("RES:{}", eddsa_verify(data.as_ptr(), data.len(), &pk_bytes, &signature));
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

