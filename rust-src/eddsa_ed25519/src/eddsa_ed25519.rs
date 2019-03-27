use rand::*;
use ed25519_dalek::*;

use std::slice;


//foreign function interfacee

#[no_mangle]
pub extern fn eddsa_priv_key(secret_key_bytes: &mut[u8;SECRET_KEY_LENGTH])-> i32{
     let mut csprng = thread_rng();
     let sk = SecretKey::generate(&mut csprng);
     secret_key_bytes.copy_from_slice(&sk.to_bytes());
     1
  }

//error encodeing
//-1 bad input
#[no_mangle]
pub extern fn eddsa_pub_key(secret_key_bytes: &[u8;32], public_key_bytes: &mut [u8;32])->i32{
      let res_sk = SecretKey::from_bytes(secret_key_bytes);
      if res_sk.is_err() { return -1 };
      let sk = res_sk.unwrap();
      let pk = PublicKey::from(&sk);
      public_key_bytes.copy_from_slice(&pk.to_bytes());
      1
}

#[no_mangle]
pub extern fn eddsa_sign(message: *const u8, len: usize, secret_key_bytes: &[u8;32], public_key_bytes: &[u8;32], signature_bytes: &mut [u8; SIGNATURE_LENGTH]){ 
    let sk = SecretKey::from_bytes(secret_key_bytes).expect("bad secret key bytes");
    let pk = PublicKey::from_bytes(public_key_bytes).expect("bad public key bytes");
    assert!(!message.is_null(), "Null pointer in eddsa_sign()");
    let data: &[u8]= unsafe { slice::from_raw_parts(message, len)};
    let expanded_sk = ExpandedSecretKey::from(&sk); 
    let signature = expanded_sk.sign(data, &pk);
    signature_bytes.copy_from_slice(&signature.to_bytes());
}
//Error encoding
//-2 bad public key 
//-1 badly formatted signature
//0 verification failed
#[no_mangle]
pub extern fn eddsa_verify(message: *const u8, len: usize, public_key_bytes:&[u8;32], signature_bytes: &[u8; SIGNATURE_LENGTH])-> i32{
    let pk_res = PublicKey::from_bytes(public_key_bytes);
    if pk_res.is_err() { return -2 }; 
    let sig_res = Signature::from_bytes(signature_bytes);
    if sig_res.is_err() { return -1 }; 

    let pk = pk_res.unwrap();
    let sig = sig_res.unwrap();
    assert!(!message.is_null(), "Null pointer in ec_vrf_prove");
    let data: &[u8]= unsafe { slice::from_raw_parts(message, len)};
    match pk.verify(data, &sig){
        Ok(_) => 1,
        _     => 0
    }
}
