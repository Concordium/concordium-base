use crate::constants::*;
use crate::value::*;
use crate::key::*;
use crate::commitment::*;
use rand::*;

//foreign interface

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn commitment_key(n: usize, key_bytes: &mut[u8]){
    assert_eq!((n+1)*GROUP_ELEMENT_LENGTH, key_bytes.len());
    let mut csprng= thread_rng();
    let ck = CommitmentKey::generate(n, &mut csprng);
    key_bytes.copy_from_slice(&*ck.to_bytes());
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn commit(key_bytes: &[u8], values: &[u8], commitment: &mut[u8;COMMITMENT_LENGTH], randomness:&mut[u8;RANDOMNESS_LENGTH]) -> i32 {
    match CommitmentKey::from_bytes(key_bytes){
        Err(_) => return -1,
        Ok(ck) => match Value::from_bytes(values){
            Err(_) => return -2,
            Ok(vs) => {
                let mut csprng = thread_rng();
                let (c,r) = ck.commit(&vs, &mut csprng);
                randomness.copy_from_slice(&Value::value_to_bytes(&r));
                commitment.copy_from_slice(&c.to_bytes());
                return 1;
            }
        }
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn open(key_bytes: &[u8], values: &[u8], commitment: &[u8;COMMITMENT_LENGTH], randomness:&[u8;RANDOMNESS_LENGTH]) -> i32 {
    match CommitmentKey::from_bytes(key_bytes){
        Err(_) => return -1,
        Ok(ck) => match Value::from_bytes(values){
            Err(_) => return -2,
            Ok(vs) => match Value::value_from_bytes(randomness){
                Err(_) => return -3,
                Ok(r) => match Commitment::from_bytes(commitment){
                    Err(_) => return -4,
                    Ok(c) => if ck.open(&vs, r, c) { return 1} else {return 0} 
                }
            }
        }
    }
}


