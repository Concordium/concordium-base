use crate::constants::*;
use crate::value::*;
use crate::key::*;
use crate::commitment::*;
use rand::*;
use std::slice;

//foreign interface

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn pedersen_commitment_key(n: usize, key_bytes: *mut u8){
    //assert_eq!((n+1)*GROUP_ELEMENT_LENGTH, key_bytes.len());
    assert!(!key_bytes.is_null(), "Null pointer");
    let key_slice: &mut[u8] = unsafe{ slice::from_raw_parts_mut(key_bytes, (n+1)*GROUP_ELEMENT_LENGTH)};
    let mut csprng= thread_rng();
    let ck = CommitmentKey::generate(n, &mut csprng);
    &key_slice.copy_from_slice(&*ck.to_bytes());
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn pedersen_commit(n :usize, key_bytes: *const u8, values: *const u8, commitment: &mut[u8;COMMITMENT_LENGTH], randomness:&mut[u8;RANDOMNESS_LENGTH]) -> i32 {
    assert!(!key_bytes.is_null(), "Null pointer");
    assert!(!values.is_null(), "Null pointer");
    let key_slice: &[u8] = unsafe{ slice::from_raw_parts(key_bytes, (n+1)*GROUP_ELEMENT_LENGTH)};
    let values_slice: &[u8] = unsafe{ slice::from_raw_parts(values, (n)*FIELD_ELEMENT_LENGTH)};
    match CommitmentKey::from_bytes(key_slice){
        Err(_) => -1,
        Ok(ck) => match Value::from_bytes(values_slice){
            Err(_) => -2,
            Ok(vs) => {
                let mut csprng = thread_rng();
                let (c,r) = ck.commit(&vs, &mut csprng);
                randomness.copy_from_slice(&Value::value_to_bytes(&r));
                commitment.copy_from_slice(&c.to_bytes());
                1
            }
        }
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn pedersen_open(n: usize, key_bytes: *const u8, values: *const u8, commitment: &[u8;COMMITMENT_LENGTH], randomness:&[u8;RANDOMNESS_LENGTH]) -> i32 {
    assert!(!key_bytes.is_null(), "Null pointer");
    assert!(!values.is_null(), "Null pointer");
    let key_slice: &[u8] = unsafe{ slice::from_raw_parts(key_bytes, (n+1)*GROUP_ELEMENT_LENGTH)};
    let values_slice: &[u8] = unsafe{ slice::from_raw_parts(values, (n)*FIELD_ELEMENT_LENGTH)};
    match CommitmentKey::from_bytes(key_slice){
        Err(_) => -1,
        Ok(ck) => match Value::from_bytes(values_slice){
            Err(_) => -2,
            Ok(vs) => match Value::value_from_bytes(randomness){
                Err(_) => -3,
                Ok(r) => match Commitment::from_bytes(commitment){
                    Err(_) => -4,
                    Ok(c) => if ck.open(&vs, r, c) { 1} else {0} 
                }
            }
        }
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn pedersen_random_values(n: usize, values_bytes : *mut u8){
   let mut csprng = thread_rng();
   let vs = Value::generate(n, &mut csprng); 
   let v_slice: &mut[u8] = unsafe{ slice::from_raw_parts_mut(values_bytes, n*FIELD_ELEMENT_LENGTH)};
   &v_slice.copy_from_slice(&*vs.to_bytes());
}
#[test]
pub fn commit_open(){
    let mut key_bytes = [0u8; 11 * GROUP_ELEMENT_LENGTH];
    //let mut values = [0u8; 10 * FIELD_ELEMENT_LENGTH];
    let mut csprng = thread_rng();
    let mut commitment_bytes = [0u8; COMMITMENT_LENGTH];
    let mut randomness_bytes = [0u8; RANDOMNESS_LENGTH];
    for i in 1..10{
        let mut key_slice = &mut key_bytes[..(i+1)*GROUP_ELEMENT_LENGTH];
        pedersen_commitment_key(i, key_slice.as_mut_ptr());  
        let vs=Value::generate(i, &mut csprng);
        let v_slice : &[u8] = &*&vs.to_bytes();
        let suc1 = pedersen_commit(i, key_slice.as_ptr(),
                       v_slice.as_ptr(),
                       &mut commitment_bytes,
                       &mut randomness_bytes);
        assert!(suc1 > 0);
        assert!(pedersen_open(i,key_slice.as_ptr(), 
                     v_slice.as_ptr(),
                     &commitment_bytes,
                     &randomness_bytes) > 0);
    }
    

}


