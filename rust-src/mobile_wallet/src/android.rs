#![cfg(target_os = "android")]
#![allow(non_snake_case)]

use jni::{
    objects::JClass,
    sys::{jbyte, jchar, jstring},
    JNIEnv,
};
use std::ffi::{CStr, CString};
use wallet::{create_credential, create_id_request_and_private_data, free_response_string};

#[no_mangle]
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_id_request_and_private_data(
    env: JNIEnv,
    _: JClass,
    input: *const jbyte,
    success: *mut jchar,
) -> jstring {
    let cstr = unsafe { CStr::from_ptr(input) };

    let res = unsafe {
        CString::from_raw(create_id_request_and_private_data(
            cstr.as_ptr(),
            success as *mut u8,
        ))
    };

    let output = env
        .new_string(res.to_str().unwrap())
        .expect("Could not create a Java string!");

    output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_credential(
    env: JNIEnv,
    _: JClass,
    input: *const jbyte,
    success: *mut jchar,
) -> jstring {
    let cstr = unsafe { CStr::from_ptr(input) };

    let res = unsafe { CString::from_raw(create_credential(cstr.as_ptr(), success as *mut u8)) };

    let output = env
        .new_string(res.to_str().unwrap())
        .expect("Could not create a Java string!");

    output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_free_response_string(
    _: JNIEnv,
    _: JClass,
    ptr: *mut jbyte,
) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        free_response_string(ptr);
    }
}
