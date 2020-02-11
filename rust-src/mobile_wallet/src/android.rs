#![cfg(target_os = "android")]
#![allow(non_snake_case)]
#![allow(unused_assignments)]

use jni::{
    objects::{JClass, JString, JValue},
    sys::{jint, jobject, jstring},
    JNIEnv,
};
use std::ffi::CString;
use wallet::{create_credential_ext, create_id_request_and_private_data_ext};

#[no_mangle]
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1id_1request_1and_1private_1data(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    ndk_logger::init().unwrap();
    let _str = env.get_string(input).expect("Could not create Java String");

    let mut success = 127;

    let res = unsafe {
        CString::from_raw(create_id_request_and_private_data_ext(
            _str.as_ptr(),
            &mut success,
        ))
    };

    let output = env
        .new_string(res.to_str().unwrap())
        .expect("Could not create a Java string!");

    let cls_name = "com/concordium/mobile_wallet_lib/ReturnValue";

    let cls = env.find_class(cls_name).unwrap();

    let ctr_sig = "(ILjava/lang/String;)V";

    let method_id = env.get_method_id(cls, "<init>", ctr_sig).unwrap();

    env.new_object_unchecked(cls, method_id, &[
        JValue::Int(success as jint),
        JValue::Object(*output),
    ])
    .unwrap()
    .into_inner()
}

#[no_mangle]

pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1credential(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let _str = env.get_string(input).expect("Could not create Java String");

    let mut success: u8 = 127;

    let res = unsafe {
        let creds_ptr = create_credential_ext(_str.as_ptr(), &mut success);
        CString::from_raw(creds_ptr)
    };

    let output = env
        .new_string(res.to_str().unwrap())
        .expect("Could not create a Java string!");

    let cls_name = "com/concordium/mobile_wallet_lib/ReturnValue";

    let cls = env.find_class(cls_name).unwrap();

    let ctr_sig = "(ILjava/lang/String;)V";

    let method_id = env.get_method_id(cls, "<init>", ctr_sig).unwrap();

    env.new_object_unchecked(cls, method_id, &[
        JValue::Int(success as jint),
        JValue::Object(*output),
    ])
    .unwrap()
    .into_inner()
}

#[no_mangle]

pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_link_1check(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jstring {
    let input = env.get_string(input).unwrap();

    env.new_string(&format!("Hello, World {}!", input.to_str().unwrap()))
        .unwrap()
        .into_inner()
}
