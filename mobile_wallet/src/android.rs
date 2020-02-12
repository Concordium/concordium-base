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
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                127,
                format!("Could not read java.lang.String given as input due to {:?}", e),
            )
        }
    };
    let cstr_res = unsafe {
        let unsafe_res_ptr =
            create_id_request_and_private_data_ext(input_str.as_ptr(), &mut success);
        if (unsafe_res_ptr.is_null()) {
            return wrap_return_tuple(127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };
    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(success, str_ref),
        Err(e) => {
            wrap_return_tuple(127, &format!("Could not read CString from crypto library {:?}", e))
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1credential(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                127,
                format!("Could not read java.lang.String given as input due to {:?}", e),
            )
        }
    };
    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = create_credential_ext(input_str.as_ptr(), &mut success);
        if (unsafe_res_ptr.is_null()) {
            return wrap_return_tuple(127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };
    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(success, str_ref),
        Err(e) => {
            wrap_return_tuple(127, &format!("Could not read CString from crypto library {:?}", e))
        }
    }
}

fn wrap_return_tuple(code: u8, message: &str) -> jobject {
    let class_name = "com/concordium/mobile_wallet_lib/ReturnValue";
    let class = match env.find_class(cls_name) {
        Ok(clazz) => clazz,
        Err(e) => {
            return wrap_return_tuple(
                127,
                &format!("Can't find Java return tuple class {}", class_name),
            )
        }
    };
    let ctr_sig = "(ILjava/lang/String;)V";
    let jstr_value = match env.new_string(message) {
        Ok(new_str) => new_str,
        Err(e) => {
            return wrap_return_tuple(
                127,
                &format!(
                    "Can't wrap returned string from crypto library to a java.lang.String due to \
                     {:?}",
                    e
                ),
            )
        }
    };
    let method_id = match env.get_method_id(cls, "<init>", ctr_sig) {
        Ok(method_looked_up) => method_looked_up,
        Err(e) => {
            return wrap_return_tuple(
                127,
                &format!(
                    "Can't find constructor of (java.lang.Integer,java.lang.String) for class {} \
                     due to {:?}",
                    class_name, e
                ),
            )
        }
    };
    match env.new_object_unchecked(cls, method_id, &[
        JValue::Int(success as jint),
        JValue::Object(*output),
    ]) {
        Ok(res) => res.into_inner(),
        Err(e) => {
            return wrap_return_tuple(
                127,
                &format!("Can't create new instance of {} due to {:?}", class_name, e),
            )
        }
    }
}
