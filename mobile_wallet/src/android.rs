#![allow(non_snake_case)]
#![allow(unused_assignments)]

use crate::{
    check_account_address, combine_encrypted_amounts, create_credential, create_encrypted_transfer,
    create_id_request_and_private_data, create_pub_to_sec_transfer, create_sec_to_pub_transfer,
    create_transfer, decrypt_encrypted_amount, generate_accounts,
};
use jni::{
    objects::{JClass, JString, JValue},
    sys::{jboolean, jint, jobject},
    JNIEnv,
};
use std::ffi::CString;

#[no_mangle]
/// The JNI wrapper for the `create_id_request_and_private_data` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1id_1request_1and_1private_1data(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;

    let cstr_res = unsafe {
        let unsafe_res_ptr = create_id_request_and_private_data(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `create_credential` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1credential(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = create_credential(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `generate_accounts` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_generate_1accounts(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = generate_accounts(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `create_transfer` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1transfer(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = create_transfer(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `create_configure_delegation_transaction` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1configure_1delegation_1transaction(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr =
            create_configure_delegation_transaction(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `create_configure_baker_transaction` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1configure_1baker_1transaction(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = create_configure_baker_transaction(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `generate_baker_keys` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_generate_1baker_1keys(
    env: JNIEnv,
    _: JClass,
) -> jobject {
    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = generate_baker_keys(&mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `create_encrypted_transfer` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1encrypted_1transfer(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = create_encrypted_transfer(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `create_pub_to_sec_transfer` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1pub_1to_1sec_1transfer(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = create_pub_to_sec_transfer(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `create_sec_to_pub_transfer` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_create_1sec_1to_1pub_1transfer(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr = create_sec_to_pub_transfer(input_str.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `combine_encrypted_amounts` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_combine_1encrypted_1amounts(
    env: JNIEnv,
    _: JClass,
    input1: JString,
    input2: JString,
) -> jobject {
    let input_str_1 = match env.get_string(input1) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let input_str_2 = match env.get_string(input2) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let cstr_res = unsafe {
        let unsafe_res_ptr =
            combine_encrypted_amounts(input_str_1.as_ptr(), input_str_2.as_ptr(), &mut success);
        if unsafe_res_ptr.is_null() {
            return wrap_return_tuple(&env, 127, "Pointer returned from crypto library was NULL");
        }
        CString::from_raw(unsafe_res_ptr)
    };

    match cstr_res.to_str() {
        Ok(str_ref) => wrap_return_tuple(&env, success, str_ref),
        Err(e) => wrap_return_tuple(
            &env,
            127,
            &format!("Could not read CString from crypto library {:?}", e),
        ),
    }
}

#[no_mangle]
/// The JNI wrapper for the `decrypt_encrypted_amount` method.
/// The `input` parameter must be a properly initalized `java.lang.String` that
/// is non-null. The input must be valid JSON according to specified format.
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_decrypt_1encrypted_1amount(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jobject {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Could not read java.lang.String given as input due to {:?}",
                    e
                ),
            )
        }
    };

    let mut success: u8 = 127;
    let decrypted_amount_res: String =
        unsafe { decrypt_encrypted_amount(input_str.as_ptr(), &mut success) }.to_string();

    wrap_return_tuple(&env, success, &decrypted_amount_res)
}

#[no_mangle]
/// The JNI wrapper for the `check_account_address` method.
/// The `input` parameter must be a `java.lang.String` that is non-null.
pub extern "system" fn Java_com_concordium_mobile_1wallet_1lib_WalletKt_check_1account_1address(
    env: JNIEnv,
    _: JClass,
    input: JString,
) -> jboolean {
    let input_str = match env.get_string(input) {
        Ok(res_str) => res_str,
        Err(_) => return 0,
    };
    unsafe { check_account_address(input_str.as_ptr()) }
}

/// Method for wrapping the return value to Java
/// We use a class in Java land for returning data from Rust
/// If everything succeeds, then the `result` field will be 1 and the `output`
/// field will contain the JSON response If something fails, then the `result`
/// field will be different from 1, and the `output` field will contain the
/// error message as a string
fn wrap_return_tuple(env: &JNIEnv, code: u8, message: &str) -> jobject {
    let class_name = "com/concordium/mobile_wallet_lib/ReturnValue";
    let class = match env.find_class(class_name) {
        Ok(clazz) => clazz,
        Err(_e) => {
            return wrap_return_tuple(
                &env,
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
                &env,
                127,
                &format!(
                    "Can't wrap returned string from crypto library to a java.lang.String due to \
                     {:?}",
                    e
                ),
            )
        }
    };

    let method_id = match env.get_method_id(class, "<init>", ctr_sig) {
        Ok(method_looked_up) => method_looked_up,
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!(
                    "Can't find constructor of (java.lang.Integer,java.lang.String) for class {} \
                     due to {:?}",
                    class_name, e
                ),
            )
        }
    };

    match env.new_object_unchecked(class, method_id, &[
        JValue::Int(code as jint),
        JValue::Object(*jstr_value),
    ]) {
        Ok(res) => res.into_inner(),
        Err(e) => {
            return wrap_return_tuple(
                &env,
                127,
                &format!("Can't create new instance of {} due to {:?}", class_name, e),
            )
        }
    }
}
