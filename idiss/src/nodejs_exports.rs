use crate::*;
use nodejs_sys::*;

unsafe fn create_error(env: napi_env, err: &str) -> napi_value {
    let mut result: napi_value = std::mem::zeroed();
    match std::ffi::CString::new(err) {
        Ok(err) => {
            let mut msg: napi_value = std::mem::zeroed();
            napi_create_string_utf8(env, err.as_ptr(), err.as_bytes().len(), &mut msg);
            napi_create_error(env, std::ptr::null_mut(), msg, &mut result);
            result
        }
        Err(_) => {
            let s = std::ffi::CString::new(
                "[Internal error]: Cannot convert string to CString.".to_owned(),
            )
            .expect("Cannot fail.");
            let mut msg: napi_value = std::mem::zeroed();
            napi_create_string_utf8(env, s.as_ptr(), s.as_bytes().len(), &mut msg);
            napi_create_error(env, std::ptr::null_mut(), msg, &mut result);
            result
        }
    }
}

unsafe fn make_string(env: napi_env, value: &str) -> napi_value {
    let mut local: napi_value = std::mem::zeroed();
    let value = std::ffi::CString::new(value);
    match value {
        Ok(value) => {
            napi_create_string_utf8(env, value.as_ptr(), value.as_bytes().len(), &mut local);
            local
        }
        Err(_) => create_error(env, "[Internal error]: Cannot convert string to CString."),
    }
}

unsafe fn get_string_arg(env: napi_env, buf: napi_value) -> Option<String> {
    let mut cap = 0;
    napi_get_value_string_utf8(env, buf, std::ptr::null_mut(), 0, &mut cap);
    let mut ve: Vec<u8> = Vec::with_capacity(cap + 1); // + 1 for the NUL byte.
    let mut len = 0;
    let res = napi_get_value_string_utf8(
        env,
        buf,
        ve.as_mut_ptr() as *mut std::os::raw::c_char,
        cap + 1,
        &mut len,
    );
    if res == napi_status::napi_ok {
        ve.set_len(len);
        Some(String::from_utf8(ve).ok()?)
    } else {
        None
    }
}

// unsafe fn get_string_property(env: napi_env, obj: napi_value, name: &str) ->
// Option<String> {     let mut local: napi_value = std::mem::zeroed();
//     let name = std::ffi::CString::new(name).ok()?;
//     if napi_get_named_property(env, obj, name.as_ptr(), &mut local) !=
// napi_status::napi_ok {         None
//     } else {
//         get_string_arg(env, local)
//     }
// }

unsafe fn set_string_property(
    env: napi_env,
    obj: napi_value,
    name: &str,
    value: &str,
) -> Option<()> {
    let name = std::ffi::CString::new(name).ok()?;
    if napi_set_named_property(env, obj, name.as_ptr(), make_string(env, value))
        != napi_status::napi_ok
    {
        None
    } else {
        Some(())
    }
}

unsafe extern "C" fn validate_request_js(env: napi_env, info: napi_callback_info) -> napi_value {
    let mut buffer: [napi_value; 3] = std::mem::MaybeUninit::zeroed().assume_init();
    let mut argc = 3usize;
    let mut this: napi_value = std::mem::zeroed();
    let ret = napi_get_cb_info(
        env,
        info,
        &mut argc,
        buffer.as_mut_ptr(),
        &mut this,
        std::ptr::null_mut(),
    );
    if ret != napi_status::napi_ok {
        return create_error(env, "Cannot acquire context.");
    }
    if argc != 3 {
        return create_error(
            env,
            &format!("Expected 3 arguments, but provided {}.", argc),
        );
    }
    let ip_info = match get_string_arg(env, buffer[0]) {
        Some(arg1) => arg1,
        None => return create_error(env, "IpInfo must be given as a string."),
    };
    let ars_info = match get_string_arg(env, buffer[1]) {
        Some(arg1) => arg1,
        None => return create_error(env, "ArsInfo' must be given as a string."),
    };
    let request = match get_string_arg(env, buffer[2]) {
        Some(arg) => arg,
        None => return create_error(env, "Argument should be a string."),
    };
    let b = validate_request(&ip_info, &ars_info, &request);
    let mut ret: napi_value = std::mem::zeroed();
    if napi_get_boolean(env, b, &mut ret) != napi_status::napi_ok {
        create_error(env, "[Internal error]: Cannot create a boolean.")
    } else {
        ret
    }
}

#[no_mangle]
unsafe extern "C" fn create_identity_object_js(
    env: napi_env,
    info: napi_callback_info,
) -> napi_value {
    let mut buffer: [napi_value; 5] = std::mem::MaybeUninit::zeroed().assume_init();
    let mut argc = 5usize;
    let mut this: napi_value = std::mem::zeroed();
    let ret = napi_get_cb_info(
        env,
        info,
        &mut argc,
        buffer.as_mut_ptr(),
        &mut this,
        std::ptr::null_mut(),
    );
    if ret != napi_status::napi_ok {
        return create_error(env, "Cannot acquire context.");
    }
    if argc != 5 {
        return create_error(
            env,
            &format!("Expected 5 arguments, but provided {}.", argc),
        );
    }
    let ip_info = match get_string_arg(env, buffer[0]) {
        Some(arg1) => arg1,
        None => return create_error(env, "IpInfo must be given as a string."),
    };
    let request = match get_string_arg(env, buffer[1]) {
        Some(arg) => arg,
        None => return create_error(env, "Request must be given as a string."),
    };
    let alist = match get_string_arg(env, buffer[2]) {
        Some(arg1) => arg1,
        None => return create_error(env, "The attribute list must be given as a string."),
    };
    let ip_private_key = match get_string_arg(env, buffer[3]) {
        Some(arg1) => arg1,
        None => return create_error(env, "The private key must be given as a string."),
    };
    let ip_cdi_private_key = match get_string_arg(env, buffer[4]) {
        Some(arg1) => arg1,
        None => return create_error(env, "The CDI private key must be given as a string."),
    };

    let e = create_identity_object(
        &ip_info,
        &request,
        &alist,
        &ip_private_key,
        &ip_cdi_private_key,
    );
    match e {
        Ok((idobj, ar_record, icdi)) => {
            let mut ret_obj: napi_value = std::mem::zeroed();
            if napi_create_object(env, &mut ret_obj) != napi_status::napi_ok {
                return create_error(env, "Cannot make return object.");
            }
            if set_string_property(env, ret_obj, "idObject", &idobj).is_none() {
                return create_error(env, "Cannot set 'idObject' property");
            }
            if set_string_property(env, ret_obj, "arRecord", &ar_record).is_none() {
                return create_error(env, "Cannot set 'arRecord' property");
            }
            if set_string_property(env, ret_obj, "initialAccount", &icdi).is_none() {
                return create_error(env, "Cannot set 'initialAccount' property");
            }
            ret_obj
        }
        Err(err) => create_error(env, &err),
    }
}

#[no_mangle]
unsafe extern "C" fn napi_register_module_v1(env: napi_env, exports: napi_value) -> napi_value {
    let vr = std::ffi::CString::new("validate_request").expect("CString::new failed");
    let mut local: napi_value = std::mem::zeroed();
    if napi_create_function(
        env,
        vr.as_ptr(),
        "validate_request".len(),
        Some(validate_request_js),
        std::ptr::null_mut(),
        &mut local,
    ) != napi_status::napi_ok
    {
        return create_error(env, "Cannot create function 'validate_request'.");
    };
    if napi_set_named_property(env, exports, vr.as_ptr(), local) != napi_status::napi_ok {
        return create_error(env, "Could not assing 'validate_request' property.");
    }

    let create = std::ffi::CString::new("create_identity_object").expect("CString::new failed");
    let mut local_create: napi_value = std::mem::zeroed();
    if napi_create_function(
        env,
        create.as_ptr(),
        "create_identity_object".len(),
        Some(create_identity_object_js),
        std::ptr::null_mut(),
        &mut local_create,
    ) != napi_status::napi_ok
    {
        return create_error(env, "Cannot create 'create_identity_object' function.");
    }

    if napi_set_named_property(env, exports, create.as_ptr(), local_create) != napi_status::napi_ok
    {
        return create_error(env, "Could not assing 'create_identity_object' property.");
    }

    exports
}
