#[macro_export]
macro_rules! macro_derive_to_bytes {
    ($function_name:ident, $type:ty) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            input_ptr: *mut $type,
            output_len: *mut size_t,
        ) -> *const u8 {
            let input = from_ptr!(input_ptr);
            let bytes = input.to_bytes();
            unsafe { *output_len = bytes.len() as size_t }
            let ret_ptr = bytes.as_ptr();
            ::std::mem::forget(bytes);
            ret_ptr
        }
    };
    ($function_name:ident, $type:ty, $f:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            input_ptr: *mut $type,
            output_len: *mut size_t,
        ) -> *const u8 {
            let input = from_ptr!(input_ptr);
            let bytes = $f(&input);
            unsafe { *output_len = bytes.len() as size_t }
            let ret_ptr = bytes.as_ptr();
            ::std::mem::forget(bytes);
            ret_ptr
        }
    };
}

#[macro_export]
macro_rules! macro_derive_from_bytes {
    ($function_name:ident, $type:ty, $from:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(input_bytes: *mut u8, input_len: size_t) -> *const $type {
            let len = input_len as usize;
            let bytes = slice_from_c_bytes!(input_bytes, len);
            let e = $from(&bytes);
            match e {
                Ok(r) => Box::into_raw(Box::new(r)),
                Err(_) => ::std::ptr::null(),
            }
        }
    };
}

#[macro_export]
macro_rules! macro_free_ffi {
    ($function_name:ident, $type:ty) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(ptr: *mut $type) {
            if ptr.is_null() {
                return;
            }
            unsafe {
                Box::from_raw(ptr);
            }
        }
    };
}

#[macro_export]
macro_rules! from_ptr {
    ($ptr:expr) => {{
        assert!(!$ptr.is_null());
        unsafe { &*$ptr }
    }};
}

#[macro_export]
macro_rules! slice_from_c_bytes_worker {
    ($cstr:expr, $length:expr, $null_ptr_error:expr, $reader:expr) => {{
        assert!(!$cstr.is_null(), $null_ptr_error);
        unsafe { $reader($cstr, $length) }
    }};
}

#[macro_export]
macro_rules! slice_from_c_bytes {
    ($cstr:expr, $length:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, "Null pointer.", slice::from_raw_parts)
    };
    ($cstr:expr, $length:expr, $null_ptr_error:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, $null_ptr_error, slice::from_raw_parts)
    };
}

#[macro_export]
macro_rules! mut_slice_from_c_bytes {
    ($cstr:expr, $length:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, "Null pointer.", slice::from_raw_parts_mut)
    };
    ($cstr:expr, $length:expr, $null_ptr_error:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, $null_ptr_error, slice::from_raw_parts_mut)
    };
}
