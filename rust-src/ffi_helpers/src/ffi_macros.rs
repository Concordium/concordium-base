#[macro_export]
macro_rules! macro_derive_binary {
    (Arc $function_name:ident, $type:ty, $f:expr) => {
        macro_derive_binary!($function_name, $type, $f, const);
    };
    (Box $function_name:ident, $type:ty, $f:expr) => {
        macro_derive_binary!($function_name, $type, $f, mut);
    };
    ($function_name:ident, $type:ty, $f:expr, $mod:tt) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        extern "C" fn $function_name(one_ptr: *$mod $type, two_ptr: *$mod $type) -> u8 {
            let one = from_ptr!(one_ptr);
            let two = from_ptr!(two_ptr);
            u8::from($f(one, two))
        }
    };
}

/// Macro to create byte arrays from objects.
///
/// If the value was created through a `Box`, this macro should be called
/// starting with the keyword `Box`. If it was created through an `Arc`, this
/// macro should be called starting with the keyword `Arc`.
#[macro_export]
macro_rules! macro_derive_to_bytes {
    (Arc $function_name:ident, $type:ty) => {
        macro_derive_to_bytes!($function_name, $type, const);
    };
    (Box $function_name:ident, $type:ty) => {
        macro_derive_to_bytes!($function_name, $type, mut);
    };
    ($function_name:ident, $type:ty, $mod:tt) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        extern "C" fn $function_name(
            input_ptr: *$mod $type,
            output_len: *mut size_t,
        ) -> *mut u8 {
            let input = from_ptr!(input_ptr);
            let mut bytes = to_bytes(input);
            unsafe { *output_len = bytes.len() as size_t }
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
    };
    (Arc $function_name:ident, $type:ty, $f:expr) => {
        macro_derive_to_bytes!($function_name, $type, $f, const);
    };
    (Box $function_name:ident, $type:ty, $f:expr) => {
        macro_derive_to_bytes!($function_name, $type, $f, mut);
    };
    ($function_name:ident, $type:ty, $f:expr, $mod:tt) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        extern "C" fn $function_name(
            input_ptr: *$mod $type,
            output_len: *mut size_t,
        ) -> *mut u8 {
            let input = from_ptr!(input_ptr);
            let mut bytes = $f(&input);
            unsafe { *output_len = bytes.len() as size_t }
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
    };
}

/// Macro to create rust objects from bytes.
///
/// If the value will be created through a `Box`, this macro should be called
/// starting with the keyword `Box`. If it will be created through an `Arc`,
/// this macro should be called starting with the keyword `Arc`.
#[macro_export]
macro_rules! macro_derive_from_bytes {
    (Arc $function_name:ident, $type:ty) => {
        macro_derive_from_bytes!($function_name, $type, const, std::ptr::null(), |x| {
            Arc::into_raw(Arc::new(x))
        });
    };
    (Box $function_name:ident, $type:ty) => {
        macro_derive_from_bytes!($function_name, $type, mut, std::ptr::null_mut(), |x| {
            Box::into_raw(Box::new(x))
        });
    };
    ($function_name:ident, $type:ty, $mod:tt, $val:expr, $fr:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        extern "C" fn $function_name(input_bytes: *const u8,
            input_len: size_t,
        ) -> *$mod $type {
            use std::io::Cursor;
            let len = input_len as usize;
            let bytes = slice_from_c_bytes!(input_bytes, len);
            let e = from_bytes::<$type,_>(&mut Cursor::new(&bytes));
            match e {
                Ok(r) => $fr(r),
                Err(_) => $val,
            }
        }
    };
}

/// Macro to create rust objects from bytes.
///
/// If the value will be created through a `Box`, this macro should be called
/// starting with the keyword `Box`. If it will be created through an `Arc`,
/// this macro should be called starting with the keyword `Arc`.
#[macro_export]
macro_rules! macro_derive_from_bytes_no_cursor {
    (Arc $function_name:ident, $type:ty, $from:expr) => {
        macro_derive_from_bytes_no_cursor!($function_name, $type, $from, const, std::ptr::null(), |x| {
            Arc::into_raw(Arc::new(x))
        });};
    (Box $function_name:ident, $type:ty, $from:expr) => {
        macro_derive_from_bytes_no_cursor!($function_name, $type, $from, mut, std::ptr::null_mut(), |x| {
            Box::into_raw(Box::new(x))
        });
    };
    ($function_name:ident, $type:ty, $from:expr, $mod:tt, $val:expr, $fr:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        extern "C" fn $function_name(input_bytes: *const u8,
            input_len: size_t,
        ) -> *$mod $type {
            let len = input_len as usize;
            let bytes = slice_from_c_bytes!(input_bytes, len);
            let e = $from(&bytes);
            match e {
                Ok(r) => $fr(r),
                Err(_) => $val,
            }
        }
    };
}

#[macro_export]
macro_rules! macro_generate_commitment_key {
    ($function_name:ident, $type:ty, $generator:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        extern "C" fn $function_name(n: size_t) -> *mut $type {
            let mut csprng = thread_rng();
            Box::into_raw(Box::new($generator(n, &mut csprng)))
        }
    };
}

/// Macro to deallocate rust pointers.
///
/// If the value was created through a `Box`, this macro should be called
/// starting with the keyword `Box`. If it was created through an `Arc`, this
/// macro should be called starting with the keyword `Arc`.
#[macro_export]
macro_rules! macro_free_ffi {
    (Arc $function_name:ident, $t:ty) => {
        macro_free_ffi!($function_name, $t, const, Arc::from_raw);
    };
    (Box $function_name:ident, $t:ty) => {
        macro_free_ffi!($function_name, $t, mut, Box::from_raw);
    };
    ($function_name:ident, $t:ty, $mod:tt, $fr:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        extern "C" fn $function_name(ptr: *$mod $t) {
            if ptr.is_null() {
                return;
            }
            unsafe {
                let v = $fr(ptr);
                drop(v);
            }
        }
    };
}

#[macro_export]
macro_rules! from_ptr {
    ($ptr:expr) => {{
        debug_assert!(!$ptr.is_null());
        unsafe { &*$ptr }
    }};
}

#[macro_export]
macro_rules! slice_from_c_bytes_worker {
    ($cstr:expr, $length:expr, $null_ptr_error:expr, $reader:expr) => {{
        if $length != 0 {
            debug_assert!(!$cstr.is_null(), $null_ptr_error);
            unsafe { $reader($cstr, $length) }
        } else {
            &[]
        }
    }};
}

#[macro_export]
macro_rules! slice_from_c_bytes {
    ($cstr:expr, $length:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, "Null pointer.", std::slice::from_raw_parts)
    };
    ($cstr:expr, $length:expr, $null_ptr_error:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, $null_ptr_error, std::slice::from_raw_parts)
    };
}

#[macro_export]
macro_rules! mut_slice_from_c_bytes_worker {
    ($cstr:expr, $length:expr, $null_ptr_error:expr, $reader:expr) => {{
        if $length != 0 {
            debug_assert!(!$cstr.is_null(), $null_ptr_error);
            unsafe { $reader($cstr, $length) }
        } else {
            &mut []
        }
    }};
}

#[macro_export]
macro_rules! mut_slice_from_c_bytes {
    ($cstr:expr, $length:expr) => {
        mut_slice_from_c_bytes_worker!(
            $cstr,
            $length,
            "Null pointer.",
            std::slice::from_raw_parts_mut
        )
    };
    ($cstr:expr, $length:expr, $null_ptr_error:expr) => {
        mut_slice_from_c_bytes_worker!(
            $cstr,
            $length,
            $null_ptr_error,
            std::slice::from_raw_parts_mut
        )
    };
}

#[macro_export]
macro_rules! macro_derive_to_json {
    ($function_name:ident, $type:ty) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            input_ptr: *mut $type,
            output_len: *mut size_t,
        ) -> *mut u8 {
            let input = from_ptr!(input_ptr);
            // unwrap is OK here since we construct well-formed json.
            let mut bytes = serde_json::to_vec(&input).unwrap().into_boxed_slice();
            unsafe { *output_len = bytes.len() as size_t }
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
    };
    ($function_name:ident, $type:ty, $f:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            input_ptr: *mut $type,
            output_len: *mut size_t,
        ) -> *mut u8 {
            let input = from_ptr!(input_ptr);
            // unwrap is OK here since we construct well-formed json.
            let mut bytes = serde_json::to_vec(&($f(&input))).unwrap();
            unsafe { *output_len = bytes.len() as size_t }
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
    };
}

#[macro_export]
macro_rules! macro_derive_from_json {
    ($function_name:ident, $type:ty) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(input_bytes: *mut u8, input_len: size_t) -> *const $type {
            let len = input_len as usize;
            let bytes = slice_from_c_bytes!(input_bytes, len);
            match serde_json::from_slice::<'_, $type>(&bytes) {
                Err(_) => return ::std::ptr::null(),
                Ok(v) => Box::into_raw(Box::new(v)),
            }
        }
    };
}
