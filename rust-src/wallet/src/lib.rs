#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_json;

use crypto_common::{base16_decode_string, base16_encode_string, c_char, Put};
use curve_arithmetic::*;
use dodis_yampolskiy_prf::secret as prf;
use ed25519_dalek as ed25519;
use either::Either::{Left, Right};
use id::{
    account_holder::{create_credential, generate_pio},
    ffi::AttributeKind,
    secret_sharing::Threshold,
    types::*,
};
use pairing::bls12_381::{Bls12, G1};
use pedersen_scheme::Value as PedersenValue;
use std::{cmp::max, collections::BTreeMap};

use std::ffi::{CStr, CString};

use failure::Fallible;
use rand::thread_rng;
use serde_json::{from_str, from_value, to_string, Value};

use sha2::{Digest, Sha256};

use std::rc::Rc;

type ExampleCurve = G1;

fn create_transfer_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;

    let from_address: AccountAddress = {
        match v.get("from") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'from' not present, but should be."),
        }
    };

    let to_address: AccountAddress = {
        match v.get("to") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'to' not present, but should be."),
        }
    };

    let amount: u64 = {
        match v.get("amount") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'amount' not present, but should be."),
        }
    };

    let expiry: u64 = {
        match v.get("expiry") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'expiry' not present, but should be."),
        }
    };

    let nonce: u64 = {
        match v.get("nonce") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'nonce' not present, but should be."),
        }
    };

    let keys_object = match v.get("keys").and_then(Value::as_object) {
        Some(v) => v,
        None => bail!("Field 'keys' not present or not an object, but should be."),
    };

    // NB: This needs to be consistent with scheduler assigned cost.
    let energy: u64 = 6 + 53 * keys_object.len() as u64;

    let (hash, body) = {
        let mut payload = Vec::new();
        payload.put(&3u8); // transaction type is transfer
        payload.put(&0u8); // account address to send to
        payload.put(&to_address);
        payload.put(&amount);

        let payload_size: u32 = payload.len() as u32;
        assert_eq!(payload_size, 42);

        let mut body = Vec::new();
        // this needs to match with what is in Transactions.hs
        body.put(&from_address);
        body.put(&nonce);
        body.put(&energy);
        body.put(&payload_size);
        body.put(&expiry);
        body.extend_from_slice(&payload);

        let hasher = Sha256::new().chain(&body);
        (hasher.result(), body)
    };

    let signatures = {
        let mut out = BTreeMap::new();
        for (key_index_str, value) in keys_object.iter() {
            let key_index = key_index_str.parse::<u8>()?;
            match value.as_object() {
                None => bail!("Malformed keys."),
                Some(value) => {
                    let public = match value.get("verifyKey").and_then(Value::as_str) {
                        None => bail!("Malformed keys: missing verifyKey."),
                        Some(x) => base16_decode_string(&x)?,
                    };
                    let secret = match value.get("signKey").and_then(Value::as_str) {
                        None => bail!("Malformed keys: missing signKey."),
                        Some(x) => base16_decode_string(&x)?,
                    };
                    out.insert(
                        key_index,
                        base16_encode_string(&ed25519::Keypair { secret, public }.sign(&hash)),
                    );
                }
            }
        }
        out
    };

    use hex::encode;

    let response = json!({
        "signatures": signatures,
        "transaction": encode(&body)
    });

    Ok(to_string(&response)?)
}

fn check_account_address_aux(input: &str) -> bool { input.parse::<AccountAddress>().is_ok() }

fn create_id_request_and_private_data_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;

    let ip_info: IpInfo<Bls12, ExampleCurve> = {
        match v.get("ipInfo") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'ipInfo' not present, but should be."),
        }
    };

    // FIXME: IP defined threshold
    let threshold = {
        let l = ip_info.ip_ars.ars.len();
        ensure!(l > 0, "IpInfo should have at least 1 anonymity revoker.");
        Threshold(max((l - 1) as u32, 1))
    };

    // Should be safe on iOS and Android, by calling SecRandomCopyBytes/getrandom,
    // respectively.
    let mut csprng = thread_rng();

    let prf_key = prf::SecretKey::generate(&mut csprng);

    let secret = ExampleCurve::generate_scalar(&mut csprng);
    let chi = CredentialHolderInfo::<ExampleCurve> {
        id_cred: IdCredentials {
            id_cred_sec: Rc::new(PedersenValue { value: secret }),
        },
    };

    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    // Choice of anonymity revokers, all of them in this implementation.
    let ar_identities = ip_info
        .ip_ars
        .ars
        .iter()
        .map(|x| x.ar_identity)
        .collect::<Vec<_>>();
    let context = make_context_from_ip_info(ip_info, ChoiceArParameters {
        ar_identities,
        threshold,
    })
    .ok_or_else(|| format_err!("Invalid choice of anonymity revokers. Should not happen."))?;
    let (pio, randomness) = {
        match generate_pio(&context, &aci) {
            Some(x) => x,
            None => bail!("Generating the pre-identity object failed."),
        }
    };

    let id_use_data = IdObjectUseData { aci, randomness };

    let response = json!({
        "idObjectRequest": pio,
        "privateIdObjectData": id_use_data,
    });

    Ok(to_string(&response)?)
}

fn create_credential_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;
    let ip_info: IpInfo<Bls12, ExampleCurve> = {
        match v.get("ipInfo") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'ipInfo' not present, but should be."),
        }
    };

    let global: GlobalContext<ExampleCurve> = {
        match v.get("global") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'global' not present, but should be."),
        }
    };

    let id_object: IdentityObject<Bls12, ExampleCurve, AttributeKind> =
        match v.get("identityObject") {
            Some(v) => from_value(v.clone())?,
            None => bail!("Field 'identityObject' not present, but should be."),
        };

    let id_use_data: IdObjectUseData<Bls12, ExampleCurve> = match v.get("privateIdObjectData") {
        Some(v) => from_value(v.clone())?,
        None => bail!("Field 'privateIdObjectData' not present, but should be."),
    };

    let tags: Vec<AttributeTag> = match v.get("revealedAttributes") {
        Some(v) => from_value(v.clone())?,
        None => vec![],
    };

    let acc_num: u8 = match v.get("accountNumber") {
        Some(v) => from_value(v.clone())?,
        None => bail!("Account number must be present."),
    };

    // if account data is present then use it, otherwise generate new.
    let acc_data = {
        if let Some(acc_data) = v.get("accountData") {
            match from_value(acc_data.clone()) {
                Ok(acc_data) => acc_data,
                Err(e) => bail!("Cannot decode accountData {}", e),
            }
        } else {
            let mut keys = std::collections::BTreeMap::new();
            let mut csprng = thread_rng();
            keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));

            AccountData {
                keys,
                existing: Left(SignatureThreshold(1)),
            }
        }
    };

    let mut policy_vec = std::collections::BTreeMap::new();
    for tag in tags {
        if let Some(att) = id_object.alist.alist.get(&tag) {
            if policy_vec.insert(tag, att.clone()).is_some() {
                bail!("Cannot reveal an attribute more than once.")
            }
        } else {
            bail!("Cannot reveal an attribute which is not part of the attribute list.")
        }
    }

    let policy = Policy {
        valid_to: id_object.alist.valid_to,
        created_at: id_object.alist.created_at,
        policy_vec,
        _phantom: Default::default(),
    };

    let cdi = create_credential(
        &ip_info,
        &global,
        &id_object,
        &id_use_data,
        acc_num,
        &policy,
        &acc_data,
    )?;

    let address = match acc_data.existing {
        Left(_) => AccountAddress::new(&cdi.values.reg_id),
        Right(addr) => addr,
    };

    let response = json!({
        "credential": cdi,
        "accountData": acc_data,
        "accountAddress": address,
    });
    Ok(to_string(&response)?)
}

/// # Safety
/// This function does not check that the flag pointer is not null.
unsafe fn signal_error(flag: *mut u8, err_msg: String) -> *mut c_char {
    *flag = 0;
    CString::new(err_msg)
        .expect("Error message string should be non-zero and utf8.")
        .into_raw()
}

/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe fn create_transfer_ext(input_ptr: *const c_char, success: *mut u8) -> *mut c_char {
    if input_ptr.is_null() {
        return signal_error(success, "Null pointer input.".to_owned());
    }
    let input_str = {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(e) => return signal_error(success, format!("Could not decode JSON: {}", e)),
        }
    };
    let response = create_transfer_aux(input_str);
    match response {
        Ok(s) => {
            let cstr: CString = {
                match CString::new(s) {
                    Ok(s) => s,
                    Err(e) => {
                        return signal_error(success, format!("Could not encode response: {}", e))
                    }
                }
            };
            *success = 1;
            cstr.into_raw()
        }
        Err(e) => signal_error(success, format!("Could not produce response: {}", e)),
    }
}

/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe fn create_id_request_and_private_data_ext(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    if input_ptr.is_null() {
        return signal_error(success, "Null pointer input.".to_owned());
    }
    let input_str = {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(e) => return signal_error(success, format!("Could not decode JSON: {}", e)),
        }
    };
    let response = create_id_request_and_private_data_aux(input_str);
    match response {
        Ok(s) => {
            let cstr: CString = {
                match CString::new(s) {
                    Ok(s) => s,
                    Err(e) => {
                        return signal_error(success, format!("Could not encode response: {}", e))
                    }
                }
            };
            *success = 1;
            cstr.into_raw()
        }
        Err(e) => signal_error(success, format!("Could not produce response: {}", e)),
    }
}

#[no_mangle]
/// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
/// UTF8-encoded string. The input string should contain the JSON payload of an
/// attribute list, name of id object, and the identity provider public
/// information. The return value contains a JSON object with two values, one is
/// the request for the identity object that is public, and the other is the
/// private keys and other secret values that must be kept by the user.
/// These secret values will be needed later to use the identity object.
///
/// The returned string must be freed by the caller by calling the function
/// 'free_response_string'. In case of failure the function returns an error
/// message as the response, and sets the 'success' flag to 0.
///
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_id_request_and_private_data_c(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_id_request_and_private_data_ext(input_ptr, success)
}

/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe fn create_credential_ext(input_ptr: *const c_char, success: *mut u8) -> *mut c_char {
    if input_ptr.is_null() {
        return signal_error(success, "Null pointer input.".to_owned());
    }
    let input_str = {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(e) => return signal_error(success, format!("Could not decode JSON: {}", e)),
        }
    };
    let response = create_credential_aux(input_str);
    match response {
        Ok(s) => {
            let cstr: CString = {
                match CString::new(s) {
                    Ok(s) => s,
                    Err(e) => {
                        return signal_error(success, format!("Could not encode response: {}", e))
                    }
                }
            };
            *success = 1;
            cstr.into_raw()
        }
        Err(e) => signal_error(success, format!("Could not produce response: {}", e)),
    }
}

#[no_mangle]
/// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
/// UTF8-encoded string. The returned string must be freed by the caller by
/// calling the function 'free_response_string'. In case of failure the function
/// returns an error message as the response, and sets the 'success' flag to 0.
///
/// See rust-bins/wallet-notes/README.md for the description of input and output
/// formats.
///
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_credential_c(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_credential_ext(input_ptr, success)
}

#[no_mangle]
/// # Safety
/// The input must be NUL-terminated.
pub unsafe fn check_account_address_ext(input_ptr: *const c_char) -> u8 {
    let input_str = {
        match CStr::from_ptr(input_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };
    if check_account_address_aux(input_str) {
        1
    } else {
        0
    }
}

#[no_mangle]
/// Take a pointer to a NUL-terminated UTF8-string and return whether this is
/// a correct format for a concordium address.
/// A non-zero return value signals success.
///
/// # Safety
/// The input must be NUL-terminated.
pub unsafe extern "C" fn check_account_address_c(input_ptr: *const c_char) -> u8 {
    check_account_address_ext(input_ptr)
}

#[no_mangle]
/// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
/// UTF8-encoded string. The returned string must be freed by the caller by
/// calling the function 'free_response_string'. In case of failure the function
/// returns an error message as the response, and sets the 'success' flag to 0.
///
/// See rust-bins/wallet-notes/README.md for the description of input and output
/// formats.
///
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_transfer_c(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_transfer_ext(input_ptr, success)
}

/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe fn free_response_string_ext(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe extern "C" fn free_response_string_c(ptr: *mut c_char) { free_response_string_ext(ptr) }

#[cfg(test)]
mod test {}
