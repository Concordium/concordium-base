#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_json;

use curve_arithmetic::curve_arithmetic::*;
use dodis_yampolskiy_prf::secret as prf;
use id::{
    account_holder::generate_pio, ffi::AttributeKind, identity_provider::verify_credentials,
    secret_sharing::Threshold, types::*,
};
use pairing::bls12_381::{Bls12, G1};
use pedersen_scheme::Value as PedersenValue;

use std::cmp::max;

use libc::c_char;
use std::ffi::{CStr, CString};

use failure::Fallible;
use rand::thread_rng;
use serde_json::{from_str, from_value, to_string, to_value, Value};

type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;
type ExampleCurve = G1;

fn create_id_request_and_private_data_aux(input: &str) -> Fallible<String> {
    let v: Value = from_str(input)?;
    let name = {
        match v.get("name").and_then(Value::as_str) {
            Some(v) => v.to_owned(),
            None => bail!("Field 'name' must be present and be a string value."),
        }
    };

    let attributes: ExampleAttributeList = {
        match v.get("attributes") {
            Some(v) => match from_value(v.clone()) {
                Ok(v) => v,
                Err(e) => bail!("Could not decode attributes: {}", e),
            },
            None => bail!("Field 'attributes' not present, but should be."),
        }
    };

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
        id_ah:   name,
        id_cred: IdCredentials {
            id_cred_sec: PedersenValue { value: secret },
        },
    };

    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
        attributes,
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
    });
    let (pio, randomness) = generate_pio(&context, &aci);

    let id_use_data = IdObjectUseData { aci, randomness };

    let response = json!({
        "idObjectRequest": pio,
        "privateIdObjectData": id_use_data,
    });

    Ok(to_string(&response)?)
}

// Add data to the attribute list if needed. This is just to simulate the fact
// that not all attributes are needed.
fn dummy_process_alist(attributes: &mut ExampleAttributeList) {
    let alist = &mut attributes.alist;
    let len = ATTRIBUTE_NAMES.len();
    // fill in the missing pieces with dummy values.
    for i in 0..len {
        let idx = AttributeTag::from(i as u8);
        if alist.get(&idx).is_none() {
            let _ = alist.insert(idx, AttributeKind::from((i + 10) as u64));
        }
    }
}

pub fn sign_id_object(ip_data: &IpData<Bls12, ExampleCurve>, v: &str) -> Fallible<Value> {
    let v: Value = match from_str(v) {
        Ok(v) => v,
        Err(e) => bail!("Cannot decode input request: {}", e),
    };
    let id_obj_value = {
        match v.get("idObjectRequest") {
            Some(v) => v.clone(),
            None => bail!("Field 'idObjectRequest' not present but should be."),
        }
    };
    let mut request: PreIdentityObject<Bls12, ExampleCurve, AttributeKind> =
        from_value(id_obj_value)?;
    // We need to potentially add to the attribute list, which we abstract
    dummy_process_alist(&mut request.alist);
    let vf = verify_credentials(&request, &ip_data.public_ip_info, &ip_data.ip_private_key);
    match vf {
        Ok(signature) => {
            let id_object = IdentityObject {
                pre_identity_object: request,
                signature,
            };
            Ok(to_value(&id_object)?)
        }
        Err(e) => bail!("Could not generate signature because {:?}.", e),
    }
}

/// # Safety
/// This function does not check that the flag pointer is not null.
unsafe fn signal_error(flag: *mut u8, err_msg: String) -> *mut c_char {
    *flag = 0;
    CString::new(err_msg)
        .expect("Error message string should be non-zero and utf8.")
        .into_raw()
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
pub unsafe extern "C" fn create_id_request_and_private_data(
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
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe extern "C" fn free_response_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(test)]
mod test {}
