use pairing::bls12_381::{Bls12, G1};

use crypto_common::{base16_decode_string, version::*};
use curve_arithmetic::*;
use id::{
    constants::ArCurve,
    ffi::AttributeKind,
    identity_provider::{
        create_initial_cdi, sign_identity_object, validate_request as ip_validate_request,
    },
    types::*,
};
use serde_json::{from_str, from_value, ser::to_string, Value};
use std::fmt::Display;
use wasm_bindgen::prelude::*;

type ExampleCurve = G1;
type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;

// Parse an IpInfo taking into account the version.
// For now only version 0 is supported.
fn parse_exact_versioned_ip_info(ip_info_str: &str) -> Result<IpInfo<Bls12>, JsValue> {
    let v: Versioned<IpInfo<Bls12>> = from_str(ip_info_str).map_err(show_err)?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        Err(show_err("Incorrect IpInfo version."))
    }
}

// Parse anonymity revokers taking into account the version.
// For now only version 0 is supported.
fn parse_exact_versioned_ars_infos(ars_info_str: &str) -> Result<ArInfos<ArCurve>, JsValue> {
    let v: Versioned<ArInfos<ArCurve>> = from_str(ars_info_str).map_err(show_err)?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        Err(show_err("Incorrect Ars version."))
    }
}

// Parse an GlobalContext taking into account the version.
// For now only version 0 is supported.
fn parse_exact_versioned_global_context(
    global_context_str: &str,
) -> Result<GlobalContext<ExampleCurve>, JsValue> {
    let v: Versioned<GlobalContext<ExampleCurve>> =
        from_str(global_context_str).map_err(show_err)?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        Err(show_err("Incorrect Global context version."))
    }
}

#[wasm_bindgen]
pub fn validate_request(
    global_context_str: &str,
    ip_info_str: &str,
    ars_infos_str: &str,
    request_str: &str,
) -> bool {
    let ip_info = match parse_exact_versioned_ip_info(ip_info_str) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let ars_infos = match parse_exact_versioned_ars_infos(ars_infos_str) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let global_context = match parse_exact_versioned_global_context(global_context_str) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let request: PreIdentityObject<Bls12, ExampleCurve> = {
        let v: Value = match from_str(request_str) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let pre_id_obj_value = {
            match v.get("idObjectRequest") {
                Some(v) => v,
                None => return false,
            }
        };

        if let Ok(v) = from_value::<Versioned<PreIdentityObject<_, _>>>(pre_id_obj_value.clone()) {
            if v.version == VERSION_0 {
                v.value
            } else {
                return false;
            }
        } else {
            return false;
        }
    };

    let context = IPContext {
        ip_info:        &ip_info,
        ars_infos:      &ars_infos.anonymity_revokers,
        global_context: &global_context,
    };

    let vf = ip_validate_request(&request, context);
    vf.is_ok()
}

fn show_err<D: Display>(err: D) -> JsValue { JsValue::from_str(&format!("ERROR: {}", err)) }

#[wasm_bindgen]
pub fn create_identity_object(
    ip_info_str: &str,
    request_str: &str,
    alist_str: &str,
    ip_private_key_str: &str,
) -> Result<String, JsValue> {
    let ip_info = parse_exact_versioned_ip_info(ip_info_str)?;

    let request: Versioned<PreIdentityObject<Bls12, ExampleCurve>> = {
        let v: Value = from_str(request_str).map_err(show_err)?;
        let pre_id_obj_value = v
            .get("idObjectRequest")
            .ok_or_else(|| show_err("'idObjectRequest' field not present."))?;
        from_value(pre_id_obj_value.clone()).map_err(show_err)?
    };

    if request.version != VERSION_0 {
        return Err(show_err("Incorrect request version."));
    }

    let alist: ExampleAttributeList = from_str(alist_str).map_err(show_err)?;

    let ip_private_key: ps_sig::SecretKey<Bls12> =
        base16_decode_string(ip_private_key_str).map_err(show_err)?;

    let signature = sign_identity_object(&request.value, &ip_info, &alist, &ip_private_key)
        .map_err(show_err)?;

    let id = IdentityObject {
        pre_identity_object: request.value,
        alist,
        signature,
    };
    let vid = Versioned::new(VERSION_0, id);
    Ok(to_string(&vid).expect("JSON serialization of versioned identity objects should not fail."))
}

#[wasm_bindgen]
pub fn create_initial_credential(
    ip_info_str: &str,
    request_str: &str,
    alist_str: &str,
    ip_cdi_secret_key_str: &str,
) -> Result<String, JsValue> {
    let alist: ExampleAttributeList = from_str(alist_str).map_err(show_err)?;

    let request: Versioned<PreIdentityObject<Bls12, ExampleCurve>> = {
        let v: Value = from_str(request_str).map_err(show_err)?;
        let pre_id_obj_value = v
            .get("idObjectRequest")
            .ok_or_else(|| show_err("'idObjectRequest' field not present."))?;
        from_value(pre_id_obj_value.clone()).map_err(show_err)?
    };

    if request.version != VERSION_0 {
        return Err(show_err("Incorrect request version."));
    }

    let pub_info_for_ip = request.value.pub_info_for_ip;
    let ip_info = parse_exact_versioned_ip_info(ip_info_str)?;

    let ip_cdi_secret_key: ed25519_dalek::SecretKey =
        base16_decode_string(ip_cdi_secret_key_str).map_err(show_err)?;
    let addr = AccountAddress::new(&pub_info_for_ip.reg_id);
    let initial_cdi = create_initial_cdi(&ip_info, pub_info_for_ip, &alist, &ip_cdi_secret_key);

    let v_initial_cdi = Versioned::new(VERSION_0, AccountCredential::Initial::<
        id::constants::IpPairing,
        _,
        _,
    > {
        icdi: initial_cdi,
    });

    let response = serde_json::json!({
        "request": v_initial_cdi,
        "accountAddress": addr
    });
    Ok(to_string(&response)
        .expect("JSON serialization of versioned initial credential should not fail."))
}

#[wasm_bindgen]
pub fn create_anonymity_revocation_record(
    request_str: &str,
    max_accounts: u8,
) -> Result<String, JsValue> {
    let request: Versioned<PreIdentityObject<Bls12, ExampleCurve>> = {
        let v: Value = from_str(request_str).map_err(show_err)?;
        let pre_id_obj_value = v
            .get("idObjectRequest")
            .ok_or_else(|| show_err("'idObjectRequest' field not present."))?;
        from_value(pre_id_obj_value.clone()).map_err(show_err)?
    };
    if request.version != VERSION_0 {
        return Err(show_err("Incorrect request version."));
    }

    let ar_record = AnonymityRevocationRecord {
        id_cred_pub: request.value.pub_info_for_ip.id_cred_pub,
        ar_data: request.value.ip_ar_data,
        max_accounts,
    };
    Ok(to_string(&ar_record)
        .expect("JSON serialization of anonymity revocation records should not fail."))
}
