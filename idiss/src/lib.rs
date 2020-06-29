use pairing::bls12_381::{Bls12, G1};

use crypto_common::base16_decode_string;

use curve_arithmetic::*;
use id::{
    ffi::AttributeKind,
    identity_provider::{sign_identity_object, validate_request as ip_validate_request},
    types::*,
};

use serde_json::{from_str, from_value, ser::to_string, Value};

use wasm_bindgen::prelude::*;

use std::fmt::Display;

type ExampleCurve = G1;
type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;

fn parse_ip_info(ip_info_str: &str) -> Result<IpInfo<Bls12, ExampleCurve>, JsValue> {
    let v: Value = from_str(ip_info_str).map_err(show_err)?;
    let ip_info_v = v
        .get("ipInfo")
        .ok_or_else(|| show_err("Field 'ipInfo' must be present."))?;
    from_value(ip_info_v.clone()).map_err(show_err)
}

#[wasm_bindgen]
pub fn validate_request(ip_info_str: &str, request_str: &str) -> bool {
    let ip_info = match parse_ip_info(ip_info_str) {
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

        if let Ok(v) = from_value(pre_id_obj_value.clone()) {
            v
        } else {
            return false;
        }
    };

    let vf = ip_validate_request(&request, &ip_info);
    vf.is_ok()
}

fn show_err<D: Display>(err: D) -> JsValue {
    JsValue::from_str(&format!("ERROR: {}", err))
}

#[wasm_bindgen]
pub fn create_identity_object(
    ip_info_str: &str,
    request_str: &str,
    alist_str: &str,
    ip_private_key_str: &str,
) -> Result<String, JsValue> {
    let ip_info = parse_ip_info(ip_info_str)?;

    let request: PreIdentityObject<Bls12, ExampleCurve> = {
        let v: Value = from_str(request_str).map_err(show_err)?;
        let pre_id_obj_value = v
            .get("idObjectRequest")
            .ok_or_else(|| show_err("'idObjectRequest' field not present."))?;
        from_value(pre_id_obj_value.clone()).map_err(show_err)?
    };

    let alist: ExampleAttributeList = from_str(alist_str).map_err(show_err)?;

    let ip_private_key: ps_sig::SecretKey<Bls12> =
        base16_decode_string(ip_private_key_str).map_err(show_err)?;

    let signature =
        sign_identity_object(&request, &ip_info, &alist, &ip_private_key).map_err(show_err)?;

    let ret = IdentityObject {
        pre_identity_object: request,
        alist,
        signature,
    };
    Ok(to_string(&ret).expect("JSON serialization of identity objects should not fail."))
}

#[wasm_bindgen]
pub fn create_anonymity_revocation_record(request_str: &str) -> Result<String, JsValue> {
    let request: PreIdentityObject<Bls12, ExampleCurve> = {
        let v: Value = from_str(request_str).map_err(show_err)?;
        let pre_id_obj_value = v
            .get("idObjectRequest")
            .ok_or_else(|| show_err("'idObjectRequest' field not present."))?;
        from_value(pre_id_obj_value.clone()).map_err(show_err)?
    };
    let ar_record = AnonymityRevocationRecord {
        id_cred_pub: request.id_cred_pub,
        ar_data: request.ip_ar_data,
    };
    Ok(to_string(&ar_record)
        .expect("JSON serialization of anonymity revocation records should not fail."))
}
