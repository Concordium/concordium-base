use crypto_common::{base16_decode_string, types::TransactionTime, Versioned, VERSION_0};
use curve_arithmetic::*;
use id::{
    constants::ArCurve,
    ffi::AttributeKind,
    identity_provider::{
        create_initial_cdi, sign_identity_object, validate_request as ip_validate_request,
    },
    types::*,
};
use pairing::bls12_381::{Bls12, G1};
use serde_json::{from_str, from_value, ser::to_string, Value};
use std::fmt::Display;

type ExampleCurve = G1;
type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;

// Parse an IpInfo taking into account the version.
// For now only version 0 is supported.
fn parse_exact_versioned_ip_info(ip_info_str: &str) -> Result<IpInfo<Bls12>, String> {
    let v: Versioned<IpInfo<Bls12>> = from_str(ip_info_str).map_err(show_err)?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        Err(show_err("Incorrect IpInfo version."))
    }
}

// Parse anonymity revokers taking into account the version.
// For now only version 0 is supported.
fn parse_exact_versioned_ars_infos(ars_info_str: &str) -> Result<ArInfos<ArCurve>, String> {
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
) -> Result<GlobalContext<ExampleCurve>, String> {
    let v: Versioned<GlobalContext<ExampleCurve>> =
        from_str(global_context_str).map_err(show_err)?;
    if v.version == VERSION_0 {
        Ok(v.value)
    } else {
        Err(show_err("Incorrect Global context version."))
    }
}

pub fn validate_request(
    global_context_str: &str,
    ip_info_str: &str,
    ars_infos_str: &str,
    request_str: &str,
) -> (bool, String) {
    let global_context = match parse_exact_versioned_global_context(global_context_str) {
        Ok(v) => v,
        Err(_) => return (false, String::new()),
    };

    let ip_info = match parse_exact_versioned_ip_info(ip_info_str) {
        Ok(v) => v,
        Err(_) => return (false, String::new()),
    };

    let ars_infos = match parse_exact_versioned_ars_infos(ars_infos_str) {
        Ok(v) => v,
        Err(_) => return (false, String::new()),
    };

    let request: PreIdentityObject<Bls12, ExampleCurve> = {
        let v: Value = match from_str(request_str) {
            Ok(v) => v,
            Err(_) => return (false, String::new()),
        };
        let pre_id_obj_value = {
            match v.get("idObjectRequest") {
                Some(v) => v,
                None => return (false, String::new()),
            }
        };

        if let Ok(v) = from_value::<Versioned<PreIdentityObject<_, _>>>(pre_id_obj_value.clone()) {
            if v.version == VERSION_0 {
                v.value
            } else {
                return (false, String::new());
            }
        } else {
            return (false, String::new());
        }
    };

    let context = IpContext {
        ip_info:        &ip_info,
        ars_infos:      &ars_infos.anonymity_revokers,
        global_context: &global_context,
    };

    let addr = to_string(&serde_json::json!(AccountAddress::new(
        &request.pub_info_for_ip.reg_id
    )))
    .expect("JSON serialization of accounts cannot fail.");
    let vf = ip_validate_request(&request, context);
    if let Ok(()) = vf {
        (true, addr)
    } else {
        (false, addr)
    }
}

fn show_err<D: Display>(err: D) -> String { format!("ERROR: {}", err) }

/// Create an identity object, the anonymity revocation record, and the initial
/// account object.
pub fn create_identity_object(
    ip_info_str: &str,
    request_str: &str,
    alist_str: &str,
    expiry: u64,
    ip_private_key_str: &str,
    ip_cdi_private_key_str: &str,
) -> Result<(String, String, String), String> {
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
    let ip_cdi_private_key: ed25519_dalek::SecretKey =
        base16_decode_string(ip_cdi_private_key_str).map_err(show_err)?;

    let signature = sign_identity_object(&request.value, &ip_info, &alist, &ip_private_key)
        .map_err(show_err)?;

    let ar_record = Versioned::new(VERSION_0, AnonymityRevocationRecord {
        id_cred_pub:  request.value.pub_info_for_ip.id_cred_pub,
        ar_data:      request.value.ip_ar_data.clone(),
        max_accounts: alist.max_accounts,
        threshold:    request.value.choice_ar_parameters.threshold,
    });

    let icdi = create_initial_cdi(
        &ip_info,
        request.value.pub_info_for_ip.clone(),
        &alist,
        TransactionTime::from(expiry),
        &ip_cdi_private_key,
    );

    // address of the account that will be created.
    let id = IdentityObject {
        pre_identity_object: request.value,
        alist,
        signature,
    };
    let vid = Versioned::new(VERSION_0, id);
    let id_obj =
        to_string(&vid).expect("JSON serialization of versioned identity objects should not fail.");
    let ar_record = to_string(&ar_record)
        .expect("JSON serialization of anonymity revocation records should not fail.");

    let addr = AccountAddress::new(&vid.value.pre_identity_object.pub_info_for_ip.reg_id);

    let message = AccountCredentialMessage {
        message_expiry: TransactionTime { seconds: expiry },
        credential:     AccountCredential::Initial::<id::constants::IpPairing, _, _> { icdi },
    };
    let v_initial_cdi = Versioned::new(VERSION_0, message);

    let response = serde_json::json!({
        "request": v_initial_cdi,
        "accountAddress": addr
    });
    let init_acc =
        to_string(&response).expect("JSON serialization of initial credentials should not fail.");
    Ok((id_obj, ar_record, init_acc))
}

#[cfg(feature = "nodejs")]
mod nodejs_exports;
