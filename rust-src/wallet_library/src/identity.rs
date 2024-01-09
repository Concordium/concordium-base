use anyhow::{bail, ensure, Result};
use concordium_base::{
    common::*,
    id::{
        account_holder::{generate_id_recovery_request, generate_pio_v1},
        constants,
        constants::ArCurve,
        dodis_yampolskiy_prf as prf,
        pedersen_commitment::Value as PedersenValue,
        secret_sharing::Threshold,
        types::*,
    },
};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use serde_json::{json, to_string};
use std::collections::BTreeMap;

type JsonString = String;

/// Defines the JSON structure that matches the output of the function
/// generating the identity objcect request.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityObjectRequestV1 {
    id_object_request: Versioned<PreIdentityObjectV1<constants::IpPairing, ArCurve>>,
}

/// Required input for generating an identity object request.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRequestInput {
    ip_info:             IpInfo<constants::IpPairing>,
    global_context:      GlobalContext<constants::ArCurve>,
    ars_infos:           BTreeMap<ArIdentity, ArInfo<constants::ArCurve>>,
    ar_threshold:        u8,
    prf_key:             prf::SecretKey<ArCurve>,
    id_cred_sec:         PedersenValue<ArCurve>,
    // The blinding_randomness does not have a serde serializer / deserializer. Therefore
    // it is just a String here and manually handled.
    blinding_randomness: String,
}

/// Creates an identity object request.
pub fn create_id_request_v1_aux(input: IdRequestInput) -> Result<JsonString> {
    let prf_key: prf::SecretKey<ArCurve> = input.prf_key;
    let id_cred_sec: PedersenValue<ArCurve> = input.id_cred_sec;
    let id_cred: IdCredentials<ArCurve> = IdCredentials { id_cred_sec };
    let sig_retrieval_randomness: concordium_base::id::ps_sig::SigRetrievalRandomness<
        constants::IpPairing,
    > = base16_decode_string(&input.blinding_randomness)?;

    let num_of_ars = input.ars_infos.len();
    ensure!(input.ar_threshold > 0, "arThreshold must be at least 1.");
    ensure!(
        num_of_ars >= usize::from(input.ar_threshold),
        "Number of anonymity revokers in arsInfos should be at least arThreshold."
    );

    let threshold = Threshold(input.ar_threshold);
    let chi = CredentialHolderInfo::<ArCurve> { id_cred };
    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    let context = IpContext::new(&input.ip_info, &input.ars_infos, &input.global_context);
    let id_use_data = IdObjectUseData {
        aci,
        randomness: sig_retrieval_randomness,
    };
    let (pio, _) = {
        match generate_pio_v1(&context, threshold, &id_use_data) {
            Some(x) => x,
            None => bail!("Generating the pre-identity object failed."),
        }
    };

    let result = IdentityObjectRequestV1 {
        id_object_request: Versioned::new(VERSION_0, pio),
    };
    let response = json!(result);
    Ok(to_string(&response)?)
}

/// Required input for generating an identity recovery request.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRecoveryRequestInput {
    ip_info:        IpInfo<constants::IpPairing>,
    global_context: GlobalContext<constants::ArCurve>,
    timestamp:      u64,
    id_cred_sec:    PedersenValue<ArCurve>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRecoveryRequestOut {
    id_recovery_request: Versioned<IdRecoveryRequest<ArCurve>>,
}

/// Create an identity recovery request.
pub fn create_identity_recovery_request_aux(input: IdRecoveryRequestInput) -> Result<JsonString> {
    let request = generate_id_recovery_request(
        &input.ip_info,
        &input.global_context,
        &input.id_cred_sec,
        input.timestamp,
    );

    let response = json!({
        "idRecoveryRequest": Versioned::new(VERSION_0, request),
    });
    Ok(to_string(&response)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{read_ars_infos, read_global, read_ip_info};

    #[test]
    pub fn create_id_request() {
        let ar_threshold = 2;

        let ip_info = read_ip_info();
        let ars_infos = read_ars_infos();
        let global_context = read_global();

        let input: IdRequestInput = IdRequestInput {
            ar_threshold,
            ars_infos,
            global_context,
            ip_info,
            prf_key: base16_decode_string(
                "57ae5c7c108bf3eeecb34bc79a390c4d4662cefab2d95316cbdb8e68fa1632b8",
            )
            .unwrap(),
            id_cred_sec: base16_decode_string(
                "7392eb0b4840c8a6f9314e99a8dd3e2c3663a1e615d8820851e3abd2965fab18",
            )
            .unwrap(),
            blinding_randomness: "575851a4e0558d589a57544a4a9f5ad1bd8467126c1b6767d32f633ea03380e6"
                .to_string(),
        };
        let request_string = create_id_request_v1_aux(input).unwrap();
        let request: IdentityObjectRequestV1 = serde_json::from_str(&request_string).unwrap();
        let id_cred_pub: String =
            base16_encode_string(&request.id_object_request.value.id_cred_pub);

        assert_eq!(id_cred_pub, "b23e360b21cb8baad1fb1f9a593d1115fc678cb9b7c1a5b5631f82e088092d79d34b6a6c8520c06c41002a666adf792f");
        assert_eq!(
            request
                .id_object_request
                .value
                .choice_ar_parameters
                .threshold
                .0,
            ar_threshold
        );
    }

    #[test]
    pub fn create_id_recovery_request() {
        let id_cred_sec: PedersenValue<ArCurve> = base16_decode_string(
            "7392eb0b4840c8a6f9314e99a8dd3e2c3663a1e615d8820851e3abd2965fab18",
        )
        .unwrap();
        let global = read_global();
        let ip_info = read_ip_info();

        let input = IdRecoveryRequestInput {
            global_context: global,
            ip_info,
            timestamp: 0,
            id_cred_sec,
        };

        let request_string = create_identity_recovery_request_aux(input).unwrap();
        let request: IdRecoveryRequestOut = serde_json::from_str(&request_string).unwrap();
        let id_cred_pub: String =
            base16_encode_string(&request.id_recovery_request.value.id_cred_pub);

        assert_eq!(id_cred_pub, "b23e360b21cb8baad1fb1f9a593d1115fc678cb9b7c1a5b5631f82e088092d79d34b6a6c8520c06c41002a666adf792f");
    }
}
