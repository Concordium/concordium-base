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
use key_derivation::{ConcordiumHdWallet, Net};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use serde_json::{json, to_string};
use std::{collections::BTreeMap, convert::TryInto};

use crate::wallet::get_wallet;

type JsonString = String;

/// Defines the JSON structure that matches the output of the function
/// generating the identity objcect request.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityObjectRequestV1 {
    id_object_request: Versioned<PreIdentityObjectV1<constants::IpPairing, ArCurve>>,
}

/// The shared identity creation request input that is independent
/// of whether or not the request is going to be created
/// by supplying a seed phrase or the secret key material
/// directly.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRequestCommonInput {
    ip_info:        IpInfo<constants::IpPairing>,
    global_context: GlobalContext<constants::ArCurve>,
    ars_infos:      BTreeMap<ArIdentity, ArInfo<constants::ArCurve>>,
    ar_threshold:   u8,
}

/// Required input for generating an identity object request from a seed. The
/// required private keys will be derived from the seed.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRequestInputWithSeed {
    common:         IdRequestCommonInput,
    seed_as_hex:    String,
    net:            Net,
    identity_index: u32,
}

/// Required input for generating an identity object request. This input
/// contains the private keys and they will be used to generate the request
/// directly.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRequestInputWithKeys {
    common:              IdRequestCommonInput,
    prf_key:             prf::SecretKey<ArCurve>,
    id_cred_sec:         PedersenValue<ArCurve>,
    // The blinding_randomness does not have a serde serializer / deserializer. Therefore
    // it is just a String here and manually handled.
    blinding_randomness: String,
}

/// Creates an identity object request where the secret keys are provided
/// directly.
pub fn create_id_request_with_keys_v1_aux(input: IdRequestInputWithKeys) -> Result<JsonString> {
    let prf_key: prf::SecretKey<ArCurve> = input.prf_key;
    let id_cred_sec: PedersenValue<ArCurve> = input.id_cred_sec;
    let id_cred: IdCredentials<ArCurve> = IdCredentials { id_cred_sec };
    let sig_retrieval_randomness: concordium_base::id::ps_sig::SigRetrievalRandomness<
        constants::IpPairing,
    > = base16_decode_string(&input.blinding_randomness)?;

    let num_of_ars = input.common.ars_infos.len();
    ensure!(
        input.common.ar_threshold > 0,
        "arThreshold must be at least 1."
    );
    ensure!(
        num_of_ars >= usize::from(input.common.ar_threshold),
        "Number of anonymity revokers in arsInfos should be at least arThreshold."
    );

    let threshold = Threshold(input.common.ar_threshold);
    let chi = CredentialHolderInfo::<ArCurve> { id_cred };
    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key,
    };

    let context = IpContext::new(
        &input.common.ip_info,
        &input.common.ars_infos,
        &input.common.global_context,
    );
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

/// Creates an identity object request where the supplied seed phrase is
/// used to derive the required keys.
pub fn create_id_request_with_seed_v1_aux(input: IdRequestInputWithSeed) -> Result<JsonString> {
    let seed_decoded = hex::decode(&input.seed_as_hex)?;
    let seed: [u8; 64] = match seed_decoded.try_into() {
        Ok(s) => s,
        Err(_) => bail!("The provided seed {} was not 64 bytes", input.seed_as_hex),
    };

    let wallet: ConcordiumHdWallet = ConcordiumHdWallet {
        seed,
        net: input.net,
    };

    let identity_provider_index = input.common.ip_info.ip_identity.0;
    let identity_index = input.identity_index;
    let prf_key: prf::SecretKey<ArCurve> =
        wallet.get_prf_key(identity_provider_index, identity_index)?;
    let id_cred_sec: PedersenValue<ArCurve> =
        PedersenValue::new(wallet.get_id_cred_sec(identity_provider_index, identity_index)?);
    let blinding_randomness: concordium_base::id::ps_sig::SigRetrievalRandomness<
        constants::IpPairing,
    > = wallet.get_blinding_randomness(identity_provider_index, identity_index)?;

    let input = IdRequestInputWithKeys {
        common: input.common,
        prf_key,
        id_cred_sec,
        blinding_randomness: base16_encode_string(&blinding_randomness),
    };

    create_id_request_with_keys_v1_aux(input)
}

/// The shared identity recovery request input that is independent
/// of whether or not the request is going to be created
/// by supplying a seed phrase or the secret key material
/// directly.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRecoveryRequestCommonInput {
    ip_info:        IpInfo<constants::IpPairing>,
    global_context: GlobalContext<constants::ArCurve>,
    timestamp:      u64,
}

/// Required input for generating an identity recovery request. This input
/// contains the private key which will be used directly to generate
/// the request.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRecoveryRequestInputWithKeys {
    common:      IdRecoveryRequestCommonInput,
    id_cred_sec: PedersenValue<ArCurve>,
}

/// Required input for generating an identity recovery request from a seed. The
/// required private key will be derived from the seed.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRecoveryRequestInputWithSeed {
    common:         IdRecoveryRequestCommonInput,
    seed_as_hex:    String,
    net:            Net,
    identity_index: u32,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRecoveryRequestOut {
    id_recovery_request: Versioned<IdRecoveryRequest<ArCurve>>,
}

/// Create an identity recovery request taking the secret as directy input.
pub fn create_identity_recovery_request_with_keys_aux(
    input: IdRecoveryRequestInputWithKeys,
) -> Result<JsonString> {
    let request = generate_id_recovery_request(
        &input.common.ip_info,
        &input.common.global_context,
        &input.id_cred_sec,
        input.common.timestamp,
    );

    let response = json!({
        "idRecoveryRequest": Versioned::new(VERSION_0, request),
    });
    Ok(to_string(&response)?)
}

/// Create an identity recovery request using a seed phrase to
/// generate the secret.
pub fn create_identity_recovery_request_with_seed_aux(
    input: IdRecoveryRequestInputWithSeed,
) -> Result<JsonString> {
    let wallet = get_wallet(input.seed_as_hex, input.net)?;
    let id_cred_sec =
        wallet.get_id_cred_sec(input.common.ip_info.ip_identity.0, input.identity_index)?;

    let input_2 = IdRecoveryRequestInputWithKeys {
        common:      input.common,
        id_cred_sec: PedersenValue::new(id_cred_sec),
    };
    create_identity_recovery_request_with_keys_aux(input_2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{read_ars_infos, read_global, read_ip_info};

    const TEST_SEED_1: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";

    fn read_test_data(ar_threshold: u8) -> IdRequestCommonInput {
        let ip_info = read_ip_info();
        let ars_infos = read_ars_infos();
        let global_context = read_global();

        IdRequestCommonInput {
            ip_info,
            ars_infos,
            global_context,
            ar_threshold,
        }
    }

    #[test]
    pub fn create_id_request_with_seed_phrase() {
        let ar_threshold = 2;
        let test_data = read_test_data(ar_threshold.clone());

        let input: IdRequestInputWithSeed = IdRequestInputWithSeed {
            common:         test_data,
            seed_as_hex:    TEST_SEED_1.to_string(),
            net:            Net::Testnet,
            identity_index: 0,
        };
        let request_string = create_id_request_with_seed_v1_aux(input).unwrap();
        let request: IdentityObjectRequestV1 = serde_json::from_str(&request_string).unwrap();
        let id_cred_pub = base16_encode_string(&request.id_object_request.value.id_cred_pub);

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
    pub fn create_id_request_with_individual_keys() {
        let ar_threshold = 2;
        let test_data = read_test_data(ar_threshold.clone());

        let input: IdRequestInputWithKeys = IdRequestInputWithKeys {
            common:              test_data,
            prf_key:             base16_decode_string(
                "57ae5c7c108bf3eeecb34bc79a390c4d4662cefab2d95316cbdb8e68fa1632b8",
            )
            .unwrap(),
            id_cred_sec:         base16_decode_string(
                "7392eb0b4840c8a6f9314e99a8dd3e2c3663a1e615d8820851e3abd2965fab18",
            )
            .unwrap(),
            blinding_randomness: "575851a4e0558d589a57544a4a9f5ad1bd8467126c1b6767d32f633ea03380e6"
                .to_string(),
        };
        let request_string = create_id_request_with_keys_v1_aux(input).unwrap();
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
    pub fn create_id_recovery_request_with_individual_keys() {
        let id_cred_sec: PedersenValue<ArCurve> = base16_decode_string(
            "7392eb0b4840c8a6f9314e99a8dd3e2c3663a1e615d8820851e3abd2965fab18",
        )
        .unwrap();
        let global = read_global();
        let ip_info = read_ip_info();

        let input = IdRecoveryRequestInputWithKeys {
            common: IdRecoveryRequestCommonInput {
                ip_info,
                global_context: global,
                timestamp: 0,
            },
            id_cred_sec,
        };

        let request_string = create_identity_recovery_request_with_keys_aux(input).unwrap();
        let request: IdRecoveryRequestOut = serde_json::from_str(&request_string).unwrap();
        let id_cred_pub: String =
            base16_encode_string(&request.id_recovery_request.value.id_cred_pub);

        assert_eq!(id_cred_pub, "b23e360b21cb8baad1fb1f9a593d1115fc678cb9b7c1a5b5631f82e088092d79d34b6a6c8520c06c41002a666adf792f");
    }

    #[test]
    pub fn create_id_recovery_request_with_seed() {
        let global = read_global();
        let ip_info = read_ip_info();

        let input: IdRecoveryRequestInputWithSeed = IdRecoveryRequestInputWithSeed {
            common:         IdRecoveryRequestCommonInput {
                ip_info,
                global_context: global,
                timestamp: 0,
            },
            seed_as_hex:    TEST_SEED_1.to_string(),
            identity_index: 0,
            net:            Net::Testnet,
        };

        let request_string = create_identity_recovery_request_with_seed_aux(input).unwrap();
        let request: IdRecoveryRequestOut = serde_json::from_str(&request_string).unwrap();
        let id_cred_pub: String =
            base16_encode_string(&request.id_recovery_request.value.id_cred_pub);

        assert_eq!(id_cred_pub, "b23e360b21cb8baad1fb1f9a593d1115fc678cb9b7c1a5b5631f82e088092d79d34b6a6c8520c06c41002a666adf792f");
    }
}
