use anyhow::{bail, Result};
use concordium_base::{
    common::{base16_encode_string, types::KeyIndex},
    contracts_common::NonZeroThresholdU8,
    id::{
        account_holder::create_unsigned_credential,
        constants,
        constants::{ArCurve, AttributeKind},
        dodis_yampolskiy_prf as prf,
        pedersen_commitment::{Randomness as PedersenRandomness, Value as PedersenValue, Value},
        types::*,
    },
};
use key_derivation::Net;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use serde_json::json;
use std::{collections::BTreeMap, str::FromStr};

use crate::wallet::get_wallet;

type JsonString = String;

/// The shared unsigned credential input that is independent of
/// whether or not the credential is going to be created by supplying
/// a seed or the secret key material directly.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedCredentialInput {
    ip_info:             IpInfo<constants::IpPairing>,
    global_context:      GlobalContext<constants::ArCurve>,
    ars_infos:           BTreeMap<ArIdentity, ArInfo<constants::ArCurve>>,
    id_object:           IdentityObjectV1<constants::IpPairing, constants::ArCurve, AttributeKind>,
    revealed_attributes: Vec<AttributeTag>,
    cred_number:         u8,
}

/// Required input for generating an unsigned credential where the private keys
/// are supplied directly.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedCredentialInputWithKeys {
    common:                 UnsignedCredentialInput,
    id_cred_sec:            PedersenValue<ArCurve>,
    prf_key:                prf::SecretKey<ArCurve>,
    blinding_randomness:    String,
    attribute_randomness:   BTreeMap<AttributeTag, PedersenRandomness<ArCurve>>,
    credential_public_keys: CredentialPublicKeys,
}

/// Required input for generating an unsigned credential from where the
/// private keys are derived from a seed and an identity index.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedCredentialInputWithSeed {
    common:         UnsignedCredentialInput,
    seed_as_hex:    String,
    net:            Net,
    identity_index: u32,
}

/// Defines the JSON structure that matches the output of the function
/// generating the unsigned credential deployment information and randomness.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedCredentialDeploymentInfoWithRandomness {
    unsigned_cdi: UnsignedCredentialDeploymentInfo<constants::IpPairing, ArCurve, AttributeKind>,
    randomness:   CommitmentsRandomness<ArCurve>,
}

/// Creates unsigned credential deployment information and the corresponding
/// randomness where the secrets are derived from the provided seed.
pub fn create_unsigned_credential_with_seed_v1_aux(
    input: UnsignedCredentialInputWithSeed,
) -> Result<JsonString> {
    let wallet = get_wallet(input.seed_as_hex, input.net)?;

    let identity_provider_index = input.common.ip_info.ip_identity.0;
    let identity_index = input.identity_index;
    let id_cred_sec =
        PedersenValue::new(wallet.get_id_cred_sec(identity_provider_index, identity_index)?);
    let prf_key = wallet.get_prf_key(identity_provider_index, identity_index)?;
    let blinding_randomness =
        wallet.get_blinding_randomness(identity_provider_index, identity_index)?;
    let encoded_blinding_randomness = base16_encode_string(&blinding_randomness);

    let mut attribute_randomness = BTreeMap::new();
    for attribute_name in ATTRIBUTE_NAMES.iter() {
        let tag = AttributeTag::from_str(attribute_name).unwrap();
        let randomness: PedersenRandomness<ArCurve> = wallet.get_attribute_commitment_randomness(
            identity_provider_index,
            identity_index,
            input.common.cred_number.into(),
            tag,
        )?;
        attribute_randomness.insert(tag, randomness);
    }

    let key = wallet.get_account_public_key(
        identity_provider_index,
        identity_index,
        input.common.cred_number.into(),
    )?;
    let mut key_map: BTreeMap<KeyIndex, VerifyKey> = BTreeMap::new();
    key_map.insert(KeyIndex(0), VerifyKey::Ed25519VerifyKey(key));
    let credential_public_keys: CredentialPublicKeys = CredentialPublicKeys {
        threshold: NonZeroThresholdU8::ONE,
        keys:      key_map,
    };

    let input_with_keys = UnsignedCredentialInputWithKeys {
        common: input.common,
        id_cred_sec,
        prf_key,
        blinding_randomness: encoded_blinding_randomness,
        credential_public_keys,
        attribute_randomness,
    };

    create_unsigned_credential_with_keys_v1_aux(input_with_keys)
}

/// Creates unsigned credential deployment information and the corresponding
/// randomness where the secrets are provided directly as input.
pub fn create_unsigned_credential_with_keys_v1_aux(
    input: UnsignedCredentialInputWithKeys,
) -> Result<JsonString> {
    let chi = CredentialHolderInfo::<constants::ArCurve> {
        id_cred: IdCredentials {
            id_cred_sec: input.id_cred_sec,
        },
    };

    let aci = AccCredentialInfo {
        cred_holder_info: chi,
        prf_key:          input.prf_key,
    };

    let blinding_randomness: Value<constants::ArCurve> = concordium_base::common::from_bytes(
        &mut hex::decode(&input.blinding_randomness)?.as_slice(),
    )?;
    let id_use_data = IdObjectUseData {
        aci,
        randomness:
            concordium_base::id::ps_sig::SigRetrievalRandomness::<constants::IpPairing>::new(
                *blinding_randomness,
            ),
    };

    let common = input.common;

    let context = IpContext::new(&common.ip_info, &common.ars_infos, &common.global_context);

    let policy = build_policy(&common.id_object.alist, common.revealed_attributes)?;

    let (cdi, rand) = create_unsigned_credential(
        context,
        &common.id_object,
        &id_use_data,
        common.cred_number,
        policy,
        input.credential_public_keys,
        None,
        &input.attribute_randomness,
    )?;

    let result = UnsignedCredentialDeploymentInfoWithRandomness {
        unsigned_cdi: cdi,
        randomness:   rand,
    };
    let response = json!(result);

    Ok(response.to_string())
}

fn build_policy(
    attributes: &AttributeList<constants::BaseField, constants::AttributeKind>,
    revealed_attributes: Vec<AttributeTag>,
) -> Result<Policy<constants::ArCurve, constants::AttributeKind>> {
    let mut policy_vec = std::collections::BTreeMap::new();
    for tag in revealed_attributes {
        if let Some(att) = attributes.alist.get(&tag) {
            if policy_vec.insert(tag, att.clone()).is_some() {
                bail!("Cannot reveal an attribute more than once.")
            }
        } else {
            bail!("Cannot reveal an attribute which is not part of the attribute list.")
        }
    }
    Ok(Policy {
        valid_to: attributes.valid_to,
        created_at: attributes.created_at,
        policy_vec,
        _phantom: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{read_ars_infos, read_global, read_identity_object, read_ip_info};
    use concordium_base::{
        common::{base16_decode_string, base16_encode_string, types::KeyIndex},
        contracts_common::NonZeroThresholdU8,
    };
    use ed25519_dalek as ed25519;
    use std::str::FromStr;

    const TEST_SEED_1: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";

    fn create_test_input() -> UnsignedCredentialInput {
        let ip_info = read_ip_info();
        let global = read_global();
        let ars_infos = read_ars_infos();
        let identity_object = read_identity_object();

        UnsignedCredentialInput {
            ars_infos,
            ip_info,
            global_context: global,
            id_object: identity_object,
            cred_number: 1,
            revealed_attributes: Vec::new(),
        }
    }

    fn assert_unsigned_credential(values: CredentialDeploymentValues<ArCurve, AttributeKind>) {
        let cred_id = values.cred_id;
        let verify_key = values.cred_key_info.keys.get(&KeyIndex(0)).unwrap();
        let threshold = values.cred_key_info.threshold;

        assert_eq!(base16_encode_string(&cred_id), "b317d3fea7de56f8c96f6e72820c5cd502cc0eef8454016ee548913255897c6b52156cc60df965d3efb3f160eff6ced4");
        assert_eq!(
            base16_encode_string(verify_key),
            "0029723ec9a0b4ca16d5d548b676a1a0adbecdedc5446894151acb7699293d69b1"
        );
        assert_eq!(threshold, 1);
        assert_eq!(values.threshold.0, 1);
    }

    #[test]
    pub fn create_unsigned_credential_with_keys_test() {
        let id_cred_sec: PedersenValue<ArCurve> = base16_decode_string(
            "7392eb0b4840c8a6f9314e99a8dd3e2c3663a1e615d8820851e3abd2965fab18",
        )
        .unwrap();
        let prf_key = base16_decode_string(
            "57ae5c7c108bf3eeecb34bc79a390c4d4662cefab2d95316cbdb8e68fa1632b8",
        )
        .unwrap();
        let blinding_randomness =
            "575851a4e0558d589a57544a4a9f5ad1bd8467126c1b6767d32f633ea03380e6".to_string();

        let mut attribute_randomness = BTreeMap::new();
        for attribute_name in ATTRIBUTE_NAMES.iter() {
            let tag = AttributeTag::from_str(attribute_name).unwrap();
            let randomness: PedersenRandomness<ArCurve> = PedersenRandomness::zero();
            attribute_randomness.insert(tag, randomness);
        }

        let key = ed25519::PublicKey::from_bytes(
            hex::decode("29723ec9a0b4ca16d5d548b676a1a0adbecdedc5446894151acb7699293d69b1")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let mut key_map: BTreeMap<KeyIndex, VerifyKey> = BTreeMap::new();
        key_map.insert(KeyIndex(0), VerifyKey::Ed25519VerifyKey(key));

        let credential_keys_threshold = NonZeroThresholdU8::ONE;
        let credential_public_keys: CredentialPublicKeys = CredentialPublicKeys {
            threshold: credential_keys_threshold,
            keys:      key_map,
        };

        let common = create_test_input();
        let input = UnsignedCredentialInputWithKeys {
            common,
            id_cred_sec,
            prf_key,
            blinding_randomness,
            attribute_randomness,
            credential_public_keys,
        };

        let result_str = create_unsigned_credential_with_keys_v1_aux(input).unwrap();
        let result: UnsignedCredentialDeploymentInfoWithRandomness =
            serde_json::from_str(&result_str).unwrap();

        assert_unsigned_credential(result.unsigned_cdi.values);
    }

    #[test]
    pub fn create_unsigned_credential_with_seed_test() {
        let common = create_test_input();
        let input = UnsignedCredentialInputWithSeed {
            common,
            identity_index: 0,
            net: Net::Testnet,
            seed_as_hex: TEST_SEED_1.to_string(),
        };

        let result_str = create_unsigned_credential_with_seed_v1_aux(input).unwrap();
        let result: UnsignedCredentialDeploymentInfoWithRandomness =
            serde_json::from_str(&result_str).unwrap();

        assert_unsigned_credential(result.unsigned_cdi.values);
    }
}
