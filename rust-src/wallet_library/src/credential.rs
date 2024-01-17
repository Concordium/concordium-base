use anyhow::{bail, Result};
use concordium_base::{
    common::{types::TransactionTime, Buffer, Serial},
    id::{
        account_holder::create_unsigned_credential,
        constants::{self, ArCurve, AttributeKind, IpPairing},
        dodis_yampolskiy_prf as prf,
        pedersen_commitment::{Randomness as PedersenRandomness, Value as PedersenValue, Value},
        types::*,
    },
};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use serde_json::json;
use std::collections::BTreeMap;

type JsonString = String;

/// Required input for generating an unsigned credential where the private keys
/// are supplied directly.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedCredentialInput {
    ip_info:                IpInfo<constants::IpPairing>,
    global_context:         GlobalContext<constants::ArCurve>,
    ars_infos:              BTreeMap<ArIdentity, ArInfo<constants::ArCurve>>,
    id_object: IdentityObjectV1<constants::IpPairing, constants::ArCurve, AttributeKind>,
    revealed_attributes:    Vec<AttributeTag>,
    cred_number:            u8,
    id_cred_sec:            PedersenValue<ArCurve>,
    prf_key:                prf::SecretKey<ArCurve>,
    blinding_randomness:    String,
    attribute_randomness:   BTreeMap<AttributeTag, PedersenRandomness<ArCurve>>,
    credential_public_keys: CredentialPublicKeys,
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
/// randomness where the secrets are provided directly as input.
pub fn create_unsigned_credential_v1_aux(input: UnsignedCredentialInput) -> Result<JsonString> {
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

    let context = IpContext::new(&input.ip_info, &input.ars_infos, &input.global_context);

    let policy = build_policy(&input.id_object.alist, input.revealed_attributes)?;

    let (cdi, rand) = create_unsigned_credential(
        context,
        &input.id_object,
        &id_use_data,
        input.cred_number,
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

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDeploymentDetails {
    expiry:       TransactionTime,
    unsigned_cdi: UnsignedCredentialDeploymentInfo<IpPairing, ArCurve, AttributeKind>,
}

/// Defines the byte serialization of the credential deployment details. Note
/// that this serialization is for a new credential being deployed, which the
/// explicit 0 byte denotes.
impl Serial for CredentialDeploymentDetails {
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.unsigned_cdi.serial(out);
        0u8.serial(out);
        self.expiry.seconds.serial(out);
    }
}

/// Serializes the credential deployment details. It is this serialization that
/// should be signed when creating a new credential for deployment.
pub fn serialize_credential_deployment_details(
    credential_deployment_details: CredentialDeploymentDetails,
) -> JsonString {
    let mut serialized_details = Vec::<u8>::new();
    credential_deployment_details.serial(&mut serialized_details);
    hex::encode(serialized_details)
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

    fn create_unsigned_credential() -> UnsignedCredentialDeploymentInfoWithRandomness {
        let cred_number = 1;
        let revealed_attributes = Vec::new();
        let ip_info = read_ip_info();
        let global_context = read_global();
        let ars_infos = read_ars_infos();
        let id_object = read_identity_object();

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

        let input = UnsignedCredentialInput {
            ars_infos,
            cred_number,
            global_context,
            id_object,
            ip_info,
            revealed_attributes,
            id_cred_sec,
            prf_key,
            blinding_randomness,
            attribute_randomness,
            credential_public_keys,
        };

        let result_str = create_unsigned_credential_v1_aux(input).unwrap();
        let result: UnsignedCredentialDeploymentInfoWithRandomness =
            serde_json::from_str(&result_str).unwrap();
        result
    }

    #[test]
    pub fn create_unsigned_credential_test() {
        let unsigned_credential = create_unsigned_credential();
        assert_unsigned_credential(unsigned_credential.unsigned_cdi.values);
    }

    #[test]
    pub fn serialize_credential_deployment_details_test() {
        let unsigned_credential = create_unsigned_credential();
        let expiry = TransactionTime::from_seconds(0x0685810406858104);

        let details = CredentialDeploymentDetails {
            expiry,
            unsigned_cdi: unsigned_credential.unsigned_cdi,
        };

        let serialized_details = serialize_credential_deployment_details(details);

        assert!(serialized_details.contains("01000029723ec9a0b4ca16d5d548b676a1a0adbecdedc5446894151acb7699293d69b101b317d3fea7de56f8c96f6e72820c5cd502cc0eef8454016ee548913255897c6b52156cc60df965d3efb3f160eff6ced40000000001000300000001"));
        assert!(serialized_details.contains("0685810406858104"));
    }
}
