use super::LockCreateConfigSimpleV0;
use crate::{
    common::{
        cbor::{
            self, value, CborDecoder, CborDeserialize, CborEncoder, CborSerializationError,
            CborSerializationResult, CborSerialize, DataItemHeader,
        },
        types::TransactionTime,
    },
    protocol_level_tokens::{CborHolderAccount, RawCbor, TokenId},
};
use concordium_base_derive::{CborDeserialize, CborSerialize, Serialize};
use std::collections::HashMap;

/// Accounts that can receive funds controlled by a lock.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LockRecipients {
    /// Any eligible account can receive funds from this lock.
    Any,
    /// Only the listed accounts can receive funds from this lock.
    Limited(Vec<CborHolderAccount>),
}

impl CborSerialize for LockRecipients {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        match self {
            Self::Any => encoder.encode_text("any"),
            Self::Limited(accounts) => accounts.serialize(encoder),
        }
    }
}

impl CborDeserialize for LockRecipients {
    fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self> {
        match decoder.peek_data_item_header()? {
            DataItemHeader::Text(_) => {
                let value = String::deserialize(decoder)?;
                if value == "any" {
                    Ok(Self::Any)
                } else {
                    Err(CborSerializationError::invalid_data(format_args!(
                        "unsupported lock recipients text value {value:?}"
                    )))
                }
            }
            DataItemHeader::Array(_) => Ok(Self::Limited(Vec::deserialize(decoder)?)),
            header => Err(CborSerializationError::invalid_data(format_args!(
                "lock recipients must be text \"any\" or an array of account addresses, was {header:?}"
            ))),
        }
    }
}

/// User-facing metadata attached to a lock at creation time.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize, Default)]
pub struct LockMetadata {
    /// Optional user-facing lock name.
    pub name: Option<String>,
    /// Optional user-facing lock description.
    pub description: Option<String>,
    /// Additional text-keyed fields preserved for user-defined metadata.
    #[cbor(other)]
    pub additional: HashMap<String, value::Value>,
}

impl LockMetadata {
    /// Decode typed metadata, failing if the bytes do not encode a metadata map.
    pub fn decode_raw_cbor(raw_cbor: &RawCbor) -> CborSerializationResult<Self> {
        cbor::cbor_decode(raw_cbor.as_ref())
    }

    /// Encode typed metadata as opaque bytes.
    pub fn encode_raw_cbor(&self) -> RawCbor {
        RawCbor::from(cbor::cbor_encode(self))
    }
}

/// Externally keyed lock creation input.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(map)]
pub enum LockCreateConfig {
    /// Simple lock with implicit holder funding permissions.
    SimpleV0(LockCreateConfigSimpleV0),
}

/// Supported output configuration version; other numeric versions fail decoding.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LockConfigVersion {
    /// Version zero.
    V0,
}

impl CborSerialize for LockConfigVersion {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_positive(0)
    }
}

impl CborDeserialize for LockConfigVersion {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        match u64::deserialize(decoder)? {
            0 => Ok(Self::V0),
            version => Err(CborSerializationError::invalid_data(format_args!(
                "unsupported lock configuration version {version}"
            ))),
        }
    }
}

/// Known creation variant reported by an output configuration.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LockVariant {
    /// Simple lock created with `simpleV0`.
    SimpleV0,
}

impl CborSerialize for LockVariant {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text("simpleV0")
    }
}

impl CborDeserialize for LockVariant {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        match String::deserialize(decoder)?.as_str() {
            "simpleV0" => Ok(Self::SimpleV0),
            variant => Err(CborSerializationError::invalid_data(format_args!(
                "unsupported lock configuration variant {variant:?}"
            ))),
        }
    }
}

/// Effective operation capability in an output configuration.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum LockCapability {
    /// Authorizes funding the lock.
    Fund,
    /// Authorizes releasing funds to their owner.
    Release,
    /// Authorizes sending funds, subject to token policies.
    Send,
    /// Authorizes cancelling the lock before expiry.
    Cancel,
}

impl CborSerialize for LockCapability {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(match self {
            Self::Fund => "fund",
            Self::Release => "release",
            Self::Send => "send",
            Self::Cancel => "cancel",
        })
    }
}

impl CborDeserialize for LockCapability {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        match String::deserialize(decoder)?.as_str() {
            "fund" => Ok(Self::Fund),
            "release" => Ok(Self::Release),
            "send" => Ok(Self::Send),
            "cancel" => Ok(Self::Cancel),
            capability => Err(CborSerializationError::invalid_data(format_args!(
                "unsupported lock capability {capability:?}"
            ))),
        }
    }
}

/// Effective capabilities for an account, including implicit holder funding.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockRole {
    /// Account receiving the capabilities.
    pub account: CborHolderAccount,
    /// Effective capabilities; output decoding permits an empty list.
    pub roles: Vec<LockCapability>,
}

/// Flat output configuration with required, strict version and variant fields.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockConfig {
    /// Output format version.
    pub version: LockConfigVersion,
    /// Variant specified at creation.
    pub variant: LockVariant,
    /// Accounts permitted to receive locked funds.
    pub recipients: LockRecipients,
    /// Accounts permitted to hold locked funds.
    pub holders: Vec<CborHolderAccount>,
    /// Expiry time of the lock.
    pub expiry: TransactionTime,
    /// Effective operation permissions, independent of recipient membership.
    pub roles: Vec<LockRole>,
    /// Token identifiers permitted in the lock.
    pub tokens: Vec<TokenId>,
    /// Opaque metadata bytes, not checked for nested CBOR validity.
    pub metadata: Option<RawCbor>,
}

/// Canonical parameters used to price lock creation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LockComplexityParameters {
    pub(crate) token_holders: u64,
    pub(crate) tokens: u64,
    pub(crate) role_accounts: u64,
}

impl LockCreateConfig {
    /// Count unique holders, case-insensitive tokens, and holder/role-account union.
    pub(crate) fn get_creation_complexity_parameters(&self) -> LockComplexityParameters {
        use crate::base::AccountAddressEq;
        use std::collections::HashSet;

        let Self::SimpleV0(config) = self;
        let holders: HashSet<AccountAddressEq> = config
            .holders
            .iter()
            .map(|holder| holder.address.into())
            .collect();
        let role_accounts: HashSet<AccountAddressEq> = holders
            .iter()
            .copied()
            .chain(config.roles.iter().map(|role| role.account.address.into()))
            .collect();
        let tokens: HashSet<_> = config
            .tokens
            .iter()
            .map(|token| token.as_ref().to_ascii_lowercase())
            .collect();
        LockComplexityParameters {
            token_holders: holders.len() as u64,
            tokens: tokens.len() as u64,
            role_accounts: role_accounts.len() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{cbor::value::Value, serialize_deserialize, to_bytes},
        contracts_common::AccountAddress,
        protocol_level_locks::{LockCreateCapability, LockCreateRole, LockId, LockInfo},
        protocol_level_tokens::{test_fixtures::ADDRESS, LockCreateDetails, Operation, Operations},
    };

    fn creation() -> LockCreateConfig {
        LockCreateConfig::SimpleV0(LockCreateConfigSimpleV0 {
            recipients: LockRecipients::Any,
            holders: vec![ADDRESS.into()],
            expiry: TransactionTime::from_seconds(1804806000),
            roles: vec![LockCreateRole {
                account: ADDRESS.into(),
                roles: vec![LockCreateCapability::Send],
            }],
            tokens: vec!["tT".parse().unwrap()],
            metadata: None,
        })
    }

    fn output() -> LockConfig {
        LockConfig {
            version: LockConfigVersion::V0,
            variant: LockVariant::SimpleV0,
            recipients: LockRecipients::Any,
            holders: vec![ADDRESS.into()],
            expiry: TransactionTime::from_seconds(1804806000),
            roles: vec![LockRole {
                account: ADDRESS.into(),
                roles: vec![LockCapability::Fund, LockCapability::Send],
            }],
            tokens: vec!["tT".parse().unwrap()],
            metadata: None,
        }
    }

    fn field<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
        let Value::Map(fields) = value else {
            panic!("expected map")
        };
        &mut fields
            .iter_mut()
            .find(|(k, _)| *k == Value::Text(key.into()))
            .unwrap()
            .1
    }

    fn first(value: &mut Value) -> &mut Value {
        let Value::Array(values) = value else {
            panic!("expected array")
        };
        &mut values[0]
    }

    fn add_unknown(value: &mut Value) {
        let Value::Map(fields) = value else {
            panic!("expected map")
        };
        fields.push((
            Value::Text("memo".into()),
            Value::Bytes(cbor::Bytes(vec![1, 2, 3])),
        ));
    }

    fn assert_unknown_options<T: CborDeserialize + std::fmt::Debug>(value: &Value) {
        let encoded = cbor::cbor_encode(value);
        assert!(cbor::cbor_decode::<T>(&encoded).is_ok());
        let err = cbor::cbor_decode_with_options::<T>(
            &encoded,
            cbor::SerializationOptions::default().unknown_map_keys(cbor::UnknownMapKeys::Fail),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown map key"), "{err}");
    }

    #[test]
    fn creation_and_output_match_fixed_fixtures() {
        let creation_fixture = "a16873696d706c655630a565726f6c657381a265726f6c6573816473656e64676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066657870697279c11a6b93277066746f6b656e738162745467686f6c6465727381d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206a726563697069656e747363616e79";
        let output_fixture = "a765726f6c657381a265726f6c6573826466756e646473656e64676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066657870697279c11a6b93277066746f6b656e738162745467686f6c6465727381d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206776617269616e746873696d706c6556306776657273696f6e006a726563697069656e747363616e79";
        assert_eq!(
            hex::encode(cbor::cbor_encode(&creation())),
            creation_fixture
        );
        assert_eq!(
            cbor::cbor_decode::<LockCreateConfig>(hex::decode(creation_fixture).unwrap()).unwrap(),
            creation()
        );
        assert_eq!(hex::encode(cbor::cbor_encode(&output())), output_fixture);
        assert_eq!(
            cbor::cbor_decode::<LockConfig>(hex::decode(output_fixture).unwrap()).unwrap(),
            output()
        );
    }

    #[test]
    fn lock_config_accepts_flat_output_and_empty_output_arrays() {
        let fixture = "a765726f6c65738066657870697279c10066746f6b656e738067686f6c64657273806776617269616e746873696d706c6556306776657273696f6e006a726563697069656e747363616e79";
        let mut config = cbor::cbor_decode::<LockConfig>(hex::decode(fixture).unwrap()).unwrap();
        assert!(config.holders.is_empty() && config.tokens.is_empty() && config.roles.is_empty());
        config.roles.push(LockRole {
            account: ADDRESS.into(),
            roles: vec![],
        });
        assert_eq!(
            cbor::cbor_decode::<LockConfig>(cbor::cbor_encode(&config)).unwrap(),
            config
        );
    }

    #[test]
    fn lock_config_requires_supported_discriminators() {
        let original: Value = cbor::cbor_decode(cbor::cbor_encode(&output())).unwrap();
        for key in ["version", "variant"] {
            let mut value = original.clone();
            let Value::Map(fields) = &mut value else {
                unreachable!()
            };
            fields.retain(|(k, _)| *k != Value::Text(key.into()));
            assert!(
                cbor::cbor_decode::<LockConfig>(cbor::cbor_encode(&value)).is_err(),
                "missing {key}"
            );
        }
        for (key, unsupported) in [
            ("version", Value::Positive(1)),
            ("version", Value::Text("0".into())),
            ("variant", Value::Text("simpleV1".into())),
            ("variant", Value::Positive(0)),
        ] {
            let mut value = original.clone();
            *field(&mut value, key) = unsupported;
            for options in [cbor::UnknownMapKeys::Ignore, cbor::UnknownMapKeys::Fail] {
                assert!(cbor::cbor_decode_with_options::<LockConfig>(
                    cbor::cbor_encode(&value),
                    cbor::SerializationOptions::default().unknown_map_keys(options)
                )
                .is_err());
            }
        }
        let unknown = Value::Map(vec![(Value::Text("simpleV1".into()), Value::Map(vec![]))]);
        assert!(cbor::cbor_decode::<LockCreateConfig>(cbor::cbor_encode(&unknown)).is_err());
        assert!(cbor::cbor_decode::<LockCreateConfig>([0xa0]).is_err());
    }

    #[test]
    fn creation_requires_nonempty_arrays_but_allows_no_explicit_roles() {
        let original: Value = cbor::cbor_decode(cbor::cbor_encode(&creation())).unwrap();
        for key in ["holders", "tokens", "roles"] {
            let mut value = original.clone();
            let Value::Map(fields) = field(&mut value, "simpleV0") else {
                unreachable!()
            };
            fields.retain(|(k, _)| *k != Value::Text(key.into()));
            assert!(
                cbor::cbor_decode::<LockCreateConfig>(cbor::cbor_encode(&value)).is_err(),
                "missing {key}"
            );
        }
        for key in ["holders", "tokens"] {
            for invalid in [Value::Array(vec![]), Value::Text("not an array".into())] {
                let mut value = original.clone();
                *field(field(&mut value, "simpleV0"), key) = invalid;
                assert!(cbor::cbor_decode::<LockCreateConfig>(cbor::cbor_encode(&value)).is_err());
            }
        }
        for invalid in [
            Value::Array(vec![]),
            Value::Array(vec![Value::Text("fund".into())]),
            Value::Text("send".into()),
        ] {
            let mut value = original.clone();
            *field(
                first(field(field(&mut value, "simpleV0"), "roles")),
                "roles",
            ) = invalid;
            assert!(cbor::cbor_decode::<LockCreateConfig>(cbor::cbor_encode(&value)).is_err());
        }
        let mut value = original;
        *field(field(&mut value, "simpleV0"), "roles") = Value::Array(vec![]);
        assert!(cbor::cbor_decode::<LockCreateConfig>(cbor::cbor_encode(&value)).is_ok());
    }

    #[test]
    fn creation_decodes_noncanonical_fixture() {
        // Reordered keys and an oversized coin-info integer remain valid CBOR.
        let fixture = "a16873696d706c655630a56a726563697069656e747363616e7966746f6b656e738162745467686f6c6465727381d99d73a201d99d71a1011a000003970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2065726f6c657381a2676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2065726f6c6573816473656e6466657870697279c11a6b932770";
        assert_eq!(
            cbor::cbor_decode::<LockCreateConfig>(hex::decode(fixture).unwrap()).unwrap(),
            creation()
        );
    }

    #[test]
    fn nested_creation_unknown_fields_follow_application_options() {
        let operations = Operations::new(vec![Operation::LockCreate(LockCreateDetails {
            config: creation(),
        })]);
        let original: Value = cbor::cbor_decode(cbor::cbor_encode(&operations)).unwrap();
        for location in [
            "config",
            "role",
            "holder",
            "recipient",
            "role account",
            "coin info",
        ] {
            let mut value = original.clone();
            let config = field(field(first(&mut value), "lockCreate"), "simpleV0");
            if location == "recipient" {
                *field(config, "recipients") = Value::Array(vec![cbor::cbor_decode(
                    cbor::cbor_encode(&CborHolderAccount::from(ADDRESS)),
                )
                .unwrap()]);
            }
            let target = match location {
                "config" => config,
                "role" => first(field(config, "roles")),
                "holder" | "coin info" => first(field(config, "holders")),
                "recipient" => first(field(config, "recipients")),
                "role account" => field(first(field(config, "roles")), "account"),
                _ => unreachable!(),
            };
            let target = if let Value::Tag(_, inner) = target {
                inner.as_mut()
            } else {
                target
            };
            let target = if location == "coin info" {
                let Value::Map(fields) = target else {
                    unreachable!()
                };
                let Value::Tag(_, inner) = &mut fields
                    .iter_mut()
                    .find(|(k, _)| *k == Value::Positive(1))
                    .unwrap()
                    .1
                else {
                    unreachable!()
                };
                inner.as_mut()
            } else {
                target
            };
            add_unknown(target);
            assert_unknown_options::<Operations>(&value);
        }
    }

    #[test]
    fn nested_output_unknown_fields_follow_application_options() {
        let info = LockInfo {
            lock: LockId::new(1, 2, 0),
            config: output(),
            funds: vec![],
        };
        let original: Value = cbor::cbor_decode(cbor::cbor_encode(&info)).unwrap();
        for location in ["config", "role", "holder"] {
            let mut value = original.clone();
            let config = field(&mut value, "config");
            let target = match location {
                "config" => config,
                "role" => first(field(config, "roles")),
                "holder" => first(field(config, "holders")),
                _ => unreachable!(),
            };
            let target = if let Value::Tag(_, inner) = target {
                inner.as_mut()
            } else {
                target
            };
            add_unknown(target);
            assert_unknown_options::<LockInfo>(&value);
        }
    }

    #[test]
    fn recipient_modes_and_opaque_metadata_round_trip() {
        for recipients in [
            LockRecipients::Any,
            LockRecipients::Limited(vec![]),
            LockRecipients::Limited(vec![ADDRESS.into(), ADDRESS.into()]),
        ] {
            for bytes in [
                vec![0xff],
                vec![1],
                hex::decode("a1646e616d6501").unwrap(),
                cbor::cbor_encode(&metadata()),
            ] {
                let raw = RawCbor::from(bytes);
                let LockCreateConfig::SimpleV0(mut simple) = creation();
                simple.recipients = recipients.clone();
                simple.metadata = Some(raw.clone());
                let input = LockCreateConfig::SimpleV0(simple);
                let mut output = output();
                output.recipients = recipients.clone();
                output.metadata = Some(raw);
                let options = cbor::SerializationOptions::default()
                    .unknown_map_keys(cbor::UnknownMapKeys::Fail);
                assert_eq!(
                    cbor::cbor_decode_with_options::<LockCreateConfig>(
                        cbor::cbor_encode(&input),
                        options
                    )
                    .unwrap(),
                    input
                );
                assert_eq!(
                    cbor::cbor_decode_with_options::<LockConfig>(
                        cbor::cbor_encode(&output),
                        options
                    )
                    .unwrap(),
                    output
                );
            }
        }
        assert!(cbor::cbor_decode::<LockRecipients>(cbor::cbor_encode("all")).is_err());
    }

    #[test]
    fn effective_capabilities_match_cbor_and_binary_fixtures() {
        for (capability, cbor_fixture, binary_fixture) in [
            (LockCapability::Fund, "6466756e64", "00"),
            (LockCapability::Release, "6772656c65617365", "01"),
            (LockCapability::Send, "6473656e64", "02"),
            (LockCapability::Cancel, "6663616e63656c", "03"),
        ] {
            assert_eq!(hex::encode(cbor::cbor_encode(&capability)), cbor_fixture);
            assert_eq!(
                cbor::cbor_decode::<LockCapability>(hex::decode(cbor_fixture).unwrap()).unwrap(),
                capability
            );
            assert_eq!(serialize_deserialize(&capability).unwrap(), capability);
            assert_eq!(hex::encode(to_bytes(&capability)), binary_fixture);
        }
        assert!(cbor::cbor_decode::<LockCapability>(cbor::cbor_encode("recipient")).is_err());
    }

    #[test]
    fn creation_complexity_normalizes_holders_roles_tokens_and_excludes_recipients() {
        let address = |n| AccountAddress([n; 32]);
        let mut alias = address(9);
        alias.0[31] = 42;
        let role = |account, roles| LockCreateRole {
            account: CborHolderAccount::from(account),
            roles,
        };
        let LockCreateConfig::SimpleV0(mut simple) = creation();
        simple.holders = vec![
            address(9).into(),
            address(1).into(),
            alias.into(),
            address(1).into(),
        ];
        simple.roles = vec![
            role(alias, vec![LockCreateCapability::Send]),
            role(address(5), vec![LockCreateCapability::Release]),
            role(address(5), vec![LockCreateCapability::Cancel]),
        ];
        simple.tokens = vec![
            "A".parse().unwrap(),
            "B".parse().unwrap(),
            "a".parse().unwrap(),
        ];
        let first = LockCreateConfig::SimpleV0(simple.clone());
        assert_eq!(
            first.get_creation_complexity_parameters(),
            LockComplexityParameters {
                token_holders: 2,
                tokens: 2,
                role_accounts: 3
            }
        );
        assert_eq!(
            crate::transactions::cost::plt_lock_create(&first).energy,
            2130
        );
        simple.holders.reverse();
        simple.roles.reverse();
        simple.tokens.reverse();
        simple.recipients = LockRecipients::Limited(vec![address(7).into(), address(8).into()]);
        assert_eq!(
            first.get_creation_complexity_parameters(),
            LockCreateConfig::SimpleV0(simple.clone()).get_creation_complexity_parameters()
        );
        simple.holders = vec![address(1).into(), address(9).into()];
        simple.roles = vec![
            role(
                address(5),
                vec![LockCreateCapability::Release, LockCreateCapability::Cancel],
            ),
            role(address(9), vec![LockCreateCapability::Send]),
        ];
        simple.tokens = vec!["a".parse().unwrap(), "B".parse().unwrap()];
        assert_eq!(
            crate::transactions::cost::plt_lock_create(&LockCreateConfig::SimpleV0(simple.clone()))
                .energy,
            2130
        );
        simple.roles.clear();
        assert_eq!(
            crate::transactions::cost::plt_lock_create(&LockCreateConfig::SimpleV0(simple)).energy,
            2120
        );
    }

    fn metadata() -> LockMetadata {
        LockMetadata {
            name: Some("Vesting lock".into()),
            description: Some("Tokens locked by vesting schedule".into()),
            additional: HashMap::from([
                ("issuer".into(), Value::Text("Concordium".into())),
                ("version".into(), Value::Positive(1)),
            ]),
        }
    }

    #[test]
    fn metadata_matches_fixed_fixture() {
        let expected = "a4646e616d656c56657374696e67206c6f636b666973737565726a436f6e636f726469756d6776657273696f6e016b6465736372697074696f6e7821546f6b656e73206c6f636b65642062792076657374696e67207363686564756c65";
        assert_eq!(hex::encode(cbor::cbor_encode(&metadata())), expected);
        assert_eq!(
            LockMetadata::decode_raw_cbor(&RawCbor::from(hex::decode(expected).unwrap())).unwrap(),
            metadata()
        );
    }

    #[test]
    fn metadata_raw_decode_rejects_invalid_and_noncanonical_input() {
        assert!(LockMetadata::decode_raw_cbor(&RawCbor::from(vec![1])).is_err());
        assert!(LockMetadata::decode_raw_cbor(&RawCbor::from(
            hex::decode("b8646e616d656178").unwrap()
        ))
        .is_err());
    }
}
