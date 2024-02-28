use crate::statement::{RequestCheckError, WalletConfig, WalletConfigRules};
use concordium_base::id::{
    constants::{self, AttributeKind},
    types::*,
};
use std::{collections::BTreeMap, marker::PhantomData};

/// Check whether a string is ISO 8601 compliant on the form YYYYMMDD
pub fn is_iso8601(date: &str) -> bool { chrono::NaiveDate::parse_from_str(date, "%Y%m%d").is_ok() }

/// Check whether a string is ISO 3166-1 Alpha-2 compliant
pub fn is_iso3166_alpha_2(code: &str) -> bool { rust_iso3166::from_alpha2(code).is_some() }

/// Check whether a string is ISO 3166-2 compliant
pub fn is_iso3166_2(code: &str) -> bool { rust_iso3166::iso3166_2::from_code(code).is_some() }

/// The attribute check for identity statement used by the Concordium wallet
/// Checks that countryOfResidence and nationality tags are ISO 3166-1 Alpha-2
/// compliant, that idDocIssuer tags are ISO 3166-1 Alpha-2 or ISO 3166-2
/// compliant and that DOB, idDocIssuedAt, idDocExpiresAt tags are all ISO 8601
/// YYYYMMDD date
pub fn default_attribute_rules(
    tag: &AttributeTag,
    value: &AttributeKind,
) -> Result<(), RequestCheckError> {
    match tag.0 {
        // countryOfResidence | nationality
        4 | 5 => {
            if !is_iso3166_alpha_2(&value.to_string()) {
                return Err(RequestCheckError::InvalidValue(
                    "countryOfResidence and nationality attributes must be ISO 3166-1 Alpha-2"
                        .to_owned(),
                ));
            }
        }
        // idDocIssuer
        8 => {
            if !is_iso3166_alpha_2(&value.to_string()) && !is_iso3166_2(&value.to_string()) {
                return Err(RequestCheckError::InvalidValue(
                    "idDocIssuer attributes must be ISO 3166-1 Alpha-2 or ISO 3166-2".to_owned(),
                ));
            }
        }
        // dob, idDocIssuedAt, idDocExpiresAt
        3 | 9 | 10 => {
            if !is_iso8601(&value.to_string()) {
                return Err(RequestCheckError::InvalidValue(
                    "dob, idDocIssuedAt and idDocExpiresAt attributes must be ISO 8601".to_owned(),
                ));
            }
        }
        _ => (),
    }
    Ok(())
}

/// List of identity attribute tags that we allow range statements for.
/// The list should correspond to "dob", "idDocIssuedAt", "idDocExpiresAt".
pub const ALLOWED_IDENTITY_RANGE_TAGS: [AttributeTag; 3] =
    [AttributeTag(3), AttributeTag(9), AttributeTag(10)];
/// List of identity attribute tags that we allow set statements
/// (membership/nonMembership) for. The list should correspond to "Country
/// of residence", "Nationality", "IdDocType", "IdDocIssuer".
pub const ALLOWED_IDENTITY_SET_TAGS: [AttributeTag; 4] = [
    AttributeTag(4),
    AttributeTag(5),
    AttributeTag(6),
    AttributeTag(8),
];

/// Returns the `WalletConfig` that is used by our wallet implementations for
/// identity proofs. Note that it does not contain any rules for web3
/// statements.
pub fn get_default_wallet_config() -> WalletConfig<'static, constants::ArCurve, AttributeKind> {
    WalletConfig {
        identity_rules: Some(WalletConfigRules::<_, AttributeTag, _> {
            range_tags:      ALLOWED_IDENTITY_RANGE_TAGS.into(),
            set_tags:        ALLOWED_IDENTITY_SET_TAGS.into(),
            attribute_check: Box::new(default_attribute_rules),
            _marker:         PhantomData,
        }),
        web3_rules:     BTreeMap::new(),
    }
}
