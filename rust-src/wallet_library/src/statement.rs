use std::{
    collections::{BTreeMap, HashSet},
    fmt::Display,
    hash::Hash,
    marker::PhantomData,
};

use concordium_base::{
    base::ContractAddress,
    common::Serialize,
    curve_arithmetic::Curve,
    id::{
        constants::{self, AttributeKind},
        id_proof_types::AtomicStatement,
        types::*,
    },
    web3id::{CredentialStatement, Request},
};

fn is_iso8601(date: &str) -> bool { chrono::NaiveDate::parse_from_str(date, "%Y%m%d").is_ok() }

fn is_iso3166_alpha_2(code: &str) -> bool { rust_iso3166::from_alpha2(code).is_some() }

fn is_iso3166_2(code: &str) -> bool { rust_iso3166::iso3166_2::from_code(code).is_some() }

pub trait AcceptableRequest<C: Curve, AttributeType: Attribute<C::Scalar>> {
    fn acceptable_request(
        &self,
        config: &WalletConfig<C, AttributeType>,
    ) -> Result<(), RequestCheckError>;
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum RequestCheckError {
    #[error("Credential statement must include atomic statements")]
    EmptyCredentialStatement,
    #[error("Credential statement may not reuse attribute tags across atomic statements")]
    DuplicateTag,
    #[error("Web3Id statement support have not been added yet")]
    Web3IdStatementNotSupported,
    #[error("`{0}`")]
    InvalidValue(String),
    #[error("Range statement min must be less than max")]
    RangeMinMaxError,
    #[error("The tag `{0}` is not allowed to be used for range statements")]
    IllegalRangeTag(String),
    #[error("Membership and NonMembership statement's may not have empty sets")]
    EmptySet,
    #[error("The tag `{0}` is not allowed to be used for set statements")]
    IllegalSetTag(String),
}

pub struct WalletConfig<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub identity_rules: Option<WalletConfigRules<C, AttributeTag, AttributeType>>,
    pub web3_rules:     BTreeMap<ContractAddress, WalletConfigRules<C, String, AttributeType>>,
}

pub trait AttributeTagType: Serialize + Ord + Hash + Display {}
impl<T: Serialize + Ord + Hash + Display> AttributeTagType for T {}

type AttributeCheck<TagType, AttributeType> =
    Box<dyn Fn(&TagType, &AttributeType) -> AcceptableRequestResult>;
type AcceptableRequestResult = Result<(), RequestCheckError>;

pub struct WalletConfigRules<
    C: Curve,
    TagType: AttributeTagType,
    AttributeType: Attribute<C::Scalar>,
> {
    pub range_tags:   HashSet<TagType>,
    pub set_tags:     HashSet<TagType>,
    pub attribute_check: AttributeCheck<TagType, AttributeType>,
    _marker:          PhantomData<C>,
}

fn default_attribute_rules(
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

pub fn get_default_wallet_config() -> WalletConfig<constants::ArCurve, AttributeKind> {
    /// List of identity attribute tags that we allow range statements for.
    /// The list should correspond to "dob", "idDocIssuedAt", "idDocExpiresAt".
    const IDENTITY_RANGE_TAGS: [AttributeTag; 3] =
        [AttributeTag(3), AttributeTag(9), AttributeTag(10)];
    /// List of identity attribute tags that we allow set statements
    /// (membership/nonMembership) for. The list should correspond to "Country
    /// of residence", "Nationality", "IdDocType", "IdDocIssuer".
    const IDENTITY_SET_TAGS: [AttributeTag; 4] = [
        AttributeTag(4),
        AttributeTag(5),
        AttributeTag(6),
        AttributeTag(8),
    ];

    WalletConfig {
        identity_rules: Some(WalletConfigRules::<_, AttributeTag, _> {
            range_tags:   IDENTITY_RANGE_TAGS.into(),
            set_tags:     IDENTITY_SET_TAGS.into(),
            attribute_check: Box::new(default_attribute_rules),
            _marker:      PhantomData,
        }),
        web3_rules:     BTreeMap::new(),
    }
}

pub trait AcceptableAtomicStatement<
    C: Curve,
    TagType: AttributeTagType,
    AttributeType: Attribute<C::Scalar>,
> {
    fn acceptable_atomic_statement(
        &self,
        rules: &Option<WalletConfigRules<C, TagType, AttributeType>>,
    ) -> Result<(), RequestCheckError>;
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AcceptableRequest<C, AttributeType>
    for Request<C, AttributeType>
{
    fn acceptable_request(
        &self,
        config: &WalletConfig<C, AttributeType>,
    ) -> Result<(), RequestCheckError> {
        self.credential_statements
            .iter()
            .try_for_each(|s| s.acceptable_request(config))
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AcceptableRequest<C, AttributeType>
    for CredentialStatement<C, AttributeType>
{
    fn acceptable_request(
        &self,
        config: &WalletConfig<C, AttributeType>,
    ) -> Result<(), RequestCheckError> {
        match self {
            CredentialStatement::Account {
                statement,
                network: _,
                cred_id: _,
            } => {
                if statement.is_empty() {
                    return Err(RequestCheckError::EmptyCredentialStatement);
                }
                let mut used_tags = HashSet::<AttributeTag>::new();
                for atomic_statement in statement {
                    let attribute = atomic_statement.attribute();
                    if used_tags.contains(&attribute) {
                        return Err(RequestCheckError::DuplicateTag);
                    }
                    used_tags.insert(attribute);

                    atomic_statement.acceptable_atomic_statement(&config.identity_rules)?
                }
                Ok(())
            }
            CredentialStatement::Web3Id {
                ty: _,
                network: _,
                contract: _,
                credential: _,
                statement: _,
            } => Err(RequestCheckError::Web3IdStatementNotSupported),
        }
    }
}

// Note that this is an implementation only for the account statement, the tag
// is AttributeTag.
impl<C: Curve, TagType: AttributeTagType, AttributeType: Attribute<C::Scalar>>
    AcceptableAtomicStatement<C, TagType, AttributeType>
    for AtomicStatement<C, TagType, AttributeType>
{
    fn acceptable_atomic_statement(
        &self,
        config_rules: &Option<WalletConfigRules<C, TagType, AttributeType>>,
    ) -> Result<(), RequestCheckError> {
        // Simple checks
        match self {
            AtomicStatement::RevealAttribute { statement: _ } => return Ok(()),
            AtomicStatement::AttributeInRange { statement } => {
                if statement.lower >= statement.upper {
                    return Err(RequestCheckError::RangeMinMaxError);
                }
            }
            AtomicStatement::AttributeInSet { statement } => {
                if statement.set.is_empty() {
                    return Err(RequestCheckError::EmptySet);
                }
            }
            AtomicStatement::AttributeNotInSet { statement } => {
                if statement.set.is_empty() {
                    return Err(RequestCheckError::EmptySet);
                }
            }
        }
        // checks based on wallet config
        if let Some(rules) = config_rules {
            let check = &rules.attribute_check;
            match self {
                AtomicStatement::RevealAttribute { statement: _ } => (),
                AtomicStatement::AttributeInRange { statement } => {
                    let tag = &statement.attribute_tag;
                    if !rules.range_tags.contains(tag) {
                        return Err(RequestCheckError::IllegalRangeTag(format!("{}", tag)));
                    }
                    check(tag, &statement.lower)?;
                    check(tag, &statement.upper)?;
                }
                AtomicStatement::AttributeInSet { statement } => {
                    let tag = &statement.attribute_tag;
                    if !rules.set_tags.contains(tag) {
                        return Err(RequestCheckError::IllegalSetTag(format!("{}", tag)));
                    }
                    return statement.set.iter().try_for_each(|a| check(tag, a));
                }
                AtomicStatement::AttributeNotInSet { statement } => {
                    let tag = &statement.attribute_tag;
                    if !rules.set_tags.contains(tag) {
                        return Err(RequestCheckError::IllegalSetTag(format!("{}", tag)));
                    }
                    return statement.set.iter().try_for_each(|a| check(tag, a));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, marker::PhantomData, str::FromStr};

    use super::*;
    use concordium_base::{
        base::CredentialRegistrationID,
        id::{
            constants,
            id_proof_types::{
                AttributeInRangeStatement, AttributeInSetStatement, RevealAttributeStatement,
            },
        },
        web3id::did::Network,
    };

    #[test]
    pub fn range_min_max_test() {
        let statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: AttributeTag(3),
                lower:         constants::AttributeKind::from(20150101),
                upper:         constants::AttributeKind::from(20140101),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };
        assert!(matches!(
            statement.acceptable_atomic_statement(&get_default_wallet_config().identity_rules),
            Err(RequestCheckError::RangeMinMaxError)
        ));
    }

    #[test]
    pub fn dob_must_be_valid_dates_test() {
        let statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: AttributeTag(3),
                lower:         constants::AttributeKind::from(20144040),
                upper:         constants::AttributeKind::from(20154040),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };
        assert!(matches!(
            statement.acceptable_atomic_statement(&get_default_wallet_config().identity_rules),
            Err(RequestCheckError::InvalidValue(_))
        ));
    }

    #[test]
    pub fn nationality_must_be_country_code_test() {
        let good_statement = AtomicStatement::AttributeInSet {
            statement: AttributeInSetStatement {
                attribute_tag: AttributeTag(5),
                set:           BTreeSet::from([constants::AttributeKind("GB".into())]),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };
        let bad_statement = AtomicStatement::AttributeInSet {
            statement: AttributeInSetStatement {
                attribute_tag: AttributeTag(5),
                set:           BTreeSet::from([constants::AttributeKind("HI".into())]),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };

        assert!(matches!(
            bad_statement.acceptable_atomic_statement(&get_default_wallet_config().identity_rules),
            Err(RequestCheckError::InvalidValue(_))
        ));
        assert!(
            good_statement
                .acceptable_atomic_statement(&get_default_wallet_config().identity_rules)
                .is_ok(),
            "Nationality statement must be country code"
        );
    }

    #[test]
    pub fn id_doc_issuer_can_be_iso_3166_2_test() {
        let statement = AtomicStatement::AttributeInSet {
            statement: AttributeInSetStatement {
                attribute_tag: AttributeTag(8),
                set:           BTreeSet::from([
                    constants::AttributeKind("DK-81".into()),
                    constants::AttributeKind("GB-UKM".into()),
                ]),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };
        assert!(
            statement
                .acceptable_atomic_statement(&get_default_wallet_config().identity_rules)
                .is_ok(),
            "idDocIssuer should be allowed ISO3166-2 values"
        );
    }

    #[test]
    pub fn range_statements_are_only_allowed_on_some_tags_test() {
        let dob_statement: AtomicStatement<
            constants::ArCurve,
            AttributeTag,
            constants::AttributeKind,
        > = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: AttributeTag(3),
                lower:         constants::AttributeKind::from(20140101),
                upper:         constants::AttributeKind::from(20150101),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };

        let name_statement: AtomicStatement<
            constants::ArCurve,
            AttributeTag,
            constants::AttributeKind,
        > = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: AttributeTag(2),
                lower:         constants::AttributeKind::from(20140101),
                upper:         constants::AttributeKind::from(20150101),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };
        assert!(
            dob_statement
                .acceptable_atomic_statement(&get_default_wallet_config().identity_rules)
                .is_ok(),
            "Range statement should be allowed on tag 3 (dob)"
        );
        assert!(matches!(
            name_statement.acceptable_atomic_statement(&get_default_wallet_config().identity_rules),
            Err(RequestCheckError::IllegalRangeTag(_))
        ));
    }

    #[test]
    pub fn multiple_statements_on_tag_test() -> anyhow::Result<()> {
        let statement1: AtomicStatement<
            constants::ArCurve,
            AttributeTag,
            constants::AttributeKind,
        > = AtomicStatement::RevealAttribute {
            statement: RevealAttributeStatement {
                attribute_tag: AttributeTag(3),
            },
        };

        let statement2: AtomicStatement<
            constants::ArCurve,
            AttributeTag,
            constants::AttributeKind,
        > = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: AttributeTag(3),
                lower:         constants::AttributeKind::from(5),
                upper:         constants::AttributeKind::from(10),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };

        let statement: CredentialStatement<constants::ArCurve, constants::AttributeKind> = CredentialStatement::Account { network: Network::Testnet, cred_id: CredentialRegistrationID::from_str("8a3a87f3f38a7a507d1e85dc02a92b8bcaa859f5cf56accb3c1bc7c40e1789b4933875a38dd4c0646ca3e940a02c42d8")?, statement: vec![statement1, statement2]};

        assert!(matches!(
            statement.acceptable_request(&get_default_wallet_config()),
            Err(RequestCheckError::DuplicateTag)
        ));
        Ok(())
    }
}
