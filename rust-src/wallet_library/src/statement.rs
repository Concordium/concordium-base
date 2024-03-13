use concordium_base::{
    base::ContractAddress,
    common::Serialize,
    curve_arithmetic::Curve,
    id::{id_proof_types::AtomicStatement, types::*},
    web3id::{CredentialStatement, Request},
};
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Display,
    hash::Hash,
    marker::PhantomData,
};

/// This trait is used to check that a Request is acceptable according to a set
/// of rules. It is used by wallets to restrict the incoming request to those
/// they are able to handle, willing to expose to the user.
pub trait AcceptableRequest<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Method to check whether the request is acceptable given the provided
    /// config. i.e. that it satifies the rules in the config, and some
    /// general rules.
    fn acceptable_request(
        &self,
        config: &WalletConfig<C, AttributeType>,
    ) -> AcceptableRequestResult;
}

pub trait AcceptableAtomicStatement<
    C: Curve,
    TagType: AttributeTagType,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Method to check that the statement is acceptable given the provided
    /// rules.
    fn acceptable_atomic_statement(
        &self,
        rules: Option<&WalletConfigRules<C, TagType, AttributeType>>,
    ) -> AcceptableRequestResult;
}

pub type AcceptableRequestResult = Result<(), RequestCheckError>;

pub struct WalletConfig<'a, C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Rules that statements on identity credentials should satisfy
    pub identity_rules: Option<WalletConfigRules<'a, C, AttributeTag, AttributeType>>,
    /// Rules that statements on web3Id credentials should satisfy. If a
    /// statement uses a contract index without an entry, it should only
    /// consider for basic, global, rules.
    pub web3_rules:     BTreeMap<ContractAddress, WalletConfigRules<'a, C, String, AttributeType>>,
}

pub struct WalletConfigRules<
    'a,
    C: Curve,
    TagType: AttributeTagType,
    AttributeType: Attribute<C::Scalar>,
> {
    /// The set of tags, which are allowed to be used for range statements.
    pub range_tags:      HashSet<TagType>,
    /// The set of tags, which are allowed to be used for membership and
    /// nonMembership statements.
    pub set_tags:        HashSet<TagType>,
    /// A function to check attributes using custom behaviour.
    pub attribute_check: AttributeCheck<'a, TagType, AttributeType>,
    pub _marker:         PhantomData<C>,
}

pub trait AttributeTagType: Serialize + Ord + Hash + Display {}
impl<T: Serialize + Ord + Hash + Display> AttributeTagType for T {}

type AttributeCheck<'a, TagType, AttributeType> =
    Box<dyn Fn(&TagType, &AttributeType) -> AcceptableRequestResult + 'a>;

#[derive(Debug, thiserror::Error, Clone)]
pub enum RequestCheckError {
    #[error("Credential statement must include atomic statements")]
    EmptyCredentialStatement,
    #[error("Credential statement may not reuse attribute tags across atomic statements")]
    DuplicateTag,
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

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AcceptableRequest<C, AttributeType>
    for Request<C, AttributeType>
{
    fn acceptable_request(
        &self,
        config: &WalletConfig<C, AttributeType>,
    ) -> AcceptableRequestResult {
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
    ) -> AcceptableRequestResult {
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

                    atomic_statement.acceptable_atomic_statement(config.identity_rules.as_ref())?
                }
                Ok(())
            }
            CredentialStatement::Web3Id {
                ty: _,
                network: _,
                contract,
                credential: _,
                statement,
            } => {
                if statement.is_empty() {
                    return Err(RequestCheckError::EmptyCredentialStatement);
                }
                let mut used_tags = HashSet::<String>::new();
                for atomic_statement in statement {
                    let attribute = match atomic_statement {
                        AtomicStatement::RevealAttribute { statement } => &statement.attribute_tag,
                        AtomicStatement::AttributeInRange { statement } => &statement.attribute_tag,
                        AtomicStatement::AttributeInSet { statement } => &statement.attribute_tag,
                        AtomicStatement::AttributeNotInSet { statement } => {
                            &statement.attribute_tag
                        }
                    };
                    if used_tags.contains(attribute) {
                        return Err(RequestCheckError::DuplicateTag);
                    }
                    used_tags.insert(attribute.clone());

                    atomic_statement.acceptable_atomic_statement(config.web3_rules.get(contract))?
                }
                Ok(())
            }
        }
    }
}

impl<C: Curve, TagType: AttributeTagType, AttributeType: Attribute<C::Scalar>>
    AcceptableAtomicStatement<C, TagType, AttributeType>
    for AtomicStatement<C, TagType, AttributeType>
{
    fn acceptable_atomic_statement(
        &self,
        config_rules: Option<&WalletConfigRules<C, TagType, AttributeType>>,
    ) -> AcceptableRequestResult {
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
                        return Err(RequestCheckError::IllegalRangeTag(tag.to_string()));
                    }
                    check(tag, &statement.lower)?;
                    check(tag, &statement.upper)?;
                }
                AtomicStatement::AttributeInSet { statement } => {
                    let tag = &statement.attribute_tag;
                    if !rules.set_tags.contains(tag) {
                        return Err(RequestCheckError::IllegalSetTag(tag.to_string()));
                    }
                    return statement.set.iter().try_for_each(|a| check(tag, a));
                }
                AtomicStatement::AttributeNotInSet { statement } => {
                    let tag = &statement.attribute_tag;
                    if !rules.set_tags.contains(tag) {
                        return Err(RequestCheckError::IllegalSetTag(tag.to_string()));
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
    use crate::default_wallet_config::default_wallet_config;
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
            statement.acceptable_atomic_statement(default_wallet_config().identity_rules.as_ref()),
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
            statement.acceptable_atomic_statement(default_wallet_config().identity_rules.as_ref()),
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
            bad_statement
                .acceptable_atomic_statement(default_wallet_config().identity_rules.as_ref()),
            Err(RequestCheckError::InvalidValue(_))
        ));
        assert!(
            good_statement
                .acceptable_atomic_statement(default_wallet_config().identity_rules.as_ref())
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
                .acceptable_atomic_statement(default_wallet_config().identity_rules.as_ref())
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
                .acceptable_atomic_statement(default_wallet_config().identity_rules.as_ref())
                .is_ok(),
            "Range statement should be allowed on tag 3 (dob)"
        );
        assert!(matches!(
            name_statement
                .acceptable_atomic_statement(default_wallet_config().identity_rules.as_ref()),
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

        let statement: CredentialStatement<constants::ArCurve, constants::AttributeKind> = CredentialStatement::Account {
            network: Network::Testnet,
            cred_id: CredentialRegistrationID::from_str("8a3a87f3f38a7a507d1e85dc02a92b8bcaa859f5cf56accb3c1bc7c40e1789b4933875a38dd4c0646ca3e940a02c42d8")?,
            statement: vec![statement1, statement2]
        };

        assert!(matches!(
            statement.acceptable_request(&default_wallet_config()),
            Err(RequestCheckError::DuplicateTag)
        ));
        Ok(())
    }
}
