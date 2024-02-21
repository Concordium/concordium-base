use concordium_base::{
    curve_arithmetic::Curve,
    id::{id_proof_types::AtomicStatement, types::*},
    web3id::{CredentialStatement, Request},
};

const IDENTITY_RANGE_TAGS: &[AttributeTag] = &[AttributeTag(3), AttributeTag(9), AttributeTag(10)]; // dob, idDocIssuedAt, idDocExpiresAt
const IDENTITY_SET_TAGS: &[AttributeTag] = &[
    AttributeTag(4),
    AttributeTag(5),
    AttributeTag(6),
    AttributeTag(8),
]; // Country of residence, Nationality, IdDocType, IdDocIssuer

fn is_iso8601(date: &str) -> bool {
    println!("{}", date);
    chrono::NaiveDate::parse_from_str(date, "%Y%m%d").is_ok()
}

fn is_iso3166_alpha_2(code: &str) -> bool { rust_iso3166::from_alpha2(code).is_some() }

fn is_iso3166_2(code: &str) -> bool { rust_iso3166::iso3166_2::from_code(code).is_some() }

pub trait WalletCheck {
    fn satisfies_wallet_restrictions(&self) -> bool;
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> WalletCheck for Request<C, AttributeType> {
    fn satisfies_wallet_restrictions(&self) -> bool {
        self.credential_statements
            .iter()
            .all(|s| s.satisfies_wallet_restrictions())
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> WalletCheck
    for CredentialStatement<C, AttributeType>
{
    fn satisfies_wallet_restrictions(&self) -> bool {
        match self {
            CredentialStatement::Account {
                statement,
                network: _,
                cred_id: _,
            } => {
                if statement.is_empty() {
                    return false;
                }
                let mut used_tags = Vec::<AttributeTag>::new();
                for atomic_statement in statement {
                    if used_tags.contains(&atomic_statement.attribute()) {
                        return false;
                    }
                    used_tags.push(atomic_statement.attribute());

                    if !atomic_statement.satisfies_wallet_restrictions() {
                        return false;
                    }
                }
            }
            CredentialStatement::Web3Id {
                ty: _,
                network: _,
                contract: _,
                credential: _,
                statement: _,
            } => todo!(),
        }
        return true;
    }
}

// Note that this is an implementation only for the account statement, the tag
// is AttributeTag.
impl<C: Curve, AttributeType: Attribute<C::Scalar>> WalletCheck
    for AtomicStatement<C, AttributeTag, AttributeType>
{
    fn satisfies_wallet_restrictions(&self) -> bool {
        let check_attribute_value = |value: &AttributeType| match self.attribute().0 {
            // countryOfResidence | nationality
            4 | 5 => is_iso3166_alpha_2(&value.to_string()),
            // idDocIssuer
            8 => is_iso3166_alpha_2(&value.to_string()) || is_iso3166_2(&value.to_string()),
            // dob, idDocIssuedAt, idDocExpiresAt
            3 | 9 | 10 => is_iso8601(&value.to_string()),
            _ => true,
        };

        match self {
            AtomicStatement::RevealAttribute { statement: _ } => true,
            AtomicStatement::AttributeInRange { statement } => {
                check_attribute_value(&statement.lower)
                    && check_attribute_value(&statement.upper)
                    && statement.lower < statement.upper
                    && IDENTITY_RANGE_TAGS.contains(&statement.attribute_tag)
            }
            AtomicStatement::AttributeInSet { statement } => {
                !statement.set.is_empty()
                    && statement.set.iter().all(check_attribute_value)
                    && IDENTITY_SET_TAGS.contains(&statement.attribute_tag)
            }
            AtomicStatement::AttributeNotInSet { statement } => {
                !statement.set.is_empty()
                    && statement.set.iter().all(check_attribute_value)
                    && IDENTITY_SET_TAGS.contains(&statement.attribute_tag)
            }
        }
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
        assert!(
            !statement.satisfies_wallet_restrictions(),
            "Statement with min > max should not satisfy"
        );
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
        assert!(
            !statement.satisfies_wallet_restrictions(),
            "Dob statement must have valid dates"
        );
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

        assert!(
            !bad_statement.satisfies_wallet_restrictions(),
            "Nationality statement must be country code"
        );
        assert!(
            good_statement.satisfies_wallet_restrictions(),
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
            statement.satisfies_wallet_restrictions(),
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
            !name_statement.satisfies_wallet_restrictions(),
            "Range statement should not be allowed on tag 1"
        );
        assert!(
            dob_statement.satisfies_wallet_restrictions(),
            "Range statement should be allowed on tag 3"
        );
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

        assert!(
            !statement.satisfies_wallet_restrictions(),
            "Using the same attribute twice is not allowed"
        );
        Ok(())
    }
}
