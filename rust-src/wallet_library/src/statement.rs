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

impl<C: Curve, AttributeType: Attribute<C::Scalar>> WalletCheck
    for AtomicStatement<C, AttributeTag, AttributeType>
{
    fn satisfies_wallet_restrictions(&self) -> bool {
        match self {
            AtomicStatement::RevealAttribute { statement: _ } => true,
            AtomicStatement::AttributeInRange { statement } => {
                statement.lower < statement.upper
                    && IDENTITY_RANGE_TAGS.contains(&statement.attribute_tag)
            }
            AtomicStatement::AttributeInSet { statement } => {
                !statement.set.is_empty() && IDENTITY_SET_TAGS.contains(&statement.attribute_tag)
            }
            AtomicStatement::AttributeNotInSet { statement } => {
                !statement.set.is_empty() && IDENTITY_SET_TAGS.contains(&statement.attribute_tag)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, str::FromStr};

    use super::*;
    use concordium_base::{
        base::CredentialRegistrationID,
        id::{
            constants,
            id_proof_types::{AttributeInRangeStatement, RevealAttributeStatement},
        },
        web3id::did::Network,
    };

    #[test]
    pub fn range_min_max_test() {
        let statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: AttributeTag(3),
                lower:         constants::AttributeKind::from(11),
                upper:         constants::AttributeKind::from(10),
                _phantom:      PhantomData::<constants::ArCurve>,
            },
        };
        assert!(
            !statement.satisfies_wallet_restrictions(),
            "Statement with min > max should not satisfy"
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
                lower:         constants::AttributeKind::from(5),
                upper:         constants::AttributeKind::from(10),
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
                lower:         constants::AttributeKind::from(5),
                upper:         constants::AttributeKind::from(10),
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
