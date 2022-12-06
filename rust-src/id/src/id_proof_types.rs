//! Types used to represent statements and proofs.
//! A statement is what the user is requested to prove by the verifier.
//! The proofs are for proving properties about the attribute values inside
//! on-chain commitments that account credentials can have.
//! Given the statement and relevant secret data (being the attribute value and
//! the commitment randomness), the user can construct a proof of the statement
//! (if the statement is true).
use crate::{constants::AttributeKind, sigma_protocols::dlog::Witness as DlogWitness, types::*};
use bulletproofs::{
    range_proof::RangeProof, set_membership_proof::SetMembershipProof,
    set_non_membership_proof::SetNonMembershipProof,
};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use pairing::bls12_381::G1;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{collections::BTreeSet, convert::TryFrom, marker::PhantomData, str::FromStr};

/// For the case where the verifier wants the user to show the value of an
/// attribute and prove that it is indeed the value inside the on-chain
/// commitment. Since the verifier does not know the attribute value before
/// seing the proof, the value is not present here.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
pub struct RevealAttributeStatement {
    /// The attribute that the verifier wants the user to reveal.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
}

/// For the case where the verifier wants the user to prove that an attribute is
/// in a range. The statement is that the attribute value lies in `[lower,
/// upper)` in the scalar field.
#[derive(Debug, Clone, Serialize, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct AttributeInRangeStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// The attribute that the verifier wants the user to prove is in a range.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
    /// The lower bound on the range.
    #[serde(rename = "lower")]
    pub lower:         AttributeType,
    #[serde(rename = "upper")]
    /// The upper bound of the range.
    pub upper:         AttributeType,
    #[serde(skip)]
    pub _phantom:      PhantomData<C>,
}

/// For the case where the verifier wants the user to prove that an attribute is
/// in a set of attributes.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct AttributeInSetStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// The attribute that the verifier wants the user prove lies in a set.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
    /// The set that the attribute should lie in.
    #[serde(rename = "set")]
    pub set:           std::collections::BTreeSet<AttributeType>,
    #[serde(skip)]
    pub _phantom:      PhantomData<C>,
}

/// For the case where the verifier wants the user to prove that an attribute is
/// not in a set of attributes.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct AttributeNotInSetStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// The attribute that the verifier wants the user to prove does not lie in
    /// a set.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
    /// The set that the attribute should not lie in.
    #[serde(rename = "set")]
    pub set:           std::collections::BTreeSet<AttributeType>,
    #[serde(skip)]
    pub _phantom:      PhantomData<C>,
}

/// Statements are composed of one or more atomic statements.
/// This type defines the different types of atomic statements.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> +
SerdeSerialize",
    deserialize = "C: Curve, AttributeType:
Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
#[serde(tag = "type")]
pub enum AtomicStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// The atomic statement stating that an attribute should be revealed.
    RevealAttribute {
        #[serde(flatten)]
        statement: RevealAttributeStatement,
    },
    /// The atomic statement stating that an attribute is in a range.
    AttributeInRange {
        #[serde(flatten)]
        statement: AttributeInRangeStatement<C, AttributeType>,
    },
    /// The atomic statement stating that an attribute is in a set.
    AttributeInSet {
        #[serde(flatten)]
        statement: AttributeInSetStatement<C, AttributeType>,
    },
    /// The atomic statement stating that an attribute is not in a set.
    AttributeNotInSet {
        #[serde(flatten)]
        statement: AttributeNotInSetStatement<C, AttributeType>,
    },
}

/// The different types of proofs, corresponding to the statements above.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> +
SerdeSerialize",
    deserialize = "C: Curve, AttributeType:
Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
#[serde(tag = "type")]
pub enum AtomicProof<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Revealing an attribute and a proof that it equals the attribute value
    /// inside the attribute commitment.
    RevealAttribute {
        attribute: AttributeType, /* The verifier has to learn this, so it is sent together with
                                   * the proof. */
        proof:     super::sigma_protocols::common::SigmaProof<DlogWitness<C>>,
    },
    /// A proof that an attribute is in a range
    AttributeInRange {
        #[serde(
            rename = "proof",
            serialize_with = "base16_encode",
            deserialize_with = "base16_decode"
        )]
        proof: RangeProof<C>,
    },
    /// A proof that an attribute is in a set
    AttributeInSet {
        #[serde(
            rename = "proof",
            serialize_with = "base16_encode",
            deserialize_with = "base16_decode"
        )]
        proof: SetMembershipProof<C>,
    },
    /// A proof that an attribute is not in a set
    AttributeNotInSet {
        #[serde(
            rename = "proof",
            serialize_with = "base16_encode",
            deserialize_with = "base16_decode"
        )]
        proof: SetNonMembershipProof<C>,
    },
}

/// A statement with a context is a statement about a credential,
/// the context being the credential.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct StatementWithContext<C: Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(serialize_with = "base16_encode", deserialize_with = "base16_decode")]
    /// The credential that the statement is about.
    pub credential: CredId<C>,
    /// The statement composed by one or more atomic statements.
    pub statement:  Statement<C, AttributeType>,
}

/// A statement is a list of atomic statements.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
#[serde(transparent)]
pub struct Statement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// The list of atomic statements
    pub statements: Vec<AtomicStatement<C, AttributeType>>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Default for Statement<C, AttributeType> {
    fn default() -> Self { Statement { statements: vec![] } }
}

/// Helper functions for constructing statements
impl Statement<G1, AttributeKind> {
    /// For stating that the user is at least `age` years old.
    /// The functions returns `None` if
    /// - the current year does not fit into a u64, or
    /// - the given age is larger than the current year.
    /// Otherwise it returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "older than" statement.
    pub fn older_than(mut self, age: u64) -> Option<Self> {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        let year = u64::try_from(now.year()).ok()?;
        let years_ago = year.checked_sub(age)?;
        let date_years_ago = format!("{:04}{:02}{:02}", years_ago, now.month(), now.day());
        let upper = AttributeKind(date_years_ago);
        let lower = AttributeKind(String::from("18000101"));

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag::from_str("dob").ok()?, // date of birth tag
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        Some(self)
    }

    /// For stating that the user is strictly younger than `age` years old.
    /// The functions returns `None` if
    /// - the current year does not fit into a u64, or
    /// - the given age is larger than the current year.
    /// Otherwise it returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "younger than" statement.
    pub fn younger_than(mut self, age: u64) -> Option<Self> {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        let year = u64::try_from(now.year()).ok()?;
        let years_ago = year.checked_sub(age)?;
        let date_years_ago = format!("{:04}{:02}{:02}", years_ago, now.month(), now.day());
        let today = format!("{:04}{:02}{:02}", year, now.month(), now.day());
        let lower = AttributeKind(date_years_ago);
        let upper = AttributeKind(today);

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag::from_str("dob").ok()?, // date of birth tag
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        Some(self)
    }

    /// For stating that the user's age in years is in `[lower, upper)`.
    /// The functions returns `None` if
    /// - the current year does not fit into a u64, or
    /// - the given lower or upper bound is larger than the current year.
    /// Otherwise it returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "age in range" statement.
    pub fn age_in_range(mut self, lower: u64, upper: u64) -> Option<Self> {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        let year = u64::try_from(now.year()).ok()?;
        let lower_year = year.checked_sub(upper)?;
        let upper_year = year.checked_sub(lower)?;
        let lower_date = format!("{:04}{:02}{:02}", lower_year, now.month(), now.day());
        let upper_date = format!("{:04}{:02}{:02}", upper_year, now.month(), now.day());
        let lower = AttributeKind(lower_date);
        let upper = AttributeKind(upper_date);

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag::from_str("dob").ok()?, // date of birth tag
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        Some(self)
    }

    /// For stating that the user's document expiry is at least `lower`.
    /// The function returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "document expiry no earlier than" statement.
    pub fn doc_expiry_no_earlier_than(mut self, lower: AttributeKind) -> Option<Self> {
        let upper = AttributeKind(String::from("99990101"));

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag::from_str("idDocExpiresAt").ok()?, // doc expiry
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        Some(self)
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Statement<C, AttributeType> {
    /// For constructing the empty statement.
    pub fn new() -> Self { Self::default() }

    /// For revealing an attribute. This is resquests the user to reveal the
    /// attribute value corresponding to `attribute_tag` and to prove that
    /// the value is the one inside the on-chain commitment.
    /// The function returns the statements in `self` composed with the "reveal
    /// attribute" statement.
    pub fn reveal_attribute(mut self, attribute_tag: AttributeTag) -> Self {
        let statement = RevealAttributeStatement { attribute_tag };
        self.statements
            .push(AtomicStatement::RevealAttribute { statement });
        self
    }

    /// For stating that an attribute is in `[lower, upper)`.
    /// The function returns the statements in `self` composed with the range
    /// statement.
    pub fn in_range(
        mut self,
        tag: AttributeTag,
        lower: AttributeType,
        upper: AttributeType,
    ) -> Self {
        let statement = AttributeInRangeStatement {
            attribute_tag: tag,
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        self
    }

    /// For stating that an attribute is in a set.
    /// The function returns the statements in `self` composed with the "member
    /// of" statement.
    pub fn member_of(mut self, tag: AttributeTag, set: BTreeSet<AttributeType>) -> Self {
        let statement = AttributeInSetStatement {
            attribute_tag: tag,
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInSet { statement });
        self
    }

    /// For stating that that an attribute does not lie in a set.
    /// The function returns the statements in `self` composed with the "not
    /// member of" statement.
    pub fn not_member_of(mut self, tag: AttributeTag, set: BTreeSet<AttributeType>) -> Self {
        let statement = AttributeNotInSetStatement {
            attribute_tag: tag,
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeNotInSet { statement });
        self
    }

    /// For stating that the user's country of residence is in a set.
    /// The function returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "residence in" statement.
    pub fn residence_in(mut self, set: BTreeSet<AttributeType>) -> Option<Self> {
        let statement = AttributeInSetStatement {
            attribute_tag: AttributeTag::from_str("countryOfResidence").ok()?, /* country of
                                                                                * residence */
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInSet { statement });
        Some(self)
    }

    /// For stating that the user's country of residence does not lie in set.
    /// The function returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "residence not in" statement.
    pub fn residence_not_in(mut self, set: BTreeSet<AttributeType>) -> Option<Self> {
        let statement = AttributeNotInSetStatement {
            attribute_tag: AttributeTag::from_str("countryOfResidence").ok()?, /* country of
                                                                                * residence */
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeNotInSet { statement });
        Some(self)
    }

    /// For stating that the user's document issuer is in a set.
    /// The function returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "document issuer in" statement.
    pub fn document_issuer_in(mut self, set: BTreeSet<AttributeType>) -> Option<Self> {
        let statement = AttributeInSetStatement {
            attribute_tag: AttributeTag::from_str("idDocIssuer").ok()?,
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInSet { statement });
        Some(self)
    }

    /// For stating that the user's document issuer does not lie in a set.
    /// The function returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "document issuer not in" statement.
    pub fn document_issuer_not_in(mut self, set: BTreeSet<AttributeType>) -> Option<Self> {
        let statement = AttributeNotInSetStatement {
            attribute_tag: AttributeTag::from_str("idDocIssuer").ok()?,
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeNotInSet { statement });
        Some(self)
    }

    /// For stating that the user's nationality is in a set.
    /// The function returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "document issuer in" statement.
    pub fn nationality_in(mut self, set: BTreeSet<AttributeType>) -> Option<Self> {
        let statement = AttributeInSetStatement {
            attribute_tag: AttributeTag::from_str("nationality").ok()?,
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInSet { statement });
        Some(self)
    }

    /// For stating that the user's nationality does not lie in a set.
    /// The function returns `Some(statement)` where
    /// `statement` is composed by the statements in `self` and
    /// the "document issuer not in" statement.
    pub fn nationality_not_in(mut self, set: BTreeSet<AttributeType>) -> Option<Self> {
        let statement = AttributeNotInSetStatement {
            attribute_tag: AttributeTag::from_str("nationality").ok()?,
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeNotInSet { statement });
        Some(self)
    }
}

/// A proof of a statement, composed of one or more atomic proofs.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct Proof<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub proofs: Vec<AtomicProof<C, AttributeType>>,
}
