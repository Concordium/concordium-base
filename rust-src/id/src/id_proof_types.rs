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
use pedersen_scheme::Randomness as PedersenRandomness;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{collections::BTreeSet, marker::PhantomData};

/// For the case where the verifier wants the user to show the value of an
/// attribute and prove that it is indeed the value inside the on-chain
/// commitment. Since the verifier does not know the attribute value before
/// seing the proof, the value is not present here.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
pub struct RevealAttributeStatement {
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
}

/// For the case where the verifier wants the user to prove that an attribute is
/// in a range. The statement is that the attribute value lies in `[lower,
/// upper)` in the scalar field.
#[derive(Debug, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct AttributeInRangeStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
    #[serde(rename = "lower")]
    pub lower:         AttributeType,
    #[serde(rename = "lower")]
    pub upper:         AttributeType,
    #[serde(skip)]
    pub _phantom:      PhantomData<C>,
}

/// For the case where the verifier wants the user to prove that an attribute is
/// in a set of attributes.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct AttributeInSetStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
    // #[set_size_length = 2]
    #[serde(rename = "set")]
    pub set:           std::collections::BTreeSet<AttributeType>,
    #[serde(skip)]
    pub _phantom:      PhantomData<C>,
}

/// For the case where the verifier wants the user to prove that an attribute is
/// not in a set of attributes.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct AttributeNotInSetStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    #[serde(rename = "attributeTag")]
    pub attribute_tag: AttributeTag,
    #[serde(rename = "set")]
    pub set:           std::collections::BTreeSet<AttributeType>,
    #[serde(skip)]
    pub _phantom:      PhantomData<C>,
}

/// The different types of statements.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> +
SerdeSerialize",
    deserialize = "C: Curve, AttributeType:
Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
#[serde(tag = "type")]
pub enum AtomicStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    RevealAttribute {
        statement: RevealAttributeStatement,
    },
    AttributeInRange {
        statement: AttributeInRangeStatement<C, AttributeType>,
    },
    AttributeInSet {
        statement: AttributeInSetStatement<C, AttributeType>,
    },
    AttributeNotInSet {
        statement: AttributeNotInSetStatement<C, AttributeType>,
    },
}

/// The secret is always an attribute value together with randomness.
pub type AtomicSecret<C, AttributeType> = (AttributeType, PedersenRandomness<C>);

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
    RevealAttribute {
        #[serde(rename = "attributeTag")]
        attribute_tag: AttributeTag,
        attribute:     AttributeType,
        proof:         super::sigma_protocols::common::SigmaProof<DlogWitness<C>>,
    },
    AttributeInRange {
        statement: AttributeInRangeStatement<C, AttributeType>,
        #[serde(
            rename = "proof",
            serialize_with = "base16_encode",
            deserialize_with = "base16_decode"
        )]
        proof:     RangeProof<C>,
    },
    AttributeInSet {
        statement: AttributeInSetStatement<C, AttributeType>,
        #[serde(
            rename = "proof",
            serialize_with = "base16_encode",
            deserialize_with = "base16_decode"
        )]
        proof:     SetMembershipProof<C>,
    },
    AttributeNotInSet {
        statement: AttributeNotInSetStatement<C, AttributeType>,
        #[serde(
            rename = "proof",
            serialize_with = "base16_encode",
            deserialize_with = "base16_decode"
        )]
        proof:     SetNonMembershipProof<C>,
    },
}

/// A statement about a credential on an account.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct StatementWithContext<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub account:    AccountAddress,
    #[serde(serialize_with = "base16_encode", deserialize_with = "base16_decode")]
    pub credential: CredId<C>,
    pub statement:  Statement<C, AttributeType>,
}

/// A secret needed for proving a statement
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct Secret<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub secrets: Vec<AtomicSecret<C, AttributeType>>,
}

/// A statement is a list of atomic statements.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct Statement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub statements: Vec<AtomicStatement<C, AttributeType>>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Default for Statement<C, AttributeType> {
    fn default() -> Self { Statement { statements: vec![] } }
}

/// Helper functions for constructing statements
impl Statement<G1, AttributeKind> {
    pub fn older_than(mut self, age: u64) -> Self {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        let date_years_ago = format!(
            "{:04}{:02}{:02}",
            (now.year() as u64) - age,
            now.month(),
            now.day()
        );
        let upper = AttributeKind(date_years_ago);
        let lower = AttributeKind(String::from("18000101"));

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag(3u8), // DOB tag
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        self
    }

    pub fn younger_than(mut self, age: u64) -> Self {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        let date_years_ago = format!(
            "{:04}{:02}{:02}",
            (now.year() as u64) - age,
            now.month(),
            now.day()
        );
        let today = format!(
            "{:04}{:02}{:02}",
            (now.year() as u64),
            now.month(),
            now.day()
        );
        let lower = AttributeKind(date_years_ago);
        let upper = AttributeKind(today);

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag(3u8), // DOB tag
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        self
    }

    pub fn age_in_range(mut self, lower: u64, upper: u64) -> Self {
        use chrono::Datelike;
        let now = chrono::Utc::now();
        let lower_date = format!(
            "{:04}{:02}{:02}",
            (now.year() as u64) - lower,
            now.month(),
            now.day()
        );
        let upper_date = format!(
            "{:04}{:02}{:02}",
            (now.year() as u64) - upper,
            now.month(),
            now.day()
        );
        let lower = AttributeKind(lower_date);
        let upper = AttributeKind(upper_date);

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag(3u8), // DOB tag
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        self
    }

    pub fn doc_expiry_no_earlier_than(mut self, lower: AttributeKind) -> Self {
        let upper = AttributeKind(String::from("30000101"));

        let statement = AttributeInRangeStatement::<G1, _> {
            attribute_tag: AttributeTag(10u8), // doc expiry
            lower,
            upper,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInRange { statement });
        self
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Statement<C, AttributeType> {
    pub fn new() -> Self { Self::default() }

    pub fn reveal_attribute(mut self, attribute_tag: AttributeTag) -> Self {
        let statement = RevealAttributeStatement { attribute_tag };
        self.statements
            .push(AtomicStatement::RevealAttribute { statement });
        self
    }

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

    pub fn residence_in(mut self, set: BTreeSet<AttributeType>) -> Self {
        let statement = AttributeInSetStatement {
            attribute_tag: AttributeTag(4u8), // country of residence
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInSet { statement });
        self
    }

    pub fn residence_not_in(mut self, set: BTreeSet<AttributeType>) -> Self {
        let statement = AttributeNotInSetStatement {
            attribute_tag: AttributeTag(4u8), // country of residence
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeNotInSet { statement });
        self
    }

    pub fn document_issuer(&mut self, set: BTreeSet<AttributeType>) -> &mut Self {
        let statement = AttributeInSetStatement {
            attribute_tag: AttributeTag(4u8),
            set,
            _phantom: PhantomData::default(),
        };
        self.statements
            .push(AtomicStatement::AttributeInSet { statement });
        self
    }
}

/// A proof about a credential on an account
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct Proof<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub account:    AccountAddress,
    #[serde(serialize_with = "base16_encode", deserialize_with = "base16_decode")]
    pub credential: CredId<C>,
    pub proofs:     Vec<AtomicProof<C, AttributeType>>,
}
