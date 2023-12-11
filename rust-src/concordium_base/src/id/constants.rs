//! Collection of constants that fix choices, be it values or types, that are
//! used in various places.
use super::types::Attribute;
use crate::{
    common::{
        Buffer, Deserial, Get, ParseResult, Put, ReadBytesExt, SerdeDeserialize, SerdeSerialize,
        Serial,
    },
    curve_arithmetic::{
        arkworks_instances::{ArkField, ArkGroup},
        Curve, Pairing,
    },
};
use anyhow::bail;
use ark_bls12_381::{g1, G1Projective};
use ark_ec::{bls12::Bls12, short_weierstrass::Projective};
use serde::{
    de::{self, Visitor},
    Deserializer, Serializer,
};
use std::{fmt, io::Cursor, str::FromStr};
use thiserror::Error;

/// Curve used by the anonymity revoker.
pub type ArCurve = ArkGroup<Projective<g1::Config>>;
/// Pairing used by the identity provider.
pub type IpPairing = Bls12<ark_bls12_381::Config>;
/// Field used by the identity provider and anonymity revoker.
/// This is the base field of both the ArCurve and the IpPairing.
pub type BaseField = <IpPairing as Pairing>::ScalarField;
// pub type BaseField = ArkField<Fr>;

/// Index used to create the RegId of the initial credential.
pub const INITIAL_CREDENTIAL_INDEX: u8 = 0;

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
/// Concrete attribute values.
/// All currently supported attributes are string values.
pub struct AttributeKind(pub String);

impl SerdeSerialize for AttributeKind {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> SerdeDeserialize<'de> for AttributeKind {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        struct AttributeKindVisitor;

        impl<'de> Visitor<'de> for AttributeKindVisitor {
            type Value = AttributeKind;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "A string less than 31 bytes when decoded.")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.as_bytes().len() > 31 {
                    Err(de::Error::custom("Value too big."))
                } else {
                    Ok(AttributeKind(v.to_string()))
                }
            }
        }
        des.deserialize_str(AttributeKindVisitor)
    }
}

impl Deserial for AttributeKind {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u8 = source.get()?;
        if len <= 31 {
            let mut buf = vec![0u8; len as usize];
            source.read_exact(&mut buf)?;
            Ok(AttributeKind(String::from_utf8(buf)?))
        } else {
            bail!("Attributes can be at most 31 bytes.")
        }
    }
}

impl Serial for AttributeKind {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&(self.0.as_bytes().len() as u8));
        out.write_all(self.0.as_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

#[derive(Debug, Error)]
/// Errors occurring when parsing attribute values.
pub enum ParseAttributeError {
    #[error("Value out of range.")]
    ValueTooLarge,
}

impl FromStr for AttributeKind {
    type Err = ParseAttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().len() <= 31 {
            Ok(AttributeKind(s.to_string()))
        } else {
            Err(ParseAttributeError::ValueTooLarge)
        }
    }
}

impl fmt::Display for AttributeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<u64> for AttributeKind {
    fn from(x: u64) -> Self { AttributeKind(x.to_string()) }
}

impl Attribute<<ArkGroup<G1Projective> as Curve>::Scalar> for AttributeKind {
    fn to_field_element(&self) -> <ArkGroup<G1Projective> as Curve>::Scalar {
        let mut buf = [0u8; 32];
        let len = self.0.as_bytes().len();
        buf[1 + (31 - len)..].copy_from_slice(self.0.as_bytes());
        buf[0] = len as u8; // this should be valid because len <= 31 so the first two bits will be unset
        <<ArkGroup<G1Projective> as Curve>::Scalar as Deserial>::deserial(&mut Cursor::new(&buf))
            .expect("31 bytes + length fits into a scalar.")
    }
}
