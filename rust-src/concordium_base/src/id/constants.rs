//! Collection of constants that fix choices, be it values or types, that are
//! used in various places.
use super::types::Attribute;
use crate::{
    common::{
        Buffer, Deserial, Get, ParseResult, Put, ReadBytesExt, SerdeDeserialize, SerdeSerialize,
        Serial,
    },
    curve_arithmetic::{arkworks_instances::ArkGroup, Curve, Pairing},
};
use anyhow::bail;
use ark_bls12_381::{G1Projective, G2Projective};
use ark_ec::bls12::Bls12;
use serde::{
    de::{self, Visitor},
    Deserializer, Serializer,
};
use std::{fmt, io::Cursor, str::FromStr};
use thiserror::Error;

/// Curve used by the anonymity revoker.
pub type ArCurve = ArkGroup<G1Projective>;
/// G2 group of the BLS12-381 curve
pub type BlsG2 = ArkGroup<G2Projective>;
/// Pairing used by the identity provider.
pub type IpPairing = Bls12<ark_bls12_381::Config>;
/// Field used by the identity provider and anonymity revoker.
/// This is the scalar field of both the ArCurve and the IpPairing.
pub type BaseField = <IpPairing as Pairing>::ScalarField;

/// Index used to create the RegId of the initial credential.
pub const INITIAL_CREDENTIAL_INDEX: u8 = 0;

const MAX_ATTRIBUTE_LENGTH: u8 = 31;

#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
/// Concrete attribute values.
/// All currently supported attributes are string values.
pub struct AttributeKind(String);

impl AttributeKind {
    /// Create `AttributeKind` value from a string. Returns error if the string is longer than
    /// 31 bytes.
    pub fn try_new(value: String) -> Result<Self, AttributeValueTooLong> {
        if value.len() > MAX_ATTRIBUTE_LENGTH as usize {
            Err(AttributeValueTooLong)
        } else {
            Ok(Self(value))
        }
    }
}

/// Value was too long to be represented in an attribute
#[derive(Debug, Error)]
#[error("attribute value too long")]
pub struct AttributeValueTooLong;

impl SerdeSerialize for AttributeKind {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> SerdeDeserialize<'de> for AttributeKind {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        struct AttributeKindVisitor;

        impl Visitor<'_> for AttributeKindVisitor {
            type Value = AttributeKind;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "A string less than 31 bytes when decoded.")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                AttributeKind::try_new(v.to_string())
                    .map_err(|_| de::Error::custom("Value too big."))
            }
        }
        des.deserialize_str(AttributeKindVisitor)
    }
}

impl Deserial for AttributeKind {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u8 = source.get()?;
        if len <= MAX_ATTRIBUTE_LENGTH {
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
        out.put(&(self.0.len() as u8));
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
        Self::try_new(s.to_string()).map_err(|_| ParseAttributeError::ValueTooLarge)
    }
}

impl fmt::Display for AttributeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for AttributeKind {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<AttributeKind> for String {
    fn from(value: AttributeKind) -> Self {
        value.0
    }
}

impl From<u64> for AttributeKind {
    fn from(x: u64) -> Self {
        AttributeKind(x.to_string())
    }
}

impl Attribute<<ArkGroup<G1Projective> as Curve>::Scalar> for AttributeKind {
    fn to_field_element(&self) -> <ArkGroup<G1Projective> as Curve>::Scalar {
        let mut buf = [0u8; 32];
        let len = self.0.len();
        buf[1 + (31 - len)..].copy_from_slice(self.0.as_bytes());
        buf[0] = len as u8; // this should be valid because len <= 31 so the first two bits will be unset
        <<ArkGroup<G1Projective> as Curve>::Scalar as Deserial>::deserial(&mut Cursor::new(&buf))
            .expect("31 bytes + length fits into a scalar.")
    }
}

#[cfg(test)]
mod test {
    use crate::common;
    use crate::id::constants::AttributeKind;
    use nom::AsBytes;
    use std::str::FromStr;

    #[test]
    fn test_attribute_kind_try_new() {
        let attr = AttributeKind::try_new("".to_string()).expect("try_new");
        assert_eq!(attr.as_ref(), "");

        let attr = AttributeKind::try_new("abc".to_string()).expect("try_new");
        assert_eq!(attr.as_ref(), "abc");

        let attr = AttributeKind::try_new("a".repeat(31)).expect("try_new");
        assert_eq!(attr.as_ref(), "a".repeat(31));

        AttributeKind::try_new("a".repeat(32)).expect_err("try_new");
    }

    #[test]
    fn test_attribute_kind_from_str() {
        let attr = AttributeKind::from_str("").expect("from_str");
        assert_eq!(attr.as_ref(), "");

        let attr = AttributeKind::from_str("abc").expect("from_str");
        assert_eq!(attr.as_ref(), "abc");

        let attr = AttributeKind::from_str(&"a".repeat(31)).expect("from_str");
        assert_eq!(attr.as_ref(), "a".repeat(31));

        AttributeKind::from_str(&"a".repeat(32)).expect_err("from_str");
    }

    #[test]
    fn test_attribute_kind_serial_deserial() {
        let attr = AttributeKind::try_new("".to_string()).unwrap();
        let bytes_hex = hex::encode(common::to_bytes(&attr));
        assert_eq!(bytes_hex, "00");
        let attr_deserial: AttributeKind =
            common::from_bytes(&mut hex::decode(bytes_hex).unwrap().as_bytes()).expect("deserial");
        assert_eq!(attr_deserial, attr);

        let attr = AttributeKind::try_new("abc".to_string()).unwrap();
        let bytes_hex = hex::encode(common::to_bytes(&attr));
        assert_eq!(bytes_hex, "03616263");
        let attr_deserial: AttributeKind =
            common::from_bytes(&mut hex::decode(bytes_hex).unwrap().as_bytes()).expect("deserial");
        assert_eq!(attr_deserial, attr);

        let attr = AttributeKind::try_new("a".repeat(31)).unwrap();
        let bytes_hex = hex::encode(common::to_bytes(&attr));
        assert_eq!(
            bytes_hex,
            "1f61616161616161616161616161616161616161616161616161616161616161"
        );
        let attr_deserial: AttributeKind =
            common::from_bytes(&mut hex::decode(bytes_hex).unwrap().as_bytes()).expect("deserial");
        assert_eq!(attr_deserial, attr);

        let bytes_hex = "206161616161616161616161616161616161616161616161616161616161616161";
        let err =
            common::from_bytes::<AttributeKind, _>(&mut hex::decode(bytes_hex).unwrap().as_bytes())
                .expect_err("deserial");
        assert!(
            err.to_string().contains("Attributes can be at most"),
            "message: {}",
            err
        );
    }

    #[test]
    fn test_attribute_kind_serde_serialize_deserialize() {
        let attr = AttributeKind::try_new("".to_string()).unwrap();
        let json = serde_json::to_string(&attr).expect("serialize");
        assert_eq!(json, r#""""#);
        let attr_deserialized: AttributeKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(attr_deserialized, attr);

        let attr = AttributeKind::try_new("abc".to_string()).unwrap();
        let json = serde_json::to_string(&attr).expect("serialize");
        assert_eq!(json, r#""abc""#);
        let attr_deserialized: AttributeKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(attr_deserialized, attr);

        let attr = AttributeKind::try_new("a".repeat(31)).unwrap();
        let json = serde_json::to_string(&attr).expect("serialize");
        assert_eq!(json, r#""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#);
        let attr_deserialized: AttributeKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(attr_deserialized, attr);

        let json = r#""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#;
        let err = serde_json::from_str::<AttributeKind>(&json).expect_err("deserial");
        assert!(
            err.to_string().contains("Value too big"),
            "message: {}",
            err
        );
    }
}
