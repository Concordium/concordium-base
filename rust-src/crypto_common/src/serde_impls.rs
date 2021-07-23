use crate::*;
use serde::{de, de::Visitor, Deserializer};
use std::convert::TryInto;

/// A manual implementation of the Serde deserializer to support
/// reading both from strings and from integers.
impl<'de> SerdeDeserialize<'de> for types::KeyIndex {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        // expect a u8, but also handle string
        des.deserialize_any(KeyIndexVisitor)
    }
}

struct KeyIndexVisitor;

impl<'de> Visitor<'de> for KeyIndexVisitor {
    type Value = types::KeyIndex;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Either a string or a u8.")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let x = v.parse().map_err(de::Error::custom)?;
        Ok(types::KeyIndex(x))
    }

    fn visit_u64<E: de::Error>(self, x: u64) -> Result<Self::Value, E> {
        if let Ok(x) = x.try_into() {
            Ok(types::KeyIndex(x))
        } else {
            Err(de::Error::custom("Key index value out of range."))
        }
    }
}
