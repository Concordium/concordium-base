pub(crate) mod byte_array_hex {
    /// Serialize (via Serde) chrono::DateTime in milliseconds as an u64.
    pub fn serialize<S: serde::Serializer>(dt: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(hex::encode(dt).as_str())
    }

    /// Deserialize (via Serde) chrono::Duration in milliseconds as an i64.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(des: D) -> Result<Vec<u8>, D::Error> {
        struct HexVisitor;
        impl<'de> serde::de::Visitor<'de> for HexVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "A hex string.")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error, {
                let r = hex::decode(v).map_err(serde::de::Error::custom)?;
                Ok(r)
            }
        }
        des.deserialize_str(HexVisitor)
    }
}

/// Module to help checking that a value is not default during serialization.
/// This is particularly interesting for various integer types, where the
/// default value is 0.
pub(crate) mod deserialize_non_default {
    use crypto_common::SerdeDeserialize;

    pub fn deserialize<'de, D, A>(des: D) -> Result<A, D::Error>
    where
        D: serde::Deserializer<'de>,
        A: SerdeDeserialize<'de> + Default + PartialEq + Eq, {
        let s = A::deserialize(des)?;
        if s == A::default() {
            return Err(serde::de::Error::custom("Expected a non-default value."));
        }
        Ok(s)
    }
}
