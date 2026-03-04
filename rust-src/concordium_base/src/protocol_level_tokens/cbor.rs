use crate::common;
use crate::common::Get;

/// CBOR encoded byte string.
///
/// Note: There are no checks for whether the bytes represent a valid CBOR
/// encoding.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq, Hash)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct RawCbor {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for RawCbor {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl From<RawCbor> for Vec<u8> {
    fn from(value: RawCbor) -> Self {
        value.bytes
    }
}

impl From<Vec<u8>> for RawCbor {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl std::fmt::Display for RawCbor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.bytes.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for RawCbor {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hex::decode(s)?.into())
    }
}

impl TryFrom<String> for RawCbor {
    type Error = hex::FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().parse()
    }
}

impl From<RawCbor> for String {
    fn from(value: RawCbor) -> Self {
        value.to_string()
    }
}

/// Serial implementation matching the serialization of `TokenParameter`
/// in the Haskell module `Concordium.Types`.
impl common::Serial for RawCbor {
    fn serial<B: common::Buffer>(&self, out: &mut B) {
        let len = u32::try_from(self.bytes.len())
            .expect("Invariant violation for byte length of RawCbor");
        len.serial(out);
        common::serial_vector_no_length(&self.bytes, out);
    }
}

/// Deserial implementation matching the serialization of `TokenParameter`
/// in the Haskell module `Concordium.Types`.
impl common::Deserial for RawCbor {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> common::ParseResult<Self> {
        let len: u32 = source.get()?;
        let bytes = common::deserial_vector_no_length(source, len as usize)?;
        Ok(Self { bytes })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test binary serialization of [`RawCbor`]
    #[test]
    fn test_raw_cbor_serialize() {
        let raw_cbor = RawCbor::from(vec![1, 2, 3, 4]);

        let bytes = common::to_bytes(&raw_cbor);
        assert_eq!(hex::encode(&bytes), "0000000401020304");

        let deserialized: RawCbor = common::from_bytes(&mut bytes.as_slice()).unwrap();
        assert_eq!(deserialized, raw_cbor);
    }
}
