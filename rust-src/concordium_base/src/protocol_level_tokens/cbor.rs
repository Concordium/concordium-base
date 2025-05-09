use crate::common;

/// CBOR encoded byte string.
///
/// Note: There are not checks for whether the bytes represents a valid CBOR
/// encoding.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct RawCbor {
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for RawCbor {
    fn as_ref(&self) -> &[u8] { self.bytes.as_ref() }
}

impl From<RawCbor> for Vec<u8> {
    fn from(value: RawCbor) -> Self { value.bytes }
}

impl From<Vec<u8>> for RawCbor {
    fn from(bytes: Vec<u8>) -> Self { Self { bytes } }
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

    fn from_str(s: &str) -> Result<Self, Self::Err> { Ok(hex::decode(s)?.into()) }
}

impl TryFrom<String> for RawCbor {
    type Error = hex::FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> { value.as_str().parse() }
}

impl From<RawCbor> for String {
    fn from(value: RawCbor) -> Self { value.to_string() }
}

impl common::Serial for RawCbor {
    fn serial<B: common::Buffer>(&self, out: &mut B) {
        u32::try_from(self.bytes.len())
            .expect("Invariant violation for byte length of RawCbor")
            .serial(out);
        out.write_all(&self.bytes)
            .expect("Writing RawCbor bytes to buffer should not fail");
    }
}

impl common::Deserial for RawCbor {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> common::ParseResult<Self> {
        let len = source.read_u32::<byteorder::BE>()?;
        let mut buf = vec![0u8; len as usize];
        source.read_exact(&mut buf)?;
        Ok(buf.into())
    }
}
