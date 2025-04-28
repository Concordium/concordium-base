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
