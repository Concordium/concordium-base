use crate::common;

/// The limit for the length of the byte encoding of a Token ID.
pub const TOKEN_ID_MAX_BYTE_LEN: usize = 255;

/// Protocol level token (PLT) ID.
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize, Clone,
)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct TokenId {
    /// Unique symbol identifying the PLT on chain.
    symbol: String,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "Byte encoding of TokenID must be within {TOKEN_ID_MAX_BYTE_LEN} bytes, instead got \
     {actual_size}"
)]
pub struct TokenIdFromStringError {
    actual_size: usize,
}

impl AsRef<str> for TokenId {
    fn as_ref(&self) -> &str { self.symbol.as_str() }
}

impl std::str::FromStr for TokenId {
    type Err = TokenIdFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { s.to_owned().try_into() }
}

impl TryFrom<String> for TokenId {
    type Error = TokenIdFromStringError;

    fn try_from(symbol: String) -> Result<Self, Self::Error> {
        let symbol_byte_len = symbol.as_bytes().len();
        if symbol_byte_len > TOKEN_ID_MAX_BYTE_LEN {
            Err(TokenIdFromStringError {
                actual_size: symbol_byte_len,
            })
        } else {
            Ok(Self { symbol })
        }
    }
}

impl From<TokenId> for String {
    fn from(value: TokenId) -> Self { value.symbol }
}

impl common::Serial for TokenId {
    fn serial<B: common::Buffer>(&self, out: &mut B) {
        let bytes = self.symbol.as_bytes();
        u8::try_from(bytes.len())
            .expect("Invariant violation for byte length of TokenId")
            .serial(out);
        out.write_all(bytes)
            .expect("Writing TokenId bytes to buffer should not fail");
    }
}

impl common::Deserial for TokenId {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> common::ParseResult<Self> {
        let len = source.read_u8()?;
        let mut buf = vec![0u8; len as usize];
        source.read_exact(&mut buf)?;
        let symbol = String::from_utf8(buf)?;
        Ok(Self { symbol })
    }
}
