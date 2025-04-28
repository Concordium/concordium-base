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
pub enum TokenIdFromStringError {
    #[error(
        "Byte encoding of TokenID must be within {TOKEN_ID_MAX_BYTE_LEN} bytes, instead got {0}"
    )]
    ExceedsMaxByteLength(usize),
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
            Err(TokenIdFromStringError::ExceedsMaxByteLength(
                symbol_byte_len,
            ))
        } else {
            Ok(Self { symbol })
        }
    }
}

impl From<TokenId> for String {
    fn from(value: TokenId) -> Self { value.symbol }
}
