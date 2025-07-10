use crate::common;

/// The limit for the length of the byte encoding of a Token ID.
pub const TOKEN_ID_MIN_BYTE_LEN: usize = 1;
pub const TOKEN_ID_MAX_BYTE_LEN: usize = 128;

/// Protocol level token (PLT) ID.
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize, Clone,
)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct TokenId {
    /// Unique symbol identifying the PLT on chain.
    value: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenIdFromStringError {
    #[error("TokenId must be between {TOKEN_ID_MIN_BYTE_LEN} and {TOKEN_ID_MAX_BYTE_LEN} characters, got {actual_size}")]
    InvalidLength {
        actual_size: usize,
    },
    #[error("TokenId contains invalid characters: only a-z, A-Z, 0-9, '-', '.', '%' are allowed")]
    InvalidCharacters,
}

impl AsRef<str> for TokenId {
    fn as_ref(&self) -> &str { self.value.as_str() }
}

impl std::str::FromStr for TokenId {
    type Err = TokenIdFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { s.to_owned().try_into() }
}

impl TryFrom<String> for TokenId {
    type Error = TokenIdFromStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let byte_len = value.as_bytes().len();
        if byte_len < TOKEN_ID_MIN_BYTE_LEN || byte_len > TOKEN_ID_MAX_BYTE_LEN {
            return Err(TokenIdFromStringError::InvalidLength {
                actual_size: byte_len,
            })
        }

        if !value.chars().all(|c| matches!(c,
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '%')) {
            return Err(TokenIdFromStringError::InvalidCharacters);
        }

        Ok(Self { value })
    }
}

impl From<TokenId> for String {
    fn from(token_id: TokenId) -> Self { token_id.value }
}

impl common::Serial for TokenId {
    fn serial<B: common::Buffer>(&self, out: &mut B) {
        let bytes = self.value.as_bytes();
        u8::try_from(bytes.len())
            .expect("Invariant violation for byte length of TokenId") // This error will never occur due to length being at most 128
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
        let value = String::from_utf8(buf)?;
        Ok(value.try_into()?)
    }
}
