use crate::common;
use crate::common::{Get, SerdeDeserialize};
use serde::de::Error;
use serde::Deserializer;
use std::fmt::{Display, Formatter};

/// The limit for the length of the byte encoding of a Token ID.
pub const TOKEN_ID_MIN_BYTE_LEN: usize = 1;
pub const TOKEN_ID_MAX_BYTE_LEN: usize = 128;

/// Protocol level token (PLT) ID.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, Clone)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct TokenId {
    /// Unique symbol identifying the PLT on chain.
    value: String,
}

impl<'de> SerdeDeserialize<'de> for TokenId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = String::deserialize(deserializer)?;

        Self::try_from(string).map_err(|err| D::Error::custom(err))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenIdFromStringError {
    #[error(
        "TokenId must be between {TOKEN_ID_MIN_BYTE_LEN} and {TOKEN_ID_MAX_BYTE_LEN} characters, \
         got {actual_size}"
    )]
    InvalidLength { actual_size: usize },
    #[error("TokenId contains invalid characters: only a-z, A-Z, 0-9, '-', '.', '%' are allowed")]
    InvalidCharacters,
}

impl AsRef<str> for TokenId {
    fn as_ref(&self) -> &str {
        self.value.as_str()
    }
}

impl Display for TokenId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

impl std::str::FromStr for TokenId {
    type Err = TokenIdFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl TryFrom<String> for TokenId {
    type Error = TokenIdFromStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let byte_len = value.len();
        #[allow(clippy::manual_range_contains)]
        if byte_len < TOKEN_ID_MIN_BYTE_LEN || byte_len > TOKEN_ID_MAX_BYTE_LEN {
            return Err(TokenIdFromStringError::InvalidLength {
                actual_size: byte_len,
            });
        }

        if !value.chars().all(|c| {
            matches!(c,
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '%')
        }) {
            return Err(TokenIdFromStringError::InvalidCharacters);
        }

        Ok(Self { value })
    }
}

impl From<TokenId> for String {
    fn from(token_id: TokenId) -> Self {
        token_id.value
    }
}

/// Serial implementation matching the serialization of `TokenId`
/// in the Haskell module `Concordium.Types.Token`.
impl common::Serial for TokenId {
    fn serial<B: common::Buffer>(&self, out: &mut B) {
        // length is always less or equal to TYPE_MAX_BYTE_LEN
        let len =
            u8::try_from(self.value.len()).expect("Invariant violation for byte length of TokenId");
        len.serial(out);
        common::serial_string(&self.value, out);
    }
}

/// Deserial implementation matching the serialization of `TokenId`
/// in the Haskell module `Concordium.Types.Token`.
impl common::Deserial for TokenId {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> common::ParseResult<Self> {
        let len: u8 = source.get()?;
        let value = common::deserial_string(source, len as usize)?;
        Ok(Self::try_from(value)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn valid_token_ids() {
        // Min length
        assert!(TokenId::from_str("a").is_ok());

        // Max length (128)
        let max_len_token = "a".repeat(TOKEN_ID_MAX_BYTE_LEN);
        assert!(TokenId::from_str(&max_len_token).is_ok());

        // Allowed chars
        let valid_chars = "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ012345676789.-%";
        assert!(TokenId::from_str(valid_chars).is_ok());
    }

    #[test]
    fn invalid_token_ids_due_to_length() {
        // Empty string
        let err = TokenId::from_str("").unwrap_err();
        matches!(
            err,
            TokenIdFromStringError::InvalidLength { actual_size: 0 }
        );

        // Over 128 bytes
        let too_long = "a".repeat(TOKEN_ID_MAX_BYTE_LEN + 1);
        let err = TokenId::from_str(&too_long).unwrap_err();
        matches!(err, TokenIdFromStringError::InvalidLength { .. });
    }

    #[test]
    fn invalid_token_ids_due_to_characters() {
        let cases = [
            "abc@",    // '@' not allowed
            "abc#",    // '#' not allowed
            "abc ",    // space  not allowed
            "abc/def", // '/'  not allowed
            "æøå",     // non-ASCII
            "abc😀",   // emoji
            "é",
        ];

        for case in cases {
            let err = TokenId::from_str(case).unwrap_err();
            assert!(
                matches!(err, TokenIdFromStringError::InvalidCharacters),
                "Failed for: {}",
                case
            );
        }
    }

    /// Test binary serialization of [`TokenId`]
    #[test]
    fn test_token_id_serialize() {
        // simple token id
        let token_id: TokenId = "tokenid1".parse().unwrap();
        let bytes = common::to_bytes(&token_id);
        assert_eq!(hex::encode(&bytes), "08746f6b656e696431");
        let deserialized: TokenId = common::from_bytes(&mut bytes.as_slice()).unwrap();
        assert_eq!(deserialized, token_id);

        // token id which is too long
        let bytes: Vec<_> = [129]
            .into_iter()
            .chain("a".repeat(129).as_bytes().to_vec().into_iter())
            .collect();
        let err = common::from_bytes::<TokenId, _>(&mut bytes.as_slice()).expect_err("deserial");
        assert!(
            err.to_string()
                .contains("TokenId must be between 1 and 128 characters"),
            "err: {}",
            err
        );
    }

    /// Test JSON serialization of [`TokenId`]
    #[test]
    fn test_token_id_json_serialize() {
        // test simple token id
        let token_id: TokenId = "tokenid1".parse().unwrap();
        let json = serde_json::to_string(&token_id).expect("serialize");
        assert_eq!(json, r#""tokenid1""#);
        let token_id_deserialized: TokenId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(token_id_deserialized, token_id);

        // test token id above max length
        let json = format!("\"{}\"", "a".repeat(129));
        let err = serde_json::from_str::<TokenId>(&json).expect_err("deserialize");
        assert!(
            err.to_string()
                .contains("TokenId must be between 1 and 128 characters"),
            "err: {}",
            err
        );
    }
}
