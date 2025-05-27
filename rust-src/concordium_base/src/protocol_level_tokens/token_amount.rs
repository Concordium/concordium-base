use crate::common::cbor::{CborDecoder, CborDeserialize, CborEncoder, CborResult, CborSerialize};
use concordium_base_derive::{CborDeserialize, CborSerialize};

const DECIMAL_FRACTION_TAG: u64 = 4;

/// Protocol level token (PLT) amount representation.
#[derive(
    Debug, Clone, Copy, serde::Deserialize, serde::Serialize,
)]
#[serde(try_from = "TokenAmountJson", into = "TokenAmountJson")]
pub struct TokenAmount {
    /// The number of decimals in the token amount.
    decimals: u8,
    /// The amount of tokens without decimal places.
    value: u64,
}

/// [`TokenAmount`] representation that resembles CBOR structure, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-decimal-fractions-and-bigfl>
#[derive(
    Debug, Clone, Copy, CborSerialize, CborDeserialize,
)]
#[cbor(tag = DECIMAL_FRACTION_TAG)] // todo ar
struct TokenAmountCbor {
    scale: u64,
    value: u64,
}

impl TokenAmount {
    /// Construct a [`TokenAmount`] from a value without decimal places and the
    /// number of decimals, meaning the token amount is computed as `value *
    /// 10^(-decimals)`.
    pub fn from_raw(value: u64, decimals: u8) -> Self {
        Self { value, decimals }
    }

    /// Construct a [`TokenAmount`] representing an integer amount and zero
    /// decimals.
    pub fn from_integer(value: u64) -> Self {
        Self { value, decimals: 0 }
    }

    /// The number of decimals in the token amount.
    ///
    /// Together with the `raw_value` the token amount can be represented as
    /// `raw_value * 10^(-decimals)`
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// The amount of tokens without decimal places.
    ///
    /// Together with the `decimals` the token amount can be represented as
    /// `raw_value * 10^(-decimals)`
    pub fn raw_value(&self) -> u64 {
        self.value
    }
}

impl std::fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.decimals == 0 {
            self.value.fmt(f)
        } else {
            let mut value = format!(
                "{value:0.*}",
                self.decimals as usize + 1,
                value = self.value
            );
            value.insert(value.len() - self.decimals() as usize, '.');
            write!(f, "{}", value)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenAmountParseError {
    #[error("The number of digits after the decimal point can be at most 255, found {0}")]
    InvalidNumberOfDecimals(usize),
    #[error("Unable to parse digits before the decimal point: {0}")]
    FailedParsingWholeNumber(std::num::ParseIntError),
    #[error("Unable to parse digits after the decimal point: {0}")]
    FailedParsingFractionalPart(std::num::ParseIntError),
    #[error("Parse digits are invalid and caused an overflow")]
    Overflow,
}

impl std::str::FromStr for TokenAmount {
    type Err = TokenAmountParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((integer, fraction)) = s.split_once('.') {
            let decimals: u8 = fraction
                .len()
                .try_into()
                .map_err(|_| TokenAmountParseError::InvalidNumberOfDecimals(fraction.len()))?;
            let integer: u64 = integer
                .parse()
                .map_err(TokenAmountParseError::FailedParsingWholeNumber)?;
            let fraction: u64 = fraction
                .parse()
                .map_err(TokenAmountParseError::FailedParsingFractionalPart)?;
            let value = 10u64
                .checked_pow(decimals.into())
                .ok_or(TokenAmountParseError::Overflow)?
                .checked_mul(integer)
                .ok_or(TokenAmountParseError::Overflow)?
                .checked_add(fraction)
                .ok_or(TokenAmountParseError::Overflow)?;
            Ok(Self { value, decimals })
        } else {
            Ok(Self {
                value: s
                    .parse()
                    .map_err(TokenAmountParseError::FailedParsingWholeNumber)?,
                decimals: 0,
            })
        }
    }
}

impl PartialOrd for TokenAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TokenAmount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let ord_decimals = self.decimals.cmp(&other.decimals);
        // If the decimals are equal we can compare the values directly.
        if ord_decimals.is_eq() {
            return self.value.cmp(&other.value);
        }
        // If either of the values are 0 we can ignore the decimals and compare the
        // values directly.
        if self.value == 0 || other.value == 0 {
            return self.value.cmp(&other.value);
        };
        // To avoid overflows we check the ordering in floored log_10 first
        let self_log = self.value.ilog10(); // Safe since the value cannot be 0.
        let other_log = other.value.ilog10(); // Safe since the value cannot be 0.
        let left = self_log + u32::from(other.decimals);
        let right = other_log + u32::from(self.decimals);
        let log_ord = left.cmp(&right);
        // When floored log_10 values are not equal we can return this ordering.
        if !log_ord.is_eq() {
            return log_ord;
        }
        // When floored log_10 values are equal, there must be the same number of digits
        // in the representation, so we scale value with fewest decimals up to the same
        // number of decimals and compare.
        // If this overflows we know the scaled value must be greater.
        match ord_decimals {
            std::cmp::Ordering::Equal => panic!("Impossible case: this should be handled above"),
            std::cmp::Ordering::Less => {
                let decimal_diff = other.decimals - self.decimals;
                if let Some(scaled_self) = self.value.checked_mul(10u64.pow(decimal_diff.into())) {
                    scaled_self.cmp(&other.value)
                } else {
                    std::cmp::Ordering::Greater
                }
            }
            std::cmp::Ordering::Greater => {
                let decimal_diff = self.decimals - other.decimals;
                if let Some(scaled_other) = other.value.checked_mul(10u64.pow(decimal_diff.into()))
                {
                    scaled_other.cmp(&self.value)
                } else {
                    std::cmp::Ordering::Less
                }
            }
        }
    }
}

impl PartialEq for TokenAmount {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.cmp(other), std::cmp::Ordering::Equal)
    }
}
impl Eq for TokenAmount {}

/// JSON representation of the token amount.
/// The purpose of this type is to derive the JSON representation matching other
/// SDKs.
#[derive(serde::Serialize, serde::Deserialize)]
struct TokenAmountJson {
    value: String,
    decimals: u8,
}

impl From<TokenAmount> for TokenAmountJson {
    fn from(amount: TokenAmount) -> Self {
        Self {
            value: amount.value.to_string(),
            decimals: amount.decimals,
        }
    }
}

impl TryFrom<TokenAmountJson> for TokenAmount {
    type Error = std::num::ParseIntError;

    fn try_from(json: TokenAmountJson) -> Result<Self, Self::Error> {
        Ok(Self {
            value: json.value.parse()?,
            decimals: json.decimals,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;

    #[test]
    fn display_token_amount() {
        let amount = TokenAmount {
            value: 123456,
            decimals: 3,
        };
        assert_eq!(amount.to_string().as_str(), "123.456")
    }

    #[test]
    fn parse_token_amount() {
        let amount = TokenAmount {
            value: 123456,
            decimals: 3,
        };
        let parsed: TokenAmount = "123.456"
            .parse()
            .expect("Parsing token amount should succeed");
        assert_eq!(amount.value, parsed.value);
        assert_eq!(amount.decimals, parsed.decimals);
    }

    #[test]
    fn ord_token_amount() {
        // Check using same decimals.
        {
            let first = TokenAmount {
                value: 123,
                decimals: 3,
            };

            let last = TokenAmount {
                value: 456,
                decimals: 3,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert!(first < last);
            assert!(last > first);
        }

        {
            // Check using different decimals.
            // 0.123
            let first = TokenAmount {
                value: 123,
                decimals: 3,
            };
            // 1.23
            let last = TokenAmount {
                value: 123,
                decimals: 2,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert!(first < last);
            assert!(last > first);
        }

        {
            // Check with matching max decimal
            // 0.123
            let first = TokenAmount {
                value: 1,
                decimals: u8::MAX,
            };
            // 1.23
            let last = TokenAmount {
                value: u64::MAX,
                decimals: u8::MAX,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert!(first < last);
            assert!(last > first);
        }

        {
            // Check with large difference in decimals
            // 0.123
            let first = TokenAmount {
                value: u64::MAX,
                decimals: u8::MAX,
            };
            // 1.23
            let last = TokenAmount {
                value: u64::MAX,
                decimals: u8::MIN,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert!(first < last);
            assert!(last > first);
        }

        {
            // Check with large difference in decimals
            // 0.123
            let first = TokenAmount {
                value: 10_000_000_000_000_000_000,
                decimals: 19,
            };
            // 1.23
            let last = TokenAmount {
                value: 2,
                decimals: 0,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert!(first < last);
            assert!(last > first);
        }
    }

    #[test]
    fn eq_token_amount() {
        // Same number of decimals
        {
            // 123.456
            let a = TokenAmount {
                value: 123456,
                decimals: 3,
            };
            // 123.456
            let b = TokenAmount {
                value: 123456,
                decimals: 3,
            };
            assert_eq!(a, b);
        }
        // Different number of decimals
        {
            // 5.0
            let a = TokenAmount {
                value: 50,
                decimals: 1,
            };
            // 5
            let b = TokenAmount {
                value: 5,
                decimals: 0,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert_eq!(a, b);
            assert_eq!(b, a);
        }
    }

    #[test]
    fn test_token_amount_cbor() {
        let token_amount = TokenAmount {
            value: 12300,
            decimals: 3,
        };

        // let cbor = cbor::cbor_encode(&token_amount).unwrap();
        // assert_eq!(hex::encode(&cbor), "d99d71a101190397");
        // let token_amount_decoded: TokenAmount = cbor::cbor_decode(&cbor).unwrap();
        // assert_eq!(token_amount_decoded, token_amount); // todo ar
    }
}
