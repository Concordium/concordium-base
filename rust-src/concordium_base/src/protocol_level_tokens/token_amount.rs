/// Protocol level token (PLT) amount representation.
#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "TokenAmountJson", into = "TokenAmountJson")]
pub struct TokenAmount {
    /// The amount of tokens without decimal places.
    pub value:    u64,
    /// The number of decimals in the token amount.
    pub decimals: u8,
}

impl TokenAmount {
    /// Construct a [`TokenAmount`] representing an integer amount and zero
    /// decimals.
    pub fn from_integer(value: u64) -> Self { Self { value, decimals: 0 } }

    /// The number of decimals in the token amount.
    ///
    /// Together with the `raw_value` the token amount can be represented as
    /// `raw_value * 10^(-decimals)`
    pub fn decimals(&self) -> u8 { self.decimals }

    /// The amount of tokens without decimal places.
    ///
    /// Together with the `decimals` the token amount can be represented as
    /// `raw_value * 10^(-decimals)`
    pub fn raw_value(&self) -> u64 { self.value }
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
            let value = integer * 10u64.pow(decimals.into()) + fraction;
            Ok(Self { value, decimals })
        } else {
            Ok(Self {
                value:    s
                    .parse()
                    .map_err(TokenAmountParseError::FailedParsingWholeNumber)?,
                decimals: 0,
            })
        }
    }
}

impl PartialOrd for TokenAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for TokenAmount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.decimals.cmp(&other.decimals) {
            std::cmp::Ordering::Equal => self.value.cmp(&other.value),
            std::cmp::Ordering::Less => {
                let decimal_diff = other.decimals - self.decimals;
                let scaled_self = u128::from(self.value) * 10u128.pow(decimal_diff.into());
                scaled_self.cmp(&u128::from(other.value))
            }
            std::cmp::Ordering::Greater => {
                let decimal_diff = self.decimals - other.decimals;
                let scaled_other = u128::from(other.value) * 10u128.pow(decimal_diff.into());
                u128::from(self.value).cmp(&scaled_other)
            }
        }
    }
}

impl PartialEq for TokenAmount {
    fn eq(&self, other: &Self) -> bool { matches!(self.cmp(other), std::cmp::Ordering::Equal) }
}
impl Eq for TokenAmount {}

/// JSON representation of the token amount.
/// The purpose of this type is to derive the JSON representation matching other
/// SDKs.
#[derive(serde::Serialize, serde::Deserialize)]
struct TokenAmountJson {
    value:    String,
    decimals: u8,
}

impl From<TokenAmount> for TokenAmountJson {
    fn from(amount: TokenAmount) -> Self {
        Self {
            value:    amount.value.to_string(),
            decimals: amount.decimals,
        }
    }
}

impl TryFrom<TokenAmountJson> for TokenAmount {
    type Error = std::num::ParseIntError;

    fn try_from(json: TokenAmountJson) -> Result<Self, Self::Error> {
        Ok(Self {
            value:    json.value.parse()?,
            decimals: json.decimals,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display_token_amount() {
        let amount = TokenAmount {
            value:    123456,
            decimals: 3,
        };
        assert_eq!(amount.to_string().as_str(), "123.456")
    }

    #[test]
    fn parse_token_amount() {
        let amount = TokenAmount {
            value:    123456,
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
                value:    123,
                decimals: 3,
            };

            let last = TokenAmount {
                value:    456,
                decimals: 3,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert!(first < last);
            assert!(last > first);
        }

        // Check using different decimals.
        // 0.123
        let first = TokenAmount {
            value:    123,
            decimals: 3,
        };
        // 1.23
        let last = TokenAmount {
            value:    123,
            decimals: 2,
        };
        // Note that both directions are needed to cover both branches in the
        // implementation.
        assert!(first < last);
        assert!(last > first);
    }

    #[test]
    fn eq_token_amount() {
        // Same number of decimals
        {
            // 123.456
            let a = TokenAmount {
                value:    123456,
                decimals: 3,
            };
            // 123.456
            let b = TokenAmount {
                value:    123456,
                decimals: 3,
            };
            assert_eq!(a, b);
        }
        // Different number of decimals
        {
            // 5.0
            let a = TokenAmount {
                value:    50,
                decimals: 1,
            };
            // 5
            let b = TokenAmount {
                value:    5,
                decimals: 0,
            };
            // Note that both directions are needed to cover both branches in the
            // implementation.
            assert_eq!(a, b);
            assert_eq!(b, a);
        }
    }
}
