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

impl PartialOrd for TokenAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for TokenAmount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.decimals == other.decimals {
            self.value.cmp(&other.value)
        } else {
            todo!()
        }
    }
}

impl PartialEq for TokenAmount {
    fn eq(&self, other: &Self) -> bool {
        if self.decimals == other.decimals {
            self.value == other.value
        } else {
            todo!()
        }
    }
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

    ///
    #[test]
    fn display_token_amount() {
        let amount = TokenAmount {
            value:    123456,
            decimals: 3,
        };
        assert_eq!(amount.to_string().as_str(), "123.456")
    }

    #[test]
    fn ord_token_amount() {
        let first = TokenAmount {
            value:    123,
            decimals: 3,
        };

        let last = TokenAmount {
            value:    456,
            decimals: 3,
        };
        assert!(first < last)
    }

    #[test]
    fn eq_token_amount() {
        let a = TokenAmount {
            value:    123456,
            decimals: 3,
        };
        let b = TokenAmount {
            value:    123456,
            decimals: 3,
        };
        assert!(a == b)
    }
}
