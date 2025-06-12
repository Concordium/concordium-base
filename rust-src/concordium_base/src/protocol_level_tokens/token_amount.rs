use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationResult, CborSerialize,
    DecimalFraction,
};
use anyhow::{bail, Context};

/// Protocol level token (PLT) amount representation. The numerical amount
/// represented is `value * 10^(-decimals)`.
/// The number of decimals in the token amount should always match the number of
/// decimals for the token it represents an amount for. As such, `TokenAmount`
/// can be considered a fixed point decimal.
///
/// Notice that the `decimal` part could hence be left out of the representation
/// without loss of information, but it is there to make `TokenAmount`
/// self-contained with regard to the numerical value represented. This enables
/// additional validation, both programmatic and at user level.
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "TokenAmountJson", into = "TokenAmountJson")]
pub struct TokenAmount {
    /// The amount of tokens as an unscaled integer value.
    value:    u64,
    /// The number of decimals in the token amount.
    decimals: u8,
}

impl CborSerialize for TokenAmount {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        let decimal_fraction = DecimalFraction::new(
            i64::from(self.decimals)
                .checked_neg()
                .context("convert decimals to exponent")?,
            i64::try_from(self.value).context("convert value to mantissa")?,
        );

        decimal_fraction.serialize(encoder)
    }
}

impl CborDeserialize for TokenAmount {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let decimal_fraction = DecimalFraction::deserialize(decoder)?;

        let decimals = decimal_fraction
            .exponent()
            .checked_neg()
            .and_then(|val| u8::try_from(val).ok())
            .context("convert exponent to decimals")?;
        let value =
            u64::try_from(decimal_fraction.mantissa()).context("convert mantissa to value")?;

        Ok(Self { decimals, value })
    }
}

impl TokenAmount {
    /// Construct a [`TokenAmount`] from a value without decimal places and the
    /// number of decimals, meaning the token amount is computed as `value *
    /// 10^(-decimals)`.
    pub fn from_raw(value: u64, decimals: u8) -> Self { Self { value, decimals } }

    /// The number of decimals in the token amount.
    ///
    /// The numerical amount represented by the `TokenAmount`
    /// is `value * 10^(-decimals)`
    pub fn decimals(&self) -> u8 { self.decimals }

    /// The amount of tokens as an unscaled integer value.
    ///
    /// The numerical amount represented by the `TokenAmount`
    /// is `value * 10^(-decimals)`
    pub fn value(&self) -> u64 { self.value }

    /// Converts [`rust_decimal::Decimal`] to a token amount of the same
    /// numerical value but represented with the given number of `decimals`.
    /// This may require rescaling but no rounding will be performed.
    /// If rounding is required to represent the numeric value with the given
    /// number of `decimals`, an error is returned.
    ///
    /// The given number of `decimals` should
    /// be equal to tbe number of decimals for the token it represents an amount
    /// for.
    pub fn try_from_rust_decimal(
        decimal: rust_decimal::Decimal,
        decimals: u8,
    ) -> anyhow::Result<Self> {
        let decimals = decimals as u32;
        let original_scale = decimal.scale();
        let mut decimal_scaled = decimal;
        decimal_scaled.rescale(decimals);
        if decimal_scaled.scale() != decimals {
            bail!("rust_decimal::Decimal cannot be rescaled to match token amount");
        }
        let this = Self::from_raw(
            decimal_scaled.mantissa().try_into().context(
                "rust_decimal::Decimal mantissa cannot be converted to token amount value",
            )?,
            decimal_scaled.scale().try_into().context(
                "rust_decimal::Decimal scale cannot be converted to token amount decimals",
            )?,
        );
        decimal_scaled.rescale(decimal.scale());
        if decimal_scaled.mantissa() != decimal.mantissa() {
            bail!("rust_decimal::Decimal rescaling results in rounding");
        }
        Ok(this)
    }

    /// Converts the token amount to a [`rust_decimal::Decimal`] of the same
    /// scale.
    pub fn try_to_rust_decimal(&self) -> anyhow::Result<rust_decimal::Decimal> {
        rust_decimal::Decimal::try_from_i128_with_scale(self.value as i128, self.decimals as u32)
            .context("token amount cannot be represented as rust_decimal::Decimal")
    }

    /// Interprets the given string as a decimal number (decimal separator must
    /// be "." if specified) and parses it into a token amount of the same
    /// numerical value represented with the given number of `decimals`.
    /// If rounding is required to represent the numeric value with the
    /// given number of `decimals`, an error is returned.
    ///
    /// The given number of `decimals` should
    /// be equal to tbe number of decimals for the token it represents an amount
    /// for.
    pub fn try_from_str(decimal_str: &str, decimals: u8) -> anyhow::Result<Self> {
        let decimal = rust_decimal::Decimal::from_str_exact(decimal_str)
            .context("cannot convert string to rust_decimal::Decimal")?;
        Self::try_from_rust_decimal(decimal, decimals)
    }
}

impl std::fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.decimals == 0 {
            self.value.fmt(f)
        } else {
            let mut value = format!(
                "{value:0width$}",
                width = self.decimals as usize + 1,
                value = self.value
            );
            value.insert(value.len() - self.decimals() as usize, '.');
            write!(f, "{}", value)
        }
    }
}

impl PartialOrd for TokenAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (self.decimals == other.decimals).then(|| self.value.cmp(&other.value))
    }
}

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
    use crate::common::cbor;
    use std::cmp::Ordering;

    #[test]
    fn test_display() {
        let amount = TokenAmount {
            value:    123450,
            decimals: 3,
        };
        assert_eq!(amount.to_string().as_str(), "123.450");

        let amount = TokenAmount {
            value:    10,
            decimals: 5,
        };
        assert_eq!(amount.to_string().as_str(), "0.00010");
    }

    #[test]
    fn test_try_from_str() {
        let str = "123.450";

        let token_amount = TokenAmount::try_from_str(str, 3).unwrap();
        assert_eq!(token_amount, TokenAmount::from_raw(123450, 3));
        let token_amount = TokenAmount::try_from_str(str, 2).unwrap();
        assert_eq!(token_amount, TokenAmount::from_raw(12345, 2));
        let token_amount = TokenAmount::try_from_str(str, 5).unwrap();
        assert_eq!(token_amount, TokenAmount::from_raw(12345000, 5));

        let err = TokenAmount::try_from_str(str, 1).unwrap_err().to_string();
        assert!(
            err.contains("rescaling results in rounding"),
            "error: {}",
            err
        );
    }

    #[test]
    fn test_partial_cmp() {
        // Check using same decimals.
        {
            let amount1 = TokenAmount::from_raw(123, 3);
            let amount2 = TokenAmount::from_raw(456, 3);
            assert_eq!(amount1.partial_cmp(&amount2), Some(Ordering::Less));
        }

        {
            // Check using different decimals.
            let amount1 = TokenAmount::from_raw(123, 3);
            let amount2 = TokenAmount::from_raw(456, 2);
            assert_eq!(amount1.partial_cmp(&amount2), None);
        }
    }

    #[test]
    fn test_try_from_rust_decimal() {
        let decimal = rust_decimal::Decimal::new(12600, 4);

        let token_amount = TokenAmount::try_from_rust_decimal(decimal, 4).unwrap();
        assert_eq!(token_amount, TokenAmount::from_raw(12600, 4));

        let token_amount = TokenAmount::try_from_rust_decimal(decimal, 2).unwrap();
        assert_eq!(token_amount, TokenAmount::from_raw(126, 2));

        let token_amount = TokenAmount::try_from_rust_decimal(decimal, 6).unwrap();
        assert_eq!(token_amount, TokenAmount::from_raw(1260000, 6));

        let err = TokenAmount::try_from_rust_decimal(decimal, 30)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be rescaled"), "error: {}", err);

        let err = TokenAmount::try_from_rust_decimal(decimal, 1)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("rescaling results in rounding"),
            "error: {}",
            err
        );
    }

    #[test]
    fn test_try_to_rust_decimal() {
        let token_amount = TokenAmount::from_raw(12640, 4);

        let decimal = token_amount.try_to_rust_decimal().unwrap();
        assert_eq!(decimal.mantissa(), 12640);
        assert_eq!(decimal.scale(), 4);
    }

    #[test]
    fn test_token_amount_cbor() {
        let token_amount = TokenAmount::from_raw(12300, 3);

        let cbor = cbor::cbor_encode(&token_amount).unwrap();
        assert_eq!(hex::encode(&cbor), "c4822219300c");
        let token_amount_decoded: TokenAmount = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_amount_decoded, token_amount);
    }
}
