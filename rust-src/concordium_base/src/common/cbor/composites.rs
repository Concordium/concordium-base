use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Decimal fraction, see <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
const DECIMAL_FRACTION_TAG: u64 = 4;

/// Decimal fraction consisting of exponent `e` and mantissa `m`, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-decimal-fractions-and-bigfl>.
/// It represents the numerical value `m * 10^e`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(tag = DECIMAL_FRACTION_TAG)]
pub struct DecimalFraction(i64, i64);

impl DecimalFraction {
    pub fn new(exponent: i64, mantissa: i64) -> Self { Self(exponent, mantissa) }

    pub fn exponent(self) -> i64 { self.0 }

    pub fn mantissa(self) -> i64 { self.1 }
}

/// Unsigned decimal fraction consisting of exponent `e` and non-negative mantissa `m`, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-decimal-fractions-and-bigfl>.
/// It represents the numerical value `m * 10^e`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(tag = DECIMAL_FRACTION_TAG)]
pub struct UnsignedDecimalFraction(i64, u64);

impl UnsignedDecimalFraction {
    pub fn new(exponent: i64, mantissa: u64) -> Self { Self(exponent, mantissa) }

    pub fn exponent(self) -> i64 { self.0 }

    pub fn mantissa(self) -> u64 { self.1 }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor::{cbor_decode, cbor_encode};

    #[test]
    fn test_decimal_fraction() {
        let value = DecimalFraction::new(-3, 12345);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c48222193039");
        let value_decoded: DecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = DecimalFraction::new(3, 12345);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c48203193039");
        let value_decoded: DecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = DecimalFraction::new(3, -12345);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c48203393038");
        let value_decoded: DecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_unsigned_decimal_fraction() {
        let value = UnsignedDecimalFraction::new(0, 0);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c4820000");
        let value_decoded: UnsignedDecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = UnsignedDecimalFraction::new(3, 12345);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c48203193039");
        let value_decoded: UnsignedDecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = UnsignedDecimalFraction::new(-3, 12345);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c48222193039");
        let value_decoded: UnsignedDecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = UnsignedDecimalFraction::new(-3, u64::MAX);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c482221bffffffffffffffff");
        let value_decoded: UnsignedDecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    /// Tests decoding tag 2 bignums into decimal fraction
    #[test]
    fn test_unsigned_decimal_fraction_bignum() {
        let cbor = hex::decode("c48203C24105").unwrap();
        let value_decoded: UnsignedDecimalFraction = cbor_decode(&cbor).unwrap();
        let expected_value = UnsignedDecimalFraction::new(3, 5);
        assert_eq!(value_decoded, expected_value);
    }
}
