use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Decimal fraction, see <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
const DECIMAL_FRACTION_TAG: u64 = 4;

/// Decimal fraction consisting of exponent `e` and mantissa `m`, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-decimal-fractions-and-bigfl>.
/// It represents the value `m * 10^e`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(tag = DECIMAL_FRACTION_TAG)]
pub struct DecimalFraction(i64, i64);

impl DecimalFraction {
    pub fn new(exponent: i64, mantissa: i64) -> Self { Self(exponent, mantissa) }

    pub fn exponent(self) -> i64 { self.0 }

    pub fn mantissa(self) -> i64 { self.1 }
}
