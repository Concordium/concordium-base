use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize,
};

/// Capability that can be granted to an account for a SimpleV0 lock
/// controller.
///
/// Each capability authorizes the grantee to perform the corresponding lock
/// operation.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub enum LockControllerSimpleV0Capability {
    Fund,
    Return,
    Send,
    Cancel,
}

impl LockControllerSimpleV0Capability {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Fund => "fund",
            Self::Return => "return",
            Self::Send => "send",
            Self::Cancel => "cancel",
        }
    }

    fn from_str(s: &str) -> Result<Self, CborSerializationError> {
        match s {
            "fund" => Ok(Self::Fund),
            "return" => Ok(Self::Return),
            "send" => Ok(Self::Send),
            "cancel" => Ok(Self::Cancel),
            other => Err(CborSerializationError::invalid_data(format_args!(
                "unknown LockControllerSimpleV0Capability: \"{}\"",
                other
            ))),
        }
    }
}

impl CborSerialize for LockControllerSimpleV0Capability {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(self.as_str())
    }
}

impl CborDeserialize for LockControllerSimpleV0Capability {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let text_bytes = decoder.decode_text()?;
        let text = std::str::from_utf8(&text_bytes).map_err(|_| {
            CborSerializationError::invalid_data(format_args!(
                "LockControllerSimpleV0Capability text is not valid UTF-8"
            ))
        })?;
        Self::from_str(text)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;

    /// Round-trip test for all `LockControllerSimpleV0Capability` variants.
    #[test]
    fn test_capability_cbor_round_trip() {
        let variants = [
            LockControllerSimpleV0Capability::Fund,
            LockControllerSimpleV0Capability::Return,
            LockControllerSimpleV0Capability::Send,
            LockControllerSimpleV0Capability::Cancel,
        ];
        for variant in &variants {
            let encoded = cbor::cbor_encode(variant);
            let decoded: LockControllerSimpleV0Capability =
                cbor::cbor_decode(&encoded).expect("CBOR decode failed");
            assert_eq!(&decoded, variant);
        }
    }

    /// Fixture test: `Fund` → CBOR text "fund" → `6466756e64`
    #[test]
    fn test_capability_cbor_fixture_fund() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Fund);
        assert_eq!(hex::encode(&encoded), "6466756e64");
    }

    /// Fixture test: `Return` → CBOR text "return" → `6672657475726e`
    #[test]
    fn test_capability_cbor_fixture_return() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Return);
        assert_eq!(hex::encode(&encoded), "6672657475726e");
    }

    /// Fixture test: `Send` → CBOR text "send" → `6473656e64`
    #[test]
    fn test_capability_cbor_fixture_send() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Send);
        assert_eq!(hex::encode(&encoded), "6473656e64");
    }

    /// Fixture test: `Cancel` → CBOR text "cancel" → `6663616e63656c`
    #[test]
    fn test_capability_cbor_fixture_cancel() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Cancel);
        assert_eq!(hex::encode(&encoded), "6663616e63656c");
    }
}
