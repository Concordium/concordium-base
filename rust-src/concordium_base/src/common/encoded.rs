use super::{Deserial, ParseResult, Serial};

/// Encoded data `A` using the Concordium specific serialization
/// [`Serial`]/[`Deserial`].
///
/// This is a simple wrapper around [`Vec<u8>`](Vec) with bespoke serialization
/// and provides [`serde`] implementation as a hex string.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, derive_more::Into)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Encoded<A> {
    #[serde(with = "crate::internal::byte_array_hex")]
    pub(crate) bytes: Vec<u8>,
    _kind:            std::marker::PhantomData<A>,
}

impl<A> Encoded<A> {
    /// Serialize `A` into `Encoded<A>`.
    pub fn encode(item: &A) -> Self
    where
        A: Serial, {
        Self {
            bytes: super::to_bytes(item),
            _kind: Default::default(),
        }
    }

    /// Attempt to decode the [`Encoded`] into `A`.
    ///
    /// This also checks that all data is used, i.e. there are no remaining
    /// trailing bytes.
    pub fn decode(&self) -> ParseResult<A>
    where
        A: Deserial, {
        use super::Get;
        let mut source = std::io::Cursor::new(&self.bytes);
        let payload = source.get()?;
        // ensure payload length matches the stated size.
        let consumed = source.position();
        anyhow::ensure!(
            consumed == self.bytes.len() as u64,
            "Payload length information is inaccurate: {} bytes of input remaining.",
            self.bytes.len() as u64 - consumed
        );
        Ok(payload)
    }
}

impl<A> From<Vec<u8>> for Encoded<A> {
    fn from(encoding: Vec<u8>) -> Self {
        Self {
            bytes: encoding,
            _kind: Default::default(),
        }
    }
}

impl<A> AsRef<[u8]> for Encoded<A> {
    fn as_ref(&self) -> &[u8] { &self.bytes }
}
