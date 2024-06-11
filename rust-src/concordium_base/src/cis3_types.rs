use crate::smart_contracts::ContractEvent;
use concordium_contracts_common::{
    self as concordium_std, AccountAddress, AccountSignatures, ContractAddress, Cursor, Deserial,
    OwnedEntrypointName, OwnedParameter, ParseError, Read, Timestamp,
};
use derive_more::{AsRef, Display, Into};
use thiserror::Error;

/// A permit message, part of the CIS3 specification.
#[derive(Debug, Clone, concordium_std::Serialize)]
pub struct PermitMessage {
    /// The address of the intended contract.
    pub contract_address: ContractAddress,
    /// A nonce to prevent replay attacks.
    pub nonce:            u64,
    /// The timestamp of the message.
    pub timestamp:        Timestamp,
    /// The entry point to be invoked.
    pub entry_point:      OwnedEntrypointName,
    /// The parameters to be passed to the entry point.
    pub payload:          OwnedParameter,
}

/// The parameters for a `permit` invokation, part of the CIS3 specification.
#[derive(Debug, concordium_std::Serialize)]
pub struct PermitParams {
    /// The signature of the sponsoree.
    pub signature: AccountSignatures,
    /// The address of the sponsoree.
    pub signer:    AccountAddress,
    /// The message to be signed.
    pub message:   PermitMessage,
}

/// Error for constructing a new [`SupportsPermitQueryParams`].
#[derive(Debug, PartialEq, Eq, Error)]
#[error("Invalid number of queries for supportsPermit, must be within a length of u16::MAX.")]
pub struct NewSupportsPermitQueryParamsError;

/// The parameter type for the `supportsPermit` contract function, part of the
/// CIS3 specification.
#[derive(Debug, AsRef, Clone, Into, concordium_std::Serialize)]
pub struct SupportsPermitQueryParams(#[concordium(size_length = 2)] Vec<OwnedEntrypointName>);

impl SupportsPermitQueryParams {
    /// Create a new `SupportsPermitQueryParams`.
    /// Ensures the length of the provided entry points are within `u16::MAX`.
    pub fn new(
        entry_points: Vec<OwnedEntrypointName>,
    ) -> Result<Self, NewSupportsPermitQueryParamsError> {
        if entry_points.len() > u16::MAX.into() {
            return Err(NewSupportsPermitQueryParamsError);
        }
        Ok(Self(entry_points))
    }

    /// Create a new `SupportsPermitQueryParams` without checking that the
    /// length of the provided entry points is within `u16::MAX`.
    pub fn new_unchecked(entry_points: Vec<OwnedEntrypointName>) -> Self { Self(entry_points) }
}

/// The response type for the `supportsPermit` contract function.
/// The response is a vector of booleans, where each boolean indicates whether
/// the corresponding entry point in the query supports the `permit` function.
#[derive(Debug, PartialEq, Eq, AsRef, Clone, Into, concordium_std::Serialize)]
pub struct SupportsPermitRepsonse(#[concordium(size_length = 2)] pub Vec<bool>);

/// Smart contract logged event, part of the CIS3 specification.
#[derive(Debug, Display, Clone)]
pub enum Event {
    /// A sponsored transaction was executed.
    #[display(
        fmt = "Sponsored transaction executed for {} (nonce: {})",
        sponsoree,
        nonce
    )]
    Nonce {
        nonce:     u64,
        sponsoree: AccountAddress,
    },
    /// Custom event outside of the CIS3 specification.
    #[display(fmt = "Unknown event: Event is not part of CIS3 specification")]
    Unknown,
}

/// Deserialize the contract events according to the CIS3 specification.
impl Deserial for Event {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, ParseError> {
        let discriminant = u8::deserial(source)?;
        match discriminant {
            250 => Ok(Event::Nonce {
                nonce:     u64::deserial(source)?,
                sponsoree: AccountAddress::deserial(source)?,
            }),
            _ => Ok(Event::Unknown),
        }
    }
}

/// Attempt to parse the contract event into an event. This requires that the
/// entire input is consumed if it is a known CIS3 event.
impl<'a> TryFrom<&'a ContractEvent> for Event {
    type Error = ParseError;

    fn try_from(value: &'a super::smart_contracts::ContractEvent) -> Result<Self, Self::Error> {
        let data = value.as_ref();
        let mut cursor = Cursor::new(data);
        let res = Self::deserial(&mut cursor)?;
        if cursor.offset == data.len() || matches!(&res, Self::Unknown) {
            Ok(res)
        } else {
            Err(ParseError {})
        }
    }
}
