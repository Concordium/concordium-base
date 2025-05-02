use concordium_contracts_common::hashes::HashBytes;

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash used for referencing a protocol
/// level token module.
pub enum TokenModuleReferenceMarker {}

/// A reference to a protocol level token module deployed on the chain.
pub type TokenModuleRef = HashBytes<TokenModuleReferenceMarker>;
