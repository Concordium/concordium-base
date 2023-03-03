use super::hashes;
use crate::constants::*;
use concordium_contracts_common::ModuleReference;
/// Re-export of common helper functionality for smart contract, such as types
/// and serialization specific for smart contracts.
pub use concordium_contracts_common::{
    self, ContractName, ExceedsParameterSize, OwnedContractName, OwnedParameter, OwnedReceiveName,
    ReceiveName,
};
use crypto_common::{
    derive::{Serial, Serialize},
    Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
};
use derive_more::*;
use sha2::Digest;
use std::convert::{TryFrom, TryInto};

#[deprecated(note = "Replaced by `OwnedParameter` for consistency. Use that one instead.")]
pub type Parameter = OwnedParameter;

#[derive(
    SerdeSerialize, SerdeDeserialize, Debug, Copy, Clone, Display, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
/// Version of the module. This determines the chain API that the module can
/// access.
pub enum WasmVersion {
    #[display = "V0"]
    /// The initial smart contracts version. This has a simple state API that
    /// has very limited capacity. `V0` contracts also use message-passing as
    /// the interaction method.
    V0 = 0u8,
    #[display = "V1"]
    /// `V1` contracts were introduced with protocol version 4. In comparison to
    /// `V0` contracts they use synchronous calls as the interaction method,
    /// and they have access to a more fine-grained state API allowing for
    /// unlimited (apart from NRG costs) state size.
    V1,
}

/// V0 is the default version of smart contracts.
impl Default for WasmVersion {
    fn default() -> Self { Self::V0 }
}

impl From<WasmVersion> for u8 {
    fn from(x: WasmVersion) -> Self { x as u8 }
}

impl TryFrom<u8> for WasmVersion {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            _ => anyhow::bail!("Only versions 0 and 1 of smart contracts are supported."),
        }
    }
}

impl Serial for WasmVersion {
    #[inline(always)]
    fn serial<B: Buffer>(&self, out: &mut B) { u32::from(u8::from(*self)).serial(out) }
}

impl Deserial for WasmVersion {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x = u32::deserial(source)?;
        let tag = u8::try_from(x)?;
        tag.try_into()
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum ModuleRefMarker {}
/// Reference to a deployed Wasm module on the chain.
/// This reference is used when creating new instances.
pub type ModuleRef = hashes::HashBytes<ModuleRefMarker>;

impl From<ModuleReference> for ModuleRef {
    fn from(mr: ModuleReference) -> Self { Self::new(mr.into()) }
}

impl From<ModuleRef> for ModuleReference {
    fn from(mr: ModuleRef) -> Self { ModuleReference::from(mr.bytes) }
}

#[derive(
    SerdeSerialize,
    SerdeDeserialize,
    Serial,
    Clone,
    Debug,
    AsRef,
    From,
    Into,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
)]
#[serde(transparent)]
/// Unparsed Wasm module source.
pub struct ModuleSource {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 4]
    bytes: Vec<u8>,
}

impl ModuleSource {
    pub fn size(&self) -> u64 { self.bytes.len() as u64 }
}

impl Deserial for ModuleSource {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let s: u32 = source.get()?;
        anyhow::ensure!(
            s <= MAX_WASM_MODULE_SIZE,
            "Maximum size of a Wasm module is {}",
            MAX_WASM_MODULE_SIZE
        );
        let bytes = crypto_common::deserial_bytes(source, s as usize)?;
        Ok(ModuleSource { bytes })
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serialize, Clone, Debug, PartialEq, Eq)]
/// Unparsed module with a version indicating what operations are allowed.
pub struct WasmModule {
    pub version: WasmVersion,
    pub source:  ModuleSource,
}

impl WasmModule {
    /// Get the identifier of the module. This identifier is used to refer to
    /// the module on the chain, e.g., when initializing a new contract
    /// instance.
    pub fn get_module_ref(&self) -> ModuleRef {
        let mut hasher = sha2::Sha256::new();
        self.serial(&mut hasher);
        ModuleRef::from(<[u8; 32]>::from(hasher.finalize()))
    }
}
