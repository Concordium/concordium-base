//! Type definitions related to use of smart contracts.
use crate::{
    common::{
        Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
        Serialize,
    },
    constants::*,
};
/// Re-export of common helper functionality for smart contract, such as types
/// and serialization specific for smart contracts.
pub use concordium_contracts_common::{
    self, ContractName, ExceedsParameterSize, ModuleReference, OwnedContractName, OwnedParameter,
    OwnedReceiveName, ReceiveName,
};
use concordium_contracts_common::{AccountAddress, Address, Amount, ContractAddress};
use derive_more::*;
use sha2::Digest;
use std::convert::{TryFrom, TryInto};

/// **Deprecated:** Replaced by [`OwnedParameter`] for consistency. Use it
/// instead.
#[deprecated(
    note = "Replaced by [`OwnedParameter`](./struct.OwnedParameter.html) for consistency. Use it \
            instead."
)]
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

/// **Deprecated:** Replaced by [`ModuleReference`] for consistency. Use it
/// instead.
#[deprecated(
    note = "Replaced by [`ModuleReference`](../hashes/type.ModuleReference.html) for consistency. \
            Use it instead."
)]
pub type ModuleRef = ModuleReference;

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
        let bytes = crate::common::deserial_bytes(source, s as usize)?;
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
    pub fn get_module_ref(&self) -> ModuleReference {
        let mut hasher = sha2::Sha256::new();
        self.serial(&mut hasher);
        ModuleReference::from(<[u8; 32]>::from(hasher.finalize()))
    }
}

#[derive(Debug, Clone)]
/// A successful contract invocation produces a sequence of effects on smart
/// contracts and possibly accounts (if any contract transfers CCD to an
/// account).
pub enum ContractTraceElement {
    /// A contract instance was updated.
    Updated { data: InstanceUpdatedEvent },
    /// A contract transferred an amount to the account.
    Transferred {
        /// Sender contract.
        from:   ContractAddress,
        /// Amount transferred.
        amount: Amount,
        /// Receiver account.
        to:     AccountAddress,
    },
    Interrupted {
        address: ContractAddress,
        events:  Vec<ContractEvent>,
    },
    Resumed {
        address: ContractAddress,
        success: bool,
    },
    Upgraded {
        /// Address of the instance that was upgraded.
        address: ContractAddress,
        /// The existing module reference that is in effect before the upgrade.
        from:    ModuleReference,
        /// The new module reference that is in effect after the upgrade.
        to:      ModuleReference,
    },
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Data generated as part of updating a single contract instance.
/// In general a single [Update](crate::transactions::Payload::Update)
/// transaction will generate one or more of these events, together with
/// possibly some transfers.
pub struct InstanceUpdatedEvent {
    #[serde(default)]
    pub contract_version: WasmVersion,
    /// Address of the affected instance.
    pub address:          ContractAddress,
    /// The origin of the message to the smart contract. This can be either
    /// an account or a smart contract.
    pub instigator:       Address,
    /// The amount the method was invoked with.
    pub amount:           Amount,
    /// The message passed to method.
    pub message:          OwnedParameter,
    /// The name of the method that was executed.
    pub receive_name:     OwnedReceiveName,
    /// Any contract events that might have been generated by the contract
    /// execution.
    pub events:           Vec<ContractEvent>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, AsRef, Into, From)]
#[serde(transparent)]
/// An event logged by a smart contract initialization.
pub struct ContractEvent {
    #[serde(with = "crate::internal::byte_array_hex")]
    bytes: Vec<u8>,
}

/// Display the entire event in hex.
impl std::fmt::Display for ContractEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.bytes {
            f.write_fmt(format_args!("{:02x}", b))?
        }
        Ok(())
    }
}
