//! Type definitions related to use of smart contracts.
use crate::{
    common::{
        Buffer, Deserial, Get, ParseResult, ReadBytesExt, SerdeDeserialize, SerdeSerialize, Serial,
        Serialize,
    },
    constants::*,
};
pub use concordium_contracts_common::WasmVersion;
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

impl Serial for WasmVersion {
    #[inline(always)]
    fn serial<B: Buffer>(&self, out: &mut B) { u32::from(u8::from(*self)).serial(out) }
}

impl Deserial for WasmVersion {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x = u32::deserial(source)?;
        let tag = u8::try_from(x)?;
        Ok(tag.try_into()?)
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

#[derive(Debug, thiserror::Error)]
pub enum WasmFromFileError {
    #[error("Failed reading file: {0}")]
    Read(#[from] std::io::Error),
    #[error("Failed parsing module: {0}")]
    Parse(#[from] anyhow::Error),
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

    /// Attempt to read a [`WasmModule`] from a file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, WasmFromFileError> {
        Self::from_slice(&std::fs::read(path)?).map_err(WasmFromFileError::Parse)
    }

    /// Attempt to read a [`WasmModule`] from a byte slice. All of the slice is
    /// required to be consumed.
    pub fn from_slice(bytes: &[u8]) -> ParseResult<Self> {
        let mut cursor = std::io::Cursor::new(bytes);
        let module = super::common::from_bytes(&mut cursor)?;
        let remaining = (bytes.len() as u64).saturating_sub(cursor.position());
        anyhow::ensure!(
            remaining == 0,
            "There are {} remaining bytes of data.",
            remaining
        );
        Ok(module)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl ContractTraceElement {
    /// Get the contract address that this event relates to.
    /// This means the `address` field for all variant except `Transferred`,
    /// where it returns the `from`.
    pub fn affected_address(&self) -> ContractAddress {
        match self {
            ContractTraceElement::Interrupted { address, .. } => *address,
            ContractTraceElement::Resumed { address, .. } => *address,
            ContractTraceElement::Upgraded { address, .. } => *address,
            ContractTraceElement::Updated {
                data: InstanceUpdatedEvent { address, .. },
            } => *address,
            ContractTraceElement::Transferred { from, .. } => *from,
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, PartialEq, Eq)]
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
    /// execution since the last interrupt.
    pub events:           Vec<ContractEvent>,
}

#[derive(SerdeSerialize, SerdeDeserialize, Clone, AsRef, Into, From, PartialEq, Eq)]
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

/// Display the entire event in hex.
impl std::fmt::Debug for ContractEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            self.bytes.fmt(f)
        } else {
            for b in &self.bytes {
                f.write_fmt(format_args!("{:02x}", b))?
            }
            Ok(())
        }
    }
}

impl ContractEvent {
    /// Try to parse the event into a type that implements
    /// [`Deserial`](concordium_contracts_common::Deserial).
    ///
    /// Ensures that all the bytes in the event data are read.
    pub fn parse<T: concordium_contracts_common::Deserial>(
        &self,
    ) -> concordium_contracts_common::ParseResult<T> {
        use concordium_contracts_common::{Cursor, Get, ParseError};
        let mut cursor = Cursor::new(self.as_ref());
        let res = cursor.get()?;
        // Check that all bytes have been read, as leftover bytes usually indicate
        // errors.
        if cursor.offset != self.as_ref().len() {
            return Err(ParseError::default());
        }
        Ok(res)
    }
}
