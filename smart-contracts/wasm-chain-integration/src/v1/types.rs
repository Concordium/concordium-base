use super::{
    trie::{self, MutableState},
    Interrupt, ParameterVec, StateLessReceiveHost,
};
use crate::{constants, resumption::InterruptedState, type_matches, v0, InterpreterEnergy};
use anyhow::{bail, ensure, Context};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use concordium_contracts_common::OwnedEntrypointName;
use derive_more::{From, Into};
use serde::Deserialize as SerdeDeserialize;
use wasm_transform::{
    artifact::TryFromImport,
    output::Output,
    parse::{Byte, GetParseable, Parseable},
    types::{FunctionType, Import, Name, ValueType},
    validate,
};

/// Maximum length, in bytes, of an export function name.
pub const MAX_EXPORT_NAME_LEN: usize = 100;

pub type ReturnValue = Vec<u8>;

#[derive(Debug)]
pub enum InitResult {
    Success {
        logs:             v0::Logs,
        return_value:     ReturnValue,
        remaining_energy: u64,
        /// Initial state of the contract.
        state:            MutableState,
    },
    Reject {
        reason:           i32,
        return_value:     ReturnValue,
        remaining_energy: u64,
    },
    /// Execution stopped due to a runtime error.
    Trap {
        error:            anyhow::Error, /* this error is here so that we can print it in
                                          * cargo-concordium */
        remaining_energy: u64,
    },
    OutOfEnergy,
}

impl InitResult {
    /// Extract the result into a byte array and potentially a return value.
    /// This is only meant to be used to pass the return value to foreign code.
    /// When using this from Rust the consumer should inspect the [InitResult]
    /// enum directly.
    #[cfg(feature = "enable-ffi")]
    pub(crate) fn extract(self) -> (Vec<u8>, Option<MutableState>, Option<ReturnValue>) {
        match self {
            InitResult::OutOfEnergy => (vec![0], None, None),
            InitResult::Trap {
                remaining_energy,
                .. // ignore the error since it is not needed in ffi
            } => {
                let mut out = vec![1; 9];
                out[1..].copy_from_slice(&remaining_energy.to_be_bytes());
                (out, None, None)
            }
            InitResult::Reject {
                reason,
                return_value,
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(13);
                out.push(2);
                out.extend_from_slice(&reason.to_be_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                (out, None, Some(return_value))
            }
            InitResult::Success {
                logs,
                return_value,
                remaining_energy,
                state,
            } => {
                let mut out = Vec::with_capacity(5 + 8);
                out.push(3);
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                (out, Some(state), Some(return_value))
            }
        }
    }
}

#[derive(Debug)]
/// Host that is saved between handling of operations. This contains sufficient
/// information to resume execution once control returns to the contract.
pub struct SavedHost<Ctx> {
    pub(crate) stateless:          StateLessReceiveHost<ParameterVec, Ctx>,
    /// Current generation of the state. This is the generation before the
    /// handler for the operation is invoked. When control is handed back to the
    /// contract the contract is told whether its state has changed. If it
    /// did, this is incremented to invalidate all previously handed out
    /// iterators and entries.
    pub(crate) current_generation: InstanceCounter,
    /// A list of entries that were handed out before the handler of the
    /// operation was invoked.
    pub(crate) entry_mapping:      Vec<trie::EntryId>,
    /// A list of iterators that were handed out before the handler of the
    /// operation was invoked.
    pub(crate) iterators:          Vec<Option<trie::Iterator>>,
}

#[derive(SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReceiveContext<Policies> {
    #[serde(flatten)]
    pub common:     v0::ReceiveContext<Policies>,
    /// The entrypoint that was intended to be called.
    pub entrypoint: OwnedEntrypointName,
}

impl<'a> From<ReceiveContext<v0::PolicyBytes<'a>>> for ReceiveContext<v0::OwnedPolicyBytes> {
    fn from(borrowed: ReceiveContext<v0::PolicyBytes<'a>>) -> Self {
        Self {
            common:     borrowed.common.into(),
            entrypoint: borrowed.entrypoint,
        }
    }
}

/// State of the suspended execution of the receive function.
/// This retains both the module that is executed, as well the host.
pub type ReceiveInterruptedState<R, Ctx = ReceiveContext<v0::OwnedPolicyBytes>> =
    InterruptedState<ProcessedImports, R, SavedHost<Ctx>>;

#[derive(Debug)]
/// Result of execution of a receive function.
pub enum ReceiveResult<R, Ctx = ReceiveContext<v0::OwnedPolicyBytes>> {
    /// Execution terminated.
    Success {
        /// Logs produced since the last interrupt (or beginning of execution).
        logs:             v0::Logs,
        /// Whether the state has changed as a result of execution. Note that
        /// the meaning of this is "since the start of the last resume".
        state_changed:    bool,
        /// Return value that was produced. There is always a return value,
        /// although it might be empty.
        return_value:     ReturnValue,
        /// Remaining interpreter energy.
        remaining_energy: u64,
    },
    /// Execution triggered an operation.
    Interrupt {
        /// Remaining interpreter energy.
        remaining_energy: u64,
        /// Whether the state has changed as a result of execution. Note that
        /// the meaning of this is "since the start of the last resume".
        state_changed:    bool,
        /// Logs produced since the last interrupt (or beginning of execution).
        logs:             v0::Logs,
        /// Stored execution state that can be used to resume execution.
        config:           Box<ReceiveInterruptedState<R, Ctx>>,
        /// The operation that needs to be handled.
        interrupt:        Interrupt,
    },
    /// Contract execution terminated with a "logic error", i.e., contract
    /// decided to signal an error.
    Reject {
        /// Return code.
        reason:           i32,
        /// Return value, that may describe the error in more detail.
        return_value:     ReturnValue,
        /// Remaining interpreter energy.
        remaining_energy: u64,
    },
    /// Execution stopped due to a runtime error.
    Trap {
        error:            anyhow::Error, /* this error is here so that we can print it in
                                          * cargo-concordium */
        remaining_energy: u64,
    },
    /// Execution consumed all available interpreter energy.
    OutOfEnergy,
}

#[cfg(feature = "enable-ffi")]
/// Data extracted from the [ReceiveResult] in a format suitable to pass to
/// foreign code via FFI.
pub(crate) struct ReceiveResultExtract<R> {
    /// Encoding of the status (i.e., whether it is success, interrupt, ...),
    /// see [ReceiveResult::extract] for the format.
    pub status:          Vec<u8>,
    /// Whether the state of the contract changed or not.
    pub state_changed:   bool,
    /// If execution triggered an operation, this is the current state of
    /// execution.
    pub interrupt_state: Option<Box<ReceiveInterruptedState<R>>>,
    /// If execution terminated, this is the return value that was produced.
    pub return_value:    Option<ReturnValue>,
}

impl<R> ReceiveResult<R> {
    /// Extract the result into a byte array and potentially a return value.
    /// This is only meant to be used to pass the return value to foreign code.
    /// When using this from Rust the consumer should inspect the
    /// [ReceiveResult] enum directly.
    #[cfg(feature = "enable-ffi")]
    pub(crate) fn extract(self) -> ReceiveResultExtract<R> {
        use ReceiveResult::*;
        match self {
            OutOfEnergy => ReceiveResultExtract{
                status: vec![0],
                state_changed: false,
                interrupt_state: None,
                return_value: None
            },
            Trap {
                remaining_energy,
                .. // ignore the error since it is not needed in ffi
            } => {
                let mut out = vec![1; 9];
                out[1..].copy_from_slice(&remaining_energy.to_be_bytes());
                ReceiveResultExtract{
                    status: out,
                    state_changed: false,
                    interrupt_state: None,
                    return_value: None
                }
            }
            Reject {
                reason,
                return_value,
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(13);
                out.push(2);
                out.extend_from_slice(&reason.to_be_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                ReceiveResultExtract{
                    status: out,
                    state_changed: false,
                    interrupt_state: None,
                    return_value: Some(return_value),
                }
            }
            Success {
                logs,
                state_changed,
                return_value,
                remaining_energy,
            } => {
                let mut out = vec![3];
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                ReceiveResultExtract{
                    status: out,
                    state_changed,
                    interrupt_state: None,
                    return_value: Some(return_value),
                }
            }
            Interrupt {
                remaining_energy,
                state_changed,
                logs,
                config,
                interrupt,
            } => {
                let mut out = vec![4];
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                out.extend_from_slice(&logs.to_bytes());
                interrupt.to_bytes(&mut out).expect("Serialization to a vector never fails.");
                ReceiveResultExtract{
                    status: out,
                    state_changed,
                    interrupt_state: Some(config),
                    return_value: None,
                }
            }
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
/// An enumeration of functions that can be used both by init and receive
/// methods.
pub enum CommonFunc {
    GetParameterSize,
    GetParameterSection,
    GetPolicySection,
    LogEvent,
    GetSlotTime,
    WriteOutput,
    StateLookupEntry,
    StateCreateEntry,
    StateDeleteEntry,
    StateDeletePrefix,
    StateIteratePrefix,
    StateIteratorNext,
    StateIteratorDelete,
    StateIteratorKeySize,
    StateIteratorKeyRead,
    StateEntryRead,
    StateEntryWrite,
    StateEntrySize,
    StateEntryResize,
    // Cryptographic functions
    VerifyEd25519,
    VerifySecp256k1,
    HashSHA2_256,
    HashSHA3_256,
    HashKeccak256,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
/// An enumeration of functions that can be used only by init methods.
pub enum InitOnlyFunc {
    GetInitOrigin,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
/// An enumeration of functions that can be used only by receive methods.
pub enum ReceiveOnlyFunc {
    Invoke,
    GetReceiveInvoker,
    GetReceiveSelfAddress,
    GetReceiveSelfBalance,
    GetReceiveSender,
    GetReceiveOwner,
    GetReceiveEntrypointSize,
    GetReceiveEntryPoint,
    Upgrade,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
/// Enumeration of allowed imports.
pub enum ImportFunc {
    /// Charge for execution cost.
    ChargeEnergy,
    /// Track calling a function, increasing the activation frame count.
    TrackCall,
    /// Track returning from a function, decreasing the activation frame count.
    TrackReturn,
    /// Charge for allocating the given amount of pages.
    ChargeMemoryAlloc,
    /// Functions that are common to both init and receive methods.
    Common(CommonFunc),
    /// Functions that can only be called by init methods.
    InitOnly(InitOnlyFunc),
    /// Functions that can only be called by receive methods.
    ReceiveOnly(ReceiveOnlyFunc),
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ImportFunc {
    fn parse(
        ctx: Ctx,
        cursor: &mut std::io::Cursor<&'a [u8]>,
    ) -> wasm_transform::parse::ParseResult<Self> {
        match Byte::parse(ctx, cursor)? {
            0 => Ok(ImportFunc::ChargeEnergy),
            1 => Ok(ImportFunc::TrackCall),
            2 => Ok(ImportFunc::TrackReturn),
            3 => Ok(ImportFunc::ChargeMemoryAlloc),
            4 => Ok(ImportFunc::Common(CommonFunc::GetParameterSize)),
            5 => Ok(ImportFunc::Common(CommonFunc::GetParameterSection)),
            6 => Ok(ImportFunc::Common(CommonFunc::GetPolicySection)),
            7 => Ok(ImportFunc::Common(CommonFunc::LogEvent)),
            8 => Ok(ImportFunc::Common(CommonFunc::GetSlotTime)),
            9 => Ok(ImportFunc::Common(CommonFunc::StateLookupEntry)),
            10 => Ok(ImportFunc::Common(CommonFunc::StateCreateEntry)),
            11 => Ok(ImportFunc::Common(CommonFunc::StateDeleteEntry)),
            12 => Ok(ImportFunc::Common(CommonFunc::StateDeletePrefix)),
            13 => Ok(ImportFunc::Common(CommonFunc::StateIteratePrefix)),
            14 => Ok(ImportFunc::Common(CommonFunc::StateIteratorNext)),
            15 => Ok(ImportFunc::Common(CommonFunc::StateIteratorDelete)),
            16 => Ok(ImportFunc::Common(CommonFunc::StateIteratorKeySize)),
            17 => Ok(ImportFunc::Common(CommonFunc::StateIteratorKeyRead)),
            18 => Ok(ImportFunc::Common(CommonFunc::StateEntryRead)),
            19 => Ok(ImportFunc::Common(CommonFunc::StateEntryWrite)),
            20 => Ok(ImportFunc::Common(CommonFunc::StateEntrySize)),
            21 => Ok(ImportFunc::Common(CommonFunc::StateEntryResize)),
            22 => Ok(ImportFunc::Common(CommonFunc::WriteOutput)),
            23 => Ok(ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin)),
            24 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveInvoker)),
            25 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfAddress)),
            26 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfBalance)),
            27 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSender)),
            28 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveOwner)),
            29 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveEntrypointSize)),
            30 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveEntryPoint)),
            31 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Invoke)),
            32 => Ok(ImportFunc::Common(CommonFunc::VerifyEd25519)),
            33 => Ok(ImportFunc::Common(CommonFunc::VerifySecp256k1)),
            34 => Ok(ImportFunc::Common(CommonFunc::HashSHA2_256)),
            35 => Ok(ImportFunc::Common(CommonFunc::HashSHA3_256)),
            36 => Ok(ImportFunc::Common(CommonFunc::HashKeccak256)),
            37 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Upgrade)),
            tag => bail!("Unexpected ImportFunc tag {}.", tag),
        }
    }
}

impl Output for ImportFunc {
    fn output(&self, out: &mut impl std::io::Write) -> wasm_transform::output::OutResult<()> {
        let tag: u8 = match self {
            ImportFunc::ChargeEnergy => 0,
            ImportFunc::TrackCall => 1,
            ImportFunc::TrackReturn => 2,
            ImportFunc::ChargeMemoryAlloc => 3,
            ImportFunc::Common(c) => match c {
                CommonFunc::GetParameterSize => 4,
                CommonFunc::GetParameterSection => 5,
                CommonFunc::GetPolicySection => 6,
                CommonFunc::LogEvent => 7,
                CommonFunc::GetSlotTime => 8,
                CommonFunc::StateLookupEntry => 9,
                CommonFunc::StateCreateEntry => 10,
                CommonFunc::StateDeleteEntry => 11,
                CommonFunc::StateDeletePrefix => 12,
                CommonFunc::StateIteratePrefix => 13,
                CommonFunc::StateIteratorNext => 14,
                CommonFunc::StateIteratorDelete => 15,
                CommonFunc::StateIteratorKeySize => 16,
                CommonFunc::StateIteratorKeyRead => 17,
                CommonFunc::StateEntryRead => 18,
                CommonFunc::StateEntryWrite => 19,
                CommonFunc::StateEntrySize => 20,
                CommonFunc::StateEntryResize => 21,
                CommonFunc::WriteOutput => 22,
                CommonFunc::VerifyEd25519 => 32,
                CommonFunc::VerifySecp256k1 => 33,
                CommonFunc::HashSHA2_256 => 34,
                CommonFunc::HashSHA3_256 => 35,
                CommonFunc::HashKeccak256 => 36,
            },
            ImportFunc::InitOnly(io) => match io {
                InitOnlyFunc::GetInitOrigin => 23,
            },
            ImportFunc::ReceiveOnly(ro) => match ro {
                ReceiveOnlyFunc::GetReceiveInvoker => 24,
                ReceiveOnlyFunc::GetReceiveSelfAddress => 25,
                ReceiveOnlyFunc::GetReceiveSelfBalance => 26,
                ReceiveOnlyFunc::GetReceiveSender => 27,
                ReceiveOnlyFunc::GetReceiveOwner => 28,
                ReceiveOnlyFunc::GetReceiveEntrypointSize => 29,
                ReceiveOnlyFunc::GetReceiveEntryPoint => 30,
                ReceiveOnlyFunc::Invoke => 31,
                ReceiveOnlyFunc::Upgrade => 37,
            },
        };
        tag.output(out)
    }
}

#[derive(Debug)]
pub struct ProcessedImports {
    pub(crate) tag: ImportFunc,
    ty:             FunctionType,
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ProcessedImports {
    fn parse(
        ctx: Ctx,
        cursor: &mut std::io::Cursor<&'a [u8]>,
    ) -> wasm_transform::parse::ParseResult<Self> {
        let tag = cursor.next(ctx)?;
        let ty = cursor.next(ctx)?;
        Ok(Self {
            tag,
            ty,
        })
    }
}

impl Output for ProcessedImports {
    fn output(&self, out: &mut impl std::io::Write) -> wasm_transform::output::OutResult<()> {
        self.tag.output(out)?;
        self.ty.output(out)
    }
}

/// Allowed imports for V1 modules. Whether some imports are allowed
/// depends on the protocol version that is used to validate the module.
pub struct ConcordiumAllowedImports {
    /// Whether to allow the `upgrade` function. This is supported in protocol
    /// P5 and up, but not before.
    pub support_upgrade: bool,
}

impl validate::ValidateImportExport for ConcordiumAllowedImports {
    fn validate_import_function(
        &self,
        duplicate: bool,
        mod_name: &Name,
        item_name: &Name,
        ty: &FunctionType,
    ) -> bool {
        use ValueType::*;
        if duplicate {
            return false;
        };
        if mod_name.name == "concordium" {
            match item_name.name.as_ref() {
                "invoke" => type_matches!(ty => [I32, I32, I32]; I64),
                "write_output" => type_matches!(ty => [I32, I32, I32]; I32),
                "get_parameter_size" => type_matches!(ty => [I32]; I32),
                "get_parameter_section" => type_matches!(ty => [I32, I32, I32, I32]; I32),
                "get_policy_section" => type_matches!(ty => [I32, I32, I32]; I32),
                "log_event" => type_matches!(ty => [I32, I32]; I32),
                "get_init_origin" => type_matches!(ty => [I32]),
                "get_receive_invoker" => type_matches!(ty => [I32]),
                "get_receive_self_address" => type_matches!(ty => [I32]),
                "get_receive_self_balance" => type_matches!(ty => []; I64),
                "get_receive_sender" => type_matches!(ty => [I32]),
                "get_receive_owner" => type_matches!(ty => [I32]),
                "get_receive_entrypoint_size" => type_matches!(ty => []; I32),
                "get_receive_entrypoint" => type_matches!(ty => [I32]),
                "get_slot_time" => type_matches!(ty => []; I64),
                "state_lookup_entry" => type_matches!(ty => [I32, I32]; I64),
                "state_create_entry" => type_matches!(ty => [I32, I32]; I64),
                "state_delete_entry" => type_matches!(ty => [I32, I32]; I32),
                "state_delete_prefix" => type_matches!(ty => [I32, I32]; I32),
                "state_iterate_prefix" => type_matches!(ty => [I32, I32]; I64),
                "state_iterator_next" => type_matches!(ty => [I64]; I64),
                "state_iterator_delete" => type_matches!(ty => [I64]; I32),
                "state_iterator_key_size" => type_matches!(ty => [I64]; I32),
                "state_iterator_key_read" => type_matches!(ty => [I64, I32, I32, I32]; I32),
                "state_entry_read" => type_matches!(ty => [I64, I32, I32, I32]; I32),
                "state_entry_write" => type_matches!(ty => [I64, I32, I32, I32]; I32),
                "state_entry_size" => type_matches!(ty => [I64]; I32),
                "state_entry_resize" => type_matches!(ty => [I64, I32]; I32),
                "verify_ed25519_signature" => type_matches!(ty => [I32, I32, I32, I32]; I32),
                "verify_ecdsa_secp256k1_signature" => {
                    type_matches!(ty => [I32, I32, I32]; I32)
                }
                "hash_sha2_256" => type_matches!(ty => [I32, I32, I32]),
                "hash_sha3_256" => type_matches!(ty => [I32, I32, I32]),
                "hash_keccak_256" => type_matches!(ty => [I32, I32, I32]),
                // Upgrade is only available from P5.
                "upgrade" => self.support_upgrade && type_matches!(ty => [I32]; I64),
                _ => false,
            }
        } else {
            false
        }
    }

    /// Validate that all the exported functions either
    /// - start with `init_` and contain no `.`
    /// - do contain a `.`
    ///
    /// Names are already ensured to be valid ASCII sequences by parsing, here
    /// we additionally ensure that they contain only alphanumeric and
    /// punctuation characters.
    fn validate_export_function(&self, item_name: &Name, ty: &FunctionType) -> bool {
        let valid_name = item_name.as_ref().as_bytes().len() <= MAX_EXPORT_NAME_LEN
            && item_name
                .as_ref()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation());
        // we don't allow non-ascii names and names with weird characters since they
        // complicate matters elsewhere
        if !valid_name {
            return false;
        }
        let either_init_or_receive_name = if item_name.as_ref().starts_with("init_") {
            !item_name.as_ref().contains('.')
        } else {
            item_name.as_ref().contains('.')
        };
        if either_init_or_receive_name {
            // if it is an init or receive name then check that the type is correct
            ty.parameters.as_slice() == [ValueType::I64] && ty.result == Some(ValueType::I32)
        } else {
            // otherwise we do not care about the type
            true
        }
    }
}

impl TryFromImport for ProcessedImports {
    fn try_from_import(
        ctx: &[FunctionType],
        import: Import,
    ) -> wasm_transform::artifact::CompileResult<Self> {
        let m = &import.mod_name;
        let tag = if m.name == "concordium_metering" {
            match import.item_name.name.as_ref() {
                "account_energy" => ImportFunc::ChargeEnergy,
                "track_call" => ImportFunc::TrackCall,
                "track_return" => ImportFunc::TrackReturn,
                "account_memory" => ImportFunc::ChargeMemoryAlloc,
                name => bail!("Unsupported import {}.", name),
            }
        } else if m.name == "concordium" {
            match import.item_name.name.as_ref() {
                "write_output" => ImportFunc::Common(CommonFunc::WriteOutput),
                "invoke" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Invoke),
                "get_parameter_size" => ImportFunc::Common(CommonFunc::GetParameterSize),
                "get_parameter_section" => ImportFunc::Common(CommonFunc::GetParameterSection),
                "get_policy_section" => ImportFunc::Common(CommonFunc::GetPolicySection),
                "log_event" => ImportFunc::Common(CommonFunc::LogEvent),
                "get_init_origin" => ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin),
                "get_receive_invoker" => {
                    ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveInvoker)
                }
                "get_receive_self_address" => {
                    ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfAddress)
                }
                "get_receive_self_balance" => {
                    ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfBalance)
                }
                "get_receive_sender" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSender),
                "get_receive_owner" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveOwner),
                "get_receive_entrypoint_size" => {
                    ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveEntrypointSize)
                }
                "get_receive_entrypoint" => {
                    ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveEntryPoint)
                }
                "get_slot_time" => ImportFunc::Common(CommonFunc::GetSlotTime),
                "state_lookup_entry" => ImportFunc::Common(CommonFunc::StateLookupEntry),
                "state_create_entry" => ImportFunc::Common(CommonFunc::StateCreateEntry),
                "state_delete_entry" => ImportFunc::Common(CommonFunc::StateDeleteEntry),
                "state_delete_prefix" => ImportFunc::Common(CommonFunc::StateDeletePrefix),
                "state_iterate_prefix" => ImportFunc::Common(CommonFunc::StateIteratePrefix),
                "state_iterator_next" => ImportFunc::Common(CommonFunc::StateIteratorNext),
                "state_iterator_delete" => ImportFunc::Common(CommonFunc::StateIteratorDelete),
                "state_iterator_key_size" => ImportFunc::Common(CommonFunc::StateIteratorKeySize),
                "state_iterator_key_read" => ImportFunc::Common(CommonFunc::StateIteratorKeyRead),
                "state_entry_read" => ImportFunc::Common(CommonFunc::StateEntryRead),
                "state_entry_write" => ImportFunc::Common(CommonFunc::StateEntryWrite),
                "state_entry_size" => ImportFunc::Common(CommonFunc::StateEntrySize),
                "state_entry_resize" => ImportFunc::Common(CommonFunc::StateEntryResize),
                "verify_ed25519_signature" => ImportFunc::Common(CommonFunc::VerifyEd25519),
                "verify_ecdsa_secp256k1_signature" => {
                    ImportFunc::Common(CommonFunc::VerifySecp256k1)
                }
                "hash_sha2_256" => ImportFunc::Common(CommonFunc::HashSHA2_256),
                "hash_sha3_256" => ImportFunc::Common(CommonFunc::HashSHA3_256),
                "hash_keccak_256" => ImportFunc::Common(CommonFunc::HashKeccak256),
                "upgrade" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Upgrade),
                name => bail!("Unsupported import {}.", name),
            }
        } else {
            bail!("Unsupported import module {}.", m)
        };
        let ty = match import.description {
            wasm_transform::types::ImportDescription::Func {
                type_idx,
            } => ctx
                .get(type_idx as usize)
                .ok_or_else(|| anyhow::anyhow!("Unknown type, this should not happen."))?
                .clone(),
        };
        Ok(Self {
            tag,
            ty,
        })
    }

    fn ty(&self) -> &FunctionType { &self.ty }
}

/// The runtime representation of the contract state. This collects all the
/// pieces of data needed to efficiently use the state.
#[derive(Debug)]
pub struct InstanceState<'a, BackingStore> {
    /// The backing store that allows accessing any contract state that is not
    /// in-memory yet.
    backing_store:                 BackingStore,
    /// A flag indicating whether any of the state change functions have been
    /// called.
    pub(crate) changed:            bool,
    /// Current generation of the state.
    pub(crate) current_generation: InstanceCounter,
    pub(crate) entry_mapping:      Vec<trie::EntryId>,
    pub(crate) iterators:          Vec<Option<trie::Iterator>>,
    /// Opaque pointer to the state of the instance in consensus. Note that this
    /// is in effect a mutable reference.
    state_trie:                    trie::StateTrie<'a>,
}

/// first bit is ignored, the next 31 indicate a generation,
/// the final 32 indicates an index in the entry_mapping.
#[derive(Debug, Clone, Copy, From, Into)]
#[repr(transparent)]
pub struct InstanceStateEntry {
    index: u64,
}

/// A counter of the "state instance". When contract execution is interrupted
/// and then resumed, if the state has been modified by the handling of the
/// operation then all state entries that were handed out before the interrupt
/// are invalidated. This is achieved by incrementing the instance counter.
pub type InstanceCounter = u32;

impl InstanceStateEntry {
    /// Return the current generation together with the index in the entry
    /// mapping.
    #[inline]
    pub fn split(self) -> (InstanceCounter, usize) {
        let idx = self.index & 0xffff_ffff;
        let generation = self.index >> 32;
        (generation as u32, idx as usize)
    }

    #[inline]
    /// Construct a new index from a generation and index.
    /// This assumes both value are small enough.
    pub fn new(gen: InstanceCounter, idx: usize) -> Self {
        Self {
            index: u64::from(gen) << 32 | idx as u64,
        }
    }
}

/// Encoding of `Option<Entry>` where `Entry` is what
/// is handed out to smart contracts. See the implementation below for encoding
/// details.
#[derive(Debug, Clone, Copy, From, Into, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct InstanceStateEntryOption {
    index: u64,
}

impl InstanceStateEntryOption {
    pub const NEW_NONE: Self = Self {
        index: u64::MAX,
    };

    #[inline]
    /// Construct a new index from a generation and index.
    /// This assumes both value are small enough.
    pub fn new_some(gen: InstanceCounter, idx: usize) -> Self {
        Self {
            index: u64::from(gen) << 32 | idx as u64,
        }
    }

    /// Converting a `InstanceStateEntryOption`
    /// to a Option<InstanceStateEntry>.
    /// Returns `None` if the underlying value is
    /// [InstanceStateEntryOption::NONE]
    #[cfg(test)]
    pub fn convert(self) -> Option<InstanceStateEntry> {
        if self.index == u64::MAX {
            None
        } else {
            Some(self.index.into())
        }
    }
}

/// An encoding of `Result<Option<Iterator>>`. The Result is for the case where
/// we have too many iterators already at the given location, the Option is for
/// when the key does not point to a valid part of the tree.
#[derive(Debug, Clone, Copy, From, Into, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct InstanceStateEntryResultOption {
    index: u64,
}

impl InstanceStateEntryResultOption {
    pub const NEW_ERR: Self = Self {
        index: u64::MAX & !(1u64 << 62), // second bit is 0
    };
    pub const NEW_OK_NONE: Self = Self {
        index: u64::MAX,
    };

    /// Construct a new index from a generation and index.
    /// This assumes both values are small enough, in particular that idx <=
    /// 2^31.
    #[inline]
    pub fn new_ok_some(gen: InstanceCounter, idx: usize) -> Self {
        Self {
            index: u64::from(gen) << 32 | idx as u64,
        }
    }
}

/// Analogous to [InstanceStateEntry].
#[derive(Debug, Clone, Copy, From, Into, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct InstanceStateIterator {
    index: u64,
}

impl InstanceStateIterator {
    /// Return the current generation together with the index in the entry
    /// mapping.
    #[inline]
    pub fn split(self) -> (InstanceCounter, usize) {
        let idx = self.index & 0xffff_ffff;
        let generation = self.index >> 32;
        (generation as u32, idx as usize)
    }
}

/// An encoding of `Result<Option<Iterator>>`. The Result is for the case where
/// we have too many iterators already at the given location, the Option is for
/// when the key does not point to a valid part of the tree.
#[derive(Debug, Clone, Copy, From, Into, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct InstanceStateIteratorResultOption {
    index: u64,
}

impl InstanceStateIteratorResultOption {
    pub const NEW_ERR: Self = Self {
        index: u64::MAX & !(1u64 << 62), // second bit is 0
    };
    pub const NEW_OK_NONE: Self = Self {
        index: u64::MAX,
    };

    /// Construct a new index from a generation and index.
    /// This assumes both values are small enough, in particular that idx <=
    /// 2^31
    #[inline]
    pub fn new_ok_some(gen: InstanceCounter, idx: usize) -> Self {
        Self {
            index: u64::from(gen) << 32 | idx as u64,
        }
    }

    /// Converting a `InstanceStateIteratorOption`
    /// to a Option<InstanceStateIterator>.
    /// Returns `None` if the underlying value is
    /// [InstanceStateIteratorOption::None]
    #[cfg(test)]
    pub fn convert(self) -> Option<InstanceStateIterator> {
        if self.index == u64::MAX {
            None
        } else {
            Some(self.index.into())
        }
    }
}

pub type StateResult<A> = anyhow::Result<A>;

impl trie::TraversalCounter for InterpreterEnergy {
    type Err = anyhow::Error;

    #[inline(always)]
    fn count_key_traverse_part(&mut self, num: u64) -> Result<(), Self::Err> {
        self.tick_energy(crate::constants::TREE_TRAVERSAL_STEP_COST * num)
    }
}

/// Charge for copying the given amount of data.
/// As an example, the factor 100 means that at most 30MB of data is copied with
/// 3000000NRG.
/// The reason this is needed is that we must create a new copy of existing data
/// when an attempt to write is made. It could be that only a small amount of
/// data is written at the given entry, so charging just based on that would be
/// inadequate.
impl trie::AllocCounter<trie::Value> for InterpreterEnergy {
    type Err = anyhow::Error;

    #[inline(always)]
    fn allocate(&mut self, data: &trie::Value) -> Result<(), Self::Err> {
        self.tick_energy(constants::additional_entry_size_cost(data.len() as u64))
    }
}

impl<'a, BackingStore: trie::BackingStoreLoad> InstanceState<'a, BackingStore> {
    /// Create a new [`InstanceState`] using the given backing store to load
    /// data from disk.
    pub fn new(
        backing_store: BackingStore,
        state: &'a trie::MutableStateInner,
    ) -> InstanceState<'a, BackingStore> {
        Self {
            current_generation: 0,
            backing_store,
            changed: false,
            state_trie: state.lock(),
            iterators: Vec::new(),
            entry_mapping: Vec::new(),
        }
    }

    /// Migrate the [`InstanceState`] to a new generation.
    pub fn migrate(
        state_updated: bool,
        current_generation: InstanceCounter,
        entry_mapping: Vec<trie::EntryId>,
        iterators: Vec<Option<trie::Iterator>>,
        backing_store: BackingStore,
        state: &'a trie::MutableStateInner,
    ) -> InstanceState<'a, BackingStore> {
        // if the state has been updated invalidate everything, and start a new
        // generation.
        if state_updated {
            Self {
                current_generation: current_generation + 1,
                backing_store,
                changed: false,
                state_trie: state.lock(),
                iterators: Vec::new(),
                entry_mapping: Vec::new(),
            }
        } else {
            Self {
                current_generation,
                backing_store,
                changed: false,
                state_trie: state.lock(),
                iterators,
                entry_mapping,
            }
        }
    }

    /// Lookup an entry and return an entry id if it exists,
    /// and (an encoding of) [None] otherwise.
    pub(crate) fn lookup_entry(&mut self, key: &[u8]) -> InstanceStateEntryOption {
        if let Some(id) = self.state_trie.get_entry(&mut self.backing_store, key) {
            let idx = self.entry_mapping.len();
            self.entry_mapping.push(id);
            InstanceStateEntryOption::new_some(self.current_generation, idx)
        } else {
            InstanceStateEntryOption::NEW_NONE
        }
    }

    /// Create an entry. Return an id of the new entry if successful. This
    /// method succeeds if and only if the entry would not be created in the
    /// subtree that is locked due to an iterator. In that case this returns (an
    /// encoding of) [None].
    pub(crate) fn create_entry(&mut self, key: &[u8]) -> StateResult<InstanceStateEntryOption> {
        self.changed = true;
        ensure!(key.len() <= constants::MAX_KEY_SIZE, "Maximum key length exceeded.");
        if let Ok(id) = self.state_trie.insert(&mut self.backing_store, key, Vec::new()) {
            let idx = self.entry_mapping.len();
            self.entry_mapping.push(id.0);
            Ok(InstanceStateEntryOption::new_some(self.current_generation, idx))
        } else {
            Ok(InstanceStateEntryOption::NEW_NONE)
        }
    }

    /// Delete an entry. Return
    /// - 0 if the part of the tree with the entry was locked
    /// - 1 if the entry did not exist, or was already invalidated.
    /// - 2 if an entry was deleted
    pub(crate) fn delete_entry(&mut self, key: &[u8]) -> anyhow::Result<u32> {
        self.changed = true;
        // as u32 is safe since keys are limited by MAX_KEY_SIZE which is less than 2^32
        // - 1
        if let Ok(deleted) = self.state_trie.delete(&mut self.backing_store, key) {
            if deleted {
                Ok(2)
            } else {
                Ok(1)
            }
        } else {
            // tree was locked
            Ok(0)
        }
    }

    /// Delete a prefix in the trie. Return
    /// - 0 if the tree was locked
    /// - 1 the tree was not locked, but nothing was deleted since the key
    ///   points to an empty part of the tree.
    /// - 2 if something was deleted.
    pub(crate) fn delete_prefix(
        &mut self,
        energy: &mut InterpreterEnergy,
        key: &[u8],
    ) -> StateResult<u32> {
        self.changed = true;
        if let Ok(b) = self.state_trie.delete_prefix(&mut self.backing_store, key, energy)? {
            if b {
                Ok(2)
            } else {
                Ok(1)
            }
        } else {
            Ok(0)
        }
    }

    /// Get an iterator for the given prefix.
    /// Returns an encoding of
    /// - an error if there are too many iterators with the given prefix
    /// - Ok(None) if the prefix points to an empty part of the tree
    /// - Ok(Some(id)) with an iterator id in case an iterator is found. This
    ///   iterator will always yield at least one value.
    pub(crate) fn iterator(&mut self, prefix: &[u8]) -> InstanceStateIteratorResultOption {
        if let Ok(iter) = self.state_trie.iter(&mut self.backing_store, prefix) {
            if let Some(iter) = iter {
                let iter_id = self.iterators.len();
                self.iterators.push(Some(iter));
                InstanceStateIteratorResultOption::new_ok_some(self.current_generation, iter_id)
            } else {
                InstanceStateIteratorResultOption::NEW_OK_NONE
            }
        } else {
            InstanceStateIteratorResultOption::NEW_ERR
        }
    }

    /// Advance the iterator. Returns None if the iterator is exhausted, and
    /// otherwise an id of an entry.
    /// This charges energy based on how much of the tree needed to be
    /// traversed, expressed in terms of bytes of the key that changed.
    pub(crate) fn iterator_next(
        &mut self,
        energy: &mut InterpreterEnergy,
        iter: InstanceStateIterator,
    ) -> StateResult<InstanceStateEntryResultOption> {
        energy.tick_energy(constants::ITERATOR_NEXT_COST)?;
        let (gen, idx) = iter.split();
        if gen != self.current_generation {
            return Ok(InstanceStateEntryResultOption::NEW_ERR);
        }
        if let Some(iter) = self.iterators.get_mut(idx).and_then(Option::as_mut) {
            if let Some(id) = self.state_trie.next(&mut self.backing_store, iter, energy)? {
                let idx = self.entry_mapping.len();
                self.entry_mapping.push(id);
                Ok(InstanceStateEntryResultOption::new_ok_some(self.current_generation, idx))
            } else {
                Ok(InstanceStateEntryResultOption::NEW_OK_NONE)
            }
        } else {
            Ok(InstanceStateEntryResultOption::NEW_ERR)
        }
    }

    /// Delete the iterator.
    /// Returns
    /// - 1 if the iterator was successfully deleted
    /// - 0 if the iterator was already deleted
    /// - u32::MAX if the iterator could not be found
    pub(crate) fn iterator_delete(
        &mut self,
        energy: &mut InterpreterEnergy,
        iter: InstanceStateIterator,
    ) -> anyhow::Result<u32> {
        energy.tick_energy(constants::DELETE_ITERATOR_BASE_COST)?;
        let (gen, idx) = iter.split();
        if gen != self.current_generation {
            return Ok(u32::MAX);
        }
        match self.iterators.get_mut(idx) {
            Some(iter) => match iter {
                Some(existing_iter) => {
                    energy.tick_energy(constants::delete_iterator_cost(
                        existing_iter.get_key().len() as u32,
                    ))?;
                    // Unlock the nodes associated with this iterator.
                    self.state_trie.delete_iter(existing_iter);
                    // Finally we remove the iterator in the instance by setting it to `None`.
                    *iter = None;
                    Ok(1)
                }
                // already deleted.
                None => Ok(0),
            },
            // iterator did not exist.
            None => Ok(u32::MAX),
        }
    }

    /// Return the size (in bytes) of the key the iterator is currently located
    /// at.
    pub(crate) fn iterator_key_size(&mut self, iter: InstanceStateIterator) -> u32 {
        let (gen, idx) = iter.split();
        if gen != self.current_generation {
            return u32::MAX;
        }
        if let Some(iter) = self.iterators.get(idx).and_then(Option::as_ref) {
            iter.get_key().len() as u32
        } else {
            u32::MAX
        }
    }

    /// Read a section of the iterator key, and return how much was read.
    /// Returns u32::MAX if an invalid iterator id was supplied.
    pub(crate) fn iterator_key_read(
        &mut self,
        iter: InstanceStateIterator,
        dest: &mut [u8],
        offset: u32,
    ) -> u32 {
        let (gen, idx) = iter.split();
        if gen != self.current_generation {
            return u32::MAX;
        }
        if let Some(iter) = self.iterators.get(idx).and_then(Option::as_ref) {
            let key = iter.get_key();
            let offset = std::cmp::min(key.len(), offset as usize);
            let num_copied = std::cmp::min(key.len().saturating_sub(offset), dest.len());
            dest[0..num_copied].copy_from_slice(&key[offset..offset + num_copied]);
            num_copied as u32
        } else {
            u32::MAX
        }
    }

    /// Read a section of the entry, and return how much was read, or u32::MAX,
    /// in case the entry has already been invalidated.
    pub(crate) fn entry_read(
        &mut self,
        entry: InstanceStateEntry,
        dest: &mut [u8],
        offset: u32,
    ) -> u32 {
        let (gen, idx) = entry.split();
        if gen != self.current_generation {
            return u32::MAX;
        }
        if let Some(entry) = self.entry_mapping.get(idx) {
            let res = self.state_trie.with_entry(*entry, &mut self.backing_store, |v| {
                let offset = std::cmp::min(v.len(), offset as usize);
                let num_copied = std::cmp::min(v.len().saturating_sub(offset), dest.len());
                dest[0..num_copied].copy_from_slice(&v[offset..offset + num_copied]);
                num_copied as u32
            });
            if let Some(res) = res {
                res
            } else {
                // Entry has been invalidated.
                u32::MAX
            }
        } else {
            u32::MAX
        }
    }

    /// Write a section of the entry, and return how much was written, or
    /// u32::MAX, in case the entry has already been invalidated.
    pub(crate) fn entry_write(
        &mut self,
        energy: &mut InterpreterEnergy,
        entry: InstanceStateEntry,
        src: &[u8],
        offset: u32,
    ) -> StateResult<u32> {
        self.changed = true;
        let (gen, idx) = entry.split();
        if gen != self.current_generation {
            return Ok(u32::MAX);
        }
        if let Some(entry) = self.entry_mapping.get(idx) {
            if let Some(v) = self.state_trie.get_mut(*entry, &mut self.backing_store, energy)? {
                let offset = offset as usize;
                if offset <= v.len() {
                    // by state invariants, v.len() <= MAX_ENTRY_SIZE.
                    // Hence offset <= MAX_ENTRY_SIZE, and thus offset <= end.
                    // So the below will work correctly.
                    let end = std::cmp::min(
                        constants::MAX_ENTRY_SIZE,
                        offset.checked_add(src.len()).context("Too much data.")?,
                    );
                    if v.len() < end {
                        energy.tick_energy(constants::additional_entry_size_cost(
                            (end - v.len()) as u64,
                        ))?;
                        v.resize(end, 0u8);
                    }
                    let num_bytes_to_write = end - offset;
                    v[offset..end].copy_from_slice(&src[0..num_bytes_to_write]);
                    // as below is correct, since num_bytes_to_write <= end <= MAX_ENTRY_SIZE <
                    // u32::MAX
                    Ok(num_bytes_to_write as u32)
                } else {
                    // cannot start writing past the entry, so write nothing.
                    Ok(0)
                }
            } else {
                // Entry has been invalidated.
                Ok(u32::MAX)
            }
        } else {
            Ok(u32::MAX)
        }
    }

    /// Return the size of the entry, or u32::MAX in case the entry has already
    /// been invalidated.
    pub(crate) fn entry_size(&mut self, entry: InstanceStateEntry) -> u32 {
        let (gen, idx) = entry.split();
        if gen != self.current_generation {
            return u32::MAX;
        }
        if let Some(entry) = self.entry_mapping.get(idx) {
            let res =
                self.state_trie.with_entry(*entry, &mut self.backing_store, |v| v.len() as u32);
            if let Some(res) = res {
                res
            } else {
                // entry was invalidated.
                u32::MAX
            }
        } else {
            u32::MAX
        }
    }

    /// Resize the entry to the new size. Returns
    /// - 0 if this was unsuccessful because the new state is too big
    /// - u32::MAX if entry was already invalidated
    /// - 1 if successful
    pub(crate) fn entry_resize(
        &mut self,
        energy: &mut InterpreterEnergy,
        entry: InstanceStateEntry,
        new_size: u32,
    ) -> StateResult<u32> {
        self.changed = true;
        let (gen, idx) = entry.split();
        if gen != self.current_generation {
            return Ok(u32::MAX);
        }
        if let Some(entry) = self.entry_mapping.get(idx).copied() {
            if new_size as usize > constants::MAX_ENTRY_SIZE {
                return Ok(0);
            }
            let new_size = u64::from(new_size);
            if let Some(v) = self.state_trie.get_mut(
                entry,
                &mut self.backing_store,
                &mut ResizeAllocateCounter {
                    new_size,
                    energy,
                },
            )? {
                let existing_len = v.len();
                if new_size > existing_len as u64 {
                    // `get_mut` above charged only for the energy in case the entry
                    // was borrowed. If we are increasing the size we also must charge
                    // if the entry is owned already, to prevent excessive state growth.
                    energy.tick_energy(constants::additional_entry_size_cost(
                        new_size - existing_len as u64,
                    ))?;
                }
                v.resize(new_size as usize, 0u8);
                v.shrink_to_fit();
                Ok(1)
            } else {
                Ok(u32::MAX)
            }
        } else {
            Ok(u32::MAX)
        }
    }
}

/// A helper structure that is used to charge appropriately for
/// [InstanceState::entry_resize] function. It charges differently based on
/// whether we are adding new state or not. In the latter case it only charges
/// based on the size of the new state. In particular the intention is that
/// truncating (e.g., resizing to 0) will as a result be cheap.
/// Note that this **is only safe** in connection with using
/// [Vec::shrink_to_fit] inside [InstanceState::entry_resize]. We must not
/// retain excess memory.
struct ResizeAllocateCounter<'a> {
    new_size: u64,
    energy:   &'a mut InterpreterEnergy,
}

impl<'a> trie::AllocCounter<trie::Value> for ResizeAllocateCounter<'a> {
    type Err = anyhow::Error;

    #[inline]
    // Charge if the entry must be copied to a new one. Charge only for the smaller
    // of the sizes. If the size will be increased then the extra is charged by
    // [InstanceState::entry_resize] function.
    fn allocate(&mut self, data: &trie::Value) -> Result<(), Self::Err> {
        let existing_size = data.len() as u64;
        if self.new_size > existing_size {
            self.energy.tick_energy(constants::additional_entry_size_cost(existing_size))
        } else {
            self.energy.tick_energy(constants::additional_entry_size_cost(self.new_size))
        }
    }
}
