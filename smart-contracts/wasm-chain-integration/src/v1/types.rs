use std::io::Write;

use super::{trie, Interrupt, ParameterVec, StateLessReceiveHost};
use crate::{constants, resumption::InterruptedState, type_matches, v0, InterpreterEnergy};
use anyhow::{bail, ensure, Context};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use derive_more::{From, Into};
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
    pub(crate) fn extract(self) -> (Vec<u8>, Option<(bool, ReturnValue)>) {
        match self {
            InitResult::OutOfEnergy => (vec![0], None),
            InitResult::Trap {
                remaining_energy,
                .. // ignore the error since it is not needed in ffi
            } => {
                let mut out = vec![1; 9];
                out[1..].copy_from_slice(&remaining_energy.to_be_bytes());
                (out, None)
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
                (out, Some((false, return_value)))
            }
            InitResult::Success {
                logs,
                return_value,
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(5 + 8);
                out.push(3);
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                (out, Some((true, return_value)))
            }
        }
    }
}

/// State of the suspended execution of the receive function.
/// This retains both the module that is executed, as well the host.
pub type ReceiveInterruptedState<R, Ctx = v0::ReceiveContext<v0::OwnedPolicyBytes>> =
    InterruptedState<ProcessedImports, R, StateLessReceiveHost<ParameterVec, Ctx>>;

#[derive(Debug)]
/// Result of execution of a receive function.
pub enum ReceiveResult<R, Ctx = v0::ReceiveContext<v0::OwnedPolicyBytes>> {
    /// Execution terminated.
    Success {
        /// Logs produced since the last interrupt (or beginning of execution).
        logs:             v0::Logs,
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
pub(crate) struct ReceiveResultExtract<R> {
    pub status:          Vec<u8>,
    pub state_changed:   bool,
    pub interrupt_state: Option<Box<ReceiveInterruptedState<R>>>,
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
                return_value,
                remaining_energy,
            } => {
                let mut out = vec![3];
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                ReceiveResultExtract{
                    status: out,
                    state_changed: true,
                    interrupt_state: None,
                    return_value: Some(return_value),
                }
            }
            Interrupt {
                remaining_energy,
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
                    state_changed: true,
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
            15 => Ok(ImportFunc::Common(CommonFunc::StateEntryRead)),
            16 => Ok(ImportFunc::Common(CommonFunc::StateEntryWrite)),
            17 => Ok(ImportFunc::Common(CommonFunc::StateEntrySize)),
            18 => Ok(ImportFunc::Common(CommonFunc::StateEntryResize)),
            21 => Ok(ImportFunc::Common(CommonFunc::WriteOutput)),
            22 => Ok(ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin)),
            23 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveInvoker)),
            24 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfAddress)),
            25 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfBalance)),
            26 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSender)),
            27 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveOwner)),
            28 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Invoke)),
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
                ReceiveOnlyFunc::Invoke => 29,
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

pub struct ConcordiumAllowedImports;

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
                "get_slot_time" => type_matches!(ty => []; I64),
                "state_lookup_entry" => type_matches!(ty => [I32, I32]; I64),
                "state_create_entry" => type_matches!(ty => [I32, I32]; I64),
                "state_delete_entry" => type_matches!(ty => [I64]; I32),
                "state_delete_prefix" => type_matches!(ty => [I32, I32]; I32),
                "state_iterate_prefix" => type_matches!(ty => [I32, I32]; I32),
                "state_iterator_next" => type_matches!(ty => [I64]; I64),
                "state_iterator_delete" => type_matches!(ty => [I64]; I32),
                "state_iterator_key_size" => type_matches!(ty => [I64]; I32),
                "state_iterator_key_read" => type_matches!(ty => [I64, I32, I32, I32]; I32),
                "state_entry_read" => type_matches!(ty => [I64, I32, I32, I32]; I32),
                "state_entry_write" => type_matches!(ty => [I64, I32, I32, I32]; I32),
                "state_entry_size" => type_matches!(ty => [I64]; I32),
                "state_entry_resize" => type_matches!(ty => [I64, I32]; I32),
                "state_entry_key_read" => type_matches!(ty => [I64, I32, I32, I32]; I32),
                "state_entry_key_size" => type_matches!(ty => [I64]; I32),
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

#[derive(Debug)]
pub struct EntryWithKey {
    id:  trie::EntryId,
    key: Box<[u8]>, // FIXME: Use TinyVec here instead since most keys will be small.
}

/// Wrapper for the opaque pointers to the state of the instance managed by
/// Consensus.
#[derive(Debug)]
pub struct InstanceState<'a, BackingStore> {
    /// The backing store that allows accessing any contract state that is not
    /// in-memory yet.
    backing_store:      BackingStore,
    /// Current generation of the state.
    current_generation: Generation,
    entry_mapping:      Vec<Option<EntryWithKey>>, /* FIXME: This could be done more efficiently
                                                    * by using a usize::MAX as deleted id */
    iterators:          Vec<Option<trie::Iterator>>,
    /// Opaque pointer to the state of the instance in consensus.
    state_trie:         trie::StateTrie<'a>,
    /// Table of iterator ids and their corresponding root.
    /// Keys present in this table are to be considered locked for modification
    /// i.e., there cannot be added or removed children of the root key.
    iterator_roots:     std::collections::BTreeMap<usize, Vec<u8>>,
}

/// first bit is ignored, the next 31 indicate a generation,
/// the final 32 indicates an index in the entry_mapping.
#[derive(Debug, Clone, Copy, From, Into)]
#[repr(transparent)]
pub struct InstanceStateEntry {
    index: u64,
}

pub type Generation = u32;

impl InstanceStateEntry {
    /// Return the current generation together with the index in the entry
    /// mapping.
    #[inline]
    pub fn split(self) -> (Generation, usize) {
        let idx = self.index & 0xffff_ffff;
        let generation = (self.index >> 32) & 0x7fff_ffff; // set the first bit to 0.
        (generation as u32, idx as usize)
    }

    #[inline]
    /// Construct a new index from a generation and index.
    /// This assumes both value are small enough.
    pub fn new(gen: Generation, idx: usize) -> Self {
        Self {
            index: u64::from(gen) << 32 | idx as u64,
        }
    }
}

impl InstanceStateEntryOption {
    #[inline]
    /// Construct a new index from a generation and index.
    /// This assumes both value are small enough.
    pub fn new(opt: Option<(Generation, usize)>) -> Self {
        match opt {
            None => Self {
                index: 0,
            },
            Some((gen, idx)) => Self {
                index: u64::from(gen) << 32 | idx as u64 | 1u64 << 63,
            },
        }
    }
}

/// if the first bit is 0 then this counts as None,
/// otherwise the next 31 bits indicate the generation,
/// and the remaining 32 the index in the entry mapping.
#[derive(Debug, Clone, Copy, From, Into)]
#[repr(transparent)]
pub struct InstanceStateEntryOption {
    index: u64,
}
/// Analogous to InstanceStateEntry.
#[derive(Debug, Clone, Copy, From, Into)]
#[repr(transparent)]
pub struct InstanceStateIterator {
    index: u64,
}

/// Analogous to [InstanceStateEntryResultOption].
#[derive(Debug, Clone, Copy, From, Into)]
#[repr(transparent)]
pub struct InstanceStateIteratorResultOption {
    index: u64,
}

impl InstanceStateIterator {
    /// Return the current generation together with the index in the entry
    /// mapping.
    #[inline]
    pub fn split(self) -> (Generation, usize) {
        let idx = self.index & 0xffff_ffff;
        let generation = (self.index >> 32) & 0x7fff_ffff; // set the first bit to 0.
        (generation as u32, idx as usize)
    }

    #[inline]
    /// Construct a new index from a generation and index.
    /// This assumes both value are small enough.
    pub fn new(gen: Generation, idx: usize) -> Self {
        Self {
            index: u64::from(gen) << 32 | idx as u64,
        }
    }
}

impl InstanceStateIteratorResultOption {
    pub const NEW_ERR: Self = Self {
        index: 1u64 << 62,
    };
    pub const NEW_OK_NONE: Self = Self {
        index: 0,
    };

    /// Construct a new index from a generation and index.
    /// This assumes both value are small enough.
    #[inline]
    pub fn new_ok_some(gen: Generation, idx: usize) -> Self {
        Self {
            index: u64::from(gen) << 32 | idx as u64 | 1u64 << 63,
        }
    }
}

pub type StateResult<A> = anyhow::Result<A>;

impl trie::TraversalCounter for InterpreterEnergy {
    type Err = anyhow::Error;

    #[inline(always)]
    fn tick(&mut self) -> Result<(), Self::Err> {
        self.tick_energy(crate::constants::TREE_TRAVERSAL_STEP_COST)
    }
}

impl<'a, BackingStore: trie::BackingStoreLoad> InstanceState<'a, BackingStore> {
    pub fn new(
        current_generation: u32,
        backing_store: BackingStore,
        state: &'a trie::MutableStateInner,
    ) -> InstanceState<'a, BackingStore> {
        Self {
            current_generation,
            backing_store,
            state_trie: state.state.lock().unwrap(),
            iterators: Vec::new(),
            entry_mapping: Vec::new(),
            iterator_roots: std::collections::BTreeMap::new(),
        }
    }

    pub fn lookup_entry(&mut self, key: &[u8]) -> InstanceStateEntryOption {
        if let Some(id) = self.state_trie.get_entry(&mut self.backing_store, key) {
            let idx = self.entry_mapping.len();
            self.entry_mapping.push(Some(EntryWithKey {
                id,
                key: key.into(),
            }));
            InstanceStateEntryOption::new(Some((self.current_generation, idx)))
        } else {
            InstanceStateEntryOption::new(None)
        }
    }

    pub fn create_entry(&mut self, key: &[u8]) -> StateResult<InstanceStateEntry> {
        if let Some(id) = self.state_trie.insert(&mut self.backing_store, key, Vec::new()) {
            let idx = self.entry_mapping.len();
            self.entry_mapping.push(Some(EntryWithKey {
                id:  id.0,
                key: key.into(),
            }));
            Ok(InstanceStateEntry::new(self.current_generation, idx))
        } else {
            bail!("Cannot create entry.")
        }
    }

    pub fn delete_entry(&mut self, entry: InstanceStateEntry) -> StateResult<u32> {
        let (gen, idx) = entry.split();
        ensure!(gen == self.current_generation, "Incorrect entry id generation.");
        let entry = if let Some(entry) = self.entry_mapping.get_mut(idx) {
            if let Some(entry) = std::mem::take(entry) {
                entry
            } else {
                return Ok(0);
            }
        } else {
            return Ok(0);
        };
        if self.state_trie.delete(&mut self.backing_store, &entry.key).is_some() {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    pub fn delete_prefix(
        &mut self,
        energy: &mut InterpreterEnergy,
        key: &[u8],
    ) -> StateResult<u32> {
        if self.state_trie.delete_prefix(&mut self.backing_store, key, energy)? {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    pub fn iterator(&mut self, prefix: &[u8]) -> InstanceStateIteratorResultOption {
        if let Ok(iter) = self.state_trie.iter(&mut self.backing_store, prefix) {
            if let Some(iter) = iter {
                let iter_id = self.iterators.len();
                self.iterators.push(Some(iter));
                self.iterator_roots.insert(iter_id, prefix.to_vec());
                InstanceStateIteratorResultOption::new_ok_some(self.current_generation, iter_id)
            } else {
                InstanceStateIteratorResultOption::NEW_OK_NONE
            }
        } else {
            InstanceStateIteratorResultOption::NEW_ERR
        }
    }

    pub fn iterator_next(
        &mut self,
        iter: InstanceStateIterator,
    ) -> StateResult<InstanceStateEntryOption> {
        let (gen, idx) = iter.split();
        ensure!(gen == self.current_generation, "Incorrect iterator generation.");
        if let Some(iter) = self.iterators.get_mut(idx).and_then(Option::as_mut) {
            if let Some(id) = self.state_trie.next(&mut self.backing_store, iter) {
                let idx = self.entry_mapping.len();
                self.entry_mapping.push(Some(EntryWithKey {
                    id,
                    key: iter.get_key().into(),
                }));
                Ok(InstanceStateEntryOption::new(Some((self.current_generation, idx))))
            } else {
                Ok(InstanceStateEntryOption::new(None))
            }
        } else {
            bail!("Invalid iterator.")
        }
    }

    pub fn iterator_delete(&mut self, iter: InstanceStateIterator) -> StateResult<u32> {
        let (gen, idx) = iter.split();
        ensure!(gen == self.current_generation, "Incorrect iterator generation.");
        match self.iterators.get_mut(idx) {
            Some(iter) => match iter {
                Some(existing_iter) => {
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
            None => Ok(0),
        }
    }

    pub fn iterator_key_size(&mut self, iter: InstanceStateIterator) -> StateResult<u32> {
        let (gen, idx) = iter.split();
        ensure!(gen == self.current_generation, "Incorrect iterator generation.");
        if let Some(iter) = self.iterators.get(idx).and_then(Option::as_ref) {
            Ok(iter.get_key().len() as u32)
        } else {
            bail!("Invalid iterator.")
        }
    }

    pub fn iterator_key_read(
        &mut self,
        iter: InstanceStateIterator,
        dest: &mut [u8],
        offset: u32,
    ) -> StateResult<u32> {
        let (gen, idx) = iter.split();
        ensure!(gen == self.current_generation, "Incorrect iterator generation.");
        if let Some(iter) = self.iterators.get(idx).and_then(Option::as_ref) {
            let key = iter.get_key();
            let offset = offset as usize;
            let num_copied = std::cmp::min(
                key.len().checked_sub(offset).context("Offset is past key.")?,
                dest.len(),
            );
            dest[0..num_copied].copy_from_slice(&key[offset..offset + num_copied]);
            Ok(0)
        } else {
            bail!("Invalid iterator.")
        }
    }

    pub fn entry_read(
        &mut self,
        entry: InstanceStateEntry,
        dest: &mut [u8],
        offset: u32,
    ) -> StateResult<u32> {
        let (gen, idx) = entry.split();
        ensure!(gen == self.current_generation, "Incorrect entry id generation.");
        if let Some(entry) = self.entry_mapping.get(idx).and_then(Option::as_ref) {
            let res = self.state_trie.with_entry(entry.id, &mut self.backing_store, |v| {
                let offset = offset as usize;
                let num_copied = std::cmp::min(v.len().checked_sub(offset)?, dest.len());
                dest[0..num_copied].copy_from_slice(&v[offset..offset + num_copied]);
                Some(num_copied as u32)
            });
            if let Some(res) = res {
                if let Some(res) = res {
                    Ok(res)
                } else {
                    bail!("Offset is past end.");
                }
            } else {
                bail!("Entry does not exist.");
            }
        } else {
            bail!("Invalid entry.");
        }
    }

    pub fn entry_write(
        &mut self,
        entry: InstanceStateEntry,
        src: &[u8],
        offset: u32,
    ) -> StateResult<u32> {
        let (gen, idx) = entry.split();
        ensure!(gen == self.current_generation, "Incorrect entry id generation.");
        if let Some(entry) = self.entry_mapping.get(idx).and_then(Option::as_ref) {
            if let Some(v) = self.state_trie.get_mut(entry.id, &mut self.backing_store) {
                let offset = offset as usize;
                ensure!(offset <= v.len(), "Cannot write past the len.");
                let end = offset.checked_add(src.len()).context("Too much data.")?;
                if v.len() < end {
                    v.resize(end, 0u8);
                }
                (&mut v[offset..end]).write_all(src)?;
                Ok(src.len() as u32)
            } else {
                bail!("Entry does not exist.");
            }
        } else {
            bail!("Invalid entry.");
        }
    }

    pub fn entry_size(&mut self, entry: InstanceStateEntry) -> StateResult<u32> {
        let (gen, idx) = entry.split();
        ensure!(gen == self.current_generation, "Incorrect entry id generation.");
        if let Some(entry) = self.entry_mapping.get(idx).and_then(Option::as_ref) {
            let res =
                self.state_trie.with_entry(entry.id, &mut self.backing_store, |v| v.len() as u32);
            if let Some(res) = res {
                Ok(res)
            } else {
                bail!("Entry does not exist.");
            }
        } else {
            bail!("Invalid entry.");
        }
    }

    pub fn entry_resize(
        &mut self,
        energy: &mut InterpreterEnergy,
        entry: InstanceStateEntry,
        new_size: u32,
    ) -> StateResult<u32> {
        let (gen, idx) = entry.split();
        ensure!(gen == self.current_generation, "Incorrect entry id generation.");
        if let Some(entry) = self.entry_mapping.get(idx).and_then(Option::as_ref) {
            if let Some(v) = self.state_trie.get_mut(entry.id, &mut self.backing_store) {
                let old_size = v.len() as u64;
                let new_size = u64::from(new_size);
                if new_size > old_size {
                    energy
                        .tick_energy(constants::additional_state_size_cost(new_size - old_size))?;
                }
                v.resize(new_size as usize, 0u8);
                Ok(1)
            } else {
                bail!("Entry does not exist.");
            }
        } else {
            bail!("Invalid entry.");
        }
    }

    pub fn entry_key_read(
        &mut self,
        entry: InstanceStateEntry,
        dest: &mut [u8],
        offset: u32,
    ) -> StateResult<u32> {
        let (gen, idx) = entry.split();
        ensure!(gen == self.current_generation, "Incorrect entry id generation.");
        if let Some(entry) = self.entry_mapping.get(idx).and_then(Option::as_ref) {
            let offset = offset as usize;
            let num_copied = std::cmp::min(
                entry.key.len().checked_sub(offset).context("Offset is past key.")?,
                dest.len(),
            );
            dest[0..num_copied].copy_from_slice(&entry.key[offset..offset + num_copied]);
            Ok(num_copied as u32)
        } else {
            bail!("Invalid entry.");
        }
    }

    pub fn entry_key_size(&mut self, entry: InstanceStateEntry) -> StateResult<u32> {
        let (gen, idx) = entry.split();
        ensure!(gen == self.current_generation, "Incorrect entry id generation.");
        if let Some(entry) = self.entry_mapping.get(idx).and_then(Option::as_ref) {
            Ok(entry.key.len() as u32)
        } else {
            bail!("Invalid entry.");
        }
    }
}
