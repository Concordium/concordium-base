use super::{Interrupt, ParameterVec, ReceiveHost};
use crate::{resumption::InterruptedState, type_matches, v0};
use anyhow::bail;
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use concordium_contracts_common::{
    self, AccountAddress, Address, Amount, ChainMetadata, ContractAddress, Cursor, Get, ParseError,
    ParseResult,
};
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

/// Chain context accessible to the init methods.
///
/// TODO: We could optimize this to be initialized lazily
#[derive(Debug, SerdeDeserialize)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary, Clone))]
#[serde(rename_all = "camelCase")]
pub struct InitContext<Policies = v0::OwnedPolicyBytes> {
    pub metadata:        ChainMetadata,
    pub init_origin:     AccountAddress,
    pub sender_policies: Policies,
}

/// Convert from a borrowed variant to the owned one. This clones the slice into
/// a vector.
impl<'a> From<InitContext<v0::PolicyBytes<'a>>> for InitContext<v0::OwnedPolicyBytes> {
    fn from(borrowed: InitContext<v0::PolicyBytes<'a>>) -> Self {
        Self {
            metadata:        borrowed.metadata,
            init_origin:     borrowed.init_origin,
            sender_policies: borrowed.sender_policies.into(),
        }
    }
}

/// Chain context accessible to the receive methods.
///
/// TODO: We could optimize this to be initialized lazily.
#[derive(SerdeDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "fuzz", derive(Arbitrary, Clone))]
pub struct ReceiveContext<Policies = v0::OwnedPolicyBytes> {
    pub metadata:        ChainMetadata,
    pub invoker:         AccountAddress,  //32 bytes
    pub self_address:    ContractAddress, // 16 bytes
    pub self_balance:    Amount,          // 8 bytes
    pub sender:          Address,         // 9 or 33 bytes
    pub owner:           AccountAddress,  // 32 bytes
    pub sender_policies: Policies,
}

/// Convert from a borrowed variant to the owned one. This clones the slice into
/// a vector.
impl<'a> From<ReceiveContext<v0::PolicyBytes<'a>>> for ReceiveContext<v0::OwnedPolicyBytes> {
    fn from(borrowed: ReceiveContext<v0::PolicyBytes<'a>>) -> Self {
        Self {
            metadata:        borrowed.metadata,
            invoker:         borrowed.invoker,
            self_address:    borrowed.self_address,
            self_balance:    borrowed.self_balance,
            sender:          borrowed.sender,
            owner:           borrowed.owner,
            sender_policies: borrowed.sender_policies.into(),
        }
    }
}

impl<Policies> InitContext<Policies> {
    pub fn init_origin(&self) -> &AccountAddress { &self.init_origin }

    /// Get time in milliseconds at the beginning of this block.
    pub fn get_time(&self) -> u64 { self.metadata.slot_time.timestamp_millis() }
}

impl<Policies> ReceiveContext<Policies> {
    pub fn sender(&self) -> &Address { &self.sender }

    /// Who invoked this transaction.
    pub fn invoker(&self) -> &AccountAddress { &self.invoker }

    /// Get time in milliseconds at the beginning of this block.
    pub fn get_time(&self) -> u64 { self.metadata.slot_time.timestamp_millis() }

    /// Who is the owner of this contract.
    pub fn owner(&self) -> &AccountAddress { &self.owner }

    /// Balance on the smart contract when it was invoked.
    pub fn self_balance(&self) -> Amount { self.self_balance }

    /// Address of the smart contract.
    pub fn self_address(&self) -> &ContractAddress { &self.self_address }
}

pub(crate) fn deserial_receive_context(source: &[u8]) -> ParseResult<ReceiveContext<&[u8]>> {
    let mut cursor = Cursor::new(source);
    let metadata = cursor.get()?;
    let invoker = cursor.get()?;
    let self_address = cursor.get()?;
    let self_balance = cursor.get()?;
    let sender = cursor.get()?;
    let owner = cursor.get()?;
    if cursor.offset <= source.len() {
        let sender_policies = &source[cursor.offset..];
        Ok(ReceiveContext {
            metadata,
            invoker,
            self_address,
            self_balance,
            sender,
            owner,
            sender_policies,
        })
    } else {
        Err(ParseError {})
    }
}

pub(crate) fn deserial_init_context(source: &[u8]) -> ParseResult<InitContext<&[u8]>> {
    let mut cursor = Cursor::new(source);
    let metadata = cursor.get()?;
    let init_origin = cursor.get()?;
    if cursor.offset <= source.len() {
        let sender_policies = &source[cursor.offset..];
        Ok(InitContext {
            metadata,
            init_origin,
            sender_policies,
        })
    } else {
        Err(ParseError {})
    }
}

pub type ReturnValue = Vec<u8>;

#[derive(Debug)]
pub enum InitResult {
    Success {
        state:            v0::State,
        logs:             v0::Logs,
        return_value:     ReturnValue,
        remaining_energy: u64,
    },
    Reject {
        reason:           i32,
        return_value:     ReturnValue,
        remaining_energy: u64,
    },
    OutOfEnergy,
}

impl InitResult {
    /// Extract the
    #[cfg(feature = "enable-ffi")]
    pub(crate) fn extract(self) -> (Vec<u8>, Option<ReturnValue>) {
        match self {
            InitResult::OutOfEnergy => (vec![0], None),
            InitResult::Reject {
                reason,
                return_value,
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(13);
                out.push(1);
                out.extend_from_slice(&reason.to_be_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                (out, Some(return_value))
            }
            InitResult::Success {
                state,
                logs,
                return_value,
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(5 + state.len() as usize + 8);
                out.push(2);
                out.extend_from_slice(&(state.len() as u32).to_be_bytes());
                out.extend_from_slice(&state.state);
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                (out, Some(return_value))
            }
        }
    }
}

/// State of the suspedned execution of the receive function.
/// This retains both the module that is executed, as well the host.
pub type ReceiveInterruptedState<R> = InterruptedState<
    ProcessedImports,
    R,
    ReceiveHost<ParameterVec, ReceiveContext<v0::OwnedPolicyBytes>>,
>;

#[derive(Debug)]
pub enum ReceiveResult<R> {
    Success {
        state:            v0::State,
        logs:             v0::Logs,
        return_value:     ReturnValue,
        remaining_energy: u64,
    },
    Interrupt {
        remaining_energy: u64,
        config:           Box<ReceiveInterruptedState<R>>,
        interrupt:        Interrupt,
    },
    Reject {
        reason:           i32,
        return_value:     ReturnValue,
        remaining_energy: u64,
    },
    OutOfEnergy,
}

impl<R> ReceiveResult<R> {
    pub(crate) fn extract(
        self,
    ) -> (Vec<u8>, Option<Box<ReceiveInterruptedState<R>>>, Option<ReturnValue>) {
        use ReceiveResult::*;
        match self {
            OutOfEnergy => (vec![0], None, None),
            Reject {
                reason,
                return_value,
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(13);
                out.push(1);
                out.extend_from_slice(&reason.to_be_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                (out, None, Some(return_value))
            }
            Success {
                state,
                logs,
                return_value,
                remaining_energy,
            } => {
                let mut out = vec![2];
                let state = &state.state;
                out.extend_from_slice(&(state.len() as u32).to_be_bytes());
                out.extend_from_slice(&state);
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                (out, None, Some(return_value))
            }
            Interrupt {
                remaining_energy,
                config,
                interrupt,
            } => {
                let mut out = vec![3];
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                let state = config.host.state.as_ref();
                out.extend_from_slice(&(state.len() as u32).to_be_bytes());
                out.extend_from_slice(&state);
                interrupt.to_bytes(&mut out).expect("Serialization to a vector never fails.");
                (out, Some(config), None)
            }
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum CommonFunc {
    GetParameterSize,
    GetParameterSection,
    GetPolicySection,
    LogEvent,
    LoadState,
    WriteState,
    ResizeState,
    StateSize,
    GetSlotTime,
    WriteOutput,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum InitOnlyFunc {
    GetInitOrigin,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
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
    /// Chage for execution cost.
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
            8 => Ok(ImportFunc::Common(CommonFunc::LoadState)),
            9 => Ok(ImportFunc::Common(CommonFunc::WriteState)),
            10 => Ok(ImportFunc::Common(CommonFunc::ResizeState)),
            11 => Ok(ImportFunc::Common(CommonFunc::StateSize)),
            12 => Ok(ImportFunc::Common(CommonFunc::GetSlotTime)),
            13 => Ok(ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin)),
            19 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveInvoker)),
            20 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfAddress)),
            21 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfBalance)),
            22 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSender)),
            23 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveOwner)),
            24 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Invoke)),
            25 => Ok(ImportFunc::Common(CommonFunc::WriteOutput)),
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
                CommonFunc::LoadState => 8,
                CommonFunc::WriteState => 9,
                CommonFunc::ResizeState => 10,
                CommonFunc::StateSize => 11,
                CommonFunc::GetSlotTime => 12,
                CommonFunc::WriteOutput => 25,
            },
            ImportFunc::InitOnly(io) => match io {
                InitOnlyFunc::GetInitOrigin => 13,
            },
            ImportFunc::ReceiveOnly(ro) => match ro {
                ReceiveOnlyFunc::Invoke => 24,
                ReceiveOnlyFunc::GetReceiveInvoker => 19,
                ReceiveOnlyFunc::GetReceiveSelfAddress => 20,
                ReceiveOnlyFunc::GetReceiveSelfBalance => 21,
                ReceiveOnlyFunc::GetReceiveSender => 22,
                ReceiveOnlyFunc::GetReceiveOwner => 23,
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

// TODO: Log event could just be another invoke.

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
                "load_state" => type_matches!(ty => [I32, I32, I32]; I32),
                "write_state" => type_matches!(ty => [I32, I32, I32]; I32),
                "resize_state" => type_matches!(ty => [I32]; I32),
                "state_size" => type_matches!(ty => []; I32),
                "get_init_origin" => type_matches!(ty => [I32]),
                "get_receive_invoker" => type_matches!(ty => [I32]),
                "get_receive_self_address" => type_matches!(ty => [I32]),
                "get_receive_self_balance" => type_matches!(ty => []; I64),
                "get_receive_sender" => type_matches!(ty => [I32]),
                "get_receive_owner" => type_matches!(ty => [I32]),
                "get_slot_time" => type_matches!(ty => []; I64),
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
        let correct_type =
            ty.parameters.as_slice() == [ValueType::I64] && ty.result == Some(ValueType::I32);
        valid_name
            && correct_type
            && if item_name.as_ref().starts_with("init_") {
                !item_name.as_ref().contains('.')
            } else {
                item_name.as_ref().contains('.')
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
                "load_state" => ImportFunc::Common(CommonFunc::LoadState),
                "write_state" => ImportFunc::Common(CommonFunc::WriteState),
                "resize_state" => ImportFunc::Common(CommonFunc::ResizeState),
                "state_size" => ImportFunc::Common(CommonFunc::StateSize),
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
