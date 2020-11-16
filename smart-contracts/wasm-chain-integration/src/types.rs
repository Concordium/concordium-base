use crate::*;
use anyhow::bail;
use wasm_transform::{
    artifact::TryFromImport,
    output::Output,
    parse::{Byte, GetParseable, Parseable},
    types::{FunctionType, Import},
};

pub enum InitResult {
    Success {
        state:            State,
        logs:             Logs,
        remaining_energy: u64,
    },
    Reject {
        remaining_energy: u64,
    },
    OutOfEnergy,
}

impl InitResult {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            InitResult::OutOfEnergy => vec![0],
            InitResult::Reject {
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(9);
                out.push(1);
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                out
            }
            InitResult::Success {
                state,
                logs,
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(5 + state.len() as usize + 8);
                out.push(2);
                out.extend_from_slice(&(state.len() as u32).to_be_bytes());
                out.extend_from_slice(&state.state);
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                out
            }
        }
    }
}

#[derive(Clone)]
pub enum Action {
    Send {
        to_addr:   ContractAddress,
        name:      Vec<u8>,
        amount:    u64,
        parameter: Vec<u8>,
    },
    SimpleTransfer {
        to_addr: AccountAddress,
        amount:  u64,
    },
    And {
        l: u32,
        r: u32,
    },
    Or {
        l: u32,
        r: u32,
    },
    Accept,
}

/// This is not implementing serialize because that is currently set-up for
/// little-endian only, and we need big-endian for interoperability with the
/// rest of the system.
impl Action {
    pub fn to_bytes(&self) -> Vec<u8> {
        use Action::*;
        match self {
            Send {
                to_addr,
                name,
                amount,
                parameter,
            } => {
                let mut out = Vec::with_capacity(1 + 8 + 8 + name.len() + 4 + parameter.len() + 4);
                out.push(0);
                out.extend_from_slice(&to_addr.index.to_be_bytes());
                out.extend_from_slice(&to_addr.subindex.to_be_bytes());
                out.extend_from_slice(&(name.len() as u32).to_be_bytes());
                out.extend_from_slice(&name);
                out.extend_from_slice(&amount.to_be_bytes());
                out.extend_from_slice(&(parameter.len() as u32).to_be_bytes());
                out.extend_from_slice(&parameter);
                out
            }
            SimpleTransfer {
                to_addr,
                amount,
            } => {
                let mut out = Vec::with_capacity(1 + 32 + 8);
                out.push(1);
                out.extend_from_slice(&to_addr.0);
                out.extend_from_slice(&amount.to_be_bytes());
                out
            }
            Or {
                l,
                r,
            } => {
                let mut out = Vec::with_capacity(9);
                out.push(2);
                out.extend_from_slice(&l.to_be_bytes());
                out.extend_from_slice(&r.to_be_bytes());
                out
            }
            And {
                l,
                r,
            } => {
                let mut out = Vec::with_capacity(9);
                out.push(3);
                out.extend_from_slice(&l.to_be_bytes());
                out.extend_from_slice(&r.to_be_bytes());
                out
            }
            Accept => vec![4],
        }
    }
}

pub enum ReceiveResult {
    Success {
        state:            State,
        logs:             Logs,
        actions:          Vec<Action>,
        remaining_energy: u64,
    },
    Reject {
        remaining_energy: u64,
    },
    OutOfEnergy,
}

impl ReceiveResult {
    pub fn to_bytes(&self) -> Vec<u8> {
        use ReceiveResult::*;
        match self {
            OutOfEnergy => vec![0],
            Reject {
                remaining_energy,
            } => {
                let mut out = Vec::with_capacity(9);
                out.push(1);
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                out
            }
            Success {
                state,
                logs,
                actions,
                remaining_energy,
            } => {
                let mut out = vec![2];
                let state = &state.state;
                out.extend_from_slice(&(state.len() as u32).to_be_bytes());
                out.extend_from_slice(&state);
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&(actions.len() as u32).to_be_bytes());
                for a in actions.iter() {
                    out.extend_from_slice(&a.to_bytes());
                }
                out.extend_from_slice(&remaining_energy.to_be_bytes());
                out
            }
        }
    }
}

pub enum Which<'a> {
    Init {
        init_ctx: &'a InitContext,
    },
    Receive {
        receive_ctx:   &'a ReceiveContext,
        current_state: &'a [u8],
    },
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum CommonFunc {
    GetParameterSize,
    GetParameterSection,
    LogEvent,
    LoadState,
    WriteState,
    ResizeState,
    StateSize,
    GetSlotNumber,
    GetSlotTime,
    GetBlockHeight,
    GetFinalizedHeight,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum InitOnlyFunc {
    GetInitOrigin,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum ReceiveOnlyFunc {
    Accept,
    SimpleTransfer,
    Send,
    CombineAnd,
    CombineOr,
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
    /// Charge for additional stack usage.
    ChargeStackSize,
    /// Charge for allocating the given amount of pages.
    ChargeMemoryAlloc,
    /// Functions that are common to both init and receive methods.
    Common(CommonFunc),
    /// Functions that can only be called by init methods.
    InitOnly(InitOnlyFunc),
    /// Functions that can only be called by receive methods.
    ReceiveOnly(ReceiveOnlyFunc),
}

impl<'a> Parseable<'a> for ImportFunc {
    fn parse(cursor: &mut std::io::Cursor<&'a [u8]>) -> wasm_transform::parse::ParseResult<Self> {
        match Byte::parse(cursor)? {
            0 => Ok(ImportFunc::ChargeEnergy),
            1 => Ok(ImportFunc::ChargeStackSize),
            2 => Ok(ImportFunc::ChargeMemoryAlloc),
            3 => Ok(ImportFunc::Common(CommonFunc::GetParameterSize)),
            4 => Ok(ImportFunc::Common(CommonFunc::GetParameterSection)),
            5 => Ok(ImportFunc::Common(CommonFunc::LogEvent)),
            6 => Ok(ImportFunc::Common(CommonFunc::LoadState)),
            7 => Ok(ImportFunc::Common(CommonFunc::WriteState)),
            8 => Ok(ImportFunc::Common(CommonFunc::ResizeState)),
            9 => Ok(ImportFunc::Common(CommonFunc::StateSize)),
            10 => Ok(ImportFunc::Common(CommonFunc::GetSlotNumber)),
            11 => Ok(ImportFunc::Common(CommonFunc::GetSlotTime)),
            12 => Ok(ImportFunc::Common(CommonFunc::GetBlockHeight)),
            13 => Ok(ImportFunc::Common(CommonFunc::GetFinalizedHeight)),
            14 => Ok(ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin)),
            15 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Accept)),
            16 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::SimpleTransfer)),
            17 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Send)),
            18 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::CombineAnd)),
            19 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::CombineOr)),
            20 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveInvoker)),
            21 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfAddress)),
            22 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSelfBalance)),
            23 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveSender)),
            24 => Ok(ImportFunc::ReceiveOnly(ReceiveOnlyFunc::GetReceiveOwner)),
            tag => bail!("Unexpected ImportFunc tag {}.", tag),
        }
    }
}

impl Output for ImportFunc {
    fn output(&self, out: &mut impl std::io::Write) -> wasm_transform::output::OutResult<()> {
        let tag: u8 = match self {
            ImportFunc::ChargeEnergy => 0,
            ImportFunc::ChargeStackSize => 1,
            ImportFunc::ChargeMemoryAlloc => 2,
            ImportFunc::Common(c) => match c {
                CommonFunc::GetParameterSize => 3,
                CommonFunc::GetParameterSection => 4,
                CommonFunc::LogEvent => 5,
                CommonFunc::LoadState => 6,
                CommonFunc::WriteState => 7,
                CommonFunc::ResizeState => 8,
                CommonFunc::StateSize => 9,
                CommonFunc::GetSlotNumber => 10,
                CommonFunc::GetSlotTime => 11,
                CommonFunc::GetBlockHeight => 12,
                CommonFunc::GetFinalizedHeight => 13,
            },
            ImportFunc::InitOnly(io) => match io {
                InitOnlyFunc::GetInitOrigin => 14,
            },
            ImportFunc::ReceiveOnly(ro) => match ro {
                ReceiveOnlyFunc::Accept => 15,
                ReceiveOnlyFunc::SimpleTransfer => 16,
                ReceiveOnlyFunc::Send => 17,
                ReceiveOnlyFunc::CombineAnd => 18,
                ReceiveOnlyFunc::CombineOr => 19,
                ReceiveOnlyFunc::GetReceiveInvoker => 20,
                ReceiveOnlyFunc::GetReceiveSelfAddress => 21,
                ReceiveOnlyFunc::GetReceiveSelfBalance => 22,
                ReceiveOnlyFunc::GetReceiveSender => 23,
                ReceiveOnlyFunc::GetReceiveOwner => 24,
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

impl<'a> Parseable<'a> for ProcessedImports {
    fn parse(cursor: &mut std::io::Cursor<&'a [u8]>) -> wasm_transform::parse::ParseResult<Self> {
        let tag = cursor.next()?;
        let ty = cursor.next()?;
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

impl TryFromImport for ProcessedImports {
    fn try_from_import(
        ctx: &[FunctionType],
        import: Import,
    ) -> wasm_transform::artifact::CompileResult<Self> {
        let m = &import.mod_name;
        let tag = if m.name == "concordium_metering" {
            match import.item_name.name.as_ref() {
                "account_energy" => ImportFunc::ChargeEnergy,
                "account_stack" => ImportFunc::ChargeStackSize,
                "account_memory" => ImportFunc::ChargeMemoryAlloc,
                name => bail!("Unsupported import {}.", name),
            }
        } else if m.name == "concordium" {
            match import.item_name.name.as_ref() {
                "accept" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Accept),
                "simple_transfer" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::SimpleTransfer),
                "send" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::Send),
                "combine_and" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::CombineAnd),
                "combine_or" => ImportFunc::ReceiveOnly(ReceiveOnlyFunc::CombineOr),
                "get_parameter_size" => ImportFunc::Common(CommonFunc::GetParameterSize),
                "get_parameter_section" => ImportFunc::Common(CommonFunc::GetParameterSection),
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
                "get_slot_number" => ImportFunc::Common(CommonFunc::GetSlotNumber),
                "get_block_height" => ImportFunc::Common(CommonFunc::GetBlockHeight),
                "get_finalized_height" => ImportFunc::Common(CommonFunc::GetFinalizedHeight),
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
                .ok_or_else(|| anyhow!("Unknown type, this should not happen."))?
                .clone(),
        };
        Ok(Self {
            tag,
            ty,
        })
    }

    fn ty(&self) -> &FunctionType { &self.ty }
}
