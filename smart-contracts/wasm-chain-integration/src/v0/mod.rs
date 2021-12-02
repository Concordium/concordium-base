#[cfg(feature = "enable-ffi")]
mod ffi;
mod types;

use crate::{constants, ExecResult, InterpreterEnergy, OutOfEnergy};
use anyhow::{anyhow, bail, ensure};
use concordium_contracts_common::*;
use machine::Value;
use std::{collections::LinkedList, convert::TryInto, io::Write};
pub use types::*;
use wasm_transform::{
    artifact::{Artifact, RunnableCode},
    machine::{self, ExecutionOutcome, NoInterrupt},
    utils,
};

impl Logs {
    pub fn new() -> Self {
        Self {
            logs: LinkedList::new(),
        }
    }

    /// The return value is
    ///
    /// - 0 if data was not logged because it would exceed maximum number of
    ///   logs
    /// - 1 if data was logged.
    pub fn log_event(&mut self, event: Vec<u8>) -> i32 {
        let cur_len = self.logs.len();
        if cur_len < constants::MAX_NUM_LOGS {
            self.logs.push_back(event);
            1
        } else {
            0
        }
    }

    pub fn iterate(&self) -> impl Iterator<Item = &Vec<u8>> { self.logs.iter() }

    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.logs.len();
        let mut out = Vec::with_capacity(4 * len + 4);
        out.extend_from_slice(&(len as u32).to_be_bytes());
        for v in self.iterate() {
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(v);
        }
        out
    }
}

#[derive(Clone, Default)]
/// The Default instance of this type constructs an empty list of outcomes.
pub struct Outcome {
    pub cur_state: Vec<Action>,
}

impl Outcome {
    pub fn new() -> Outcome { Self::default() }

    pub fn accept(&mut self) -> u32 {
        let response = self.cur_state.len();
        self.cur_state.push(Action::Accept);
        response as u32
    }

    pub fn simple_transfer(&mut self, bytes: &[u8], amount: u64) -> ExecResult<u32> {
        let response = self.cur_state.len();
        let addr: [u8; 32] = bytes.try_into()?;
        let to_addr = AccountAddress(addr);
        let data = std::rc::Rc::new(SimpleTransferAction {
            to_addr,
            amount,
        });
        self.cur_state.push(Action::SimpleTransfer {
            data,
        });
        Ok(response as u32)
    }

    pub fn send(
        &mut self,
        addr_index: u64,
        addr_subindex: u64,
        receive_name_bytes: &[u8],
        amount: u64,
        parameter_bytes: &[u8],
    ) -> ExecResult<u32> {
        let response = self.cur_state.len();

        let name_str = std::str::from_utf8(receive_name_bytes)?;
        ensure!(ReceiveName::is_valid_receive_name(name_str).is_ok(), "Not a valid receive name.");
        let name = receive_name_bytes.to_vec();

        ensure!(
            parameter_bytes.len() <= constants::MAX_PARAMETER_SIZE,
            "Parameter exceeds max size."
        );

        let parameter = parameter_bytes.to_vec();

        let to_addr = ContractAddress {
            index:    addr_index,
            subindex: addr_subindex,
        };
        let data = std::rc::Rc::new(SendAction {
            to_addr,
            name,
            amount,
            parameter,
        });
        self.cur_state.push(Action::Send {
            data,
        });
        Ok(response as u32)
    }

    pub fn combine_and(&mut self, l: u32, r: u32) -> ExecResult<u32> {
        let response = self.cur_state.len() as u32;
        ensure!(l < response && r < response, "Combining unknown actions.");
        self.cur_state.push(Action::And {
            l,
            r,
        });
        Ok(response)
    }

    pub fn combine_or(&mut self, l: u32, r: u32) -> ExecResult<u32> {
        let response = self.cur_state.len() as u32;
        ensure!(l < response && r < response, "Combining unknown actions.");
        self.cur_state.push(Action::Or {
            l,
            r,
        });
        Ok(response)
    }
}

impl State {
    pub fn is_empty(&self) -> bool { self.state.is_empty() }

    // FIXME: This should not be copying so much data around, but for POC it is
    // fine. We should probably do some sort of copy-on-write here in the near term,
    // and in the long term we need to keep track of which parts were written.
    pub fn new(st: Option<&[u8]>) -> Self {
        match st {
            None => Self {
                state: Vec::new(),
            },
            Some(bytes) => Self {
                state: Vec::from(bytes),
            },
        }
    }

    pub fn len(&self) -> u32 { self.state.len() as u32 }

    pub fn write_state(&mut self, offset: u32, bytes: &[u8]) -> ExecResult<u32> {
        let length = bytes.len();
        ensure!(offset <= self.len(), "Cannot write past the offset.");
        let offset = offset as usize;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow!("Writing past the end of memory."))? as usize;
        let end = std::cmp::min(end, constants::MAX_CONTRACT_STATE as usize) as u32;
        if self.len() < end {
            self.state.resize(end as usize, 0u8);
        }
        let written = (&mut self.state[offset..end as usize]).write(bytes)?;
        Ok(written as u32)
    }

    pub fn load_state(&self, offset: u32, mut bytes: &mut [u8]) -> ExecResult<u32> {
        let offset = offset as usize;
        ensure!(offset <= self.state.len());
        // Write on slices overwrites the buffer and returns how many bytes were
        // written.
        let amt = bytes.write(&self.state[offset..])?;
        Ok(amt as u32)
    }

    pub fn resize_state(&mut self, new_size: u32) -> u32 {
        if new_size > constants::MAX_CONTRACT_STATE {
            0
        } else {
            self.state.resize(new_size as usize, 0u8);
            1
        }
    }
}

pub struct InitHost<ParamType, Ctx> {
    /// Remaining energy for execution.
    pub energy:            InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs:              Logs,
    /// The contract's state.
    pub state:             State,
    /// The parameter to the init method.
    pub param:             ParamType,
    /// The init context for this invocation.
    pub init_ctx:          Ctx,
}

pub struct ReceiveHost<ParamType, Ctx> {
    /// Remaining energy for execution.
    pub energy:            InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs:              Logs,
    /// The contract's state.
    pub state:             State,
    /// The parameter to the receive method.
    pub param:             ParamType,
    /// Outcomes of the execution, i.e., the actions tree.
    pub outcomes:          Outcome,
    /// The receive context for this call.
    pub receive_ctx:       Ctx,
}

pub trait HasCommon {
    type MetadataType: HasChainMetadata;
    type PolicyBytesType: AsRef<[u8]>;
    type PolicyType: SerialPolicies<Self::PolicyBytesType>;

    fn energy(&mut self) -> &mut InterpreterEnergy;
    fn logs(&mut self) -> &mut Logs;
    fn state(&mut self) -> &mut State;
    fn param(&self) -> &[u8];
    fn policies(&self) -> ExecResult<&Self::PolicyType>;
    fn metadata(&self) -> &Self::MetadataType;
}

impl<ParamType: AsRef<[u8]>, Ctx: HasInitContext> HasCommon for InitHost<ParamType, Ctx> {
    type MetadataType = Ctx::MetadataType;
    type PolicyBytesType = Ctx::PolicyBytesType;
    type PolicyType = Ctx::PolicyType;

    fn energy(&mut self) -> &mut InterpreterEnergy { &mut self.energy }

    fn logs(&mut self) -> &mut Logs { &mut self.logs }

    fn state(&mut self) -> &mut State { &mut self.state }

    fn param(&self) -> &[u8] { self.param.as_ref() }

    fn metadata(&self) -> &Self::MetadataType { self.init_ctx.metadata() }

    fn policies(&self) -> ExecResult<&Self::PolicyType> { self.init_ctx.sender_policies() }
}

impl<ParamType: AsRef<[u8]>, Ctx: HasReceiveContext> HasCommon for ReceiveHost<ParamType, Ctx> {
    type MetadataType = Ctx::MetadataType;
    type PolicyBytesType = Ctx::PolicyBytesType;
    type PolicyType = Ctx::PolicyType;

    fn energy(&mut self) -> &mut InterpreterEnergy { &mut self.energy }

    fn logs(&mut self) -> &mut Logs { &mut self.logs }

    fn state(&mut self) -> &mut State { &mut self.state }

    fn param(&self) -> &[u8] { self.param.as_ref() }

    fn metadata(&self) -> &Self::MetadataType { self.receive_ctx.metadata() }

    fn policies(&self) -> ExecResult<&Self::PolicyType> { self.receive_ctx.sender_policies() }
}

/// Types which can act as init contexts.
///
/// Used to enable partial JSON contexts when simulating contracts with
/// cargo-concordium.
///
/// We have two implementations:
///  - `InitContext`, which is used on-chain and always returns `Ok(..)`.
///  - `InitContextOpt`, which is used during simulation with cargo-concordium
///    and returns `Ok(..)` for fields supplied in a JSON context, and `Err(..)`
///    otherwise.
pub trait HasInitContext {
    type MetadataType: HasChainMetadata;
    type PolicyBytesType: AsRef<[u8]>;
    type PolicyType: SerialPolicies<Self::PolicyBytesType>;

    fn metadata(&self) -> &Self::MetadataType;
    fn init_origin(&self) -> ExecResult<&AccountAddress>;
    fn sender_policies(&self) -> ExecResult<&Self::PolicyType>;
}

/// Generic implementation for all references to types that already implement
/// HasInitContext. This allows using InitContext as well as &InitContext in the
/// init host, depending on whether we want to transfer ownership of the context
/// or not.
impl<'a, X: HasInitContext> HasInitContext for &'a X {
    type MetadataType = X::MetadataType;
    type PolicyBytesType = X::PolicyBytesType;
    type PolicyType = X::PolicyType;

    fn metadata(&self) -> &Self::MetadataType { (*self).metadata() }

    fn init_origin(&self) -> ExecResult<&AccountAddress> { (*self).init_origin() }

    fn sender_policies(&self) -> ExecResult<&Self::PolicyType> { (*self).sender_policies() }
}

impl HasInitContext for InitContext<Vec<OwnedPolicy>> {
    type MetadataType = ChainMetadata;
    type PolicyBytesType = Vec<u8>;
    type PolicyType = Vec<OwnedPolicy>;

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn init_origin(&self) -> ExecResult<&AccountAddress> { Ok(&self.init_origin) }

    fn sender_policies(&self) -> ExecResult<&Self::PolicyType> { Ok(&self.sender_policies) }
}

impl<'a> HasInitContext for InitContext<&'a [u8]> {
    type MetadataType = ChainMetadata;
    type PolicyBytesType = &'a [u8];
    type PolicyType = &'a [u8];

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn init_origin(&self) -> ExecResult<&AccountAddress> { Ok(&self.init_origin) }

    fn sender_policies(&self) -> ExecResult<&Self::PolicyType> { Ok(&self.sender_policies) }
}

/// Types which can act as receive contexts.
///
/// Used to enable partial JSON contexts when simulating contracts with
/// cargo-concordium.
///
/// We have two implementations:
///  - `ReceiveContext`, which is used on-chain and always returns `Ok(..)`.
///  - `ReceiveContextOpt`, which is used during simulation with
///    cargo-concordium and returns `Ok(..)` for fields supplied in a JSON
///    context, and `Err(..)` otherwise.
pub trait HasReceiveContext {
    type MetadataType: HasChainMetadata;
    type PolicyBytesType: AsRef<[u8]>;
    type PolicyType: SerialPolicies<Self::PolicyBytesType>;

    fn metadata(&self) -> &Self::MetadataType;
    fn invoker(&self) -> ExecResult<&AccountAddress>;
    fn self_address(&self) -> ExecResult<&ContractAddress>;
    fn self_balance(&self) -> ExecResult<Amount>;
    fn sender(&self) -> ExecResult<&Address>;
    fn owner(&self) -> ExecResult<&AccountAddress>;
    fn sender_policies(&self) -> ExecResult<&Self::PolicyType>;
}

/// Generic implementation for all references to types that already implement
/// HasReceiveContext. This allows using ReceiveContext as well as
/// &ReceiveContext in the receive host, depending on whether we want to
/// transfer ownership of the context or not.
impl<'a, X: HasReceiveContext> HasReceiveContext for &'a X {
    type MetadataType = X::MetadataType;
    type PolicyBytesType = X::PolicyBytesType;
    type PolicyType = X::PolicyType;

    fn metadata(&self) -> &Self::MetadataType { (*self).metadata() }

    fn invoker(&self) -> ExecResult<&AccountAddress> { (*self).invoker() }

    fn self_address(&self) -> ExecResult<&ContractAddress> { (*self).self_address() }

    fn self_balance(&self) -> ExecResult<Amount> { (*self).self_balance() }

    fn sender(&self) -> ExecResult<&Address> { (*self).sender() }

    fn owner(&self) -> ExecResult<&AccountAddress> { (*self).owner() }

    fn sender_policies(&self) -> ExecResult<&Self::PolicyType> { (*self).sender_policies() }
}

impl HasReceiveContext for ReceiveContext<Vec<OwnedPolicy>> {
    type MetadataType = ChainMetadata;
    type PolicyBytesType = Vec<u8>;
    type PolicyType = Vec<OwnedPolicy>;

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn invoker(&self) -> ExecResult<&AccountAddress> { Ok(&self.invoker) }

    fn self_address(&self) -> ExecResult<&ContractAddress> { Ok(&self.self_address) }

    fn self_balance(&self) -> ExecResult<Amount> { Ok(self.self_balance) }

    fn sender(&self) -> ExecResult<&Address> { Ok(&self.sender) }

    fn owner(&self) -> ExecResult<&AccountAddress> { Ok(&self.owner) }

    fn sender_policies(&self) -> ExecResult<&Self::PolicyType> { Ok(&self.sender_policies) }
}

impl<'a> HasReceiveContext for ReceiveContext<&'a [u8]> {
    type MetadataType = ChainMetadata;
    type PolicyBytesType = &'a [u8];
    type PolicyType = &'a [u8];

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn invoker(&self) -> ExecResult<&AccountAddress> { Ok(&self.invoker) }

    fn self_address(&self) -> ExecResult<&ContractAddress> { Ok(&self.self_address) }

    fn self_balance(&self) -> ExecResult<Amount> { Ok(self.self_balance) }

    fn sender(&self) -> ExecResult<&Address> { Ok(&self.sender) }

    fn owner(&self) -> ExecResult<&AccountAddress> { Ok(&self.owner) }

    fn sender_policies(&self) -> ExecResult<&Self::PolicyType> { Ok(&self.sender_policies) }
}

pub trait HasChainMetadata {
    fn slot_time(&self) -> ExecResult<SlotTime>;
}

impl HasChainMetadata for ChainMetadata {
    fn slot_time(&self) -> ExecResult<SlotTime> { Ok(self.slot_time) }
}

fn call_common<C: HasCommon>(
    host: &mut C,
    f: CommonFunc,
    memory: &mut Vec<u8>,
    stack: &mut machine::RuntimeStack,
) -> machine::RunResult<()> {
    match f {
        CommonFunc::GetParameterSize => {
            // the cost of this function is adequately reflected by the base cost of a
            // function call so we do not charge extra.
            stack.push_value(host.param().len() as u32);
        }
        CommonFunc::GetParameterSection => {
            let offset = unsafe { stack.pop_u32() } as usize;
            let length = unsafe { stack.pop_u32() };
            let start = unsafe { stack.pop_u32() } as usize;
            // charge energy linearly in the amount of data written.
            host.energy().tick_energy(constants::copy_from_host_cost(length))?;
            let write_end = start + length as usize; // this cannot overflow on 64-bit machines.
            ensure!(write_end <= memory.len(), "Illegal memory access.");
            let end = std::cmp::min(offset + length as usize, host.param().len());
            ensure!(offset <= end, "Attempting to read non-existent parameter.");
            let amt = (&mut memory[start..write_end]).write(&host.param()[offset..end])?;
            stack.push_value(amt as u32);
        }
        CommonFunc::GetPolicySection => {
            let offset = unsafe { stack.pop_u32() } as usize;
            let length = unsafe { stack.pop_u32() };
            // charge energy linearly in the amount of data written.
            host.energy().tick_energy(constants::copy_from_host_cost(length))?;
            let start = unsafe { stack.pop_u32() } as usize;
            let write_end = start + length as usize; // this cannot overflow on 64-bit machines.
            ensure!(write_end <= memory.len(), "Illegal memory access.");
            let policies = host.policies()?.policies_to_bytes();
            let policies_bytes = policies.as_ref();
            let end = std::cmp::min(offset + length as usize, policies_bytes.len());
            ensure!(offset <= end, "Attempting to read non-existent policy.");
            let amt = (&mut memory[start..write_end]).write(&policies_bytes[offset..end])?;
            stack.push_value(amt as u32);
        }
        CommonFunc::LogEvent => {
            let length = unsafe { stack.pop_u32() };
            let start = unsafe { stack.pop_u32() } as usize;
            let end = start + length as usize;
            ensure!(end <= memory.len(), "Illegal memory access.");
            if length <= constants::MAX_LOG_SIZE {
                // only charge if we actually log something.
                host.energy().tick_energy(constants::log_event_cost(length))?;
                stack.push_value(host.logs().log_event(memory[start..end].to_vec()))
            } else {
                // otherwise the cost is adequately reflected by just the cost of a function
                // call.
                stack.push_value(-1i32)
            }
        }
        CommonFunc::LoadState => {
            let offset = unsafe { stack.pop_u32() };
            let length = unsafe { stack.pop_u32() };
            let start = unsafe { stack.pop_u32() } as usize;
            // charge energy linearly in the amount of data written.
            host.energy().tick_energy(constants::copy_from_host_cost(length))?;
            let end = start + length as usize; // this cannot overflow on 64-bit machines.
            ensure!(end <= memory.len(), "Illegal memory access.");
            let res = host.state().load_state(offset, &mut memory[start..end])?;
            stack.push_value(res);
        }
        CommonFunc::WriteState => {
            let offset = unsafe { stack.pop_u32() };
            let length = unsafe { stack.pop_u32() };
            let start = unsafe { stack.pop_u32() } as usize;
            // charge energy linearly in the amount of data written.
            host.energy().tick_energy(constants::copy_to_host_cost(length))?;
            let end = start + length as usize; // this cannot overflow on 64-bit machines.
            ensure!(end <= memory.len(), "Illegal memory access.");
            let res = host.state().write_state(offset, &memory[start..end])?;
            stack.push_value(res);
        }
        CommonFunc::ResizeState => {
            let new_size = stack.pop();
            let new_size = unsafe { new_size.short } as u32;
            let old_size = host.state().len();
            if new_size > old_size {
                // resizing is very similar to writing 0 to the newly allocated parts,
                // but since we don't have to read anything we charge it more cheaply.
                host.energy()
                    .tick_energy(constants::additional_state_size_cost(new_size - old_size))?;
            }
            stack.push_value(host.state().resize_state(new_size));
        }
        CommonFunc::StateSize => {
            // the cost of this function is adequately reflected by the base cost of a
            // function call so we do not charge extra.
            stack.push_value(host.state().len());
        }
        CommonFunc::GetSlotTime => {
            // the cost of this function is adequately reflected by the base cost of a
            // function call so we do not charge extra.
            stack.push_value(host.metadata().slot_time()?.timestamp_millis());
        }
    }
    Ok(())
}

impl<ParamType: AsRef<[u8]>, Ctx: HasInitContext> machine::Host<ProcessedImports>
    for InitHost<ParamType, Ctx>
{
    type Interrupt = NoInterrupt;

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn tick_initial_memory(&mut self, num_pages: u32) -> machine::RunResult<()> {
        self.energy.charge_memory_alloc(num_pages)
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    fn call(
        &mut self,
        f: &ProcessedImports,
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<Option<NoInterrupt>> {
        match f.tag {
            ImportFunc::ChargeEnergy => {
                self.energy.tick_energy(unsafe { stack.pop_u64() })?;
            }
            ImportFunc::TrackCall => {
                if let Some(fr) = self.activation_frames.checked_sub(1) {
                    self.activation_frames = fr
                } else {
                    bail!("Too many nested functions.")
                }
            }
            ImportFunc::TrackReturn => self.activation_frames += 1,
            ImportFunc::ChargeMemoryAlloc => {
                self.energy.charge_memory_alloc(unsafe { stack.peek_u32() })?;
            }
            ImportFunc::Common(cf) => call_common(self, cf, memory, stack)?,
            ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin) => {
                let start = unsafe { stack.pop_u32() } as usize;
                ensure!(start + 32 <= memory.len(), "Illegal memory access for init origin.");
                (&mut memory[start..start + 32])
                    .write_all(self.init_ctx.init_origin()?.as_ref())?;
            }
            ImportFunc::ReceiveOnly(_) => {
                bail!("Not implemented for init {:#?}.", f);
            }
        }
        Ok(None)
    }
}

impl<ParamType, Ctx> ReceiveHost<ParamType, Ctx>
where
    ParamType: AsRef<[u8]>,
    Ctx: HasReceiveContext,
{
    pub fn call_receive_only(
        &mut self,
        rof: ReceiveOnlyFunc,
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
    ) -> ExecResult<()> {
        match rof {
            ReceiveOnlyFunc::Accept => {
                self.energy.tick_energy(constants::BASE_ACTION_COST)?;
                stack.push_value(self.outcomes.accept());
            }
            ReceiveOnlyFunc::SimpleTransfer => {
                self.energy.tick_energy(constants::BASE_ACTION_COST)?;
                let amount = unsafe { stack.pop_u64() };
                let addr_start = unsafe { stack.pop_u32() } as usize;
                // Overflow is not possible in the next line on 64-bit machines.
                ensure!(addr_start + 32 <= memory.len(), "Illegal memory access.");
                stack.push_value(
                    self.outcomes.simple_transfer(&memory[addr_start..addr_start + 32], amount)?,
                )
            }
            ReceiveOnlyFunc::Send => {
                // all `as usize` are safe on 64-bit systems since we are converging from a u32
                let parameter_len = unsafe { stack.pop_u32() };
                self.energy().tick_energy(constants::action_send_cost(parameter_len))?;
                let parameter_start = unsafe { stack.pop_u32() } as usize;
                // Overflow is not possible in the next line on 64-bit machines.
                let parameter_end = parameter_start + parameter_len as usize;
                let amount = unsafe { stack.pop_u64() };
                let receive_name_len = unsafe { stack.pop_u32() } as usize;
                let receive_name_start = unsafe { stack.pop_u32() } as usize;
                // Overflow is not possible in the next line on 64-bit machines.
                let receive_name_end = receive_name_start + receive_name_len;
                let addr_subindex = unsafe { stack.pop_u64() };
                let addr_index = unsafe { stack.pop_u64() };
                ensure!(parameter_end <= memory.len(), "Illegal memory access.");
                ensure!(receive_name_end <= memory.len(), "Illegal memory access.");
                let res = self.outcomes.send(
                    addr_index,
                    addr_subindex,
                    &memory[receive_name_start..receive_name_end],
                    amount,
                    &memory[parameter_start..parameter_end],
                )?;
                stack.push_value(res);
            }
            ReceiveOnlyFunc::CombineAnd => {
                self.energy.tick_energy(constants::BASE_ACTION_COST)?;
                let right = unsafe { stack.pop_u32() };
                let left = unsafe { stack.pop_u32() };
                let res = self.outcomes.combine_and(left, right)?;
                stack.push_value(res);
            }
            ReceiveOnlyFunc::CombineOr => {
                self.energy.tick_energy(constants::BASE_ACTION_COST)?;
                let right = unsafe { stack.pop_u32() };
                let left = unsafe { stack.pop_u32() };
                let res = self.outcomes.combine_or(left, right)?;
                stack.push_value(res);
            }
            ReceiveOnlyFunc::GetReceiveInvoker => {
                let start = unsafe { stack.pop_u32() } as usize;
                ensure!(start + 32 <= memory.len(), "Illegal memory access for receive invoker.");
                (&mut memory[start..start + 32]).write_all(self.receive_ctx.invoker()?.as_ref())?;
            }
            ReceiveOnlyFunc::GetReceiveSelfAddress => {
                let start = unsafe { stack.pop_u32() } as usize;
                ensure!(start + 16 <= memory.len(), "Illegal memory access for receive owner.");
                (&mut memory[start..start + 8])
                    .write_all(&self.receive_ctx.self_address()?.index.to_le_bytes())?;
                (&mut memory[start + 8..start + 16])
                    .write_all(&self.receive_ctx.self_address()?.subindex.to_le_bytes())?;
            }
            ReceiveOnlyFunc::GetReceiveSelfBalance => {
                stack.push_value(self.receive_ctx.self_balance()?.micro_ccd);
            }
            ReceiveOnlyFunc::GetReceiveSender => {
                let start = unsafe { stack.pop_u32() } as usize;
                ensure!(start < memory.len(), "Illegal memory access for receive sender.");
                self.receive_ctx
                    .sender()?
                    .serial::<&mut [u8]>(&mut &mut memory[start..])
                    .map_err(|_| anyhow!("Memory out of bounds."))?;
            }
            ReceiveOnlyFunc::GetReceiveOwner => {
                let start = unsafe { stack.pop_u32() } as usize;
                ensure!(start + 32 <= memory.len(), "Illegal memory access for receive owner.");
                (&mut memory[start..start + 32]).write_all(self.receive_ctx.owner()?.as_ref())?;
            }
        }
        Ok(())
    }
}

impl<ParamType: AsRef<[u8]>, Ctx: HasReceiveContext> machine::Host<ProcessedImports>
    for ReceiveHost<ParamType, Ctx>
{
    type Interrupt = NoInterrupt;

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn tick_initial_memory(&mut self, num_pages: u32) -> machine::RunResult<()> {
        self.energy.charge_memory_alloc(num_pages)
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    fn call(
        &mut self,
        f: &ProcessedImports,
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<Option<NoInterrupt>> {
        match f.tag {
            ImportFunc::ChargeEnergy => {
                let amount = unsafe { stack.pop_u64() };
                self.energy.tick_energy(amount)?;
            }
            ImportFunc::TrackCall => {
                if let Some(fr) = self.activation_frames.checked_sub(1) {
                    self.activation_frames = fr
                } else {
                    bail!("Too many nested functions.")
                }
            }
            ImportFunc::TrackReturn => self.activation_frames += 1,
            ImportFunc::ChargeMemoryAlloc => {
                self.energy.charge_memory_alloc(unsafe { stack.peek_u32() })?
            }
            ImportFunc::Common(cf) => call_common(self, cf, memory, stack)?,
            ImportFunc::ReceiveOnly(cro) => self.call_receive_only(cro, memory, stack)?,
            ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin) => {
                bail!("Not implemented for receive.");
            }
        }
        Ok(None)
    }
}

pub type Parameter<'a> = &'a [u8];

pub type PolicyBytes<'a> = &'a [u8];

/// Invokes an init-function from a given artifact
pub fn invoke_init<C: RunnableCode, Ctx: HasInitContext>(
    artifact: &Artifact<ProcessedImports, C>,
    amount: u64,
    init_ctx: Ctx,
    init_name: &str,
    param: Parameter,
    energy: u64,
) -> ExecResult<InitResult> {
    let mut host = InitHost {
        energy: InterpreterEnergy {
            energy,
        },
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: Logs::new(),
        state: State::new(None),
        param,
        init_ctx,
    };

    let res = match artifact.run(&mut host, init_name, &[Value::I64(amount as i64)]) {
        Ok(ExecutionOutcome::Success {
            result,
            ..
        }) => result,
        Ok(ExecutionOutcome::Interrupted {
            reason,
            ..
        }) => match reason {}, // impossible case, InitHost has no interrupts
        Err(e) => {
            if e.downcast_ref::<OutOfEnergy>().is_some() {
                return Ok(InitResult::OutOfEnergy);
            } else {
                return Err(e);
            }
        }
    };
    let remaining_energy = host.energy.energy;
    // process the return value.
    // - 0 indicates success
    // - positive values are a protocol violation, so they lead to a runtime error
    // - negative values lead to a rejection with a specific reject reason.
    if let Some(Value::I32(n)) = res {
        if n == 0 {
            Ok(InitResult::Success {
                logs: host.logs,
                state: host.state,
                remaining_energy,
            })
        } else {
            Ok(InitResult::Reject {
                reason: reason_from_wasm_error_code(n)?,
                remaining_energy,
            })
        }
    } else {
        bail!("Wasm module should return a value.")
    }
}

/// Invokes an init-function from a given artifact *bytes*
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_artifact<Ctx: HasInitContext>(
    artifact_bytes: &[u8],
    amount: u64,
    init_ctx: Ctx,
    init_name: &str,
    parameter: Parameter,
    energy: u64,
) -> ExecResult<InitResult> {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_init(&artifact, amount, init_ctx, init_name, parameter, energy)
}

/// Invokes an init-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_source<Ctx: HasInitContext>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: Ctx,
    init_name: &str,
    parameter: Parameter,
    energy: u64,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(&artifact, amount, init_ctx, init_name, parameter, energy)
}

/// Same as `invoke_init_from_source`, except that the module has cost
/// accounting instructions inserted before the init function is called.
/// metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_with_metering_from_source<Ctx: HasInitContext>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: Ctx,
    init_name: &str,
    parameter: Parameter,
    energy: u64,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(&artifact, amount, init_ctx, init_name, parameter, energy)
}

/// Invokes an receive-function from a given artifact
pub fn invoke_receive<C: RunnableCode, Ctx: HasReceiveContext>(
    artifact: &Artifact<ProcessedImports, C>,
    amount: u64,
    receive_ctx: Ctx,
    current_state: &[u8],
    receive_name: &str,
    parameter: Parameter,
    energy: u64,
) -> ExecResult<ReceiveResult> {
    let mut host = ReceiveHost {
        energy: InterpreterEnergy {
            energy,
        },
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: Logs::new(),
        state: State::new(Some(current_state)),
        param: &parameter,
        receive_ctx,
        outcomes: Outcome::new(),
    };

    let res = match artifact.run(&mut host, receive_name, &[Value::I64(amount as i64)]) {
        Ok(ExecutionOutcome::Success {
            result,
            ..
        }) => result,
        Ok(ExecutionOutcome::Interrupted {
            reason,
            ..
        }) => match reason {}, // impossible case, ReceiveHost has no interrupts
        Err(e) => {
            if e.downcast_ref::<OutOfEnergy>().is_some() {
                return Ok(ReceiveResult::OutOfEnergy);
            } else {
                return Err(e);
            }
        }
    };
    let remaining_energy = host.energy.energy;
    if let Some(Value::I32(n)) = res {
        // FIXME: We should filter out to only return the ones reachable from
        // the root.
        let mut actions = host.outcomes.cur_state;
        if n >= 0 && (n as usize) < actions.len() {
            let n = n as usize;
            actions.truncate(n + 1);
            Ok(ReceiveResult::Success {
                logs: host.logs,
                state: host.state,
                actions,
                remaining_energy,
            })
        } else if n >= 0 {
            bail!("Invalid return.")
        } else {
            Ok(ReceiveResult::Reject {
                reason: reason_from_wasm_error_code(n)?,
                remaining_energy,
            })
        }
    } else {
        bail!(
            "Invalid return. Expected a value, but receive nothing. This should not happen for \
             well-formed modules"
        );
    }
}

/// Returns the passed Wasm error code if it is negative.
/// This function should only be called on negative numbers.
fn reason_from_wasm_error_code(n: i32) -> ExecResult<i32> {
    ensure!(
        n < 0,
        "Wasm return value of {} is treated as an error. Only negative should be treated as error.",
        n
    );
    Ok(n)
}

/// A helper trait to support invoking contracts when the policy is given as a
/// byte array, as well as when it is given in structured form, such as
/// Vec<OwnedPolicy>.
pub trait SerialPolicies<R: AsRef<[u8]>> {
    fn policies_to_bytes(&self) -> R;
}

impl<'a> SerialPolicies<&'a [u8]> for &'a [u8] {
    fn policies_to_bytes(&self) -> &'a [u8] { self }
}

impl SerialPolicies<Vec<u8>> for Vec<OwnedPolicy> {
    fn policies_to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let len = self.len() as u16;
        len.serial(&mut out).expect("Cannot fail writing to vec.");
        for policy in self.iter() {
            let bytes = to_bytes(policy);
            let internal_len = bytes.len() as u16;
            internal_len.serial(&mut out).expect("Cannot fail writing to vec.");
            out.extend_from_slice(&bytes);
        }
        out
    }
}

/// Invokes an receive-function from a given artifact *bytes*
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_artifact<Ctx: HasReceiveContext>(
    artifact_bytes: &[u8],
    amount: u64,
    receive_ctx: Ctx,
    current_state: &[u8],
    receive_name: &str,
    parameter: Parameter,
    energy: u64,
) -> ExecResult<ReceiveResult> {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_receive(&artifact, amount, receive_ctx, current_state, receive_name, parameter, energy)
}

/// Invokes an receive-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_source<Ctx: HasReceiveContext>(
    source_bytes: &[u8],
    amount: u64,
    receive_ctx: Ctx,
    current_state: &[u8],
    receive_name: &str,
    parameter: Parameter,
    energy: u64,
) -> ExecResult<ReceiveResult> {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(&artifact, amount, receive_ctx, current_state, receive_name, parameter, energy)
}

/// Invokes an receive-function from Wasm module bytes, injects the module with
/// metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_with_metering_from_source<Ctx: HasReceiveContext>(
    source_bytes: &[u8],
    amount: u64,
    receive_ctx: Ctx,
    current_state: &[u8],
    receive_name: &str,
    parameter: Parameter,
    energy: u64,
) -> ExecResult<ReceiveResult> {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(&artifact, amount, receive_ctx, current_state, receive_name, parameter, energy)
}
