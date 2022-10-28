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
    pub fn log_event(&mut self, event: Vec<u8>, limit_num_logs: bool) -> i32 {
        let cur_len = self.logs.len();
        if (!limit_num_logs && cur_len <= u32::MAX as usize) || cur_len < constants::MAX_NUM_LOGS {
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
        max_parameter_size: usize,
    ) -> ExecResult<u32> {
        let response = self.cur_state.len();

        let name_str = std::str::from_utf8(receive_name_bytes)?;
        ensure!(ReceiveName::is_valid_receive_name(name_str).is_ok(), "Not a valid receive name.");
        let name = receive_name_bytes.to_vec();

        ensure!(parameter_bytes.len() <= max_parameter_size, "Parameter exceeds max size.");

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
    pub energy: InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs: Logs,
    /// The contract's state.
    pub state: State,
    /// The parameter to the init method.
    pub param: ParamType,
    /// The init context for this invocation.
    pub init_ctx: Ctx,
    /// Whether there is a limit on the number of logs and sizes of return
    /// values. Limit removed in P5.
    pub limit_logs_and_return_values: bool,
}

pub struct ReceiveHost<ParamType, Ctx> {
    /// Remaining energy for execution.
    pub energy: InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs: Logs,
    /// The contract's state.
    pub state: State,
    /// The parameter to the receive method.
    pub param: ParamType,
    /// Outcomes of the execution, i.e., the actions tree.
    pub outcomes: Outcome,
    /// The receive context for this call.
    pub receive_ctx: Ctx,
    /// The maximum parameter size.
    /// In P1-P4 it was 1024.
    /// In P5+ it is 65535.
    pub max_parameter_size: usize,
    /// Whether there is a limit on the number of logs and sizes of return
    /// values. Limit removed in P5.
    pub limit_logs_and_return_values: bool,
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

    fn metadata(&self) -> &Self::MetadataType;
    fn init_origin(&self) -> ExecResult<&AccountAddress>;
    fn sender_policies(&self) -> ExecResult<&[u8]>;
}

/// Generic implementation for all references to types that already implement
/// HasInitContext. This allows using InitContext as well as &InitContext in the
/// init host, depending on whether we want to transfer ownership of the context
/// or not.
impl<'a, X: HasInitContext> HasInitContext for &'a X {
    type MetadataType = X::MetadataType;

    fn metadata(&self) -> &Self::MetadataType { (*self).metadata() }

    fn init_origin(&self) -> ExecResult<&AccountAddress> { (*self).init_origin() }

    fn sender_policies(&self) -> ExecResult<&[u8]> { (*self).sender_policies() }
}

impl<X: AsRef<[u8]>> HasInitContext for InitContext<X> {
    type MetadataType = ChainMetadata;

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn init_origin(&self) -> ExecResult<&AccountAddress> { Ok(&self.init_origin) }

    fn sender_policies(&self) -> ExecResult<&[u8]> { Ok(self.sender_policies.as_ref()) }
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

    fn metadata(&self) -> &Self::MetadataType;
    fn invoker(&self) -> ExecResult<&AccountAddress>;
    fn self_address(&self) -> ExecResult<&ContractAddress>;
    fn self_balance(&self) -> ExecResult<Amount>;
    fn sender(&self) -> ExecResult<&Address>;
    fn owner(&self) -> ExecResult<&AccountAddress>;
    fn sender_policies(&self) -> ExecResult<&[u8]>;
}

/// Generic implementation for all references to types that already implement
/// HasReceiveContext. This allows using ReceiveContext as well as
/// &ReceiveContext in the receive host, depending on whether we want to
/// transfer ownership of the context or not.
impl<'a, X: HasReceiveContext> HasReceiveContext for &'a X {
    type MetadataType = X::MetadataType;

    fn metadata(&self) -> &Self::MetadataType { (*self).metadata() }

    fn invoker(&self) -> ExecResult<&AccountAddress> { (*self).invoker() }

    fn self_address(&self) -> ExecResult<&ContractAddress> { (*self).self_address() }

    fn self_balance(&self) -> ExecResult<Amount> { (*self).self_balance() }

    fn sender(&self) -> ExecResult<&Address> { (*self).sender() }

    fn owner(&self) -> ExecResult<&AccountAddress> { (*self).owner() }

    fn sender_policies(&self) -> ExecResult<&[u8]> { (*self).sender_policies() }
}

impl<X: AsRef<[u8]>> HasReceiveContext for ReceiveContext<X> {
    type MetadataType = ChainMetadata;

    fn metadata(&self) -> &Self::MetadataType { &self.metadata }

    fn invoker(&self) -> ExecResult<&AccountAddress> { Ok(&self.invoker) }

    fn self_address(&self) -> ExecResult<&ContractAddress> { Ok(&self.self_address) }

    fn self_balance(&self) -> ExecResult<Amount> { Ok(self.self_balance) }

    fn sender(&self) -> ExecResult<&Address> { Ok(&self.sender) }

    fn owner(&self) -> ExecResult<&AccountAddress> { Ok(&self.owner) }

    fn sender_policies(&self) -> ExecResult<&[u8]> { Ok(self.sender_policies.as_ref()) }
}

pub trait HasChainMetadata {
    fn slot_time(&self) -> ExecResult<SlotTime>;
}

impl HasChainMetadata for ChainMetadata {
    fn slot_time(&self) -> ExecResult<SlotTime> { Ok(self.slot_time) }
}

/// Low-level implementations of host functions. They are written in this way so
/// that they may be reused between init and receive functions, as well as in
/// future versions of contract specifications.
pub(crate) mod host {
    use super::*;
    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_parameter_size(
        stack: &mut machine::RuntimeStack,
        param_len: u32,
    ) -> machine::RunResult<()> {
        // the cost of this function is adequately reflected by the base cost of a
        // function call so we do not charge extra.
        stack.push_value(param_len);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_parameter_section(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        param: &[u8],
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() } as usize;
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        // charge energy linearly in the amount of data written.
        energy.tick_energy(constants::copy_parameter_cost(length))?;
        let write_end = start + length as usize; // this cannot overflow on 64-bit machines.
        ensure!(write_end <= memory.len(), "Illegal memory access.");
        let end = std::cmp::min(offset + length as usize, param.len());
        ensure!(offset <= end, "Attempting to read non-existent parameter.");
        let amt = (&mut memory[start..write_end]).write(&param[offset..end])?;
        stack.push_value(amt as u32);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_policy_section(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        policies: ExecResult<&[u8]>,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() } as usize;
        let length = unsafe { stack.pop_u32() };
        // charge energy linearly in the amount of data written.
        energy.tick_energy(constants::copy_from_host_cost(length))?;
        let start = unsafe { stack.pop_u32() } as usize;
        let write_end = start + length as usize; // this cannot overflow on 64-bit machines.
        ensure!(write_end <= memory.len(), "Illegal memory access.");
        let policies_bytes = policies?;
        let end = std::cmp::min(offset + length as usize, policies_bytes.len());
        ensure!(offset <= end, "Attempting to read non-existent policy.");
        let amt = (&mut memory[start..write_end]).write(&policies_bytes[offset..end])?;
        stack.push_value(amt as u32);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn log_event(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        logs: &mut Logs,
        limit_num_logs: bool,
    ) -> machine::RunResult<()> {
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        let end = start + length as usize;
        ensure!(end <= memory.len(), "Illegal memory access.");
        if length <= constants::MAX_LOG_SIZE {
            // only charge if we actually log something.
            energy.tick_energy(constants::log_event_cost(length))?;
            stack.push_value(logs.log_event(memory[start..end].to_vec(), limit_num_logs))
        } else {
            // otherwise the cost is adequately reflected by just the cost of a function
            // call.
            stack.push_value(-1i32)
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn load_state(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut State,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        // charge energy linearly in the amount of data written.
        energy.tick_energy(constants::copy_from_host_cost(length))?;
        let end = start + length as usize; // this cannot overflow on 64-bit machines.
        ensure!(end <= memory.len(), "Illegal memory access.");
        let res = state.load_state(offset, &mut memory[start..end])?;
        stack.push_value(res);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn write_state(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut State,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        // charge energy linearly in the amount of data written.
        energy.tick_energy(constants::copy_to_host_cost(length))?;
        let end = start + length as usize; // this cannot overflow on 64-bit machines.
        ensure!(end <= memory.len(), "Illegal memory access.");
        let res = state.write_state(offset, &memory[start..end])?;
        stack.push_value(res);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn resize_state(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut State,
    ) -> machine::RunResult<()> {
        let new_size = stack.pop();
        let new_size = unsafe { new_size.short } as u32;
        let old_size = state.len();
        if new_size > old_size {
            // resizing is very similar to writing 0 to the newly allocated parts,
            // but since we don't have to read anything we charge it more cheaply.
            energy.tick_energy(constants::additional_state_size_cost(u64::from(
                new_size - old_size,
            )))?;
        }
        stack.push_value(state.resize_state(new_size));
        Ok(())
    }

    #[inline(always)]
    pub fn state_size(
        stack: &mut machine::RuntimeStack,
        state: &mut State,
    ) -> machine::RunResult<()> {
        // the cost of this function is adequately reflected by the base cost of a
        // function call so we do not charge extra.
        stack.push_value(state.len());
        Ok(())
    }

    #[inline(always)]
    pub fn get_slot_time(
        stack: &mut machine::RuntimeStack,
        metadata: &impl HasChainMetadata,
    ) -> machine::RunResult<()> {
        // the cost of this function is adequately reflected by the base cost of a
        // function call so we do not charge extra.
        stack.push_value(metadata.slot_time()?.timestamp_millis());
        Ok(())
    }

    pub fn get_init_origin(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        init_origin: ExecResult<&AccountAddress>,
    ) -> machine::RunResult<()> {
        let start = unsafe { stack.pop_u32() } as usize;
        ensure!(start + 32 <= memory.len(), "Illegal memory access for init origin.");
        (&mut memory[start..start + 32]).write_all(init_origin?.as_ref())?;
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn accept(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        outcomes: &mut Outcome,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::BASE_ACTION_COST)?;
        stack.push_value(outcomes.accept());
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn simple_transfer(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        outcomes: &mut Outcome,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::BASE_ACTION_COST)?;
        let amount = unsafe { stack.pop_u64() };
        let addr_start = unsafe { stack.pop_u32() } as usize;
        // Overflow is not possible in the next line on 64-bit machines.
        ensure!(addr_start + 32 <= memory.len(), "Illegal memory access.");
        stack.push_value(outcomes.simple_transfer(&memory[addr_start..addr_start + 32], amount)?);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn send(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        outcomes: &mut Outcome,
        max_parameter_size: usize,
    ) -> machine::RunResult<()> {
        // all `as usize` are safe on 64-bit systems since we are converging from a u32
        let parameter_len = unsafe { stack.pop_u32() };
        energy.tick_energy(constants::action_send_cost(parameter_len))?;
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
        let res = outcomes.send(
            addr_index,
            addr_subindex,
            &memory[receive_name_start..receive_name_end],
            amount,
            &memory[parameter_start..parameter_end],
            max_parameter_size,
        )?;
        stack.push_value(res);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn combine_and(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        outcomes: &mut Outcome,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::BASE_ACTION_COST)?;
        let right = unsafe { stack.pop_u32() };
        let left = unsafe { stack.pop_u32() };
        let res = outcomes.combine_and(left, right)?;
        stack.push_value(res);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn combine_or(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        outcomes: &mut Outcome,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::BASE_ACTION_COST)?;
        let right = unsafe { stack.pop_u32() };
        let left = unsafe { stack.pop_u32() };
        let res = outcomes.combine_or(left, right)?;
        stack.push_value(res);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_receive_invoker(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        invoker: ExecResult<&AccountAddress>,
    ) -> machine::RunResult<()> {
        let start = unsafe { stack.pop_u32() } as usize;
        ensure!(start + 32 <= memory.len(), "Illegal memory access for receive invoker.");
        (&mut memory[start..start + 32]).write_all(invoker?.as_ref())?;
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_receive_self_address(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        self_address: ExecResult<&ContractAddress>,
    ) -> machine::RunResult<()> {
        let start = unsafe { stack.pop_u32() } as usize;
        ensure!(start + 16 <= memory.len(), "Illegal memory access for receive owner.");
        let self_address = self_address?;
        (&mut memory[start..start + 8]).write_all(&self_address.index.to_le_bytes())?;
        (&mut memory[start + 8..start + 16]).write_all(&self_address.subindex.to_le_bytes())?;
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_receive_self_balance(
        stack: &mut machine::RuntimeStack,
        self_balance: ExecResult<Amount>,
    ) -> machine::RunResult<()> {
        stack.push_value(self_balance?.micro_ccd);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_receive_sender(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        sender: ExecResult<&Address>,
    ) -> machine::RunResult<()> {
        let start = unsafe { stack.pop_u32() } as usize;
        ensure!(start < memory.len(), "Illegal memory access for receive sender.");
        sender?
            .serial::<&mut [u8]>(&mut &mut memory[start..])
            .map_err(|_| anyhow!("Memory out of bounds."))?;
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_receive_owner(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        owner: ExecResult<&AccountAddress>,
    ) -> machine::RunResult<()> {
        let start = unsafe { stack.pop_u32() } as usize;
        ensure!(start + 32 <= memory.len(), "Illegal memory access for receive owner.");
        (&mut memory[start..start + 32]).write_all(owner?.as_ref())?;
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn track_call(activation_frames: &mut u32) -> machine::RunResult<()> {
        if let Some(fr) = activation_frames.checked_sub(1) {
            *activation_frames = fr;
            Ok(())
        } else {
            bail!("Too many nested functions.")
        }
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn track_return(activation_frames: &mut u32) { *activation_frames += 1; }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn charge_memory_alloc(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<()> {
        energy.charge_memory_alloc(unsafe { stack.peek_u32() })
    }
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
            ImportFunc::ChargeEnergy => self.energy.tick_energy(unsafe { stack.pop_u64() })?,
            ImportFunc::TrackCall => host::track_call(&mut self.activation_frames)?,
            ImportFunc::TrackReturn => host::track_return(&mut self.activation_frames),
            ImportFunc::ChargeMemoryAlloc => host::charge_memory_alloc(stack, &mut self.energy)?,
            ImportFunc::Common(cf) => match cf {
                CommonFunc::GetParameterSize => {
                    host::get_parameter_size(stack, self.param.as_ref().len() as u32)
                }
                CommonFunc::GetParameterSection => host::get_parameter_section(
                    memory,
                    stack,
                    &mut self.energy,
                    self.param.as_ref(),
                ),
                CommonFunc::GetPolicySection => host::get_policy_section(
                    memory,
                    stack,
                    &mut self.energy,
                    self.init_ctx.sender_policies(),
                ),
                CommonFunc::LogEvent => host::log_event(
                    memory,
                    stack,
                    &mut self.energy,
                    &mut self.logs,
                    self.limit_logs_and_return_values,
                ),
                CommonFunc::LoadState => {
                    host::load_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::WriteState => {
                    host::write_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::ResizeState => {
                    host::resize_state(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateSize => host::state_size(stack, &mut self.state),
                CommonFunc::GetSlotTime => host::get_slot_time(stack, self.init_ctx.metadata()),
            }?,
            ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin) => {
                host::get_init_origin(memory, stack, self.init_ctx.init_origin())?
            }
            ImportFunc::ReceiveOnly(_) => {
                bail!("Not implemented for init {:#?}.", f);
            }
        }
        Ok(None)
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
            ImportFunc::ChargeEnergy => self.energy.tick_energy(unsafe { stack.pop_u64() })?,
            ImportFunc::TrackCall => host::track_call(&mut self.activation_frames)?,
            ImportFunc::TrackReturn => host::track_return(&mut self.activation_frames),
            ImportFunc::ChargeMemoryAlloc => host::charge_memory_alloc(stack, &mut self.energy)?,
            ImportFunc::Common(cf) => match cf {
                CommonFunc::GetParameterSize => {
                    host::get_parameter_size(stack, self.param.as_ref().len() as u32)
                }
                CommonFunc::GetParameterSection => host::get_parameter_section(
                    memory,
                    stack,
                    &mut self.energy,
                    self.param.as_ref(),
                ),
                CommonFunc::GetPolicySection => host::get_policy_section(
                    memory,
                    stack,
                    &mut self.energy,
                    self.receive_ctx.sender_policies(),
                ),
                CommonFunc::LogEvent => host::log_event(
                    memory,
                    stack,
                    &mut self.energy,
                    &mut self.logs,
                    self.limit_logs_and_return_values,
                ),
                CommonFunc::LoadState => {
                    host::load_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::WriteState => {
                    host::write_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::ResizeState => {
                    host::resize_state(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateSize => host::state_size(stack, &mut self.state),
                CommonFunc::GetSlotTime => host::get_slot_time(stack, self.receive_ctx.metadata()),
            }?,
            ImportFunc::ReceiveOnly(rof) => match rof {
                ReceiveOnlyFunc::Accept => {
                    host::accept(stack, &mut self.energy, &mut self.outcomes)
                }
                ReceiveOnlyFunc::SimpleTransfer => {
                    host::simple_transfer(memory, stack, &mut self.energy, &mut self.outcomes)
                }
                ReceiveOnlyFunc::Send => host::send(
                    memory,
                    stack,
                    &mut self.energy,
                    &mut self.outcomes,
                    self.max_parameter_size,
                ),
                ReceiveOnlyFunc::CombineAnd => {
                    host::combine_and(stack, &mut self.energy, &mut self.outcomes)
                }
                ReceiveOnlyFunc::CombineOr => {
                    host::combine_or(stack, &mut self.energy, &mut self.outcomes)
                }
                ReceiveOnlyFunc::GetReceiveInvoker => {
                    host::get_receive_invoker(memory, stack, self.receive_ctx.invoker())
                }
                ReceiveOnlyFunc::GetReceiveSelfAddress => {
                    host::get_receive_self_address(memory, stack, self.receive_ctx.self_address())
                }
                ReceiveOnlyFunc::GetReceiveSelfBalance => {
                    host::get_receive_self_balance(stack, self.receive_ctx.self_balance())
                }
                ReceiveOnlyFunc::GetReceiveSender => {
                    host::get_receive_sender(memory, stack, self.receive_ctx.sender())
                }
                ReceiveOnlyFunc::GetReceiveOwner => {
                    host::get_receive_owner(memory, stack, self.receive_ctx.owner())
                }
            }?,
            ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin) => {
                bail!("Not implemented for receive.");
            }
        }
        Ok(None)
    }
}

/// Collection of information relevant to invoke an init-function.
#[derive(Debug)]
pub struct InitInvocation<'a> {
    /// The amount included in the transaction.
    pub amount:    u64,
    /// The name of the init function to invoke.
    pub init_name: &'a str,
    /// A parameter to provide the init function.
    pub parameter: Parameter<'a>,
    /// The limit on the energy to be used for execution.
    pub energy:    InterpreterEnergy,
}

/// Invokes an init-function from a given artifact.
pub fn invoke_init<C: RunnableCode, Ctx: HasInitContext>(
    artifact: &Artifact<ProcessedImports, C>,
    init_ctx: Ctx,
    init_invocation: InitInvocation,
    limit_logs_and_return_values: bool,
) -> ExecResult<InitResult> {
    let mut host = InitHost {
        energy: init_invocation.energy,
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: Logs::new(),
        state: State::new(None),
        param: init_invocation.parameter,
        limit_logs_and_return_values,
        init_ctx,
    };

    let res = match artifact
        .run(&mut host, init_invocation.init_name, &[Value::I64(init_invocation.amount as i64)])
    {
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
    limit_logs_and_return_values: bool,
    energy: InterpreterEnergy,
) -> ExecResult<InitResult> {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_init(
        &artifact,
        init_ctx,
        InitInvocation {
            amount,
            init_name,
            parameter,
            energy,
        },
        limit_logs_and_return_values,
    )
}

/// Invokes an init-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_source<Ctx: HasInitContext>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: Ctx,
    init_name: &str,
    parameter: Parameter,
    limit_logs_and_return_values: bool,
    energy: InterpreterEnergy,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(
        &artifact,
        init_ctx,
        InitInvocation {
            amount,
            init_name,
            parameter,
            energy,
        },
        limit_logs_and_return_values,
    )
}

/// Same as `invoke_init_from_source`, except that the module has cost
/// accounting instructions inserted before the init function is called.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_with_metering_from_source<Ctx: HasInitContext>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: Ctx,
    init_name: &str,
    parameter: Parameter,
    limit_logs_and_return_values: bool,
    energy: InterpreterEnergy,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(
        &artifact,
        init_ctx,
        InitInvocation {
            amount,
            init_name,
            parameter,
            energy,
        },
        limit_logs_and_return_values,
    )
}

/// Collection of information relevant to invoke a receive-function.
#[derive(Debug)]
pub struct ReceiveInvocation<'a> {
    /// The amount included in the transaction.
    pub amount:       u64,
    /// The name of the receive function to invoke.
    pub receive_name: &'a str,
    /// A parameter to provide the receive function.
    pub parameter:    Parameter<'a>,
    /// The limit on the energy to be used for execution.
    pub energy:       InterpreterEnergy,
}

/// Invokes an receive-function from a given artifact
pub fn invoke_receive<C: RunnableCode, Ctx: HasReceiveContext>(
    artifact: &Artifact<ProcessedImports, C>,
    receive_ctx: Ctx,
    receive_invocation: ReceiveInvocation,
    current_state: &[u8],
    max_parameter_size: usize,
    limit_logs_and_return_values: bool,
) -> ExecResult<ReceiveResult> {
    let mut host = ReceiveHost {
        energy: receive_invocation.energy,
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: Logs::new(),
        state: State::new(Some(current_state)),
        param: &receive_invocation.parameter,
        max_parameter_size,
        limit_logs_and_return_values,
        receive_ctx,
        outcomes: Outcome::new(),
    };

    let res = match artifact.run(&mut host, receive_invocation.receive_name, &[Value::I64(
        receive_invocation.amount as i64,
    )]) {
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

/// Invokes an receive-function from a given artifact *bytes*
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_artifact<Ctx: HasReceiveContext>(
    artifact_bytes: &[u8],
    receive_ctx: Ctx,
    receive_invocation: ReceiveInvocation,
    current_state: &[u8],
    max_parameter_size: usize,
    limit_logs_and_return_values: bool,
) -> ExecResult<ReceiveResult> {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_receive(
        &artifact,
        receive_ctx,
        receive_invocation,
        current_state,
        max_parameter_size,
        limit_logs_and_return_values,
    )
}

/// Invokes an receive-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_source<Ctx: HasReceiveContext>(
    source_bytes: &[u8],
    receive_ctx: Ctx,
    receive_invocation: ReceiveInvocation,
    current_state: &[u8],
    max_parameter_size: usize,
    limit_logs_and_return_values: bool,
) -> ExecResult<ReceiveResult> {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(
        &artifact,
        receive_ctx,
        receive_invocation,
        current_state,
        max_parameter_size,
        limit_logs_and_return_values,
    )
}

/// Invokes an receive-function from Wasm module bytes, injects the module with
/// metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_with_metering_from_source<Ctx: HasReceiveContext>(
    source_bytes: &[u8],
    receive_ctx: Ctx,
    receive_invocation: ReceiveInvocation,
    current_state: &[u8],
    max_parameter_size: usize,
    limit_logs_and_return_values: bool,
) -> ExecResult<ReceiveResult> {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(
        &artifact,
        receive_ctx,
        receive_invocation,
        current_state,
        max_parameter_size,
        limit_logs_and_return_values,
    )
}
