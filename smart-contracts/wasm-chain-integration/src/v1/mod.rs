#[cfg(feature = "enable-ffi")]
mod ffi;
pub mod trie;
mod types;

use crate::{constants, v0, ExecResult, InterpreterEnergy, OutOfEnergy};
use anyhow::{bail, ensure};
use concordium_contracts_common::{AccountAddress, Amount, ContractAddress, OwnedEntrypointName};
use machine::Value;
use std::{borrow::Borrow, io::Write, sync::Arc};
use trie::BackingStoreLoad;
pub use types::*;
use wasm_transform::{
    artifact::{Artifact, CompiledFunction, CompiledFunctionBytes, RunnableCode},
    machine::{self, ExecutionOutcome, NoInterrupt},
    utils,
};

/// Interrupt triggered by the smart contract to execute an instruction on the
/// host, either an account transfer or a smart contract call.
#[derive(Debug)]
pub enum Interrupt {
    Transfer {
        to:     AccountAddress,
        amount: Amount,
    },
    Call {
        address:   ContractAddress,
        parameter: ParameterVec,
        name:      OwnedEntrypointName,
        amount:    Amount,
    },
}

impl Interrupt {
    pub fn to_bytes(&self, out: &mut Vec<u8>) -> anyhow::Result<()> {
        match self {
            Interrupt::Transfer {
                to,
                amount,
            } => {
                out.push(0u8);
                out.write_all(to.as_ref())?;
                out.write_all(&amount.micro_ccd.to_be_bytes())?;
                Ok(())
            }
            Interrupt::Call {
                address,
                parameter,
                name,
                amount,
            } => {
                out.push(1u8);
                out.write_all(&address.index.to_be_bytes())?;
                out.write_all(&address.subindex.to_be_bytes())?;
                out.write_all(&(parameter.len() as u16).to_be_bytes())?;
                out.write_all(&parameter)?;
                let name_str: &str = name.as_entrypoint_name().into();
                out.write_all(&(name_str.as_bytes().len() as u16).to_be_bytes())?;
                out.write_all(&name_str.as_bytes())?;
                out.write_all(&amount.micro_ccd.to_be_bytes())?;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
/// A host implementation that provides access to host information needed for
/// execution of contract initialization functions. The "host" in this context
/// refers to the Wasm concept of a host.
/// This keeps track of the current state and logs, gives access to the context,
/// and makes sure that execution stays within resource bounds dictated by
/// allocated energy.
pub struct InitHost<'a, BackingStore, ParamType, Ctx> {
    /// Remaining energy for execution.
    pub energy:            InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs:              v0::Logs,
    /// The contract's state.
    pub state:             InstanceState<'a, BackingStore>,
    /// The response from the call.
    pub return_value:      ReturnValue,
    /// The parameter to the init method.
    pub parameter:         ParamType,
    /// The init context for this invocation.
    pub init_ctx:          Ctx,
}

impl<'a, 'b, BackingStore, Ctx2, Ctx1: Into<Ctx2>>
    From<InitHost<'b, BackingStore, ParameterRef<'a>, Ctx1>>
    for InitHost<'b, BackingStore, ParameterVec, Ctx2>
{
    fn from(host: InitHost<'b, BackingStore, ParameterRef<'a>, Ctx1>) -> Self {
        Self {
            energy:            host.energy,
            activation_frames: host.activation_frames,
            logs:              host.logs,
            state:             host.state,
            return_value:      host.return_value,
            parameter:         host.parameter.into(),
            init_ctx:          host.init_ctx.into(),
        }
    }
}

#[derive(Debug)]
/// A host implementation that provides access to host information needed for
/// execution of contract receive methods. The "host" in this context
/// refers to the Wasm concept of a host.
/// This keeps track of the current state and logs, gives access to the context,
/// and makes sure that execution stays within resource bounds dictated by
/// allocated energy.
pub struct ReceiveHost<'a, BackingStore, ParamType, Ctx> {
    pub energy:    InterpreterEnergy,
    pub stateless: StateLessReceiveHost<ParamType, Ctx>,
    pub state:     InstanceState<'a, BackingStore>,
}

#[derive(Debug)]
pub struct StateLessReceiveHost<ParamType, Ctx> {
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs:              v0::Logs,
    /// Return value from execution.
    pub return_value:      ReturnValue,
    /// The parameter to the receive method, as well as any responses from
    /// calls to other contracts during execution.
    pub parameters:        Vec<ParamType>,
    /// The receive context for this call.
    pub receive_ctx:       Ctx,
    /// Latest generation that was used. This is incremented on each resume to
    /// invalidate all entries and iterators from before the out-call.
    pub latest_generation: u32,
}

impl<'a, Ctx2, Ctx1: Into<Ctx2>> From<StateLessReceiveHost<ParameterRef<'a>, Ctx1>>
    for StateLessReceiveHost<ParameterVec, Ctx2>
{
    fn from(host: StateLessReceiveHost<ParameterRef<'a>, Ctx1>) -> Self {
        Self {
            activation_frames: host.activation_frames,
            logs:              host.logs,
            return_value:      host.return_value,
            parameters:        host.parameters.into_iter().map(|x| x.to_vec()).collect(),
            receive_ctx:       host.receive_ctx.into(),
            latest_generation: host.latest_generation,
        }
    }
}

/// v1 host functions.
mod host {
    use super::*;
    use concordium_contracts_common::{Cursor, Get, ParseError, ParseResult, ACCOUNT_ADDRESS_SIZE};

    const TRANSFER_TAG: u32 = 0;
    const CALL_TAG: u32 = 1;

    // Parse the call arguments. This is using the serialization as defined in the
    // smart contracts code since the arguments will be written by a smart
    // contract. Returns Ok(None) if there is insufficient energy.
    fn parse_call_args(
        energy: &mut InterpreterEnergy,
        cursor: &mut Cursor<&[u8]>,
    ) -> ParseResult<Result<Interrupt, OutOfEnergy>> {
        let address = cursor.get()?;
        let parameter_len: u16 = cursor.get()?;
        if energy.tick_energy(constants::copy_to_host_cost(parameter_len.into())).is_err() {
            return Ok(Err(OutOfEnergy));
        }
        let start = cursor.offset;
        let end = cursor.offset + parameter_len as usize;
        if end > cursor.data.len() {
            return Err(ParseError {});
        }
        let parameter: ParameterVec = cursor.data[start..end].to_vec();
        cursor.offset = end;
        let name = cursor.get()?;
        let amount = cursor.get()?;
        Ok(Ok(Interrupt::Call {
            address,
            parameter,
            name,
            amount,
        }))
    }

    /// Write to the return value.
    fn write_return_value_helper(
        rv: &mut ReturnValue,
        offset: u32,
        bytes: &[u8],
    ) -> ExecResult<u32> {
        let length = bytes.len();
        ensure!(offset as usize <= rv.len(), "Cannot write past the offset.");
        let offset = offset as usize;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("Writing past the end of memory."))?
            as usize;
        let end = std::cmp::min(end, constants::MAX_CONTRACT_STATE as usize) as u32;
        if rv.len() < end as usize {
            rv.resize(end as usize, 0u8);
        }
        let written = (&mut rv[offset..end as usize]).write(bytes)?;
        Ok(written as u32)
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn write_return_value(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        rv: &mut ReturnValue,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        // charge energy linearly in the amount of data written.
        energy.tick_energy(constants::copy_to_host_cost(length))?;
        let end = start + length as usize; // this cannot overflow on 64-bit machines.
        ensure!(end <= memory.len(), "Illegal memory access.");
        let res = write_return_value_helper(rv, offset, &memory[start..end])?;
        stack.push_value(res);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn invoke(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<Option<Interrupt>> {
        energy.tick_energy(constants::INVOKE_BASE_COST)?;
        let length = unsafe { stack.pop_u32() } as usize; // length of the instruction payload in memory
        let start = unsafe { stack.pop_u32() } as usize; // start of the instruction payload in memory
        let tag = unsafe { stack.pop_u32() }; // tag of the instruction
        match tag {
            TRANSFER_TAG => {
                ensure!(
                    length == ACCOUNT_ADDRESS_SIZE + 8,
                    "Transfers must have exactly 40 bytes of payload."
                );
                // Overflow is not possible in the next line on 64-bit machines.
                ensure!(start + length <= memory.len(), "Illegal memory access.");
                let mut addr_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
                addr_bytes.copy_from_slice(&memory[start..start + ACCOUNT_ADDRESS_SIZE]);
                let to = AccountAddress(addr_bytes);
                let mut amount_bytes = [0; 8];
                amount_bytes.copy_from_slice(
                    &memory[start + ACCOUNT_ADDRESS_SIZE..start + ACCOUNT_ADDRESS_SIZE + 8],
                );
                let amount = Amount {
                    micro_ccd: u64::from_le_bytes(amount_bytes),
                };
                Ok(Interrupt::Transfer {
                    to,
                    amount,
                }
                .into())
            }
            CALL_TAG => {
                ensure!(start + length <= memory.len(), "Illegal memory access.");
                let mut cursor = Cursor::new(&memory[start..start + length]);
                match parse_call_args(energy, &mut cursor) {
                    Ok(Ok(i)) => Ok(Some(i)),
                    Ok(Err(OutOfEnergy)) => bail!(OutOfEnergy),
                    Err(e) => bail!("Illegal call, cannot parse arguments: {:?}", e),
                }
            }
            c => bail!("Illegal instruction code {}.", c),
        }
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Get the parameter section. This differs from the v0 version in that it
    /// expects an argument on the stack to indicate which parameter to check.
    pub fn get_parameter_size(
        stack: &mut machine::RuntimeStack,
        parameters: &[impl AsRef<[u8]>],
    ) -> machine::RunResult<()> {
        // TODO: Verify cost below.
        // the cost of this function is adequately reflected by the base cost of a
        // function call so we do not charge extra.
        let param_num = unsafe { stack.pop_u32() } as usize;
        if let Some(param) = parameters.get(param_num as usize) {
            stack.push_value(param.as_ref().len() as u32);
        } else {
            stack.push_value(-1i32);
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn get_parameter_section(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        parameters: &[impl AsRef<[u8]>],
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() } as usize;
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        let param_num = unsafe { stack.pop_u32() } as usize;
        // charge energy linearly in the amount of data written.
        energy.tick_energy(constants::copy_from_host_cost(length))?;
        if let Some(param) = parameters.get(param_num as usize) {
            let write_end = start + length as usize; // this cannot overflow on 64-bit machines.
            ensure!(write_end <= memory.len(), "Illegal memory access.");
            let end = std::cmp::min(offset + length as usize, param.as_ref().len());
            ensure!(offset <= end, "Attempting to read non-existent parameter.");
            let amt = (&mut memory[start..write_end]).write(&param.as_ref()[offset..end])?;
            stack.push_value(amt as u32);
        } else {
            stack.push_value(-1i32);
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_lookup_entry<'a, BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        let key_len = unsafe { stack.pop_u32() };
        let key_start = unsafe { stack.pop_u32() } as usize;
        let key_end = key_start + key_len as usize;
        energy.tick_energy(constants::traverse_key_cost(key_len))?;
        ensure!(key_end <= memory.len(), "Illegal memory access.");
        let key = &memory[key_start..key_end];
        let result = state.lookup_entry(key);
        stack.push_value(u64::from(result));
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_create_entry<'a, BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        let key_len = unsafe { stack.pop_u32() };
        let key_start = unsafe { stack.pop_u32() } as usize;
        let key_end = key_start + key_len as usize;
        energy.tick_energy(constants::modify_key_cost(key_len))?;
        ensure!(key_end <= memory.len(), "Illegal memory access.");
        let key = &memory[key_start..key_end];
        let entry_index = state.create_entry(key)?;
        stack.push_value(u64::from(entry_index));
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_delete_entry<'a, BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::DELETE_ENTRY_COST)?;
        let entry_index = unsafe { stack.pop_u64() };
        let result = state.delete_entry(InstanceStateEntry::from(entry_index))?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_delete_prefix<'a, BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        let key_len = unsafe { stack.pop_u32() };
        let key_start = unsafe { stack.pop_u32() } as usize;
        let key_end = key_start + key_len as usize;
        // this cannot overflow on 64-bit platforms, so it is safe to just add
        ensure!(key_end <= memory.len(), "Illegal memory access.");
        let key = &memory[key_start..key_end];
        energy.tick_energy(constants::delete_prefix_find_cost(key_len))?;
        let result = state.delete_prefix(energy, key)?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_iterator<'a, BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        // TODO: Charge.
        let prefix_len = unsafe { stack.pop_u32() };
        let prefix_start = unsafe { stack.pop_u32() } as usize;
        let prefix_end = prefix_start + prefix_len as usize;
        ensure!(prefix_end <= memory.len(), "Illegal memory access.");
        energy.tick_energy(constants::new_iterator_cost(prefix_len))?;
        let prefix = &memory[prefix_start..prefix_end];
        let iterator_index = state.iterator(prefix);
        stack.push_value(u64::from(iterator_index));
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_iterator_next<'a, BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        // TODO: Charge cost. This needs to be dynamic.
        let iter_index = unsafe { stack.pop_u64() };
        let entry_option = state.iterator_next(InstanceStateIterator::from(iter_index))?;
        stack.push_value(u64::from(entry_option));
        Ok(())
    }

    pub fn state_iterator_delete<'a, BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::DELETE_ITERATOR_COST)?;
        let iter = unsafe { stack.pop_u64() };
        let result = state.iterator_delete(InstanceStateIterator::from(iter))?;
        stack.push_value(result);
        Ok(())
    }

    pub fn state_iterator_key_size<'a, BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        // TODO: Verify cost below.
        // the cost of this function is adequately reflected by the base cost of a
        // function call so we do not charge extra.
        let iter = unsafe { stack.pop_u64() };
        let result = state.iterator_key_size(InstanceStateIterator::from(iter))?;
        stack.push_value(result);
        Ok(())
    }

    pub fn state_iterator_key_read<'a, BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        let iter = unsafe { stack.pop_u64() };
        energy.tick_energy(constants::copy_from_host_cost(length))?;
        let dest_end = start + length as usize;
        ensure!(dest_end <= memory.len(), "Illegal memory access.");
        let dest = &mut memory[start..dest_end];
        let result = state.iterator_key_read(InstanceStateIterator::from(iter), dest, offset)?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_entry_read<'a, BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let dest_start = unsafe { stack.pop_u32() } as usize;
        let entry_index = unsafe { stack.pop_u64() };
        energy.tick_energy(constants::copy_from_host_cost(length))?;
        let dest_end = dest_start + length as usize;
        ensure!(dest_end <= memory.len(), "Illegal memory access.");
        let dest = &mut memory[dest_start..dest_end];
        let result = state.entry_read(InstanceStateEntry::from(entry_index), dest, offset)?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_entry_write<'a, BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let source_start = unsafe { stack.pop_u32() } as usize;
        let entry_index = unsafe { stack.pop_u64() };
        energy.tick_energy(constants::copy_to_host_cost(length))?;
        let source_end = source_start + length as usize;
        ensure!(source_end <= memory.len(), "Illegal memory access.");
        let source = &memory[source_start..source_end];
        let result = state.entry_write(InstanceStateEntry::from(entry_index), source, offset)?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_entry_size<'a, BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        let entry_index = unsafe { stack.pop_u64() };
        let result = state.entry_size(InstanceStateEntry::from(entry_index))?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_entry_resize<'a, BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<'a, BackingStore>,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::RESIZE_ENTRY_BASE_COST)?;
        let new_size = unsafe { stack.pop_u32() };
        let entry_index = unsafe { stack.pop_u64() };
        let result = state.entry_resize(energy, InstanceStateEntry::from(entry_index), new_size)?;
        stack.push_value(result);
        Ok(())
    }
}

// The use of Vec<u8> is ugly, and we really should have [u8] there, but FFI
// prevents us doing that without ugly hacks.
impl<'a, BackingStore: BackingStoreLoad, ParamType: AsRef<[u8]>, Ctx: v0::HasInitContext>
    machine::Host<ProcessedImports> for InitHost<'a, BackingStore, ParamType, Ctx>
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
    ) -> machine::RunResult<Option<Self::Interrupt>> {
        match f.tag {
            ImportFunc::ChargeEnergy => self.energy.tick_energy(unsafe { stack.pop_u64() })?,
            ImportFunc::TrackCall => v0::host::track_call(&mut self.activation_frames)?,
            ImportFunc::TrackReturn => v0::host::track_return(&mut self.activation_frames),
            ImportFunc::ChargeMemoryAlloc => {
                v0::host::charge_memory_alloc(stack, &mut self.energy)?
            }
            ImportFunc::Common(cf) => match cf {
                CommonFunc::WriteOutput => host::write_return_value(
                    memory,
                    stack,
                    &mut self.energy,
                    &mut self.return_value,
                ),
                CommonFunc::GetParameterSize => host::get_parameter_size(stack, &[&self.parameter]),
                CommonFunc::GetParameterSection => {
                    host::get_parameter_section(memory, stack, &mut self.energy, &[&self.parameter])
                }
                CommonFunc::GetPolicySection => v0::host::get_policy_section(
                    memory,
                    stack,
                    &mut self.energy,
                    self.init_ctx.sender_policies(),
                ),
                CommonFunc::LogEvent => {
                    v0::host::log_event(memory, stack, &mut self.energy, &mut self.logs)
                }
                CommonFunc::GetSlotTime => v0::host::get_slot_time(stack, self.init_ctx.metadata()),
                CommonFunc::StateLookupEntry => {
                    host::state_lookup_entry(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateCreateEntry => {
                    host::state_create_entry(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateDeleteEntry => {
                    host::state_delete_entry(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateDeletePrefix => {
                    host::state_delete_prefix(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratePrefix => {
                    host::state_iterator(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorNext => {
                    host::state_iterator_next(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorDelete => {
                    host::state_iterator_delete(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorKeySize => {
                    host::state_iterator_key_size(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorKeyRead => {
                    host::state_iterator_key_read(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntryRead => {
                    host::state_entry_read(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntryWrite => {
                    host::state_entry_write(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntrySize => host::state_entry_size(stack, &mut self.state),
                CommonFunc::StateEntryResize => {
                    host::state_entry_resize(stack, &mut self.energy, &mut self.state)
                }
            }?,
            ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin) => {
                v0::host::get_init_origin(memory, stack, self.init_ctx.init_origin())?
            }
            ImportFunc::ReceiveOnly(_) => {
                bail!("Not implemented for init {:#?}.", f);
            }
        }
        Ok(None)
    }
}

impl<'a, BackingStore: BackingStoreLoad, ParamType: AsRef<[u8]>, Ctx: v0::HasReceiveContext>
    machine::Host<ProcessedImports> for ReceiveHost<'a, BackingStore, ParamType, Ctx>
{
    type Interrupt = Interrupt;

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
    ) -> machine::RunResult<Option<Self::Interrupt>> {
        match f.tag {
            ImportFunc::ChargeEnergy => self.energy.tick_energy(unsafe { stack.pop_u64() })?,
            ImportFunc::TrackCall => v0::host::track_call(&mut self.stateless.activation_frames)?,
            ImportFunc::TrackReturn => {
                v0::host::track_return(&mut self.stateless.activation_frames)
            }
            ImportFunc::ChargeMemoryAlloc => {
                v0::host::charge_memory_alloc(stack, &mut self.energy)?
            }
            ImportFunc::Common(cf) => match cf {
                CommonFunc::WriteOutput => host::write_return_value(
                    memory,
                    stack,
                    &mut self.energy,
                    &mut self.stateless.return_value,
                ),
                CommonFunc::GetParameterSize => {
                    host::get_parameter_size(stack, &self.stateless.parameters)
                }
                CommonFunc::GetParameterSection => host::get_parameter_section(
                    memory,
                    stack,
                    &mut self.energy,
                    &self.stateless.parameters,
                ),
                CommonFunc::GetPolicySection => v0::host::get_policy_section(
                    memory,
                    stack,
                    &mut self.energy,
                    self.stateless.receive_ctx.sender_policies(),
                ),
                CommonFunc::LogEvent => {
                    v0::host::log_event(memory, stack, &mut self.energy, &mut self.stateless.logs)
                }
                CommonFunc::GetSlotTime => {
                    v0::host::get_slot_time(stack, self.stateless.receive_ctx.metadata())
                }
                CommonFunc::StateLookupEntry => {
                    host::state_lookup_entry(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateCreateEntry => {
                    host::state_create_entry(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateDeleteEntry => {
                    host::state_delete_entry(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateDeletePrefix => {
                    host::state_delete_prefix(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratePrefix => {
                    host::state_iterator(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorNext => {
                    host::state_iterator_next(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorDelete => {
                    host::state_iterator_delete(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorKeySize => {
                    host::state_iterator_key_size(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateIteratorKeyRead => {
                    host::state_iterator_key_read(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntryRead => {
                    host::state_entry_read(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntryWrite => {
                    host::state_entry_write(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntrySize => host::state_entry_size(stack, &mut self.state),
                CommonFunc::StateEntryResize => {
                    host::state_entry_resize(stack, &mut self.energy, &mut self.state)
                }
            }?,
            ImportFunc::ReceiveOnly(rof) => match rof {
                ReceiveOnlyFunc::Invoke => {
                    return host::invoke(memory, stack, &mut self.energy);
                }
                ReceiveOnlyFunc::GetReceiveInvoker => v0::host::get_receive_invoker(
                    memory,
                    stack,
                    self.stateless.receive_ctx.invoker(),
                ),
                ReceiveOnlyFunc::GetReceiveSelfAddress => v0::host::get_receive_self_address(
                    memory,
                    stack,
                    self.stateless.receive_ctx.self_address(),
                ),
                ReceiveOnlyFunc::GetReceiveSelfBalance => v0::host::get_receive_self_balance(
                    stack,
                    self.stateless.receive_ctx.self_balance(),
                ),
                ReceiveOnlyFunc::GetReceiveSender => {
                    v0::host::get_receive_sender(memory, stack, self.stateless.receive_ctx.sender())
                }
                ReceiveOnlyFunc::GetReceiveOwner => {
                    v0::host::get_receive_owner(memory, stack, self.stateless.receive_ctx.owner())
                }
            }?,
            ImportFunc::InitOnly(InitOnlyFunc::GetInitOrigin) => {
                bail!("Not implemented for receive.");
            }
        }
        Ok(None)
    }
}

/// Parameter whose ownership is tracked statically.
pub type ParameterRef<'a> = &'a [u8];
/// Parameter whose ownership is tracked dynamically.
/// This is needed, for example, when execution passes through Haskell and Rust.
/// Ideally this would be Arc<[u8]> but then this cannot be passed via the FFI
/// boundary directly since [u8] is not Sized. To avoid a third type we settle
/// on Vec<u8>.
pub type ParameterVec = Vec<u8>;

/// Invokes an init-function from a given artifact
pub fn invoke_init<'a, BackingStore: BackingStoreLoad, R: RunnableCode>(
    artifact: impl Borrow<Artifact<ProcessedImports, R>>,
    amount: u64,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    parameter: ParameterRef,
    energy: InterpreterEnergy,
    state: InstanceState<'a, BackingStore>,
) -> ExecResult<InitResult> {
    let mut host = InitHost {
        energy,
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: v0::Logs::new(),
        state,
        return_value: Vec::new(),
        parameter,
        init_ctx,
    };

    let result = artifact.borrow().run(&mut host, init_name, &[Value::I64(amount as i64)]);
    process_init_result(host, result)
}

fn process_init_result<BackingStore: BackingStoreLoad, Param, Ctx>(
    host: InitHost<'_, BackingStore, Param, Ctx>,
    result: machine::RunResult<ExecutionOutcome<NoInterrupt>>,
) -> ExecResult<InitResult> {
    match result {
        Ok(ExecutionOutcome::Success {
            result,
            ..
        }) => {
            let remaining_energy = host.energy.energy;
            // process the return value.
            // - 0 indicates success
            // - positive values are a protocol violation, so they lead to a runtime error
            // - negative values lead to a rejection with a specific reject reason.
            if let Some(Value::I32(n)) = result {
                if n == 0 {
                    Ok(InitResult::Success {
                        logs: host.logs,
                        return_value: host.return_value,
                        remaining_energy,
                    })
                } else {
                    Ok(InitResult::Reject {
                        reason: reason_from_wasm_error_code(n)?,
                        return_value: host.return_value,
                        remaining_energy,
                    })
                }
            } else {
                bail!("Wasm module should return a value.")
            }
        }
        Ok(ExecutionOutcome::Interrupted {
            reason,
            config: _,
        }) => match reason {},
        Err(error) => {
            if error.downcast_ref::<OutOfEnergy>().is_some() {
                Ok(InitResult::OutOfEnergy)
            } else {
                Ok(InitResult::Trap {
                    error,
                    remaining_energy: host.energy.energy,
                })
            }
        }
    }
}

/// Response from an invoke call.
pub enum InvokeResponse {
    /// Execution was successful, and the state potentially changed.
    Success {
        /// New state, if it changed.
        new_state:   bool,
        /// Balance after the execution of the interrupt.
        new_balance: Amount,
        /// Some calls do not have any return values, such as transfers.
        data:        Option<ParameterVec>,
    },
    /// Execution was not successful. The state did not change
    /// and the contract responded with the given error code and data.
    Failure {
        code: u64,
        data: Option<ParameterVec>,
    },
}

/// Invokes an init-function from a given artifact *bytes*
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_artifact<'a, 'b, BackingStore: BackingStoreLoad>(
    artifact_bytes: &'a [u8],
    amount: u64,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    parameter: ParameterRef,
    energy: InterpreterEnergy,
    state: InstanceState<'b, BackingStore>,
) -> ExecResult<InitResult> {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_init(artifact, amount, init_ctx, init_name, parameter, energy, state)
}

/// Invokes an init-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_source<'b, BackingStore: BackingStoreLoad>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    parameter: ParameterRef,
    energy: InterpreterEnergy,
    state: InstanceState<'b, BackingStore>,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(artifact, amount, init_ctx, init_name, parameter, energy, state)
}

/// Same as `invoke_init_from_source`, except that the module has cost
/// accounting instructions inserted before the init function is called.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_with_metering_from_source<'b, BackingStore: BackingStoreLoad>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    parameter: ParameterRef,
    energy: InterpreterEnergy,
    state: InstanceState<'b, BackingStore>,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(artifact, amount, init_ctx, init_name, parameter, energy, state)
}

fn process_receive_result<BackingStore, Param, R: RunnableCode, Ctx1, Ctx2>(
    artifact: Arc<Artifact<ProcessedImports, R>>,
    host: ReceiveHost<'_, BackingStore, Param, Ctx1>,
    result: machine::RunResult<ExecutionOutcome<Interrupt>>,
) -> ExecResult<ReceiveResult<R, Ctx2>>
where
    StateLessReceiveHost<ParameterVec, Ctx2>: From<StateLessReceiveHost<Param, Ctx1>>, {
    let mut stateless = host.stateless;
    match result {
        Ok(ExecutionOutcome::Success {
            result,
            ..
        }) => {
            let remaining_energy = host.energy.energy;
            if let Some(Value::I32(n)) = result {
                if n >= 0 {
                    Ok(ReceiveResult::Success {
                        logs: stateless.logs,
                        return_value: stateless.return_value,
                        remaining_energy,
                    })
                } else {
                    Ok(ReceiveResult::Reject {
                        reason: reason_from_wasm_error_code(n)?,
                        return_value: stateless.return_value,
                        remaining_energy,
                    })
                }
            } else {
                bail!(
                    "Invalid return. Expected a value, but receive nothing. This should not \
                     happen for well-formed modules"
                );
            }
        }
        Ok(ExecutionOutcome::Interrupted {
            reason,
            config,
        }) => {
            let remaining_energy = host.energy.energy;
            // logs are returned per section that is executed.
            // So here we set the host logs to empty and return any
            // existing logs.
            let logs = std::mem::take(&mut stateless.logs);
            Ok(ReceiveResult::Interrupt {
                remaining_energy,
                logs,
                config: Box::new(ReceiveInterruptedState {
                    host: stateless.into(),
                    artifact,
                    config,
                }),
                interrupt: reason,
            })
        }
        Err(error) => {
            if error.downcast_ref::<OutOfEnergy>().is_some() {
                Ok(ReceiveResult::OutOfEnergy)
            } else {
                Ok(ReceiveResult::Trap {
                    error,
                    remaining_energy: host.energy.energy,
                })
            }
        }
    }
}

/// Invokes an receive-function from a given artifact
pub fn invoke_receive<
    'b,
    BackingStore: BackingStoreLoad,
    R: RunnableCode,
    Ctx1: v0::HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    artifact: Arc<Artifact<ProcessedImports, R>>,
    amount: u64,
    receive_ctx: Ctx1,
    receive_name: &str,
    param: ParameterRef,
    energy: InterpreterEnergy,
    instance_state: InstanceState<'b, BackingStore>,
) -> ExecResult<ReceiveResult<R, Ctx2>> {
    let mut host = ReceiveHost {
        energy,
        stateless: StateLessReceiveHost {
            activation_frames: constants::MAX_ACTIVATION_FRAMES,
            logs: v0::Logs::new(),
            return_value: Vec::new(),
            parameters: vec![param],
            latest_generation: 0,
            receive_ctx,
        },
        state: instance_state,
    };

    let result = artifact.run(&mut host, receive_name, &[Value::I64(amount as i64)]);
    process_receive_result(artifact, host, result)
}

pub fn resume_receive<BackingStore: BackingStoreLoad>(
    interrupted_state: Box<ReceiveInterruptedState<CompiledFunction>>,
    response: InvokeResponse,  // response from the call
    energy: InterpreterEnergy, // remaining energy for execution
    instance_state: InstanceState<'_, BackingStore>, // New instance state
) -> ExecResult<ReceiveResult<CompiledFunction>> {
    let mut host = ReceiveHost {
        stateless: interrupted_state.host,
        energy,
        state: instance_state,
    };
    // invalidate previous entries and iterators.
    host.stateless.latest_generation += 1;
    let response = match response {
        InvokeResponse::Success {
            new_state,
            new_balance,
            data,
        } => {
            host.stateless.receive_ctx.self_balance = new_balance;
            // the response value is constructed by setting the last 5 bytes to 0
            // for the first 3 bytes, the first bit is 1 if the state changed, and 0
            // otherwise the remaining bits are the index of the parameter.
            let tag = if new_state {
                0b1000_0000_0000_0000_0000_0000u64
            } else {
                0
            };
            if let Some(data) = data {
                let len = host.stateless.parameters.len();
                if len > 0b0111_1111_1111_1111_1111_1111 {
                    bail!("Too many calls.")
                }
                host.stateless.parameters.push(data);
                // return the index of the parameter to retrieve.
                (len as u64 | tag) << 40
            } else {
                // modulo the tag, 0 indicates that there is no new response. This works
                // because if there is a response
                // len must be at least 1 since every contract starts by being
                // called with a parameter
                tag << 40
            }
        }
        InvokeResponse::Failure {
            code,
            data,
        } => {
            // state did not change
            if let Some(data) = data {
                let len = host.stateless.parameters.len();
                if len > 0b0111_1111_1111_1111_1111_1111 {
                    bail!("Too many calls.")
                }
                host.stateless.parameters.push(data);
                // return the index of the parameter to retrieve.
                (len as u64) << 40 | code
            } else {
                code
            }
        }
    };
    // push the response from the invoke
    let mut config = interrupted_state.config;
    config.push_value(response);
    let result = interrupted_state.artifact.run_config(&mut host, config);
    process_receive_result(interrupted_state.artifact, host, result)
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
pub fn invoke_receive_from_artifact<
    'a,
    'b,
    BackingStore: BackingStoreLoad,
    Ctx1: v0::HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    artifact_bytes: &'a [u8],
    amount: u64,
    receive_ctx: Ctx1,
    receive_name: &str,
    parameter: ParameterRef,
    energy: InterpreterEnergy,
    instance_state: InstanceState<'b, BackingStore>,
) -> ExecResult<ReceiveResult<CompiledFunctionBytes<'a>, Ctx2>> {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_receive(
        Arc::new(artifact),
        amount,
        receive_ctx,
        receive_name,
        parameter,
        energy,
        instance_state,
    )
}

/// Invokes an receive-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_source<
    'b,
    BackingStore: BackingStoreLoad,
    Ctx1: v0::HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    source_bytes: &[u8],
    amount: u64,
    receive_ctx: Ctx1,
    receive_name: &str,
    parameter: ParameterRef,
    energy: InterpreterEnergy,
    instance_state: InstanceState<'b, BackingStore>,
) -> ExecResult<ReceiveResult<CompiledFunction, Ctx2>> {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(
        Arc::new(artifact),
        amount,
        receive_ctx,
        receive_name,
        parameter,
        energy,
        instance_state,
    )
}

/// Invokes an receive-function from Wasm module bytes, injects the module with
/// metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_with_metering_from_source<
    'b,
    BackingStore: BackingStoreLoad,
    Ctx1: v0::HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    source_bytes: &[u8],
    amount: u64,
    receive_ctx: Ctx1,
    receive_name: &str,
    parameter: ParameterRef,
    energy: InterpreterEnergy,
    instance_state: InstanceState<'b, BackingStore>,
) -> ExecResult<ReceiveResult<CompiledFunction, Ctx2>> {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(
        Arc::new(artifact),
        amount,
        receive_ctx,
        receive_name,
        parameter,
        energy,
        instance_state,
    )
}
