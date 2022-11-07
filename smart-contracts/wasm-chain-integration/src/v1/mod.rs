#[cfg(test)]
mod crypto_primitives_tests;
#[cfg(test)]
mod tests;

#[cfg(feature = "enable-ffi")]
mod ffi;
pub mod trie;
mod types;

use crate::{constants, v0, ExecResult, InterpreterEnergy, OutOfEnergy};
use anyhow::{bail, ensure};
use concordium_contracts_common::{
    AccountAddress, Address, Amount, ChainMetadata, ContractAddress, EntrypointName,
    ModuleReference, OwnedEntrypointName, ReceiveName,
};
use machine::Value;
use sha3::Digest;
use std::{borrow::Borrow, io::Write, sync::Arc};
use trie::BackingStoreLoad;
pub use types::*;
use wasm_transform::{
    artifact::{Artifact, CompiledFunction, CompiledFunctionBytes, RunnableCode},
    machine::{self, ExecutionOutcome, NoInterrupt},
    utils,
};

/// Interrupt triggered by the smart contract to execute an instruction on the
/// host, either an account transfer, a smart contract call or an upgrade
/// instruction.
#[derive(Debug)]
pub enum Interrupt {
    /// Transfer an amount of tokens to the **account**.
    Transfer {
        to:     AccountAddress,
        amount: Amount,
    },
    /// Invoke an entrypoint on the given contract.
    Call {
        address:   ContractAddress,
        parameter: ParameterVec,
        name:      OwnedEntrypointName,
        amount:    Amount,
    },
    /// Upgrade the smart contract code to the provided module.
    Upgrade {
        module_ref: ModuleReference,
    },
    /// Query the balance and staked balance of an account.
    QueryAccountBalance {
        address: AccountAddress,
    },
    /// Query the balance of a contract.
    QueryContractBalance {
        address: ContractAddress,
    },
    /// Query the CCD/EUR and EUR/NRG exchange rates.
    QueryExchangeRates,
}

impl Interrupt {
    /// Whether the logs should be cleared for handling this interrupt or not.
    /// This is somewhat hacky, but it is needed because there are two kinds of
    /// interrupts. The queries which do not affect the state, and the state
    /// affecting ones. The latter ones produce "Interrupt" events in the
    /// scheduler, which record the log trace up to that point in execution.
    /// The query ones do not.
    ///
    /// This is admittedly rather hairy and could be done better. But that is
    /// the semantics we have now, and changing it is a bigger reorganization.
    pub(crate) fn should_clear_logs(&self) -> bool {
        match self {
            Interrupt::Transfer {
                ..
            } => true,
            Interrupt::Call {
                ..
            } => true,
            Interrupt::Upgrade {
                ..
            } => true,
            Interrupt::QueryAccountBalance {
                ..
            } => false,
            Interrupt::QueryContractBalance {
                ..
            } => false,
            Interrupt::QueryExchangeRates => false,
        }
    }
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
                out.write_all(parameter)?;
                let name_str: &str = name.as_entrypoint_name().into();
                out.write_all(&(name_str.as_bytes().len() as u16).to_be_bytes())?;
                out.write_all(name_str.as_bytes())?;
                out.write_all(&amount.micro_ccd.to_be_bytes())?;
                Ok(())
            }
            Interrupt::Upgrade {
                module_ref,
            } => {
                out.push(2u8);
                out.write_all(module_ref.as_ref().as_slice())?;
                Ok(())
            }
            Interrupt::QueryAccountBalance {
                address,
            } => {
                out.push(3u8);
                out.write_all(address.as_ref())?;
                Ok(())
            }
            Interrupt::QueryContractBalance {
                address,
            } => {
                out.push(4u8);
                out.write_all(&address.index.to_be_bytes())?;
                out.write_all(&address.subindex.to_be_bytes())?;
                Ok(())
            }
            Interrupt::QueryExchangeRates => {
                out.push(5u8);
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
    pub energy:                   InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames:        u32,
    /// Logs produced during execution.
    pub logs:                     v0::Logs,
    /// The contract's state.
    pub state:                    InstanceState<'a, BackingStore>,
    /// The response from the call.
    pub return_value:             ReturnValue,
    /// The parameter to the init method.
    pub parameter:                ParamType,
    /// The init context for this invocation.
    pub init_ctx:                 Ctx,
    /// Whether there is a limit on the number of logs and sizes of return
    /// values. Limit removed in P5.
    limit_logs_and_return_values: bool,
}

impl<'a, 'b, BackingStore, Ctx2, Ctx1: Into<Ctx2>>
    From<InitHost<'b, BackingStore, ParameterRef<'a>, Ctx1>>
    for InitHost<'b, BackingStore, ParameterVec, Ctx2>
{
    fn from(host: InitHost<'b, BackingStore, ParameterRef<'a>, Ctx1>) -> Self {
        Self {
            energy: host.energy,
            activation_frames: host.activation_frames,
            logs: host.logs,
            state: host.state,
            return_value: host.return_value,
            parameter: host.parameter.into(),
            init_ctx: host.init_ctx.into(),
            limit_logs_and_return_values: host.limit_logs_and_return_values,
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
/// Part of the receive host that is stored to handle the interrupt.
/// This part is not changed during the handling of the interrupt, however
/// before execution resumes, after returning from handling of the interrupt,
/// the logs and parameters are set appropriately.
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
    /// Configuration determining which options are allowed at runtime.
    pub params:            ReceiveParams,
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
            params:            host.params,
        }
    }
}

mod host {
    //! v1 host function implementations. Functions in this inner module are
    //! mostly just wrappers. They parse relevant arguments from the
    //! machine, e.g., read values from the stack or memory, and push values to
    //! the stack and update the memory, and account for some energy use.
    //! The main logic (e.g., updating state) is usually handed over to the
    //! relevant component (e.g., the state), except when the logic is very
    //! simple. For this reason the functions generally don't have much
    //! documentation on their own, and one should look at underlying
    //! function to determine detailed behaviour.
    //!
    //! These functions are safety-critical, and must withstand malicious use.
    //! Thus they are written in a very defensive way to make sure no out of
    //! bounds accesses occur.
    use std::convert::TryFrom;

    use super::*;
    use concordium_contracts_common::{
        Cursor, EntrypointName, Get, ParseError, ParseResult, ACCOUNT_ADDRESS_SIZE,
    };

    const TRANSFER_TAG: u32 = 0;
    const CALL_TAG: u32 = 1;
    const QUERY_ACCOUNT_BALANCE_TAG: u32 = 2;
    const QUERY_CONTRACT_BALANCE_TAG: u32 = 3;
    const QUERY_EXCHANGE_RATE_TAG: u32 = 4;

    /// Parse the call arguments. This is using the serialization as defined in
    /// the smart contracts code since the arguments will be written by a
    /// smart contract. Returns `Ok(Err(OutOfEnergy))` if there is
    /// insufficient energy.
    fn parse_call_args(
        energy: &mut InterpreterEnergy,
        cursor: &mut Cursor<&[u8]>,
        max_parameter_size: usize,
    ) -> ParseResult<Result<Interrupt, OutOfEnergy>> {
        let address = cursor.get()?;
        let parameter_len: u16 = cursor.get()?;
        if usize::from(parameter_len) > max_parameter_size {
            return Err(ParseError {});
        }
        if energy.tick_energy(constants::copy_parameter_cost(parameter_len.into())).is_err() {
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
        energy: &mut InterpreterEnergy,
        offset: u32,
        bytes: &[u8],
        limit_return_value_size: bool,
    ) -> ExecResult<u32> {
        let length = bytes.len();
        let offset = offset as usize;
        ensure!(offset <= rv.len(), "Cannot write past the offset.");
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("Writing past the end of memory."))?;
        let end = if limit_return_value_size {
            std::cmp::min(end, constants::MAX_CONTRACT_STATE as usize)
        } else {
            end
        };
        if rv.len() < end {
            energy.tick_energy(constants::additional_output_size_cost(
                end as u64 - rv.len() as u64,
            ))?;
            rv.resize(end, 0u8);
        }
        let written = (&mut rv[offset..end]).write(bytes)?;
        Ok(written as u32)
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn write_return_value(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        rv: &mut ReturnValue,
        limit_return_value_size: bool,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        // charge energy linearly in the amount of data written.
        energy.tick_energy(constants::write_output_cost(length))?;
        let end = start + length as usize; // this cannot overflow on 64-bit machines.
        ensure!(end <= memory.len(), "Illegal memory access.");
        let res = write_return_value_helper(
            rv,
            energy,
            offset,
            &memory[start..end],
            limit_return_value_size,
        )?;
        stack.push_value(res);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `invoke` host function.
    pub fn invoke(
        support_queries: bool,
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        max_parameter_size: usize,
    ) -> machine::RunResult<Option<Interrupt>> {
        energy.tick_energy(constants::INVOKE_BASE_COST)?;
        let length = unsafe { stack.pop_u32() } as usize; // length of the instruction payload in memory
        let start = unsafe { stack.pop_u32() } as usize; // start of the instruction payload in memory
        let tag = unsafe { stack.pop_u32() }; // tag of the instruction
        match tag {
            TRANSFER_TAG => {
                ensure!(
                    length == ACCOUNT_ADDRESS_SIZE + 8,
                    "Transfers must have exactly 40 bytes of payload, but was {}",
                    length
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
                match parse_call_args(energy, &mut cursor, max_parameter_size) {
                    Ok(Ok(i)) => Ok(Some(i)),
                    Ok(Err(OutOfEnergy)) => bail!(OutOfEnergy),
                    Err(e) => bail!("Illegal call, cannot parse arguments: {:?}", e),
                }
            }
            QUERY_ACCOUNT_BALANCE_TAG if support_queries => {
                ensure!(
                    length == ACCOUNT_ADDRESS_SIZE,
                    "Account balance queries must have exactly 32 bytes of payload, but was {}",
                    length
                );
                // Overflow is not possible in the next line on 64-bit machines.
                ensure!(start + length <= memory.len(), "Illegal memory access.");
                let mut addr_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
                addr_bytes.copy_from_slice(&memory[start..start + ACCOUNT_ADDRESS_SIZE]);
                let address = AccountAddress(addr_bytes);
                Ok(Interrupt::QueryAccountBalance {
                    address,
                }
                .into())
            }
            QUERY_CONTRACT_BALANCE_TAG if support_queries => {
                ensure!(
                    length == 8 + 8,
                    "Contract balance queries must have exactly 16 bytes of payload, but was {}",
                    length
                );
                // Overflow is not possible in the next line on 64-bit machines.
                ensure!(start + length <= memory.len(), "Illegal memory access.");
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&memory[start..start + 8]);
                let index = u64::from_le_bytes(buf);
                buf.copy_from_slice(&memory[start + 8..start + 16]);
                let subindex = u64::from_le_bytes(buf);
                let address = ContractAddress {
                    index,
                    subindex,
                };
                Ok(Interrupt::QueryContractBalance {
                    address,
                }
                .into())
            }
            QUERY_EXCHANGE_RATE_TAG if support_queries => {
                ensure!(
                    length == 0,
                    "Exchange rate query must have no payload, but was {}",
                    length
                );
                Ok(Interrupt::QueryExchangeRates.into())
            }
            c => bail!("Illegal instruction code {}.", c),
        }
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Get the parameter size. This differs from the v0 version in that it
    /// expects an argument on the stack to indicate which parameter to use.
    pub fn get_parameter_size(
        stack: &mut machine::RuntimeStack,
        parameters: &[impl AsRef<[u8]>],
    ) -> machine::RunResult<()> {
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
    /// Get the parameter section. This differs from the v0 version in that it
    /// expects an argument on the stack to indicate which parameter to use.
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
        energy.tick_energy(constants::copy_parameter_cost(length))?;
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
    /// Handle the `state_lookup_entry` host function. See
    /// [InstanceState::lookup_entry] for detailed documentation.
    pub fn state_lookup_entry<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let key_len = unsafe { stack.pop_u32() };
        let key_start = unsafe { stack.pop_u32() } as usize;
        let key_end = key_start + key_len as usize;
        energy.tick_energy(constants::lookup_entry_cost(key_len))?;
        ensure!(key_end <= memory.len(), "Illegal memory access.");
        let key = &memory[key_start..key_end];
        let result = state.lookup_entry(key);
        stack.push_value(u64::from(result));
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `state_create_entry` host function. See
    /// [InstanceState::create_entry] for detailed documentation.
    pub fn state_create_entry<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let key_len = unsafe { stack.pop_u32() };
        let key_start = unsafe { stack.pop_u32() } as usize;
        let key_end = key_start + key_len as usize;
        energy.tick_energy(constants::create_entry_cost(key_len))?;
        ensure!(key_end <= memory.len(), "Illegal memory access.");
        let key = &memory[key_start..key_end];
        let entry_index = state.create_entry(key)?;
        stack.push_value(u64::from(entry_index));
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `state_delete_entry` host function. See
    /// [InstanceState::delete_entry] for detailed documentation.
    pub fn state_delete_entry<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let key_len = unsafe { stack.pop_u32() };
        let key_start = unsafe { stack.pop_u32() } as usize;
        let key_end = key_start + key_len as usize;
        energy.tick_energy(constants::delete_entry_cost(key_len))?;
        ensure!(key_end <= memory.len(), "Illegal memory access.");
        let key = &memory[key_start..key_end];
        let result = state.delete_entry(key)?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `state_delete_prefix` host function. See
    /// [InstanceState::delete_prefix] for detailed documentation.
    pub fn state_delete_prefix<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
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
    /// Handle the `state_iterator` host function. See
    /// [InstanceState::iterator] for detailed documentation.
    pub fn state_iterator<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
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
    /// Handle the `state_iterator_next` host function. See
    /// [InstanceState::iterator_next] for detailed documentation.
    pub fn state_iterator_next<BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let iter_index = unsafe { stack.pop_u64() };
        let entry_option = state.iterator_next(energy, InstanceStateIterator::from(iter_index))?;
        stack.push_value(u64::from(entry_option));
        Ok(())
    }

    /// Handle the `state_iterator_delete` host function. See
    /// [InstanceState::iterator_delete] for detailed documentation.
    pub fn state_iterator_delete<BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let iter = unsafe { stack.pop_u64() };
        let result = state.iterator_delete(energy, InstanceStateIterator::from(iter))?;
        stack.push_value(result);
        Ok(())
    }

    /// Handle the `state_iterator_key_size` host function. See
    /// [InstanceState::iterator_key_size] for detailed documentation.
    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn state_iterator_key_size<BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::ITERATOR_KEY_SIZE_COST)?;
        // the cost of this function is adequately reflected by the base cost of a
        // function call so we do not charge extra.
        let iter = unsafe { stack.pop_u64() };
        let result = state.iterator_key_size(InstanceStateIterator::from(iter));
        stack.push_value(result);
        Ok(())
    }

    /// Handle the `state_iterator_key_read` host function. See
    /// [InstanceState::iterator_key_read] for detailed documentation.
    pub fn state_iterator_key_read<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let start = unsafe { stack.pop_u32() } as usize;
        let iter = unsafe { stack.pop_u64() };
        energy.tick_energy(constants::copy_from_host_cost(length))?;
        let dest_end = start + length as usize;
        ensure!(dest_end <= memory.len(), "Illegal memory access.");
        let dest = &mut memory[start..dest_end];
        let result = state.iterator_key_read(InstanceStateIterator::from(iter), dest, offset);
        stack.push_value(result);
        Ok(())
    }

    /// Handle the `state_entry_read` host function. See
    /// [InstanceState::entry_read] for detailed documentation.
    pub fn state_entry_read<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let dest_start = unsafe { stack.pop_u32() } as usize;
        let entry_index = unsafe { stack.pop_u64() };
        energy.tick_energy(constants::read_entry_cost(length))?;
        let dest_end = dest_start + length as usize;
        ensure!(dest_end <= memory.len(), "Illegal memory access.");
        let dest = &mut memory[dest_start..dest_end];
        let result = state.entry_read(InstanceStateEntry::from(entry_index), dest, offset);
        stack.push_value(result);
        Ok(())
    }

    /// Handle the `state_entry_write` host function. See
    /// [InstanceState::entry_write] for detailed documentation.
    pub fn state_entry_write<BackingStore: BackingStoreLoad>(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let offset = unsafe { stack.pop_u32() };
        let length = unsafe { stack.pop_u32() };
        let source_start = unsafe { stack.pop_u32() } as usize;
        let entry_index = unsafe { stack.pop_u64() };
        energy.tick_energy(constants::write_entry_cost(length))?;
        let source_end = source_start + length as usize;
        ensure!(source_end <= memory.len(), "Illegal memory access.");
        let source = &memory[source_start..source_end];
        let result =
            state.entry_write(energy, InstanceStateEntry::from(entry_index), source, offset)?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `state_entry_size` host function. See
    /// [InstanceState::entry_size] for detailed documentation.
    pub fn state_entry_size<BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        let entry_index = unsafe { stack.pop_u64() };
        energy.tick_energy(constants::ENTRY_SIZE_COST)?;
        let result = state.entry_size(InstanceStateEntry::from(entry_index));
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `state_entry_resize` host function. See
    /// [InstanceState::entry_resize] for detailed documentation.
    pub fn state_entry_resize<BackingStore: BackingStoreLoad>(
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
        state: &mut InstanceState<BackingStore>,
    ) -> machine::RunResult<()> {
        energy.tick_energy(constants::RESIZE_ENTRY_BASE_COST)?;
        let new_size = unsafe { stack.pop_u32() };
        let entry_index = unsafe { stack.pop_u64() };
        let result = state.entry_resize(energy, InstanceStateEntry::from(entry_index), new_size)?;
        stack.push_value(result);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `get_receive_entrypoint_size` host function.
    pub fn get_receive_entrypoint_size(
        stack: &mut machine::RuntimeStack,
        entrypoint: EntrypointName,
    ) -> machine::RunResult<()> {
        let size: u32 = entrypoint.size();
        stack.push_value(size);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `get_receive_entrypoint` host function.
    pub fn get_receive_entrypoint(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        entrypoint: EntrypointName,
    ) -> machine::RunResult<()> {
        let start = unsafe { stack.pop_u32() };
        let size = entrypoint.size();
        // overflow here is not possible on 64-bit machines
        let end: usize = start as usize + size as usize;
        ensure!(end <= memory.len(), "Illegal memory access.");
        let entrypoint_str: &str = entrypoint.into();
        memory[start as usize..end].copy_from_slice(entrypoint_str.as_bytes());
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn verify_ed25519_signature(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<()> {
        let message_len = unsafe { stack.pop_u32() };
        let message_start = unsafe { stack.pop_u32() };
        let signature_start = unsafe { stack.pop_u32() };
        let public_key_start = unsafe { stack.pop_u32() };
        let message_end = message_start as usize + message_len as usize;
        ensure!(message_end <= memory.len(), "Illegal memory access.");
        let public_key_end = public_key_start as usize + 32;
        ensure!(public_key_end <= memory.len(), "Illegal memory access.");
        let signature_end = signature_start as usize + 64;
        ensure!(signature_end <= memory.len(), "Illegal memory access.");
        // expensive operations start now.
        energy.tick_energy(constants::verify_ed25519_cost(message_len))?;
        let signature =
            ed25519_zebra::Signature::try_from(&memory[signature_start as usize..signature_end]);
        let message = &memory[message_start as usize..message_end];
        let public_key = ed25519_zebra::VerificationKey::try_from(
            &memory[public_key_start as usize..public_key_end],
        );
        match (signature, public_key) {
            (Ok(ref signature), Ok(public_key)) => {
                if public_key.verify(signature, message).is_ok() {
                    stack.push_value(1u32);
                } else {
                    stack.push_value(0u32);
                }
            }
            _ => stack.push_value(0u32),
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn verify_ecdsa_secp256k1_signature(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<()> {
        let message_start = unsafe { stack.pop_u32() };
        let signature_start = unsafe { stack.pop_u32() };
        let public_key_start = unsafe { stack.pop_u32() };
        let message_end = message_start as usize + 32;
        ensure!(message_end <= memory.len(), "Illegal memory access.");
        let public_key_end = public_key_start as usize + 33;
        ensure!(public_key_end <= memory.len(), "Illegal memory access.");
        let signature_end = signature_start as usize + 64;
        ensure!(signature_end <= memory.len(), "Illegal memory access.");
        // expensive operations start now.
        energy.tick_energy(constants::VERIFY_ECDSA_SECP256K1_COST)?;
        let signature = secp256k1::ecdsa::Signature::from_compact(
            &memory[signature_start as usize..signature_end],
        );
        let message = secp256k1::Message::from_slice(&memory[message_start as usize..message_end]);
        let public_key =
            secp256k1::PublicKey::from_slice(&memory[public_key_start as usize..public_key_end]);
        match (signature, message, public_key) {
            (Ok(signature), Ok(message), Ok(public_key)) => {
                let verifier = secp256k1::Secp256k1::verification_only();
                if verifier.verify_ecdsa(&message, &signature, &public_key).is_ok() {
                    stack.push_value(1u32);
                } else {
                    stack.push_value(0u32);
                }
            }
            _ => stack.push_value(0u32),
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn hash_sha2_256(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<()> {
        let output_start = unsafe { stack.pop_u32() };
        let data_len = unsafe { stack.pop_u32() };
        let data_start = unsafe { stack.pop_u32() };
        let data_end = data_start as usize + data_len as usize;
        ensure!(data_end <= memory.len(), "Illegal memory access.");
        let output_end = output_start as usize + 32;
        ensure!(output_end <= memory.len(), "Illegal memory access.");
        // expensive operations start here
        energy.tick_energy(constants::hash_sha2_256_cost(data_len))?;
        let hash = sha2::Sha256::digest(&memory[data_start as usize..data_end]);
        memory[output_start as usize..output_end].copy_from_slice(&hash);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn hash_sha3_256(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<()> {
        let output_start = unsafe { stack.pop_u32() };
        let data_len = unsafe { stack.pop_u32() };
        let data_start = unsafe { stack.pop_u32() };
        let data_end = data_start as usize + data_len as usize;
        ensure!(data_end <= memory.len(), "Illegal memory access.");
        let output_end = output_start as usize + 32;
        ensure!(output_end <= memory.len(), "Illegal memory access.");
        // expensive operations start here
        energy.tick_energy(constants::hash_sha3_256_cost(data_len))?;
        let hash = sha3::Sha3_256::digest(&memory[data_start as usize..data_end]);
        memory[output_start as usize..output_end].copy_from_slice(&hash);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub fn hash_keccak_256(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<()> {
        let output_start = unsafe { stack.pop_u32() };
        let data_len = unsafe { stack.pop_u32() };
        let data_start = unsafe { stack.pop_u32() };
        let data_end = data_start as usize + data_len as usize;
        ensure!(data_end <= memory.len(), "Illegal memory access.");
        let output_end = output_start as usize + 32;
        ensure!(output_end <= memory.len(), "Illegal memory access.");
        // expensive operations start here
        energy.tick_energy(constants::hash_keccak_256_cost(data_len))?;
        let hash = sha3::Keccak256::digest(&memory[data_start as usize..data_end]);
        memory[output_start as usize..output_end].copy_from_slice(&hash);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `upgrade` host function.
    pub fn upgrade(
        memory: &mut Vec<u8>,
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<Option<Interrupt>> {
        let module_ref_start = unsafe { stack.pop_u32() } as usize;
        let module_ref_end = module_ref_start + 32;
        ensure!(module_ref_end <= memory.len(), "Illegal memory access.");
        let mut module_reference_bytes = [0u8; 32];
        module_reference_bytes.copy_from_slice(&memory[module_ref_start..module_ref_end]);
        let module_ref = ModuleReference::from(module_reference_bytes);
        // We tick a base action cost here and
        // tick the remaining cost in the 'Scheduler' as it knows the size
        // of the new module.
        energy.tick_energy(constants::INVOKE_BASE_COST)?;
        Ok(Some(Interrupt::Upgrade {
            module_ref,
        }))
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
                    self.limit_logs_and_return_values,
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
                CommonFunc::LogEvent => v0::host::log_event(
                    memory,
                    stack,
                    &mut self.energy,
                    &mut self.logs,
                    self.limit_logs_and_return_values,
                ),
                CommonFunc::GetSlotTime => v0::host::get_slot_time(stack, self.init_ctx.metadata()),
                CommonFunc::StateLookupEntry => {
                    host::state_lookup_entry(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateCreateEntry => {
                    host::state_create_entry(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateDeleteEntry => {
                    host::state_delete_entry(memory, stack, &mut self.energy, &mut self.state)
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
                CommonFunc::StateEntrySize => {
                    host::state_entry_size(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntryResize => {
                    host::state_entry_resize(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::VerifyEd25519 => {
                    host::verify_ed25519_signature(memory, stack, &mut self.energy)
                }
                CommonFunc::VerifySecp256k1 => {
                    host::verify_ecdsa_secp256k1_signature(memory, stack, &mut self.energy)
                }
                CommonFunc::HashSHA2_256 => host::hash_sha2_256(memory, stack, &mut self.energy),
                CommonFunc::HashSHA3_256 => host::hash_sha3_256(memory, stack, &mut self.energy),
                CommonFunc::HashKeccak256 => host::hash_keccak_256(memory, stack, &mut self.energy),
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

/// A receive context for V1 contracts.
pub trait HasReceiveContext: v0::HasReceiveContext {
    /// Get the name of the entrypoint that was actually invoked.
    /// This may differ from the name of the entrypoint that is actually invoked
    /// in case the entrypoint that is invoked is the fallback one.
    fn entrypoint(&self) -> ExecResult<EntrypointName>;
}

impl<X: AsRef<[u8]>> v0::HasReceiveContext for ReceiveContext<X> {
    type MetadataType = ChainMetadata;

    fn metadata(&self) -> &Self::MetadataType { &self.common.metadata }

    fn invoker(&self) -> ExecResult<&AccountAddress> { Ok(&self.common.invoker) }

    fn self_address(&self) -> ExecResult<&ContractAddress> { Ok(&self.common.self_address) }

    fn self_balance(&self) -> ExecResult<Amount> { Ok(self.common.self_balance) }

    fn sender(&self) -> ExecResult<&Address> { Ok(&self.common.sender) }

    fn owner(&self) -> ExecResult<&AccountAddress> { Ok(&self.common.owner) }

    fn sender_policies(&self) -> ExecResult<&[u8]> { Ok(self.common.sender_policies.as_ref()) }
}

impl<X: AsRef<[u8]>> HasReceiveContext for ReceiveContext<X> {
    #[inline(always)]
    fn entrypoint(&self) -> ExecResult<EntrypointName> { Ok(self.entrypoint.as_entrypoint_name()) }
}

impl<'a, X: HasReceiveContext> HasReceiveContext for &'a X {
    #[inline(always)]
    fn entrypoint(&self) -> ExecResult<EntrypointName> { (*self).entrypoint() }
}

impl<'a, BackingStore: BackingStoreLoad, ParamType: AsRef<[u8]>, Ctx: HasReceiveContext>
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
                    self.stateless.params.limit_logs_and_return_values,
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
                CommonFunc::LogEvent => v0::host::log_event(
                    memory,
                    stack,
                    &mut self.energy,
                    &mut self.stateless.logs,
                    self.stateless.params.limit_logs_and_return_values,
                ),
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
                    host::state_delete_entry(memory, stack, &mut self.energy, &mut self.state)
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
                CommonFunc::StateEntrySize => {
                    host::state_entry_size(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateEntryResize => {
                    host::state_entry_resize(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::VerifyEd25519 => {
                    host::verify_ed25519_signature(memory, stack, &mut self.energy)
                }
                CommonFunc::VerifySecp256k1 => {
                    host::verify_ecdsa_secp256k1_signature(memory, stack, &mut self.energy)
                }
                CommonFunc::HashSHA2_256 => host::hash_sha2_256(memory, stack, &mut self.energy),
                CommonFunc::HashSHA3_256 => host::hash_sha3_256(memory, stack, &mut self.energy),
                CommonFunc::HashKeccak256 => host::hash_keccak_256(memory, stack, &mut self.energy),
            }?,
            ImportFunc::ReceiveOnly(rof) => match rof {
                ReceiveOnlyFunc::Invoke => {
                    return host::invoke(
                        self.stateless.params.support_queries,
                        memory,
                        stack,
                        &mut self.energy,
                        self.stateless.params.max_parameter_size,
                    );
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
                ReceiveOnlyFunc::GetReceiveEntrypointSize => host::get_receive_entrypoint_size(
                    stack,
                    self.stateless.receive_ctx.entrypoint()?,
                ),
                ReceiveOnlyFunc::GetReceiveEntryPoint => host::get_receive_entrypoint(
                    memory,
                    stack,
                    self.stateless.receive_ctx.entrypoint()?,
                ),
                ReceiveOnlyFunc::Upgrade => {
                    return host::upgrade(memory, stack, &mut self.energy);
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

/// Collection of information relevant to invoke a init-function.
#[derive(Debug)]
pub struct InitInvocation<'a> {
    /// The amount included in the transaction.
    pub amount:    Amount,
    /// The name of the init function to invoke.
    pub init_name: &'a str,
    /// A parameter to provide the init function.
    pub parameter: ParameterRef<'a>,
    /// The limit on the energy to be used for execution.
    pub energy:    InterpreterEnergy,
}

/// Invokes an init-function from a given artifact
pub fn invoke_init<BackingStore: BackingStoreLoad, R: RunnableCode>(
    artifact: impl Borrow<Artifact<ProcessedImports, R>>,
    init_ctx: impl v0::HasInitContext,
    init_invocation: InitInvocation,
    limit_logs_and_return_values: bool,
    mut loader: BackingStore,
) -> ExecResult<InitResult> {
    let mut initial_state = trie::MutableState::initial_state();
    let inner = initial_state.get_inner(&mut loader);
    let state_ref = InstanceState::new(loader, inner);
    let mut host = InitHost {
        energy: init_invocation.energy,
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: v0::Logs::new(),
        state: state_ref,
        return_value: Vec::new(),
        parameter: init_invocation.parameter,
        limit_logs_and_return_values,
        init_ctx,
    };
    let result = artifact.borrow().run(&mut host, init_invocation.init_name, &[Value::I64(
        init_invocation.amount.micro_ccd() as i64,
    )]);
    let return_value = std::mem::take(&mut host.return_value);
    let remaining_energy = host.energy.energy;
    let logs = std::mem::take(&mut host.logs);
    // release lock on the state
    drop(host);
    match result {
        Ok(ExecutionOutcome::Success {
            result,
            ..
        }) => {
            // process the return value.
            // - 0 indicates success
            // - positive values are a protocol violation, so they lead to a runtime error
            // - negative values lead to a rejection with a specific reject reason.
            if let Some(Value::I32(n)) = result {
                if n == 0 {
                    Ok(InitResult::Success {
                        logs,
                        return_value,
                        remaining_energy,
                        state: initial_state,
                    })
                } else {
                    Ok(InitResult::Reject {
                        reason: reason_from_wasm_error_code(n)?,
                        return_value,
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
                    remaining_energy,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
/// The kind of errors that may occur during handling of contract `invoke` or
/// `upgrade`.
pub enum InvokeFailure {
    /// The V1 contract rejected the call with the specific code. The code is
    /// always negative.
    ContractReject {
        code: i32,
        data: ParameterVec,
    },
    /// A transfer was attempted, but the sender did not have sufficient funds.
    InsufficientAmount,
    /// The receiving account of the transfer did not exist.
    NonExistentAccount,
    /// Contract to invoke did not exist (i.e., there is no contract on the
    /// supplied address).
    NonExistentContract,
    /// The contract existed, but the entrypoint did not.
    NonExistentEntrypoint,
    /// Sending a message to a V0 contact failed.
    SendingV0Failed,
    /// Invoking a contract failed with a runtime error.
    RuntimeError,
    UpgradeInvalidModuleRef,
    UpgradeInvalidContractName,
    UpgradeInvalidVersion,
}

impl InvokeFailure {
    /// Encode the failure kind in a format that is expected from a host
    /// function. If the return value is present it is pushed to the supplied
    /// vector of parameters.
    pub(crate) fn encode_as_u64(self, parameters: &mut Vec<ParameterVec>) -> anyhow::Result<u64> {
        Ok(match self {
            InvokeFailure::ContractReject {
                code,
                data,
            } => {
                let len = parameters.len();
                if len > 0b0111_1111_1111_1111_1111_1111 {
                    bail!("Too many calls.")
                }
                parameters.push(data);
                (len as u64) << 40 | (code as u32 as u64)
            }
            InvokeFailure::InsufficientAmount => 0x01_0000_0000,
            InvokeFailure::NonExistentAccount => 0x02_0000_0000,
            InvokeFailure::NonExistentContract => 0x03_0000_0000,
            InvokeFailure::NonExistentEntrypoint => 0x04_0000_0000,
            InvokeFailure::SendingV0Failed => 0x05_0000_0000,
            InvokeFailure::RuntimeError => 0x06_0000_0000,
            InvokeFailure::UpgradeInvalidModuleRef => 0x07_0000_0000,
            InvokeFailure::UpgradeInvalidContractName => 0x08_0000_0000,
            InvokeFailure::UpgradeInvalidVersion => 0x09_0000_0000,
        })
    }
}

/// Response from an invoke call.
pub enum InvokeResponse {
    /// Execution was successful, and the state potentially changed.
    Success {
        /// Balance after the execution of the interrupt.
        new_balance: Amount,
        /// Some calls do not have any return values, such as transfers.
        data:        Option<ParameterVec>,
    },
    /// Execution was not successful. The state did not change
    /// and the contract or environment responded with the given error.
    Failure {
        kind: InvokeFailure,
    },
}

#[cfg(feature = "enable-ffi")]
impl InvokeResponse {
    // NB: This must match the response encoding in V1.hs in consensus
    pub(crate) fn try_from_ffi_response(
        response_status: u64,
        new_balance: Amount,
        data: Option<ParameterVec>,
    ) -> anyhow::Result<Self> {
        // If the first 3 bytes are all set that indicates an error.
        let response = if response_status & 0xffff_ff00_0000_0000 == 0xffff_ff00_0000_0000 {
            let kind = match response_status & 0x0000_00ff_0000_0000 {
                0x0000_0000_0000_0000 => {
                    // The return value is present since this was a logic error.
                    if response_status & 0x0000_0000_ffff_ffff == 0 {
                        // Host violated precondition. There must be a non-zero error code.
                        bail!("Host violated precondition.")
                    }
                    let code = (response_status & 0x0000_0000_ffff_ffff) as u32 as i32;
                    if let Some(data) = data {
                        InvokeFailure::ContractReject {
                            code,
                            data,
                        }
                    } else {
                        bail!("Return value should be present in case of logic error.")
                    }
                }
                0x0000_0001_0000_0000 => InvokeFailure::InsufficientAmount,
                0x0000_0002_0000_0000 => InvokeFailure::NonExistentAccount,
                0x0000_0003_0000_0000 => InvokeFailure::NonExistentContract,
                0x0000_0004_0000_0000 => InvokeFailure::NonExistentEntrypoint,
                0x0000_0005_0000_0000 => InvokeFailure::SendingV0Failed,
                0x0000_0006_0000_0000 => InvokeFailure::RuntimeError,
                0x0000_0007_0000_0000 => InvokeFailure::UpgradeInvalidModuleRef,
                0x0000_0008_0000_0000 => InvokeFailure::UpgradeInvalidContractName,
                0x0000_0009_0000_0000 => InvokeFailure::UpgradeInvalidVersion,
                x => bail!("Unrecognized error code: {}", x),
            };
            InvokeResponse::Failure {
                kind,
            }
        } else {
            InvokeResponse::Success {
                new_balance,
                data,
            }
        };
        Ok(response)
    }
}

#[derive(Copy, Clone, Debug)]
/// Common data used by the `invoke_*_from_artifact` family of functions.
pub struct InvokeFromArtifactCtx<'a> {
    /// The source of the artifact, serialized in the format specified by the
    /// `wasm_transform` crate.
    pub artifact:  &'a [u8],
    /// Amount to invoke with.
    pub amount:    Amount,
    /// Parameter to supply to the call.
    pub parameter: ParameterRef<'a>,
    /// Energy to allow for execution.
    pub energy:    InterpreterEnergy,
}

/// Invokes an init-function from a given artifact *bytes*
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_artifact<BackingStore: BackingStoreLoad>(
    ctx: InvokeFromArtifactCtx,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    loader: BackingStore,
    limit_logs_and_return_values: bool,
) -> ExecResult<InitResult> {
    let artifact = utils::parse_artifact(ctx.artifact)?;
    invoke_init(
        artifact,
        init_ctx,
        InitInvocation {
            amount: ctx.amount,
            init_name,
            parameter: ctx.parameter,
            energy: ctx.energy,
        },
        limit_logs_and_return_values,
        loader,
    )
}

#[derive(Copy, Clone, Debug)]
/// Common data used by the `invoke_*_from_source` family of functions.
pub struct InvokeFromSourceCtx<'a> {
    /// The source Wasm module.
    pub source:          &'a [u8],
    /// Amount to invoke with.
    pub amount:          Amount,
    /// Parameter to supply to the call.
    pub parameter:       ParameterRef<'a>,
    /// Energy to allow for execution.
    pub energy:          InterpreterEnergy,
    /// Whether the module should be processed to allow upgrades or not.
    /// Upgrades are only allowed in protocol P5 and later. If this is set to
    /// `false` then parsing and validation will reject modules that use the
    /// `upgrade` function.
    pub support_upgrade: bool,
}

/// Invokes an init-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_source<BackingStore: BackingStoreLoad>(
    ctx: InvokeFromSourceCtx,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    loader: BackingStore,
    limit_logs_and_return_values: bool,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate(
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
        },
        ctx.source,
    )?;
    invoke_init(
        artifact,
        init_ctx,
        InitInvocation {
            amount: ctx.amount,
            init_name,
            parameter: ctx.parameter,
            energy: ctx.energy,
        },
        limit_logs_and_return_values,
        loader,
    )
}

/// Same as `invoke_init_from_source`, except that the module has cost
/// accounting instructions inserted before the init function is called.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_with_metering_from_source<BackingStore: BackingStoreLoad>(
    ctx: InvokeFromSourceCtx,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    loader: BackingStore,
    limit_logs_and_return_values: bool,
) -> ExecResult<InitResult> {
    let artifact = utils::instantiate_with_metering(
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
        },
        ctx.source,
    )?;
    invoke_init(
        artifact,
        init_ctx,
        InitInvocation {
            amount: ctx.amount,
            init_name,
            parameter: ctx.parameter,
            energy: ctx.energy,
        },
        limit_logs_and_return_values,
        loader,
    )
}

fn process_receive_result<
    BackingStore,
    Param,
    R: RunnableCode,
    Art: Into<Arc<Artifact<ProcessedImports, R>>>,
    Ctx1,
    Ctx2,
>(
    artifact: Art,
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
                        state_changed: host.state.changed,
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
            // Logs are returned per section that is executed.
            // So here we set the host logs to empty and return any
            // existing logs.
            let logs = if reason.should_clear_logs() {
                std::mem::take(&mut stateless.logs)
            } else {
                v0::Logs::new()
            };
            let state_changed = host.state.changed;
            let host = SavedHost {
                stateless:          stateless.into(),
                current_generation: host.state.current_generation,
                entry_mapping:      host.state.entry_mapping,
                iterators:          host.state.iterators,
            };
            Ok(ReceiveResult::Interrupt {
                remaining_energy,
                state_changed,
                logs,
                config: Box::new(ReceiveInterruptedState {
                    host,
                    artifact: artifact.into(),
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

/// Runtime parameters that affect the limits placed on the
/// entrypoint execution.
#[derive(Debug, Clone, Copy)]
pub struct ReceiveParams {
    /// Maximum size of a parameter that an `invoke` operation can have.
    pub max_parameter_size:           usize,
    /// Whether the amount of logs a contract may produce, and the size of the
    /// logs, is limited.
    pub limit_logs_and_return_values: bool,
    /// Whether queries should be supported or not. Queries were introduced in
    /// protocol 5.
    pub support_queries:              bool,
}

impl ReceiveParams {
    /// Parameters that are in effect in protocol version 4.
    pub fn new_p4() -> Self {
        Self {
            max_parameter_size:           1024,
            limit_logs_and_return_values: true,
            support_queries:              false,
        }
    }

    /// Parameters that are in effect in protocol version 5 and up.
    pub fn new_p5() -> Self {
        Self {
            max_parameter_size:           u16::MAX.into(),
            limit_logs_and_return_values: false,
            support_queries:              true,
        }
    }
}

/// Collection of information relevant to invoke a receive-function.
#[derive(Debug)]
pub struct ReceiveInvocation<'a> {
    /// The amount included in the transaction.
    pub amount:       Amount,
    /// The name of the receive function to invoke.
    pub receive_name: ReceiveName<'a>,
    /// A parameter to provide the receive function.
    pub parameter:    ParameterRef<'a>,
    /// The limit on the energy to be used for execution.
    pub energy:       InterpreterEnergy,
}

/// Invokes an receive-function from a given artifact
pub fn invoke_receive<
    BackingStore: BackingStoreLoad,
    R1: RunnableCode,
    R2: RunnableCode,
    Art: Borrow<Artifact<ProcessedImports, R1>> + Into<Arc<Artifact<ProcessedImports, R2>>>,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    artifact: Art,
    receive_ctx: Ctx1,
    receive_invocation: ReceiveInvocation,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> ExecResult<ReceiveResult<R2, Ctx2>> {
    let mut host = ReceiveHost {
        energy:    receive_invocation.energy,
        stateless: StateLessReceiveHost {
            activation_frames: constants::MAX_ACTIVATION_FRAMES,
            logs: v0::Logs::new(),
            return_value: Vec::new(),
            parameters: vec![receive_invocation.parameter],
            receive_ctx,
            params,
        },
        state:     instance_state,
    };

    let result =
        artifact.borrow().run(&mut host, receive_invocation.receive_name.get_chain_name(), &[
            Value::I64(receive_invocation.amount.micro_ccd() as i64),
        ]);
    process_receive_result(artifact, host, result)
}

/// Resume execution of the receive method after handling the interrupt.
/// The arguments
///
/// - `interrupted_state` is the state of execution that is captured when we
///   started handling the interrupt
/// - `response` is the response from the operation that was invoked
/// - `energy` is the remaning energy left for execution
/// - `state_trie` is the current state of the contract instance, **after**
///   handling the interrupt
/// - `state_updated` indicates whether the state of the instance has changed
///   during handling of the operation This can currently only happen if there
///   is re-entrancy, i.e., if during handling of the interrupt the instance
///   that invoked it is itself again invoked.
/// - `backing_store` gives access to any on-disk storage for the instance
///   state.
pub fn resume_receive<BackingStore: BackingStoreLoad>(
    interrupted_state: Box<ReceiveInterruptedState<CompiledFunction>>,
    response: InvokeResponse,  // response from the call
    energy: InterpreterEnergy, // remaining energy for execution
    state_trie: &mut trie::MutableState,
    state_updated: bool,
    mut backing_store: BackingStore,
) -> ExecResult<ReceiveResult<CompiledFunction>> {
    let inner = state_trie.get_inner(&mut backing_store);
    let state = InstanceState::migrate(
        state_updated,
        interrupted_state.host.current_generation,
        interrupted_state.host.entry_mapping,
        interrupted_state.host.iterators,
        backing_store,
        inner,
    );
    let mut host = ReceiveHost {
        stateless: interrupted_state.host.stateless,
        energy,
        state,
    };
    let response = match response {
        InvokeResponse::Success {
            new_balance,
            data,
        } => {
            host.stateless.receive_ctx.common.self_balance = new_balance;
            // the response value is constructed by setting the last 5 bytes to 0
            // for the first 3 bytes, the first bit is 1 if the state changed, and 0
            // otherwise the remaining bits are the index of the parameter.
            let tag = if state_updated {
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
            kind,
        } => kind.encode_as_u64(&mut host.stateless.parameters)?,
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
    BackingStore: BackingStoreLoad,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    ctx: InvokeFromArtifactCtx<'a>,
    receive_ctx: Ctx1,
    receive_name: ReceiveName,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> ExecResult<ReceiveResult<CompiledFunctionBytes<'a>, Ctx2>> {
    let artifact = utils::parse_artifact(ctx.artifact)?;
    invoke_receive(
        Arc::new(artifact),
        receive_ctx,
        ReceiveInvocation {
            energy: ctx.energy,
            parameter: ctx.parameter,
            receive_name,
            amount: ctx.amount,
        },
        instance_state,
        params,
    )
}

/// Invokes an receive-function from Wasm module bytes.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_source<
    BackingStore: BackingStoreLoad,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    ctx: InvokeFromSourceCtx,
    receive_ctx: Ctx1,
    receive_name: ReceiveName,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> ExecResult<ReceiveResult<CompiledFunction, Ctx2>> {
    let artifact = utils::instantiate(
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
        },
        ctx.source,
    )?;
    invoke_receive(
        Arc::new(artifact),
        receive_ctx,
        ReceiveInvocation {
            amount: ctx.amount,
            receive_name,
            parameter: ctx.parameter,
            energy: ctx.energy,
        },
        instance_state,
        params,
    )
}

/// Invokes an receive-function from Wasm module bytes, injects the module with
/// metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_with_metering_from_source<
    BackingStore: BackingStoreLoad,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
>(
    ctx: InvokeFromSourceCtx,
    receive_ctx: Ctx1,
    receive_name: ReceiveName,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> ExecResult<ReceiveResult<CompiledFunction, Ctx2>> {
    let artifact = utils::instantiate_with_metering(
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
        },
        ctx.source,
    )?;
    invoke_receive(
        Arc::new(artifact),
        receive_ctx,
        ReceiveInvocation {
            amount: ctx.amount,
            receive_name,
            parameter: ctx.parameter,
            energy: ctx.energy,
        },
        instance_state,
        params,
    )
}
