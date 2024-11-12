//! Implementation of execution of V1 contracts.
//!
//! This contains only the execution of the Wasm parts and does not include the
//! handling of invoked operations (e.g., calling another contract, sending
//! transfers). That is handled by a separate scheduler component.
//!
//! The main entrypoints in this module are
//! - [`invoke_init`] for invoking an init function to create a new instance
//! - [`invoke_receive`] for invoking an entrypoint of an existing instance
//! - [`resume_receive`] for resuming execution of an interrupted entrypoint
//!
//! These methods are intended to be used on [`Artifact`]'s obtained using
//! [`instantiate_with_metering`](utils::instantiate_with_metering) using
//! [`ConcordiumAllowedImports`] for handling imports.
//!
//! In addition to the above methods there are auxiliary helpers
//! - [`invoke_init_from_artifact`] and [`invoke_receive_from_artifact`] which
//!   first parse an [`Artifact`] and then run the corresponding `invoke_*`
//!   function.
//! - [`invoke_init_from_source`] and [`invoke_receive_from_source`] which first
//!   parse and validate a Wasm module, then convert it to an [`Artifact`], and
//!   then run it using the appropriate `invoke_*` function.
//! - [`invoke_init_with_metering_from_source`] and
//!   [`invoke_receive_with_metering_from_source`] which first parse and
//!   validate the Wasm module, then inject cost metering instructions, and then
//!   convert it to an [`Artifact`] and run it using the appropriate `invoke_*`
//!   function.
#[cfg(test)]
mod crypto_primitives_tests;
#[cfg(test)]
mod tests;

#[cfg(feature = "enable-ffi")]
mod ffi;
pub mod trie;
mod types;

use crate::{constants, v0, DebugInfo, ExecResult, InterpreterEnergy, OutOfEnergy};
use anyhow::{bail, ensure};
use concordium_contracts_common::{
    AccountAddress, Address, Amount, ChainMetadata, ContractAddress, EntrypointName,
    ModuleReference, OwnedEntrypointName, ReceiveName,
};
use concordium_wasm::{
    artifact::{Artifact, CompiledFunction, CompiledFunctionBytes, RunnableCode},
    machine::{self, ExecutionOutcome, NoInterrupt},
    utils,
    validate::ValidationConfig,
    CostConfiguration,
};
use machine::Value;
use sha3::Digest;
use std::{borrow::Borrow, collections::BTreeMap, io::Write, sync::Arc};
use trie::BackingStoreLoad;
pub use types::*;

#[derive(thiserror::Error, Debug)]
/// An invalid return value was returned by the call.
/// Allowed return values are either 0 for success, or negative for signalling
/// errors.
#[error("Unexpected return value from the invocation: {value:?}")]
pub struct InvalidReturnCodeError<Debug> {
    pub value:       Option<i32>,
    pub debug_trace: Debug,
}

impl<R, Debug: DebugInfo, Ctx> From<InvalidReturnCodeError<Debug>>
    for types::ReceiveResult<R, Debug, Ctx>
{
    fn from(value: InvalidReturnCodeError<Debug>) -> Self {
        Self::Trap {
            error:            anyhow::anyhow!("Invalid return code: {:?}", value.value),
            remaining_energy: 0.into(), // We consume all energy in case of protocol violation.
            trace:            value.debug_trace,
        }
    }
}

/// An alias for the return type of the `invoke_*` family of functions.
pub type InvokeResult<A, Debug> = Result<A, InvalidReturnCodeError<Debug>>;

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
    /// Check signatures on the provided data.
    CheckAccountSignature {
        address: AccountAddress,
        payload: Vec<u8>,
    },
    /// Query account keys.
    QueryAccountKeys {
        address: AccountAddress,
    },
    /// Query the module reference of a contract.
    QueryContractModuleReference {
        address: ContractAddress,
    },
    /// Query the constructor name of a contract.
    QueryContractName {
        address: ContractAddress,
    },
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
            Interrupt::CheckAccountSignature {
                ..
            } => false,
            Interrupt::QueryAccountKeys {
                ..
            } => false,
            Interrupt::QueryContractModuleReference {
                ..
            } => false,
            Interrupt::QueryContractName {
                ..
            } => false,
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
                out.write_all(module_ref.as_ref())?;
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
            Interrupt::CheckAccountSignature {
                address,
                payload,
            } => {
                out.push(6u8);
                out.write_all(address.as_ref())?;
                out.write_all(&(payload.len() as u64).to_be_bytes())?;
                out.write_all(payload)?;
                Ok(())
            }
            Interrupt::QueryAccountKeys {
                address,
            } => {
                out.push(7u8);
                out.write_all(address.as_ref())?;
                Ok(())
            }
            Interrupt::QueryContractModuleReference {
                address,
            } => {
                out.push(8u8);
                out.write_all(&address.index.to_be_bytes())?;
                out.write_all(&address.subindex.to_be_bytes())?;
                Ok(())
            }
            Interrupt::QueryContractName {
                address,
            } => {
                out.push(9u8);
                out.write_all(&address.index.to_be_bytes())?;
                out.write_all(&address.subindex.to_be_bytes())?;
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
pub(crate) struct InitHost<'a, BackingStore, ParamType, Ctx, A: DebugInfo> {
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
    pub trace:                    A,
}

impl<'a, 'b, BackingStore, Ctx2, Ctx1: Into<Ctx2>, A: DebugInfo>
    From<InitHost<'b, BackingStore, ParameterRef<'a>, Ctx1, A>>
    for InitHost<'b, BackingStore, ParameterVec, Ctx2, A>
{
    fn from(host: InitHost<'b, BackingStore, ParameterRef<'a>, Ctx1, A>) -> Self {
        Self {
            energy: host.energy,
            activation_frames: host.activation_frames,
            logs: host.logs,
            state: host.state,
            return_value: host.return_value,
            parameter: host.parameter.into(),
            init_ctx: host.init_ctx.into(),
            limit_logs_and_return_values: host.limit_logs_and_return_values,
            trace: host.trace,
        }
    }
}

#[derive(Copy, Clone, PartialOrd, Ord, Eq, PartialEq, Debug)]
/// Host functions supported by V1 contracts.
pub enum HostFunctionV1 {
    /// Functions allowed both in `init` and `receive` functions.
    Common(CommonFunc),
    /// Functions allowed only in `init` methods.
    Init(InitOnlyFunc),
    /// Functions allowed only in `receive` methods.
    Receive(ReceiveOnlyFunc),
}

/// The [`Display`](std::fmt::Display) implementation renders the function in
/// the same way that it is expected to be named in the imports.
impl std::fmt::Display for HostFunctionV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostFunctionV1::Common(c) => c.fmt(f),
            HostFunctionV1::Init(io) => io.fmt(f),
            HostFunctionV1::Receive(ro) => ro.fmt(f),
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// A record of a host call in the [`DebugTracker`].
pub struct HostCall {
    /// The host function that was called.
    pub host_function: HostFunctionV1,
    /// The amount of energy consumed by the call.
    pub energy_used:   InterpreterEnergy,
}

#[derive(Default, Debug)]
/// A type that implements [`DebugInfo`] and can be used for collecting
/// execution information during execution.
pub struct DebugTracker {
    /// The amount of interpreter energy used by pure Wasm instruction
    /// execution.
    pub operation:       InterpreterEnergy,
    /// The amount of interpreter energy charged due to additional memory
    /// allocation in Wasm linear memory.
    pub memory_alloc:    InterpreterEnergy,
    /// The list of host calls in the order they appeared. The first component
    /// is the event index which is shared between the host trace calls and
    /// the `emitted_events` field below so that it is possible to reconstruct
    /// one global order of events.
    pub host_call_trace: Vec<(usize, HostCall)>,
    /// Events emitted by calls to `debug_print` host function. The first
    /// component is the event index shared with the `host_call_trace` value.
    pub emitted_events:  Vec<(usize, EmittedDebugStatement)>,
    /// Internal tracker to assign event indices.
    next_index:          usize,
}

/// The [`Display`](std::fmt::Display) implementation renders all public fields
/// of the type in **multiple lines**. The host calls and emitted events are
/// interleaved so that they appear in the order that they occurred.
impl std::fmt::Display for DebugTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let DebugTracker {
            operation,
            memory_alloc,
            host_call_trace,
            emitted_events,
            next_index: _,
        } = self;
        writeln!(f, "Wasm instruction cost: {operation}")?;
        writeln!(f, "Memory alocation cost: {memory_alloc}")?;
        let mut iter1 = host_call_trace.iter().peekable();
        let mut iter2 = emitted_events.iter().peekable();
        while let (Some((i1, call)), Some((i2, event))) = (iter1.peek(), iter2.peek()) {
            if i1 < i2 {
                iter1.next();
                writeln!(f, "{} used {} interpreter energy", call.host_function, call.energy_used)?;
            } else {
                iter2.next();
                writeln!(f, "{event}")?;
            }
        }
        for (
            _,
            HostCall {
                host_function,
                energy_used,
            },
        ) in iter1
        {
            writeln!(f, "{host_function} used {energy_used} interpreter energy")?;
        }
        for (_, event) in iter2 {
            writeln!(f, "{event}")?;
        }
        Ok(())
    }
}

impl DebugTracker {
    /// Summarize all the host calls, grouping them by the host function. The
    /// value at each host function is the pair of the number of times the
    /// host function was called, and the sum of interpreter energy those
    /// calls consumed.
    pub fn host_call_summary(&self) -> BTreeMap<HostFunctionV1, (usize, InterpreterEnergy)> {
        let mut out = BTreeMap::new();
        for (
            _,
            HostCall {
                host_function,
                energy_used,
            },
        ) in self.host_call_trace.iter()
        {
            let summary = out.entry(*host_function).or_insert((0, InterpreterEnergy {
                energy: 0,
            }));
            summary.0 += 1;
            summary.1.energy += energy_used.energy;
        }
        out
    }
}

impl crate::DebugInfo for DebugTracker {
    const ENABLE_DEBUG: bool = true;

    fn empty_trace() -> Self { Self::default() }

    fn trace_host_call(&mut self, f: self::ImportFunc, energy_used: InterpreterEnergy) {
        let next_idx = self.next_index;
        match f {
            ImportFunc::ChargeMemoryAlloc => self.memory_alloc.add(energy_used),
            ImportFunc::Common(c) => {
                self.next_index += 1;
                self.host_call_trace.push((next_idx, HostCall {
                    host_function: HostFunctionV1::Common(c),
                    energy_used,
                }));
            }
            ImportFunc::InitOnly(io) => {
                self.next_index += 1;
                self.host_call_trace.push((next_idx, HostCall {
                    host_function: HostFunctionV1::Init(io),
                    energy_used,
                }));
            }
            ImportFunc::ReceiveOnly(ro) => {
                self.next_index += 1;
                self.host_call_trace.push((next_idx, HostCall {
                    host_function: HostFunctionV1::Receive(ro),
                    energy_used,
                }));
            }
        }
    }

    fn emit_debug_event(&mut self, event: EmittedDebugStatement) {
        let next_idx = self.next_index;
        self.next_index += 1;
        self.emitted_events.push((next_idx, event));
    }
}

#[derive(Debug)]
/// A host implementation that provides access to host information needed for
/// execution of contract receive methods. The "host" in this context
/// refers to the Wasm concept of a host.
/// This keeps track of the current state and logs, gives access to the context,
/// and makes sure that execution stays within resource bounds dictated by
/// allocated energy.
#[doc(hidden)] // Needed in benchmarks, but generally should not be used by
               // users of the library.
pub struct ReceiveHost<'a, BackingStore, ParamType, Ctx, A: DebugInfo> {
    pub energy:    InterpreterEnergy,
    pub stateless: StateLessReceiveHost<ParamType, Ctx>,
    pub state:     InstanceState<'a, BackingStore>,
    pub trace:     A,
}

#[derive(Debug)]
/// Part of the receive host that is stored to handle the interrupt.
/// This part is not changed during the handling of the interrupt, however
/// before execution resumes, after returning from handling of the interrupt,
/// the logs and parameters are set appropriately.
#[doc(hidden)] // Needed in benchmarks, but generally should not be used by
               // users of the library.
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

/// An event emitted by the `debug_print` host function in debug mode.
#[derive(Debug)]
pub struct EmittedDebugStatement {
    /// File in which the debug macro was used.
    pub filename:         String,
    /// The line inside the file.
    pub line:             u32,
    /// An the column.
    pub column:           u32,
    /// The message that was emitted.
    pub msg:              String,
    /// Remaining **interpreter energy** energy left for execution.
    pub remaining_energy: InterpreterEnergy,
}

impl std::fmt::Display for EmittedDebugStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:@{}:{}",
            self.filename, self.line, self.column, self.remaining_energy, self.msg
        )
    }
}

pub(crate) mod host {
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
    const CHECK_ACCOUNT_SIGNATURE_TAG: u32 = 5;
    const QUERY_ACCOUNT_KEYS_TAG: u32 = 6;
    const QUERY_CONTRACT_MODULE_REFERENCE_TAG: u32 = 7;
    const QUERY_CONTRACT_NAME_TAG: u32 = 8;

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
    pub(crate) fn write_return_value(
        memory: &mut [u8],
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
    pub(crate) fn invoke(
        params: ReceiveParams,
        memory: &mut [u8],
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<Option<Interrupt>> {
        energy.tick_energy(constants::INVOKE_BASE_COST)?;
        let length_u32 = unsafe { stack.pop_u32() }; // length of the instruction payload in memory
        let length = length_u32 as usize;
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
                match parse_call_args(energy, &mut cursor, params.max_parameter_size) {
                    Ok(Ok(i)) => Ok(Some(i)),
                    Ok(Err(OutOfEnergy)) => bail!(OutOfEnergy),
                    Err(e) => bail!("Illegal call, cannot parse arguments: {:?}", e),
                }
            }
            QUERY_ACCOUNT_BALANCE_TAG if params.support_queries => {
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
            QUERY_CONTRACT_BALANCE_TAG if params.support_queries => {
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
            QUERY_EXCHANGE_RATE_TAG if params.support_queries => {
                ensure!(
                    length == 0,
                    "Exchange rate query must have no payload, but was {}",
                    length
                );
                Ok(Interrupt::QueryExchangeRates.into())
            }
            CHECK_ACCOUNT_SIGNATURE_TAG if params.support_account_signature_checks => {
                ensure!(
                    length >= ACCOUNT_ADDRESS_SIZE,
                    "Account signature check queries must have at least the 32 bytes for an \
                     account address, but was {}",
                    length
                );
                // Overflow is not possible in the next line on 64-bit machines.
                ensure!(start + length <= memory.len(), "Illegal memory access.");
                if energy.tick_energy(constants::copy_to_host_cost(length_u32)).is_err() {
                    bail!(OutOfEnergy);
                }
                let mut addr_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
                addr_bytes.copy_from_slice(&memory[start..start + ACCOUNT_ADDRESS_SIZE]);
                let address = AccountAddress(addr_bytes);
                let payload = memory[start + ACCOUNT_ADDRESS_SIZE..start + length].to_vec();
                Ok(Interrupt::CheckAccountSignature {
                    address,
                    payload,
                }
                .into())
            }
            QUERY_ACCOUNT_KEYS_TAG if params.support_account_signature_checks => {
                ensure!(
                    length == ACCOUNT_ADDRESS_SIZE,
                    "Account keys queries must have exactly 32 bytes of payload, but was {}",
                    length
                );
                // Overflow is not possible in the next line on 64-bit machines.
                ensure!(start + length <= memory.len(), "Illegal memory access.");
                let mut addr_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
                addr_bytes.copy_from_slice(&memory[start..start + ACCOUNT_ADDRESS_SIZE]);
                let address = AccountAddress(addr_bytes);
                Ok(Interrupt::QueryAccountKeys {
                    address,
                }
                .into())
            }
            QUERY_CONTRACT_MODULE_REFERENCE_TAG if params.support_contract_inspection_queries => {
                ensure!(
                    length == 8 + 8,
                    "Contract module reference queries must have exactly 16 bytes of payload, but \
                     was {}",
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
                Ok(Interrupt::QueryContractModuleReference {
                    address,
                }
                .into())
            }
            QUERY_CONTRACT_NAME_TAG if params.support_contract_inspection_queries => {
                ensure!(
                    length == 8 + 8,
                    "Contract name queries must have exactly 16 bytes of payload, but was {}",
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
                Ok(Interrupt::QueryContractName {
                    address,
                }
                .into())
            }
            c => bail!("Illegal instruction code {}.", c),
        }
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Get the parameter size. This differs from the v0 version in that it
    /// expects an argument on the stack to indicate which parameter to use.
    pub(crate) fn get_parameter_size(
        stack: &mut machine::RuntimeStack,
        parameters: &[impl AsRef<[u8]>],
    ) -> machine::RunResult<()> {
        // the cost of this function is adequately reflected by the base cost of a
        // function call so we do not charge extra.
        let param_num = unsafe { stack.pop_u32() } as usize;
        if let Some(param) = parameters.get(param_num) {
            stack.push_value(param.as_ref().len() as u32);
        } else {
            stack.push_value(-1i32);
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Get the parameter section. This differs from the v0 version in that it
    /// expects an argument on the stack to indicate which parameter to use.
    pub(crate) fn get_parameter_section(
        memory: &mut [u8],
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
        if let Some(param) = parameters.get(param_num) {
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
    pub(crate) fn state_lookup_entry<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_create_entry<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_delete_entry<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_delete_prefix<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_iterator<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_iterator_next<BackingStore: BackingStoreLoad>(
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
    pub(crate) fn state_iterator_delete<BackingStore: BackingStoreLoad>(
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
    pub(crate) fn state_iterator_key_size<BackingStore: BackingStoreLoad>(
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
    pub(crate) fn state_iterator_key_read<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_entry_read<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_entry_write<BackingStore: BackingStoreLoad>(
        memory: &mut [u8],
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
    pub(crate) fn state_entry_size<BackingStore: BackingStoreLoad>(
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
    pub(crate) fn state_entry_resize<BackingStore: BackingStoreLoad>(
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
    pub(crate) fn get_receive_entrypoint_size(
        stack: &mut machine::RuntimeStack,
        entrypoint: EntrypointName,
    ) -> machine::RunResult<()> {
        let size: u32 = entrypoint.size();
        stack.push_value(size);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    /// Handle the `get_receive_entrypoint` host function.
    pub(crate) fn get_receive_entrypoint(
        memory: &mut [u8],
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
    pub(crate) fn verify_ed25519_signature(
        memory: &mut [u8],
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

    pub(crate) fn debug_print<Debug: DebugInfo>(
        debug: &mut Debug,
        memory: &mut [u8],
        stack: &mut machine::RuntimeStack,
        energy: &mut InterpreterEnergy,
    ) -> machine::RunResult<()> {
        let (filename, line, column, msg) = crate::utils::extract_debug(memory, stack)?;
        debug.emit_debug_event(EmittedDebugStatement {
            filename,
            line,
            column,
            msg,
            remaining_energy: *energy,
        });
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    pub(crate) fn verify_ecdsa_secp256k1_signature(
        memory: &mut [u8],
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
    pub(crate) fn hash_sha2_256(
        memory: &mut [u8],
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
    pub(crate) fn hash_sha3_256(
        memory: &mut [u8],
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
    pub(crate) fn hash_keccak_256(
        memory: &mut [u8],
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
    pub(crate) fn upgrade(
        memory: &mut [u8],
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
impl<
        'a,
        BackingStore: BackingStoreLoad,
        ParamType: AsRef<[u8]>,
        Ctx: v0::HasInitContext,
        A: DebugInfo,
    > machine::Host<ProcessedImports> for InitHost<'a, BackingStore, ParamType, Ctx, A>
{
    type Interrupt = NoInterrupt;

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn tick_initial_memory(&mut self, num_pages: u32) -> machine::RunResult<()> {
        self.energy.charge_memory_alloc(num_pages)
    }

    #[inline(always)]
    fn tick_energy(&mut self, energy: u64) -> machine::RunResult<()> {
        self.energy.tick_energy(energy)
    }

    #[inline(always)]
    fn track_call(&mut self) -> machine::RunResult<()> {
        v0::host::track_call(&mut self.activation_frames)
    }

    #[inline(always)]
    fn track_return(&mut self) { v0::host::track_return(&mut self.activation_frames) }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    fn call(
        &mut self,
        f: &ProcessedImports,
        memory: &mut [u8],
        stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<Option<Self::Interrupt>> {
        let energy_before = self.energy;
        match f.tag {
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
                CommonFunc::DebugPrint => {
                    host::debug_print(&mut self.trace, memory, stack, &mut self.energy)
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
        let energy_after: InterpreterEnergy = self.energy;
        self.trace.trace_host_call(f.tag, energy_before.saturating_sub(&energy_after));
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

impl<
        'a,
        BackingStore: BackingStoreLoad,
        ParamType: AsRef<[u8]>,
        Ctx: HasReceiveContext,
        A: DebugInfo,
    > machine::Host<ProcessedImports> for ReceiveHost<'a, BackingStore, ParamType, Ctx, A>
{
    type Interrupt = Interrupt;

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn tick_initial_memory(&mut self, num_pages: u32) -> machine::RunResult<()> {
        self.energy.charge_memory_alloc(num_pages)
    }

    #[inline(always)]
    fn tick_energy(&mut self, energy: u64) -> machine::RunResult<()> {
        self.energy.tick_energy(energy)
    }

    #[inline(always)]
    fn track_call(&mut self) -> machine::RunResult<()> {
        v0::host::track_call(&mut self.stateless.activation_frames)
    }

    #[inline(always)]
    fn track_return(&mut self) { v0::host::track_return(&mut self.stateless.activation_frames) }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline)]
    fn call(
        &mut self,
        f: &ProcessedImports,
        memory: &mut [u8],
        stack: &mut machine::RuntimeStack,
    ) -> machine::RunResult<Option<Self::Interrupt>> {
        let energy_before = self.energy;
        match f.tag {
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
                CommonFunc::DebugPrint => {
                    host::debug_print(&mut self.trace, memory, stack, &mut self.energy)
                }
                CommonFunc::HashSHA2_256 => host::hash_sha2_256(memory, stack, &mut self.energy),
                CommonFunc::HashSHA3_256 => host::hash_sha3_256(memory, stack, &mut self.energy),
                CommonFunc::HashKeccak256 => host::hash_keccak_256(memory, stack, &mut self.energy),
            }?,
            ImportFunc::ReceiveOnly(rof) => match rof {
                ReceiveOnlyFunc::Invoke => {
                    let invoke =
                        host::invoke(self.stateless.params, memory, stack, &mut self.energy);
                    let energy_after: InterpreterEnergy = self.energy;
                    self.trace.trace_host_call(f.tag, energy_before.saturating_sub(&energy_after));
                    return invoke;
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
        let energy_after: InterpreterEnergy = self.energy;
        self.trace.trace_host_call(f.tag, energy_before.saturating_sub(&energy_after));
        Ok(None)
    }
}

/// Parameter whose ownership is tracked statically.
pub type ParameterRef<'a> = &'a [u8];
/// Parameter whose ownership is tracked dynamically.
/// This is needed, for example, when execution passes through Haskell and Rust.
/// Ideally this would be Arc<[u8]> but then this cannot be passed via the FFI
/// boundary directly since [u8] is not Sized. To avoid a third type we settle
/// on [`Vec<u8>`](Vec).
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
pub fn invoke_init<BackingStore: BackingStoreLoad, R: RunnableCode, A: DebugInfo>(
    artifact: impl Borrow<Artifact<ProcessedImports, R>>,
    init_ctx: impl v0::HasInitContext,
    init_invocation: InitInvocation,
    limit_logs_and_return_values: bool,
    mut loader: BackingStore,
) -> InvokeResult<InitResult<A>, A> {
    let mut initial_state = trie::MutableState::initial_state();
    let inner = initial_state.get_inner(&mut loader);
    let state_ref = InstanceState::new(loader, inner);
    let mut host = InitHost::<_, _, _, A> {
        energy: init_invocation.energy,
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: v0::Logs::new(),
        state: state_ref,
        return_value: Vec::new(),
        parameter: init_invocation.parameter,
        limit_logs_and_return_values,
        init_ctx,
        trace: A::empty_trace(),
    };
    let result = artifact.borrow().run(&mut host, init_invocation.init_name, &[Value::I64(
        init_invocation.amount.micro_ccd() as i64,
    )]);
    let return_value = std::mem::take(&mut host.return_value);
    let remaining_energy = host.energy.energy;
    let logs = std::mem::take(&mut host.logs);
    let trace = std::mem::replace(&mut host.trace, A::empty_trace());
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
                        remaining_energy: remaining_energy.into(),
                        state: initial_state,
                        trace,
                    })
                } else {
                    let (reason, trace) = reason_from_wasm_error_code(n, trace)?;
                    Ok(InitResult::Reject {
                        reason,
                        return_value,
                        remaining_energy: remaining_energy.into(),
                        trace,
                    })
                }
            } else {
                Err(InvalidReturnCodeError {
                    value:       None,
                    debug_trace: trace,
                })
            }
        }
        Ok(ExecutionOutcome::Interrupted {
            reason,
            config: _,
        }) => match reason {},
        Err(error) => {
            if error.downcast_ref::<OutOfEnergy>().is_some() {
                Ok(InitResult::OutOfEnergy {
                    trace,
                })
            } else {
                Ok(InitResult::Trap {
                    error,
                    remaining_energy: remaining_energy.into(),
                    trace,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The module to upgrade to does not exist.
    UpgradeInvalidModuleRef,
    /// The upgrade attempted to upgrade to a module which does not have the
    /// the required contract.
    UpgradeInvalidContractName,
    /// Attempt to upgrade a V1 contract to a V0 contract.
    UpgradeInvalidVersion,
    /// Could not parse the signature and message.
    SignatureDataMalformed,
    /// Invalid signature on the provided message.
    SignatureCheckFailed,
}

impl InvokeFailure {
    /// Encode the failure kind in a format that is expected from a host
    /// function. If the return value is present it is pushed to the supplied
    /// vector of parameters.
    pub(crate) fn encode_as_u64<Debug>(
        self,
        parameters: &mut Vec<ParameterVec>,
    ) -> ResumeResult<u64, Debug> {
        Ok(match self {
            InvokeFailure::ContractReject {
                code,
                data,
            } => {
                let len = parameters.len();
                if len > 0b0111_1111_1111_1111_1111_1111 {
                    return Err(ResumeError::TooManyInterrupts);
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
            InvokeFailure::SignatureDataMalformed => 0x0a_0000_0000,
            InvokeFailure::SignatureCheckFailed => 0x0b_0000_0000,
        })
    }
}

/// Response from an invoke call.
#[derive(Debug)]
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
                0x0000_000a_0000_0000 => InvokeFailure::SignatureDataMalformed,
                0x0000_000b_0000_0000 => InvokeFailure::SignatureCheckFailed,
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

/// Invokes an init-function from a given **serialized** artifact.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_artifact<BackingStore: BackingStoreLoad, A: DebugInfo>(
    ctx: InvokeFromArtifactCtx,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    loader: BackingStore,
    limit_logs_and_return_values: bool,
) -> ExecResult<InitResult<A>> {
    let artifact = utils::parse_artifact(ctx.artifact)?;
    let r = invoke_init(
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
    )?;
    Ok(r)
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

/// Invokes an init-function from a **serialized** Wasm module.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_source<BackingStore: BackingStoreLoad, A: DebugInfo>(
    ctx: InvokeFromSourceCtx,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    loader: BackingStore,
    validation_config: ValidationConfig,
    limit_logs_and_return_values: bool,
) -> ExecResult<InitResult<A>> {
    let artifact = utils::instantiate(
        validation_config,
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
            enable_debug:    A::ENABLE_DEBUG,
        },
        ctx.source,
    )?
    .artifact;
    let r = invoke_init(
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
    )?;
    Ok(r)
}

/// Same as `invoke_init_from_source`, except that the module has cost
/// accounting instructions inserted before the init function is called.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_with_metering_from_source<BackingStore: BackingStoreLoad, A: DebugInfo>(
    ctx: InvokeFromSourceCtx,
    init_ctx: impl v0::HasInitContext,
    init_name: &str,
    loader: BackingStore,
    validation_config: ValidationConfig,
    cost_config: impl CostConfiguration,
    limit_logs_and_return_values: bool,
) -> ExecResult<InitResult<A>> {
    let artifact = utils::instantiate_with_metering(
        validation_config,
        cost_config,
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
            enable_debug:    A::ENABLE_DEBUG,
        },
        ctx.source,
    )?
    .artifact;
    let r = invoke_init(
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
    )?;
    Ok(r)
}

fn process_receive_result<
    BackingStore,
    Param,
    R: RunnableCode,
    Art: Into<Arc<Artifact<ProcessedImports, R>>>,
    Ctx1,
    Ctx2,
    A: DebugInfo,
>(
    artifact: Art,
    host: ReceiveHost<'_, BackingStore, Param, Ctx1, A>,
    result: machine::RunResult<ExecutionOutcome<Interrupt>>,
) -> InvokeResult<ReceiveResult<R, A, Ctx2>, A>
where
    StateLessReceiveHost<ParameterVec, Ctx2>: From<StateLessReceiveHost<Param, Ctx1>>, {
    let mut stateless = host.stateless;
    match result {
        Ok(ExecutionOutcome::Success {
            result,
            ..
        }) => {
            let remaining_energy = host.energy;
            if let Some(Value::I32(n)) = result {
                if n >= 0 {
                    Ok(ReceiveResult::Success {
                        logs: stateless.logs,
                        state_changed: host.state.changed,
                        return_value: stateless.return_value,
                        remaining_energy,
                        trace: host.trace,
                    })
                } else {
                    let (reason, trace) = reason_from_wasm_error_code(n, host.trace)?;
                    Ok(ReceiveResult::Reject {
                        reason,
                        return_value: stateless.return_value,
                        remaining_energy,
                        trace,
                    })
                }
            } else {
                Err(InvalidReturnCodeError {
                    value:       None,
                    debug_trace: host.trace,
                })
            }
        }
        Ok(ExecutionOutcome::Interrupted {
            reason,
            config,
        }) => {
            let remaining_energy = host.energy;
            // Logs are returned per section that is executed.
            // So here we set the host logs to empty and return any
            // existing logs.
            let logs = if reason.should_clear_logs() {
                std::mem::take(&mut stateless.logs)
            } else {
                v0::Logs::new()
            };
            let state_changed = host.state.changed;
            let trace = host.trace;
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
                trace,
            })
        }
        Err(error) => {
            if error.downcast_ref::<OutOfEnergy>().is_some() {
                Ok(ReceiveResult::OutOfEnergy {
                    trace: host.trace,
                })
            } else {
                Ok(ReceiveResult::Trap {
                    error,
                    remaining_energy: host.energy,
                    trace: host.trace,
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
    pub max_parameter_size:                  usize,
    /// Whether the amount of logs a contract may produce, and the size of the
    /// logs, is limited.
    pub limit_logs_and_return_values:        bool,
    /// Whether queries should be supported or not. Queries were introduced in
    /// protocol 5.
    pub support_queries:                     bool,
    /// Whether querying account public keys and checking account signatures is
    /// supported.
    pub support_account_signature_checks:    bool,
    /// Whether queries for inspecting a smart contract's module reference and
    /// contract name should be supported or not. These queries were introduced
    /// in protocol 7.
    pub support_contract_inspection_queries: bool,
}

impl ReceiveParams {
    /// Parameters that are in effect in protocol version 4.
    pub fn new_p4() -> Self {
        Self {
            max_parameter_size:                  1024,
            limit_logs_and_return_values:        true,
            support_queries:                     false,
            support_account_signature_checks:    false,
            support_contract_inspection_queries: false,
        }
    }

    /// Parameters that are in effect in protocol version 5.
    pub fn new_p5() -> Self {
        Self {
            max_parameter_size:                  u16::MAX.into(),
            limit_logs_and_return_values:        false,
            support_queries:                     true,
            support_account_signature_checks:    false,
            support_contract_inspection_queries: false,
        }
    }

    /// Parameters that are in effect in protocol version 6.
    pub fn new_p6() -> Self {
        Self {
            max_parameter_size:                  u16::MAX.into(),
            limit_logs_and_return_values:        false,
            support_queries:                     true,
            support_account_signature_checks:    true,
            support_contract_inspection_queries: false,
        }
    }

    /// Parameters that are in effect in protocol version 7 and up.
    pub fn new_p7() -> Self {
        Self {
            max_parameter_size:                  u16::MAX.into(),
            limit_logs_and_return_values:        false,
            support_queries:                     true,
            support_account_signature_checks:    true,
            support_contract_inspection_queries: true,
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

/// Invokes a receive-function from a given [artifact](Artifact).
pub fn invoke_receive<
    BackingStore: BackingStoreLoad,
    R1: RunnableCode,
    R2: RunnableCode,
    Art: Borrow<Artifact<ProcessedImports, R1>> + Into<Arc<Artifact<ProcessedImports, R2>>>,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
    A: DebugInfo,
>(
    artifact: Art,
    receive_ctx: Ctx1,
    receive_invocation: ReceiveInvocation,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> InvokeResult<ReceiveResult<R2, A, Ctx2>, A> {
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
        trace:     A::empty_trace(),
    };

    let result =
        artifact.borrow().run(&mut host, receive_invocation.receive_name.get_chain_name(), &[
            Value::I64(receive_invocation.amount.micro_ccd() as i64),
        ]);
    process_receive_result(artifact, host, result)
}

pub type ResumeResult<A, Debug> = Result<A, ResumeError<Debug>>;

#[derive(Debug, thiserror::Error)]
pub enum ResumeError<Debug> {
    /// There have been too many interrupts during this contract execution.
    #[error("Too many interrupts in a contract call.")]
    TooManyInterrupts,
    #[error("Invalid return value from a contract call: {error:?}")]
    InvalidReturn {
        #[from]
        error: InvalidReturnCodeError<Debug>,
    },
}

impl<R, Debug: DebugInfo, Ctx> From<ResumeError<Debug>> for types::ReceiveResult<R, Debug, Ctx> {
    fn from(value: ResumeError<Debug>) -> Self {
        match value {
            ResumeError::TooManyInterrupts => {
                Self::Trap {
                    error:            anyhow::anyhow!("Too many interrupts in a contract call."),
                    remaining_energy: 0.into(), /* Protocol violations lead to consuming all
                                                 * energy. */
                    trace:            Debug::empty_trace(), // nothing was executed, so no trace.
                }
            }
            ResumeError::InvalidReturn {
                error,
            } => error.into(),
        }
    }
}

/// Resume execution of the receive method after handling the interrupt.
///
/// The arguments are as follows
///
/// - `interrupted_state` is the state of execution that is captured when we
///   started handling the interrupt
/// - `response` is the response from the operation that was invoked
/// - `energy` is the remaning energy left for execution
/// - `state_trie` is the current state of the contract instance, **after**
///   handling the interrupt
/// - `state_updated` indicates whether the state of the instance has changed
///   during handling of the operation. This can currently only happen if there
///   is re-entrancy, i.e., if during handling of the interrupt the instance
///   that invoked it is itself again invoked. Note that this indicates only
///   **state changes**. Amount changes are no reflected in this.
/// - `backing_store` gives access to any on-disk storage for the instance
///   state.
pub fn resume_receive<BackingStore: BackingStoreLoad, A: DebugInfo>(
    interrupted_state: Box<ReceiveInterruptedState<CompiledFunction>>,
    response: InvokeResponse,  // response from the call
    energy: InterpreterEnergy, // remaining energy for execution
    state_trie: &mut trie::MutableState,
    state_updated: bool,
    mut backing_store: BackingStore,
) -> ResumeResult<ReceiveResult<CompiledFunction, A>, A> {
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
        trace: A::empty_trace(),
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
                    return Err(ResumeError::TooManyInterrupts);
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
    let r = process_receive_result(interrupted_state.artifact, host, result)?;
    Ok(r)
}

/// Returns the passed Wasm error code if it is negative.
/// This function should only be called on negative numbers.
fn reason_from_wasm_error_code<A>(
    n: i32,
    debug_trace: A,
) -> Result<(i32, A), InvalidReturnCodeError<A>> {
    if n < 0 {
        Ok((n, debug_trace))
    } else {
        Err(InvalidReturnCodeError {
            value: Some(n),
            debug_trace,
        })
    }
}

/// Invokes a receive-function from a given **serialized** artifact.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_artifact<
    'a,
    BackingStore: BackingStoreLoad,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
    A: DebugInfo,
>(
    ctx: InvokeFromArtifactCtx<'a>,
    receive_ctx: Ctx1,
    receive_name: ReceiveName,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> ExecResult<ReceiveResult<CompiledFunctionBytes<'a>, A, Ctx2>> {
    let artifact = utils::parse_artifact(ctx.artifact)?;
    let r = invoke_receive(
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
    )?;
    Ok(r)
}

/// Invokes a receive-function from a given **serialized** Wasm module.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_source<
    BackingStore: BackingStoreLoad,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
    A: DebugInfo,
>(
    validation_config: ValidationConfig,
    ctx: InvokeFromSourceCtx,
    receive_ctx: Ctx1,
    receive_name: ReceiveName,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> ExecResult<ReceiveResult<CompiledFunction, A, Ctx2>> {
    let artifact = utils::instantiate(
        validation_config,
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
            enable_debug:    A::ENABLE_DEBUG,
        },
        ctx.source,
    )?
    .artifact;
    let r = invoke_receive(
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
    )?;
    Ok(r)
}

/// Invokes a receive-function from a given **serialized** Wasm module. Before
/// execution the Wasm module is injected with cost metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_with_metering_from_source<
    BackingStore: BackingStoreLoad,
    Ctx1: HasReceiveContext,
    Ctx2: From<Ctx1>,
    A: DebugInfo,
>(
    validation_config: ValidationConfig,
    cost_config: impl CostConfiguration,
    ctx: InvokeFromSourceCtx,
    receive_ctx: Ctx1,
    receive_name: ReceiveName,
    instance_state: InstanceState<BackingStore>,
    params: ReceiveParams,
) -> ExecResult<ReceiveResult<CompiledFunction, A, Ctx2>> {
    let artifact = utils::instantiate_with_metering(
        validation_config,
        cost_config,
        &ConcordiumAllowedImports {
            support_upgrade: ctx.support_upgrade,
            enable_debug:    A::ENABLE_DEBUG,
        },
        ctx.source,
    )?
    .artifact;
    let r = invoke_receive(
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
    )?;
    Ok(r)
}
