#[cfg(feature = "enable-ffi")]
mod ffi;
mod types;

use crate::{constants, v0, ExecResult, InterpreterEnergy, OutOfEnergy};
use anyhow::{bail, ensure};
use concordium_contracts_common::{
    AccountAddress, Address, Amount, ChainMetadata, ContractAddress, OwnedEntrypointName, SlotTime,
};
use machine::Value;
use std::{borrow::Borrow, io::Write, sync::Arc};
pub use types::*;
use wasm_transform::{
    artifact::{Artifact, CompiledFunction, CompiledFunctionBytes, RunnableCode},
    machine::{self, ExecutionOutcome, NoInterrupt},
    utils,
};

/// Interrupt triggered by the smart contract to execute an instruction on the
/// host, either an account transfer, or a smart contract.
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
pub struct InitHost<ParamType, Ctx> {
    /// Remaining energy for execution.
    pub energy:            InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs:              v0::Logs,
    /// The contract's state.
    pub state:             v0::State,
    /// The response from the call.
    pub return_value:      ReturnValue,
    /// The parameter to the init method, as well as any responses from
    /// calls to other contracts during execution.
    pub parameters:        Vec<ParamType>,
    /// The init context for this invocation.
    pub init_ctx:          Ctx,
}

impl<'a, Ctx2, Ctx1: Into<Ctx2>> From<InitHost<ParameterRef<'a>, Ctx1>>
    for InitHost<ParameterVec, Ctx2>
{
    fn from(host: InitHost<ParameterRef<'a>, Ctx1>) -> Self {
        Self {
            energy:            host.energy,
            activation_frames: host.activation_frames,
            logs:              host.logs,
            state:             host.state,
            return_value:      host.return_value,
            parameters:        host.parameters.into_iter().map(|x| x.to_vec()).collect(),
            init_ctx:          host.init_ctx.into(),
        }
    }
}

#[derive(Debug)]
pub struct ReceiveHost<ParamType, Ctx> {
    /// Remaining energy for execution.
    pub energy:            InterpreterEnergy,
    /// Remaining amount of activation frames.
    /// In other words, how many more functions can we call in a nested way.
    pub activation_frames: u32,
    /// Logs produced during execution.
    pub logs:              v0::Logs,
    /// The contract's state.
    pub state:             v0::State,
    /// Return value from execution.
    pub return_value:      ReturnValue,
    /// The parameter to the receive method.
    pub parameters:        Vec<ParamType>,
    /// The receive context for this call.
    pub receive_ctx:       Ctx,
}

impl<'a, Ctx2, Ctx1: Into<Ctx2>> From<ReceiveHost<ParameterRef<'a>, Ctx1>>
    for ReceiveHost<ParameterVec, Ctx2>
{
    fn from(host: ReceiveHost<ParameterRef<'a>, Ctx1>) -> Self {
        Self {
            energy:            host.energy,
            activation_frames: host.activation_frames,
            logs:              host.logs,
            state:             host.state,
            return_value:      host.return_value,
            parameters:        host.parameters.into_iter().map(|x| x.to_vec()).collect(),
            receive_ctx:       host.receive_ctx.into(),
        }
    }
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
    type MetadataType: v0::HasChainMetadata;

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
    type MetadataType: v0::HasChainMetadata;

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

/// v1 host functions.
mod host {
    use concordium_contracts_common::{Cursor, Get, ParseError, ParseResult, ACCOUNT_ADDRESS_SIZE};

    use super::*;

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
}

// The use of Vec<u8> is ugly, and we really should have [u8] there, but FFI
// prevents us doing that without ugly hacks.
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
                CommonFunc::GetParameterSize => host::get_parameter_size(stack, &self.parameters),
                CommonFunc::GetParameterSection => {
                    host::get_parameter_section(memory, stack, &mut self.energy, &self.parameters)
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
                CommonFunc::LoadState => {
                    v0::host::load_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::WriteState => {
                    v0::host::write_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::ResizeState => {
                    v0::host::resize_state(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateSize => v0::host::state_size(stack, &mut self.state),
                CommonFunc::GetSlotTime => v0::host::get_slot_time(stack, self.init_ctx.metadata()),
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

impl<ParamType: AsRef<[u8]>, Ctx: HasReceiveContext> machine::Host<ProcessedImports>
    for ReceiveHost<ParamType, Ctx>
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
                CommonFunc::GetParameterSize => host::get_parameter_size(stack, &self.parameters),
                CommonFunc::GetParameterSection => {
                    host::get_parameter_section(memory, stack, &mut self.energy, &self.parameters)
                }
                CommonFunc::GetPolicySection => v0::host::get_policy_section(
                    memory,
                    stack,
                    &mut self.energy,
                    self.receive_ctx.sender_policies(),
                ),
                CommonFunc::LogEvent => {
                    v0::host::log_event(memory, stack, &mut self.energy, &mut self.logs)
                }
                CommonFunc::LoadState => {
                    v0::host::load_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::WriteState => {
                    v0::host::write_state(memory, stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::ResizeState => {
                    v0::host::resize_state(stack, &mut self.energy, &mut self.state)
                }
                CommonFunc::StateSize => v0::host::state_size(stack, &mut self.state),
                CommonFunc::GetSlotTime => {
                    v0::host::get_slot_time(stack, self.receive_ctx.metadata())
                }
            }?,
            ImportFunc::ReceiveOnly(rof) => match rof {
                ReceiveOnlyFunc::Invoke => {
                    return host::invoke(memory, stack, &mut self.energy);
                }
                ReceiveOnlyFunc::GetReceiveInvoker => {
                    v0::host::get_receive_invoker(memory, stack, self.receive_ctx.invoker())
                }
                ReceiveOnlyFunc::GetReceiveSelfAddress => v0::host::get_receive_self_address(
                    memory,
                    stack,
                    self.receive_ctx.self_address(),
                ),
                ReceiveOnlyFunc::GetReceiveSelfBalance => {
                    v0::host::get_receive_self_balance(stack, self.receive_ctx.self_balance())
                }
                ReceiveOnlyFunc::GetReceiveSender => {
                    v0::host::get_receive_sender(memory, stack, self.receive_ctx.sender())
                }
                ReceiveOnlyFunc::GetReceiveOwner => {
                    v0::host::get_receive_owner(memory, stack, self.receive_ctx.owner())
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
pub fn invoke_init<Policy: AsRef<[u8]>, R: RunnableCode>(
    artifact: impl Borrow<Artifact<ProcessedImports, R>>,
    amount: u64,
    init_ctx: InitContext<Policy>,
    init_name: &str,
    param: ParameterRef,
    energy: u64,
) -> ExecResult<InitResult>
where
    InitContext<v0::OwnedPolicyBytes>: From<InitContext<Policy>>, {
    let mut host = InitHost {
        energy: InterpreterEnergy {
            energy,
        },
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: v0::Logs::new(),
        state: v0::State::new(None),
        return_value: Vec::new(),
        parameters: vec![param],
        init_ctx,
    };

    let result = artifact.borrow().run(&mut host, init_name, &[Value::I64(amount as i64)]);
    process_init_result(host, result)
}

fn process_init_result<Param, Policy: AsRef<[u8]>>(
    host: InitHost<Param, InitContext<Policy>>,
    result: machine::RunResult<ExecutionOutcome<NoInterrupt>>,
) -> ExecResult<InitResult>
where
    InitHost<ParameterVec, InitContext<v0::OwnedPolicyBytes>>:
        From<InitHost<Param, InitContext<Policy>>>, {
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
                        state: host.state,
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
        Err(e) => {
            if e.downcast_ref::<OutOfEnergy>().is_some() {
                Ok(InitResult::OutOfEnergy)
            } else {
                Err(e)
            }
        }
    }
}

/// Response from an invoke call.
pub enum InvokeResponse {
    /// Execution was successful, and the state potentially changed.
    Success {
        /// New state, if it changed.
        new_state: Option<v0::State>,
        /// Some calls do not have any return values, such as transfers.
        data:      Option<ParameterVec>,
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
pub fn invoke_init_from_artifact<'a, Policy: AsRef<[u8]>>(
    artifact_bytes: &'a [u8],
    amount: u64,
    init_ctx: InitContext<Policy>,
    init_name: &str,
    parameter: ParameterRef,
    energy: u64,
) -> ExecResult<InitResult>
where
    InitContext<v0::OwnedPolicyBytes>: From<InitContext<Policy>>, {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_init(artifact, amount, init_ctx, init_name, parameter, energy)
}

/// Invokes an init-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_from_source<Policy: AsRef<[u8]>>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: InitContext<Policy>,
    init_name: &str,
    parameter: ParameterRef,
    energy: u64,
) -> ExecResult<InitResult>
where
    InitContext<v0::OwnedPolicyBytes>: From<InitContext<Policy>>, {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(artifact, amount, init_ctx, init_name, parameter, energy)
}

/// Same as `invoke_init_from_source`, except that the module has cost
/// accounting instructions inserted before the init function is called.
/// metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_init_with_metering_from_source<Policy: AsRef<[u8]>>(
    source_bytes: &[u8],
    amount: u64,
    init_ctx: InitContext<Policy>,
    init_name: &str,
    parameter: ParameterRef,
    energy: u64,
) -> ExecResult<InitResult>
where
    InitContext<v0::OwnedPolicyBytes>: From<InitContext<Policy>>, {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_init(artifact, amount, init_ctx, init_name, parameter, energy)
}

fn process_receive_result<Param, R: RunnableCode, Policy>(
    artifact: Arc<Artifact<ProcessedImports, R>>,
    mut host: ReceiveHost<Param, ReceiveContext<Policy>>,
    result: machine::RunResult<ExecutionOutcome<Interrupt>>,
) -> ExecResult<ReceiveResult<R>>
where
    ReceiveHost<ParameterVec, ReceiveContext<v0::OwnedPolicyBytes>>:
        From<ReceiveHost<Param, ReceiveContext<Policy>>>, {
    match result {
        Ok(ExecutionOutcome::Success {
            result,
            ..
        }) => {
            let remaining_energy = host.energy.energy;
            if let Some(Value::I32(n)) = result {
                if n >= 0 {
                    Ok(ReceiveResult::Success {
                        logs: host.logs,
                        state: host.state,
                        return_value: host.return_value,
                        remaining_energy,
                    })
                } else {
                    Ok(ReceiveResult::Reject {
                        reason: reason_from_wasm_error_code(n)?,
                        return_value: host.return_value,
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
            let logs = std::mem::take(&mut host.logs);
            Ok(ReceiveResult::Interrupt {
                remaining_energy,
                logs,
                config: Box::new(ReceiveInterruptedState {
                    host: host.into(),
                    artifact,
                    config,
                }),
                interrupt: reason,
            })
        }
        Err(e) => {
            if e.downcast_ref::<OutOfEnergy>().is_some() {
                Ok(ReceiveResult::OutOfEnergy)
            } else {
                Ok(ReceiveResult::Trap {
                    remaining_energy: host.energy.energy,
                })
            }
        }
    }
}

/// Invokes an receive-function from a given artifact
pub fn invoke_receive<R: RunnableCode, Policy: AsRef<[u8]>>(
    artifact: Arc<Artifact<ProcessedImports, R>>,
    amount: u64,
    receive_ctx: ReceiveContext<Policy>,
    current_state: &[u8],
    receive_name: &str,
    param: ParameterRef,
    energy: u64,
) -> ExecResult<ReceiveResult<R>>
where
    ReceiveContext<v0::OwnedPolicyBytes>: From<ReceiveContext<Policy>>, {
    let mut host = ReceiveHost {
        energy: InterpreterEnergy {
            energy,
        },
        activation_frames: constants::MAX_ACTIVATION_FRAMES,
        logs: v0::Logs::new(),
        state: v0::State::new(Some(current_state)),
        return_value: Vec::new(),
        parameters: vec![param],
        receive_ctx,
    };

    let result = artifact.run(&mut host, receive_name, &[Value::I64(amount as i64)]);
    process_receive_result(artifact, host, result)
}

pub fn resume_receive(
    mut interrupted_state: Box<ReceiveInterruptedState<CompiledFunction>>,
    response: InvokeResponse,  // response from the call
    energy: InterpreterEnergy, // remaining energy for execution
) -> ExecResult<ReceiveResult<CompiledFunction>> {
    interrupted_state.host.energy = energy;
    let response = match response {
        InvokeResponse::Success {
            new_state,
            data,
        } => {
            // the response value is constructed by setting the last 5 bytes to 0
            // for the first 3 bytes, the first bit is 1 if the state changed, and 0
            // otherwise the remaining bits are the index of the parameter.
            let tag = if let Some(new_state) = new_state {
                interrupted_state.host.state = new_state;
                0b1000_0000_0000_0000_0000_0000u64
            } else {
                0
            };
            if let Some(data) = data {
                let len = interrupted_state.host.parameters.len();
                if len > 0b0111_1111_1111_1111_1111_1111 {
                    bail!("Too many calls.")
                }
                interrupted_state.host.parameters.push(data);
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
                let len = interrupted_state.host.parameters.len();
                if len > 0b0111_1111_1111_1111_1111_1111 {
                    bail!("Too many calls.")
                }
                interrupted_state.host.parameters.push(data);
                // return the index of the parameter to retrieve.
                (len as u64) << 40 | code
            } else {
                code
            }
        }
    };
    // push the response from the invoke
    interrupted_state.config.push_value(response);
    let mut host = interrupted_state.host;
    let result = interrupted_state.artifact.run_config(&mut host, interrupted_state.config);
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
pub fn invoke_receive_from_artifact<'a, Policy: AsRef<[u8]>>(
    artifact_bytes: &'a [u8],
    amount: u64,
    receive_ctx: ReceiveContext<Policy>,
    current_state: &[u8],
    receive_name: &str,
    parameter: ParameterRef,
    energy: u64,
) -> ExecResult<ReceiveResult<CompiledFunctionBytes<'a>>>
where
    ReceiveContext<v0::OwnedPolicyBytes>: From<ReceiveContext<Policy>>, {
    let artifact = utils::parse_artifact(artifact_bytes)?;
    invoke_receive(
        Arc::new(artifact),
        amount,
        receive_ctx,
        current_state,
        receive_name,
        parameter,
        energy,
    )
}

/// Invokes an receive-function from Wasm module bytes
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_from_source<Policy: AsRef<[u8]>>(
    source_bytes: &[u8],
    amount: u64,
    receive_ctx: ReceiveContext<Policy>,
    current_state: &[u8],
    receive_name: &str,
    parameter: ParameterRef,
    energy: u64,
) -> ExecResult<ReceiveResult<CompiledFunction>>
where
    ReceiveContext<v0::OwnedPolicyBytes>: From<ReceiveContext<Policy>>, {
    let artifact = utils::instantiate(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(
        Arc::new(artifact),
        amount,
        receive_ctx,
        current_state,
        receive_name,
        parameter,
        energy,
    )
}

/// Invokes an receive-function from Wasm module bytes, injects the module with
/// metering.
#[cfg_attr(not(feature = "fuzz-coverage"), inline)]
pub fn invoke_receive_with_metering_from_source<Policy: AsRef<[u8]>>(
    source_bytes: &[u8],
    amount: u64,
    receive_ctx: ReceiveContext<Policy>,
    current_state: &[u8],
    receive_name: &str,
    parameter: ParameterRef,
    energy: u64,
) -> ExecResult<ReceiveResult<CompiledFunction>>
where
    ReceiveContext<v0::OwnedPolicyBytes>: From<ReceiveContext<Policy>>, {
    let artifact = utils::instantiate_with_metering(&ConcordiumAllowedImports, source_bytes)?;
    invoke_receive(
        Arc::new(artifact),
        amount,
        receive_ctx,
        current_state,
        receive_name,
        parameter,
        energy,
    )
}
