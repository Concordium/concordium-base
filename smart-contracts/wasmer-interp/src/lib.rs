mod ffi;
mod types;

use contracts_common::*;
use std::{
    cell::Cell,
    collections::LinkedList,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
pub use types::*;
use wasmer_runtime::{
    error, func, imports, instantiate, types as wasmer_types, Array, Ctx, ImportObject, Module,
    Value, WasmPtr,
};

#[derive(Clone, Default)]
/// Structure to support logging of events from smart contracts.
pub struct Logs {
    pub logs: Arc<Mutex<LinkedList<Vec<u8>>>>,
}

impl Logs {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(Mutex::new(LinkedList::new())),
        }
    }

    pub fn log_event(&self, event: Vec<u8>) {
        if let Ok(mut guard) = self.logs.lock() {
            guard.push_back(event);
        }
        // else todo
    }

    pub fn iterate(&self) -> LinkedList<Vec<u8>> {
        if let Ok(guard) = self.logs.lock() {
            guard.clone()
        } else {
            unreachable!("Failed.");
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if let Ok(guard) = self.logs.lock() {
            let len = guard.len();
            let mut out = Vec::with_capacity(4 * len + 4);
            out.extend_from_slice(&(len as u32).to_be_bytes());
            for v in guard.iter() {
                out.extend_from_slice(&(v.len() as u32).to_be_bytes());
                out.extend_from_slice(v);
            }
            out
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }
}

#[derive(Clone)]
pub struct Energy {
    /// Energy left to use
    pub energy: Arc<AtomicU64>,
}

impl Energy {
    pub fn new(initial_energy: u64) -> Self {
        Self {
            energy: Arc::new(AtomicU64::new(initial_energy)),
        }
    }

    pub fn tick_energy(&self, e: u32) -> Result<(), error::RuntimeError> {
        let e = u64::from(e);
        let old_val = self.energy.fetch_sub(e, Ordering::SeqCst);
        if old_val >= e {
            Ok(())
        } else {
            Err(error::RuntimeError::User(Box::new("out of energy")))
        }
    }

    pub fn get_remaining_energy(&self) -> u64 { self.energy.load(Ordering::Acquire) }
}

// FIXME: Add support for trees, not just accept/reject.
#[derive(Clone)]
pub struct Outcome {
    pub cur_state: Arc<Mutex<Vec<Action>>>,
}

impl Outcome {
    // FIXME: This allow is only temporary, until we have more outcomes.
    #[allow(clippy::mutex_atomic)]
    pub fn init() -> Outcome {
        Self {
            cur_state: Arc::new(Mutex::new(Vec::new())),
        }
    }

    // FIXME: This is not how it should be.
    pub fn accept(&self) -> u32 {
        if let Ok(mut guard) = self.cur_state.lock() {
            let response = guard.len();
            guard.push(Action::Accept);
            response as u32
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    pub fn simple_transfer(
        &self,
        bytes: &[Cell<u8>],
        amount: u64,
    ) -> Result<u32, error::RuntimeError> {
        if let Ok(mut guard) = self.cur_state.lock() {
            let response = guard.len();
            if bytes.len() != 32 {
                Err(error::RuntimeError::User(Box::new("simple-transfer: Bytes length not 32.")))
            } else {
                let mut addr = [0u8; 32];
                for (place, byte) in addr.iter_mut().zip(bytes) {
                    *place = byte.get();
                }
                let to_addr = AccountAddress(addr);
                guard.push(Action::SimpleTransfer {
                    to_addr,
                    amount,
                });
                Ok(response as u32)
            }
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    pub fn send(
        &self,
        addr_index: u64,
        addr_subindex: u64,
        receive_name_bytes: &[Cell<u8>],
        amount: u64,
        parameter_bytes: &[Cell<u8>],
    ) -> Result<u32, error::RuntimeError> {
        if let Ok(mut guard) = self.cur_state.lock() {
            let response = guard.len();

            let mut name = Vec::with_capacity(receive_name_bytes.len());
            for cell in receive_name_bytes.iter() {
                name.push(cell.get());
            }

            let mut parameter = Vec::with_capacity(parameter_bytes.len());
            for cell in parameter_bytes.iter() {
                parameter.push(cell.get());
            }

            let to_addr = ContractAddress {
                index:    addr_index,
                subindex: addr_subindex,
            };

            guard.push(Action::Send {
                to_addr,
                name,
                amount,
                parameter,
            });

            Ok(response as u32)
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    pub fn combine_and(&self, l: u32, r: u32) -> Result<u32, error::RuntimeError> {
        if let Ok(mut guard) = self.cur_state.lock() {
            let response = guard.len() as u32;
            if l < response && r < response {
                guard.push(Action::And {
                    l,
                    r,
                });
                Ok(response)
            } else {
                Err(error::RuntimeError::User(Box::new("Actions not known already.")))
            }
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    pub fn combine_or(&self, l: u32, r: u32) -> Result<u32, error::RuntimeError> {
        if let Ok(mut guard) = self.cur_state.lock() {
            let response = guard.len() as u32;
            if l < response && r < response {
                guard.push(Action::Or {
                    l,
                    r,
                });
                Ok(response)
            } else {
                Err(error::RuntimeError::User(Box::new("Actions not known already.")))
            }
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    pub fn get(&self) -> Vec<Action> {
        if let Ok(guard) = self.cur_state.lock() {
            guard.clone()
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }
}

/// Smart contract state.
#[derive(Clone)]
pub struct State {
    pub state: Arc<Mutex<Vec<u8>>>,
}

impl State {
    pub fn is_empty(&self) -> bool {
        if let Ok(guard) = self.state.lock() {
            guard.is_empty()
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    // FIXME: This should not be copying so much data around, but for POC it is
    // fine.
    pub fn new(st: Option<&[u8]>) -> Self {
        match st {
            None => Self {
                state: Arc::new(Mutex::new(Vec::new())),
            },
            Some(bytes) => Self {
                state: Arc::new(Mutex::new(Vec::from(bytes))),
            },
        }
    }

    pub fn len(&self) -> u32 {
        if let Ok(guard) = self.state.lock() {
            guard.len() as u32
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    pub fn write_state(&self, offset: u32, bytes: &[Cell<u8>]) -> Result<u32, ()> {
        let length = bytes.len();
        let offset = offset as usize;
        match self.state.lock() {
            Ok(mut guard) => {
                if offset > guard.len() {
                    // cannot write past the offset
                    Err(())
                } else {
                    match offset.checked_add(length) {
                        None => Err(()),
                        Some(new_length) => {
                            if guard.len() < new_length as usize {
                                guard.resize(new_length as usize, 0u8);
                            }
                            for (place, byte) in guard[offset..].iter_mut().zip(bytes) {
                                *place = byte.get();
                            }
                            Ok(length as u32)
                        }
                    }
                }
            }
            Err(_) => Err(()),
        }
    }

    pub fn load_state(&self, offset: u32, bytes: &mut [Cell<u8>]) -> Result<u32, ()> {
        let offset = offset as usize;
        let length = bytes.len();
        match self.state.lock() {
            Ok(guard) => {
                if offset > guard.len() {
                    Ok(0)
                } else {
                    for (place, byte) in bytes.iter_mut().zip(guard[offset..].iter().take(length)) {
                        place.set(*byte);
                    }
                    Ok(std::cmp::min(length as u32, (guard.len() - offset) as u32))
                }
            }
            Err(_) => Err(()),
        }
    }

    pub fn resize_state(&self, new_size: u32) -> Result<u32, ()> {
        match self.state.lock() {
            Ok(mut guard) => {
                guard.resize(new_size as usize, 0u8);
                Ok(1)
            }
            Err(_) => Err(()),
        }
    }

    pub fn get(&self) -> Vec<u8> {
        if let Ok(guard) = self.state.lock() {
            guard.clone()
        } else {
            todo!("Should not happen.")
        }
    }
}

#[inline(always)]
fn put_in_memory(ctx: &mut Ctx, ptr: WasmPtr<u8, Array>, bytes: &Vec<u8>) -> Result<(), ()> {
    let bytes_len = bytes.len() as u32;
    let memory = ctx.memory(0);
    match unsafe { ptr.deref_mut(memory, 0, bytes_len) } {
        Some(cells) => {
            for (place, byte) in cells.iter_mut().zip(bytes) {
                place.set(*byte);
            }
            Ok(())
        }
        None => Err(()),
    }
}

pub fn make_imports(
    which: Which,
    parameter: Parameter,
    energy: u64,
) -> (ImportObject, Logs, Energy, State, Outcome) {
    let logs = Logs::new();
    let energy = Energy::new(energy);
    let energy_clone = energy.clone();
    let tick_energy =
        move |e: u32| -> Result<(), error::RuntimeError> { energy_clone.tick_energy(e) };
    let state = match which {
        Which::Init {
            ..
        } => State::new(None),
        Which::Receive {
            current_state,
            ..
        } => State::new(Some(current_state)),
    };
    let event_logs = logs.clone();
    let log_event = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>, len: u32| {
        let memory = ctx.memory(0);
        if let Some(cells) = ptr.deref(memory, 0, len) {
            let res = cells.iter().map(|x| x.get()).collect::<Vec<u8>>();
            event_logs.log_event(res);
            Ok(())
        } else {
            Err(())
        }
    };
    let w_state = state.clone();
    let g_state = state.clone();
    let l_state = state.clone();
    let s_state = state.clone();
    let write_state = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>, length: u32, offset: u32| {
        let memory = ctx.memory(0);
        match ptr.deref(memory, 0, length) {
            Some(cells) => w_state.write_state(offset, cells),
            _ => Err(()),
        }
    };
    let load_state = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>, length: u32, offset: u32| {
        let memory = ctx.memory(0);
        match unsafe { ptr.deref_mut(memory, 0, length) } {
            Some(cells) => l_state.load_state(offset, cells),
            None => Err(()),
        }
    };

    let resize_state = move |new_size: u32| g_state.resize_state(new_size);
    let state_size = move || s_state.len();

    let outcome = Outcome::init();
    let a_outcome = outcome.clone();
    let simple_transfer_outcome = a_outcome.clone();
    let send_outcome = a_outcome.clone();
    let and_outcome = a_outcome.clone();
    let accept = move || a_outcome.accept();

    let parameter_size = parameter.len() as u32;
    let get_parameter_size = move |_ctx: &mut Ctx| parameter_size;
    let get_parameter_section =
        move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>, len: u32, offset: u32| -> Result<u32, _> {
            let memory = ctx.memory(0);
            if offset as usize >= parameter.len() {
                return Ok(0u32);
            }
            match unsafe { ptr.deref_mut(memory, 0, len) } {
                Some(cells) => {
                    // at this point offset < parameter.len()
                    let offset = offset as usize;
                    let end = std::cmp::min(offset + len as usize, parameter.len());
                    for (place, byte) in cells.iter_mut().zip(&parameter[offset..end]) {
                        place.set(*byte);
                    }
                    Ok((end - offset) as u32)
                }
                None => Err(error::RuntimeError::User(Box::new("Cannot get parameter."))),
            }
        };

    let simple_transfer = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>, amount: u64| {
        let memory = ctx.memory(0);
        match unsafe { ptr.deref_mut(memory, 0, 32) } {
            Some(cells) => simple_transfer_outcome.simple_transfer(cells, amount),
            None => {
                Err(error::RuntimeError::User(Box::new("Cannot read address for simple transfer.")))
            }
        }
    };

    let send = move |ctx: &mut Ctx,
                     addr_index: u64,
                     addr_subindex: u64,
                     receive_name_ptr: WasmPtr<u8, Array>,
                     receive_name_len: u32,
                     amount: u64,
                     parameter_ptr: WasmPtr<u8, Array>,
                     parameter_len: u32| {
        let memory = ctx.memory(0);
        match unsafe { receive_name_ptr.deref_mut(memory, 0, receive_name_len) } {
            Some(receive_name_bytes) => match unsafe {
                parameter_ptr.deref_mut(memory, 0, parameter_len)
            } {
                Some(parameter_bytes) => send_outcome.send(
                    addr_index,
                    addr_subindex,
                    receive_name_bytes,
                    amount,
                    parameter_bytes,
                ),
                None => Err(error::RuntimeError::User(Box::new("Cannot read parameter for send."))),
            },
            None => Err(error::RuntimeError::User(Box::new(
                "Cannot read receive function name for send.",
            ))),
        }
    };

    let or_outcome = and_outcome.clone();

    let combine_and =
        move |l: u32, r: u32| -> Result<u32, error::RuntimeError> { and_outcome.combine_and(l, r) };

    let combine_or =
        move |l: u32, r: u32| -> Result<u32, error::RuntimeError> { or_outcome.combine_or(l, r) };

    match which {
        Which::Init {
            init_ctx
        } => {
            let init_origin_bytes = to_bytes(&init_ctx.init_origin);
            let get_init_origin = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| put_in_memory(ctx, ptr, &init_origin_bytes);
            
            // Chain meta data getters
            let slot_number = init_ctx.metadata.slot_number;
            let get_slot_number = move || slot_number;
            let block_height = init_ctx.metadata.block_height;
            let get_block_height = move || block_height;
            let finalized_height = init_ctx.metadata.finalized_height;
            let get_finalized_height = move || finalized_height;
            let slot_time = init_ctx.metadata.slot_time;
            let get_slot_time = move || slot_time;

            let err_func_u64 = || -> Result<u64, ()> { Err(()) };
            let err_func_memory = |_ctx: &mut Ctx, _ptr: WasmPtr<u8, Array>|  -> Result<(), ()> { Err(()) };
            
            let imps = imports! {
                "concordium" => {
                    // NOTE: validation will only allow access to a given list of these functions (check to be added)
                    "get_init_origin" => func!(get_init_origin),
                    "get_receive_invoker" => func!(err_func_memory),
                    "get_receive_self_address" => func!(err_func_memory),
                    "get_receive_self_balance" => func!(err_func_u64),
                    "get_receive_sender" => func!(err_func_memory),
                    "get_receive_owner" => func!(err_func_memory),
                    "get_slot_number" => func!(get_slot_number),
                    "get_block_height" => func!(get_block_height),
                    "get_finalized_height" => func!(get_finalized_height),
                    "get_slot_time" => func!(get_slot_time),
                    "get_parameter_section" => func!(get_parameter_section),
                    "get_parameter_size" => func!(get_parameter_size),
                    "combine_and" => func!(combine_and),
                    "combine_or" => func!(combine_or),
                    "accept" => func!(accept),
                    "simple_transfer" => func!(simple_transfer),
                    "send" => func!(send),
                    "tick_energy" => func!(tick_energy),
                    "log_event" => func!(log_event),
                    "write_state" => func!(write_state),
                    "load_state" => func!(load_state),
                    "resize_state" => func!(resize_state),
                    "state_size" => func!(state_size),
                },
            };
            (imps, logs, energy, state, outcome)
        }
        Which::Receive {
            receive_ctx,
            ..
        } => {

            // Chain meta data getters
            let slot_number = receive_ctx.metadata.slot_number;
            let get_slot_number = move || slot_number;
            let block_height = receive_ctx.metadata.block_height;
            let get_block_height = move || block_height;
            let finalized_height = receive_ctx.metadata.finalized_height;
            let get_finalized_height = move || finalized_height;
            let slot_time = receive_ctx.metadata.slot_time;
            let get_slot_time = move || slot_time;

            let invoker_bytes = to_bytes(&receive_ctx.invoker);
            let get_receive_invoker = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| put_in_memory(ctx, ptr, &invoker_bytes);
            let self_address_bytes = to_bytes(&receive_ctx.self_address);
            let get_receive_self_address = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| put_in_memory(ctx, ptr, &self_address_bytes);
            let receive_self_balance = receive_ctx.self_balance;
            let get_receive_self_balance = move || receive_self_balance;
            let sender_bytes = to_bytes(&receive_ctx.sender);
            let get_receive_sender = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| put_in_memory(ctx, ptr, &sender_bytes);
            let owner_bytes = to_bytes(&receive_ctx.owner);
            let get_receive_owner = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| put_in_memory(ctx, ptr, &owner_bytes);

            let err_func = |_ctx: &mut Ctx, _ptr: WasmPtr<u8, Array>| -> Result<(), ()> { Err(()) };

            let imps = imports! {
                "concordium" => {
                    "get_init_origin" => func!(err_func),
                    "get_receive_invoker" => func!(get_receive_invoker),
                    "get_receive_self_address" => func!(get_receive_self_address),
                    "get_receive_self_balance" => func!(get_receive_self_balance),
                    "get_receive_sender" => func!(get_receive_sender),
                    "get_receive_owner" => func!(get_receive_owner),
                    "get_slot_number" => func!(get_slot_number),
                    "get_block_height" => func!(get_block_height),
                    "get_finalized_height" => func!(get_finalized_height),
                    "get_slot_time" => func!(get_slot_time),
                    "get_parameter_section" => func!(get_parameter_section),
                    "get_parameter_size" => func!(get_parameter_size),
                    "combine_and" => func!(combine_and),
                    "combine_or" => func!(combine_or),
                    "accept" => func!(accept),
                    "simple_transfer" => func!(simple_transfer),
                    "send" => func!(send),
                    "tick_energy" => func!(tick_energy),
                    "log_event" => func!(log_event),
                    "write_state" => func!(write_state),
                    "load_state" => func!(load_state),
                    "resize_state" => func!(resize_state),
                    "state_size" => func!(state_size),
                },
            };
            (imps, logs, energy, state, outcome)
        }
    }
}

type Parameter = Vec<u8>;

pub fn invoke_init(
    wasm: &[u8],
    amount: Amount,
    init_ctx: InitContext,
    init_name: &str,
    parameter: Parameter,
    energy: u64,
) -> Result<InitResult, error::CallError> {
    let (import_obj, logs, energy, state, _) = make_imports(
        Which::Init {
            init_ctx: &init_ctx,
        },
        parameter,
        energy,
    );
    // FIXME: We should cache instantiated modules, depending on how expensive
    // instantiation actually is.
    // Wasmer supports cacheing of modules into Artifacts.
    let inst = instantiate(wasm, &import_obj)
        .expect("Instantiation should always succeed for well-formed modules.");
    let res = inst.call(init_name, &[Value::I64(amount as i64)])?;
    let remaining_energy = energy.get_remaining_energy();
    if let Some(wasmer_runtime::Value::I32(0)) = res.first() {
        Ok(InitResult::Success {
            logs,
            state,
            remaining_energy,
        })
    } else {
        Ok(InitResult::Reject {
            remaining_energy,
        })
    }
}

pub fn invoke_receive(
    wasm: &[u8],
    amount: Amount,
    receive_ctx: ReceiveContext,
    current_state: &[u8],
    receive_name: &str,
    parameter: Parameter,
    energy: u64,
) -> Result<ReceiveResult, error::CallError> {
    // Make the imports (host functions), with shared variables for logs, energy,
    // state, outcome.
    let (import_obj, logs, energy, state, outcome) = make_imports(
        Which::Receive {
            receive_ctx: &receive_ctx,
            current_state,
        },
        parameter,
        energy,
    );
    // FIXME: We should cache instantiated modules, depending on how expensive
    // instantiation actually is.
    // Wasmer supports cacheing of modules into Artifacts.
    let inst = instantiate(wasm, &import_obj)
        .expect("Instantiation should always succeed for well-formed modules.");
    let res = inst.call(receive_name, &[Value::I64(amount as i64)])?;
    let remaining_energy = energy.get_remaining_energy();
    if let Some(wasmer_runtime::Value::I32(n)) = res.first() {
        // FIXME: We should filter out to only return the ones reachable from
        // the root.
        let mut actions = outcome.get();
        if *n >= 0 && (*n as usize) < actions.len() {
            let n = *n as usize;
            actions.truncate(n + 1);
            Ok(ReceiveResult::Success {
                logs,
                state,
                actions,
                remaining_energy,
            })
        } else if *n >= 0 {
            Err(error::CallError::Runtime(error::RuntimeError::User(Box::new("Invalid return."))))
        } else {
            Ok(ReceiveResult::Reject {
                remaining_energy,
            })
        }
    } else {
        Err(error::CallError::Runtime(error::RuntimeError::User(Box::new("Invalid return."))))
    }
}

/// Get the init methods of the module.
pub fn get_inits(module: &Module) -> Vec<String> {
    let mut out = Vec::new();
    for export in module.exports() {
        if export.name.starts_with("init") {
            if let wasmer_types::ExternDescriptor::Function(_) = export.ty {
                out.push(export.name.to_owned());
            }
        }
    }
    out
}

/// Get the receive methods of the module.
pub fn get_receives(module: &Module) -> Vec<String> {
    let mut out = Vec::new();
    for export in module.exports() {
        if export.name.starts_with("receive") {
            if let wasmer_types::ExternDescriptor::Function(_) = export.ty {
                out.push(export.name.to_owned());
            }
        }
    }
    out
}
