mod ffi;
mod types;

use contracts_common::*;
use std::{
    cell::Cell,
    collections::LinkedList,
    sync::{Arc, Mutex},
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

pub fn make_imports(which: Which, parameter: Parameter) -> (ImportObject, Logs, State, Outcome) {
    let logs = Logs::new();
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
    let s_outcome = a_outcome.clone();
    let and_outcome = a_outcome.clone();
    let accept = move || a_outcome.accept();

    let parameter_size = parameter.len() as u32;
    let get_parameter_size = move |_ctx: &mut Ctx| parameter_size;
    let get_parameter = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| {
        let memory = ctx.memory(0);
        match unsafe { ptr.deref_mut(memory, 0, parameter_size) } {
            Some(cells) => {
                for (place, byte) in cells.iter_mut().zip(&parameter) {
                    place.set(*byte);
                }
                Ok(())
            }
            None => Err(error::RuntimeError::User(Box::new("Cannot get parameter."))),
        }
    };

    let simple_transfer = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>, amount: u64| {
        let memory = ctx.memory(0);
        match unsafe { ptr.deref_mut(memory, 0, 32) } {
            Some(cells) => s_outcome.simple_transfer(cells, amount),
            None => {
                Err(error::RuntimeError::User(Box::new("Cannot read address for simple transfer.")))
            }
        }
    };

    let or_outcome = and_outcome.clone();

    let combine_and =
        move |l: u32, r: u32| -> Result<u32, error::RuntimeError> { and_outcome.combine_and(l, r) };

    let combine_or =
        move |l: u32, r: u32| -> Result<u32, error::RuntimeError> { or_outcome.combine_or(l, r) };

    match which {
        Which::Init {
            ref init_ctx,
        } => {
            // Get the init context.
            let init_bytes = to_bytes(init_ctx);
            let init_bytes_len = init_bytes.len() as u32;
            let get_init_ctx = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| {
                let memory = ctx.memory(0);
                match unsafe { ptr.deref_mut(memory, 0, init_bytes_len) } {
                    Some(cells) => {
                        for (place, byte) in cells.iter_mut().zip(&init_bytes) {
                            place.set(*byte);
                        }
                        Ok(())
                    }
                    None => Err(()),
                }
            };
            let get_receive_ctx =
                |_ctx: &mut Ctx, _ptr: WasmPtr<u8, Array>| -> Result<(), ()> { Err(()) };
            let get_receive_ctx_size = || -> Result<u32, ()> { Err(()) };

            let imps = imports! {
                "concordium" => {
                    "get_init_ctx" => func!(get_init_ctx),
                    "get_receive_ctx" => func!(get_receive_ctx),
                    "get_receive_ctx_size" => func!(get_receive_ctx_size),
                    "get_parameter" => func!(get_parameter),
                    "get_parameter_size" => func!(get_parameter_size),
                    "combine_and" => func!(combine_and),
                    "combine_or" => func!(combine_or),
                    "accept" => func!(accept),
                    "simple_transfer" => func!(simple_transfer),
                    "log_event" => func!(log_event),
                    "write_state" => func!(write_state),
                    "load_state" => func!(load_state),
                    "resize_state" => func!(resize_state),
                    "state_size" => func!(state_size),
                },
            };
            (imps, logs, state, outcome)
        }
        Which::Receive {
            ref receive_ctx,
            ..
        } => {
            let receive_bytes = to_bytes(receive_ctx);
            let receive_bytes_len = receive_bytes.len() as u32;
            let get_receive_ctx = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| {
                let memory = ctx.memory(0);
                match unsafe { ptr.deref_mut(memory, 0, receive_bytes_len) } {
                    Some(cells) => {
                        for (place, byte) in cells.iter_mut().zip(&receive_bytes) {
                            place.set(*byte);
                        }
                        Ok(())
                    }
                    None => Err(error::RuntimeError::User(Box::new(
                        "Cannot acquire memory to write receive context into.",
                    ))),
                }
            };
            let get_receive_ctx_size = move || -> u32 { receive_bytes_len };
            let get_init_ctx =
                |_ctx: &mut Ctx, _ptr: WasmPtr<u8, Array>| -> Result<(), ()> { Err(()) };

            let imps = imports! {
                "concordium" => {
                    "get_init_ctx" => func!(get_init_ctx),
                    "get_receive_ctx" => func!(get_receive_ctx),
                    "get_receive_ctx_size" => func!(get_receive_ctx_size),
                    "get_parameter" => func!(get_parameter),
                    "get_parameter_size" => func!(get_parameter_size),
                    "combine_and" => func!(combine_and),
                    "combine_or" => func!(combine_or),
                    "accept" => func!(accept),
                    "simple_transfer" => func!(simple_transfer),
                    "log_event" => func!(log_event),
                    "write_state" => func!(write_state),
                    "load_state" => func!(load_state),
                    "resize_state" => func!(resize_state),
                    "state_size" => func!(state_size),
                },
            };
            (imps, logs, state, outcome)
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
) -> Result<InitResult, error::CallError> {
    let (import_obj, logs, state, _) = make_imports(
        Which::Init {
            init_ctx,
        },
        parameter,
    );
    // FIXME: We should cache instantiated modules, depending on how expensive
    // instantiation actually is.
    // Wasmer supports cacheing of modules into Artifacts.
    let inst = instantiate(wasm, &import_obj)
        .expect("Instantiation should always succeed for well-formed modules.");
    let res = inst.call(init_name, &[Value::I64(amount as i64)])?;
    if let Some(wasmer_runtime::Value::I32(0)) = res.first() {
        Ok(InitResult::Success {
            logs,
            state,
        })
    } else {
        Ok(InitResult::Reject {
            logs,
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
) -> Result<ReceiveResult, error::CallError> {
    let (import_obj, logs, state, outcome) = make_imports(
        Which::Receive {
            receive_ctx,
            current_state,
        },
        parameter,
    );
    // FIXME: We should cache instantiated modules, depending on how expensive
    // instantiation actually is.
    // Wasmer supports cacheing of modules into Artifacts.
    let inst = instantiate(wasm, &import_obj)
        .expect("Instantiation should always succeed for well-formed modules.");
    let res = inst.call(receive_name, &[Value::I64(amount as i64)])?;
    if let Some(wasmer_runtime::Value::I32(n)) = res.first() {
        let mut actions = outcome.get();
        if *n >= 0 && (*n as usize) < actions.len() {
            let n = *n as usize;
            actions.truncate(n + 1);
            Ok(ReceiveResult::Success {
                logs,
                state,
                actions,
            })
        } else if *n >= 0 {
            Err(error::CallError::Runtime(error::RuntimeError::User(Box::new("Invalid return."))))
        } else {
            Ok(ReceiveResult::Reject {
                logs,
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
