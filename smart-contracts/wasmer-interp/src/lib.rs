mod ffi;
mod types;

use std::{
    cell::Cell,
    collections::LinkedList,
    sync::{Arc, Mutex},
};
use wasmer_runtime::{
    error, func, imports, instantiate, types as wasmer_types, Array, Ctx, ImportObject, Module,
    Value, WasmPtr,
};

pub use types::*;

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
            out[0..4].copy_from_slice(&(len as u32).to_be_bytes());
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
// FIXME: This allow is only temporary, until we have more outcomes.
pub struct Outcome {
    #[allow(clippy::mutex_atomic)]
    pub cur_state: Arc<Mutex<bool>>,
}

impl Outcome {
    // FIXME: This allow is only temporary, until we have more outcomes.
    #[allow(clippy::mutex_atomic)]
    pub fn init() -> Outcome {
        Self {
            cur_state: Arc::new(Mutex::new(true)),
        }
    }

    // FIXME: This is not how it should be.
    pub fn accept(&self) {
        if let Ok(mut guard) = self.cur_state.lock() {
            *guard = true;
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    // FIXME: This is not how it should be.
    pub fn fail(&self) {
        if let Ok(mut guard) = self.cur_state.lock() {
            *guard = false;
        } else {
            unreachable!("Failed to acquire lock.")
        }
    }

    pub fn get(&self) -> bool {
        if let Ok(guard) = self.cur_state.lock() {
            *guard
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

pub fn make_imports(which: Which) -> (ImportObject, Logs, State, Outcome) {
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

    let sender_bytes = match which {
        Which::Init {
            init_ctx,
        } => init_ctx.init_origin,
        Which::Receive {
            receive_ctx,
            ..
        } => receive_ctx.invoker,
    };

    // Get the sender of the transaction.
    let sender = move |ctx: &mut Ctx, ptr: WasmPtr<u8, Array>| {
        let memory = ctx.memory(0);
        match unsafe { ptr.deref_mut(memory, 0, 32) } {
            Some(cells) => {
                for (place, byte) in cells.iter_mut().zip(sender_bytes.as_ref()) {
                    place.set(*byte);
                }
                Ok(())
            }
            None => Err(()),
        }
    };

    let outcome = Outcome::init();
    let a_outcome = outcome.clone();
    let f_outcome = a_outcome.clone();
    let accept = move || a_outcome.accept();
    let fail = move || f_outcome.fail();

    let imps = imports! {
        "concordium" => {
            "get_sender" => func!(sender),
            "accept" => func!(accept),
            "fail" => func!(fail),
            "log_event" => func!(log_event),
            "write_state" => func!(write_state),
            "load_state" => func!(load_state),
            "resize_state" => func!(resize_state),
            "state_size" => func!(state_size),
        },
    };
    (imps, logs, state, outcome)
}

pub fn invoke_init(
    wasm: &[u8],
    amount: Amount,
    init_ctx: InitContext,
    init_name: &str,
) -> Result<InitResult, error::CallError> {
    let (import_obj, logs, state, outcome) = make_imports(Which::Init {
        init_ctx,
    });
    // FIXME: We should cache instantiated modules, depending on how expensive
    // instantiation actually is.
    // Wasmer supports cacheing of modules into Artifacts.
    let inst = instantiate(wasm, &import_obj)
        .expect("Instantiation should always succeed for well-formed modules.");
    let _ = inst.call(init_name, &[Value::I64(amount as i64)])?;
    if outcome.get() {
        Ok(InitResult::Success {
            logs,
            state,
        })
    } else {
        Ok(InitResult::Reject)
    }
}

pub fn invoke_receive(
    wasm: &[u8],
    amount: Amount,
    receive_ctx: ReceiveContext,
    current_state: &[u8],
    receive_name: &str,
) -> Result<ReceiveResult, error::CallError> {
    let (import_obj, logs, state, outcome) = make_imports(Which::Receive {
        receive_ctx,
        current_state,
    });
    // FIXME: We should cache instantiated modules, depending on how expensive
    // instantiation actually is.
    // Wasmer supports cacheing of modules into Artifacts.
    let inst = instantiate(wasm, &import_obj)
        .expect("Instantiation should always succeed for well-formed modules.");
    let _ = inst.call(receive_name, &[Value::I64(amount as i64)])?;
    if outcome.get() {
        Ok(ReceiveResult::Success {
            logs,
            state,
            actions: vec![],
        })
    } else {
        Ok(ReceiveResult::Reject {
            logs,
        })
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
