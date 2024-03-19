// TODO:
// - Read all data from instructions at once (e.g., three locals).
// - GlobalGet can be short circuited if we store all constants in the module in
//   one place together with globals.

//! An implementation of the abstract machine that can run artifacts.
//! This module defines types related to code execution. The functions to run
//! code are defined as methods on the [`Artifact`] type, e.g.,
//! [`Artifact::run`].

use crate::{
    artifact::{StackValue, *},
    constants::{MAX_NUM_PAGES, PAGE_SIZE},
    types::*,
};
use anyhow::{anyhow, bail, ensure};
use std::{convert::TryInto, io::Write};

#[cfg(not(target_endian = "little"))]
compile_error!("The intepreter only supports little endian platforms.");

/// An empty type used when no interrupt is possible by a host function call.
#[derive(Debug, Copy, Clone)]
pub enum NoInterrupt {}

/// The host that can process calls to external, host, functions.
/// This is a Wasm concept. Wasm modules are self-contained and instructions can
/// only modify the Wasm memory and stack and cannot access information about
/// the external world, such as current time for example. Host functions fill
/// that role.
pub trait Host<I> {
    type Interrupt;
    /// Charge the given amount of energy for the initial memory.
    /// The argument is the number of pages.
    fn tick_initial_memory(&mut self, num_pages: u32) -> RunResult<()>;
    /// Call the specified host function, giving it access to the current memory
    /// and stack. The return value of `Ok(None)` signifies that execution
    /// succeeded and the machine should proceeed, the return value of
    /// `Ok(Some(i))` indicates that an interrupt was triggered by the host
    /// function, and the return value of `Err(_)` signifies a trap, i.e., the
    /// host function was called with illegal arguments.
    ///
    /// Interrupts are used by Concordium to execute inter-contract calls and
    /// other similar operations. When a contract attempts to invoke another
    /// contract an interrupt is triggered and an the invocation is handled,
    /// along with any recursion. Execution of the original contract resumes
    /// after handling the interrupt.
    fn call(
        &mut self,
        f: &I,
        memory: &mut Vec<u8>,
        stack: &mut RuntimeStack,
    ) -> RunResult<Option<Self::Interrupt>>;

    /// Consume a given amount of NRG.
    fn tick_energy(&mut self, _energy: u64) -> RunResult<()>;

    /// Track a function call. This is called upon entry to a function. The
    /// corresonding [`track_return`](Host::track_return) is called upon
    /// return from a function. These two together can be used to track function
    /// call stack depth. [`track_call`](Host::track_call) can return an `Err`
    /// to indicate that a call stack depth was exceeded. This will lead to
    /// immediate termination of execution.
    fn track_call(&mut self) -> RunResult<()>;

    /// Called when a function returns. See documentation of
    /// [`track_call`](Host::track_call) for details.
    fn track_return(&mut self);
}

/// Result of execution. Runtime exceptions are returned as `Err(_)`.
/// This includes traps, illegal memory accesses, etc.
pub type RunResult<A> = anyhow::Result<A>;

/// Configuration that can be run. This maintains the snapshot of the state of
/// the machine, such as the current instruction pointer, current memory
/// contents, the function stack, etc.
#[derive(Debug)]
pub struct RunConfig {
    /// Current value of the program counter.
    pc:               usize,
    /// Index of the current instruction list that we are executing
    /// (instructions of the current function). Note that this is the index in
    /// the list of defined functions. Imported functions do not count towards
    /// it. It is assumed that this index points to a valid function in the
    /// artifact's list of functions and the interpreter is subject to undefined
    /// behaviour if this is not the case.
    instructions_idx: usize,
    /// Stack of function frames.
    function_frames:  Vec<FunctionState>,
    /// Location where the return value must be written in the locals array
    /// **after** a return is called. If `None` the function has no return
    /// value.
    return_type:      Option<(usize, ValueType)>,
    /// Current state of the memory.
    memory:           Vec<u8>,
    /// All the "locals". Including parameters, declared locals and temporary
    /// ones.
    locals_vec:       Vec<StackValue>,
    /// Position where the locals for the current frame start.
    locals_base:      usize,
    /// Current values of globals.
    globals:          Vec<StackValue>,
    /// Configuration parameter, the maximum size of the memory execution is
    /// allowed to allocate. This is fixed at startup and cannot be changed
    /// during execution.
    max_memory:       usize,
    return_value_loc: usize,
}

impl RunConfig {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    /// Push a value to the configuration's stack. This is typically used when
    /// the interrupt produced a response.
    pub fn push_value<F>(&mut self, f: F)
    where
        StackValue: From<F>, {
        let v: StackValue = f.into();
        self.locals_vec[self.locals_base + self.return_value_loc] = v;
    }
}

#[derive(Debug)]
/// A successful outcome of code execution.
pub enum ExecutionOutcome<Interrupt> {
    /// Execution was successful and the function terminated normally.
    Success {
        /// Result of execution of the function. If the function has unit result
        /// type then the result is [`None`], otherwise it is the value.
        result: Option<Value>,
        /// Final memory of the machine.
        memory: Vec<u8>,
    },
    /// Execution was interrupted in the given state. It can be resumed. There
    /// is no resulting value since execution did not yet complete.
    Interrupted {
        /// The interrupt reason provided by the host function.
        reason: Interrupt,
        /// The current configuration that can be used to resume execution.
        config: RunConfig,
    },
}

#[derive(Debug)]
/// State of a function recorded in the function frame stack.
/// This records enough information to allow us to resume execution upon return
/// from a nested function call.
struct FunctionState {
    /// The program counter relative to the instruction list.
    pc:               usize,
    /// Instructions of the function.
    instructions_idx: usize,
    /// Index in the stack where the locals start. We have a single stack for
    /// the entire execution and after entering a function all the locals
    /// are pushed on first (this includes function parameters).
    locals_base:      usize,
    /// Return type of the function.
    return_type:      Option<(usize, ValueType)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A Wasm typed value. The values are not inherently signed or unsigned,
/// but we choose signed integers as the representation type.
///
/// This works well on any two's complement platform.
pub enum Value {
    I32(i32),
    I64(i64),
}

impl From<Value> for ValueType {
    fn from(v: Value) -> Self {
        match v {
            Value::I32(_) => ValueType::I32,
            Value::I64(_) => ValueType::I64,
        }
    }
}

impl From<Value> for i64 {
    fn from(v: Value) -> Self {
        match v {
            Value::I32(x) => i64::from(x),
            Value::I64(x) => x,
        }
    }
}

/// A runtime stack. This contains both the stack in a function, as well as all
/// the function parameters and locals of the function.
#[derive(Debug)]
pub struct RuntimeStack {
    /// The vector containing the whole stack.
    stack: Vec<StackValue>,
}

#[derive(Debug)]
/// A runtime error that we impose on top of the Wasm spec.
pub enum RuntimeError {
    /// Calling an imported function directly is not supported.
    DirectlyCallImport,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::DirectlyCallImport => {
                write!(f, "Calling an imported function directly is not supported.")
            }
        }
    }
}

impl RuntimeStack {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    /// Remove and return an element from the stack **assuming the stack has at
    /// least one element.**
    pub fn pop(&mut self) -> StackValue { self.stack.pop().expect("Stack not empty") }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    /// Push an element onto the stack.
    pub fn push(&mut self, x: StackValue) { self.stack.push(x); }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    /// Push a value onto the stack, as long as it is convertible into a
    /// [`StackValue`].
    pub fn push_value<F>(&mut self, f: F)
    where
        StackValue: From<F>, {
        self.push(StackValue::from(f))
    }

    /// **Remove** and return the top of the stack, **assuming the stack is not
    /// empty.**
    ///
    /// # Safety
    /// This function is safe provided
    /// - the stack is not empty
    /// - top of the stack contains a 32-bit value.
    pub unsafe fn pop_u32(&mut self) -> u32 { self.pop().short as u32 }

    /// **Remove** and return the top of the stack, **assuming the stack is not
    /// empty.**
    ///
    /// # Safety
    /// This function is safe provided
    /// - the stack is not empty
    /// - top of the stack contains a 32-bit value.
    pub unsafe fn peek_u32(&mut self) -> u32 {
        self.stack.last().expect("Non-empty stack").short as u32
    }

    /// **Remove** and return the top of the stack, **assuming the stack is not
    /// empty.**
    ///
    /// # Safety
    /// This function is safe provided
    /// - the stack is not empty
    /// - top of the stack contains a 64-bit value.
    pub unsafe fn pop_u64(&mut self) -> u64 { self.pop().long as u64 }
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_u16(pc: &mut *const u8) -> u16 {
    let r = unsafe { pc.cast::<u16>().read_unaligned() };
    *pc = unsafe { pc.add(2) };
    r
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_u32(pc: &mut *const u8) -> u32 {
    let r = unsafe { pc.cast::<u32>().read_unaligned() };
    *pc = unsafe { pc.add(4) };
    r
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_i32(pc: &mut *const u8) -> i32 {
    let r = unsafe { pc.cast::<i32>().read_unaligned() };
    *pc = unsafe { pc.add(4) };
    r
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_local(constants: &[i64], locals: &[StackValue], pc: &mut *const u8) -> StackValue {
    let v = get_i32(pc);
    if v >= 0 {
        let v = v as usize;
        // assert!(v < locals.len());
        *unsafe { locals.get_unchecked(v) }
    } else {
        let v = (-(v + 1)) as usize;
        // assert!((v as usize) < constants.len());
        StackValue::from(*unsafe { constants.get_unchecked(v) })
    }
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_local_mut<'a>(locals: &'a mut [StackValue], pc: &mut *const u8) -> &'a mut StackValue {
    let v = get_i32(pc);
    // Targets should never be constants, so we should always have a non-negative
    // value.
    // assert!(v >= 0);
    unsafe { locals.get_unchecked_mut(v as usize) }
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_u8(bytes: &[u8], pos: usize) -> RunResult<u8> {
    bytes.get(pos).copied().ok_or_else(|| anyhow!("Memory access out of bounds."))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_u16(bytes: &[u8], pos: usize) -> RunResult<u16> {
    ensure!(pos + 2 <= bytes.len(), "Memory access out of bounds.");
    let r = unsafe { bytes.as_ptr().add(pos).cast::<u16>().read_unaligned() };
    Ok(r)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_u32(bytes: &[u8], pos: usize) -> RunResult<u32> {
    ensure!(pos + 4 <= bytes.len(), "Memory access out of bounds.");
    let r = unsafe { bytes.as_ptr().add(pos).cast::<u32>().read_unaligned() };
    Ok(r)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i8(bytes: &[u8], pos: usize) -> RunResult<i8> {
    bytes.get(pos).map(|&x| x as i8).ok_or_else(|| anyhow!("Memory access out of bounds."))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i16(bytes: &[u8], pos: usize) -> RunResult<i16> {
    ensure!(pos + 2 <= bytes.len(), "Memory access out of bounds.");
    let r = unsafe { bytes.as_ptr().add(pos).cast::<i16>().read_unaligned() };
    Ok(r)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i32(bytes: &[u8], pos: usize) -> RunResult<i32> {
    ensure!(pos + 4 <= bytes.len(), "Memory access out of bounds.");
    let r = unsafe { bytes.as_ptr().add(pos).cast::<i32>().read_unaligned() };
    Ok(r)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i64(bytes: &[u8], pos: usize) -> RunResult<i64> {
    ensure!(pos + 8 <= bytes.len(), "Memory access out of bounds.");
    let r = unsafe { bytes.as_ptr().add(pos).cast::<i64>().read_unaligned() };
    Ok(r)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn memory_load<'a>(
    constants: &[i64],
    locals: &'a mut [StackValue],
    pc: &mut *const u8,
) -> (&'a mut StackValue, usize) {
    let offset = get_u32(pc);
    let base = get_local(constants, locals, pc);
    let result = get_local_mut(locals, pc);
    let pos = unsafe { base.short } as u32 as usize + offset as usize;
    (result, pos)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn memory_store(
    constants: &[i64],
    locals: &[StackValue],
    pc: &mut *const u8,
) -> (StackValue, usize) {
    let offset = get_u32(pc);
    let value = get_local(constants, locals, pc);
    let base = get_local(constants, locals, pc);
    (value, unsafe { base.short } as u32 as usize + offset as usize)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn write_memory_at(memory: &mut [u8], pos: usize, bytes: &[u8]) -> RunResult<()> {
    let end = pos + bytes.len();
    ensure!(end <= memory.len(), "Illegal memory access.");
    memory[pos..end].copy_from_slice(bytes);
    Ok(())
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn unary_i32(
    constants: &[i64],
    locals: &mut [StackValue],
    pc: &mut *const u8,
    f: impl Fn(i32) -> i32,
) {
    let source = get_local(constants, locals, pc);
    let target = get_local_mut(locals, pc);
    target.short = f(unsafe { source.short });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn unary_i64(
    constants: &[i64],
    locals: &mut [StackValue],
    pc: &mut *const u8,
    f: impl Fn(i64) -> i64,
) {
    let source = get_local(constants, locals, pc);
    let target = get_local_mut(locals, pc);
    target.long = f(unsafe { source.long });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i32(
    constants: &[i64],
    locals: &mut [StackValue],
    pc: &mut *const u8,
    f: impl Fn(i32, i32) -> i32,
) {
    let right = get_local(constants, locals, pc);
    let left = get_local(constants, locals, pc);
    let target = get_local_mut(locals, pc);
    target.short = f(unsafe { left.short }, unsafe { right.short });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i32_partial(
    constants: &[i64],
    locals: &mut [StackValue],
    pc: &mut *const u8,
    f: impl Fn(i32, i32) -> Option<i32>,
) -> RunResult<()> {
    let right = get_local(constants, locals, pc);
    let left = get_local(constants, locals, pc);
    let target = get_local_mut(locals, pc);
    target.short = f(unsafe { left.short }, unsafe { right.short })
        .ok_or_else(|| anyhow!("Runtime exception in i32 binary."))?;
    Ok(())
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i64(
    constants: &[i64],
    locals: &mut [StackValue],
    pc: &mut *const u8,
    f: impl Fn(i64, i64) -> i64,
) {
    let right = get_local(constants, locals, pc);
    let left = get_local(constants, locals, pc);
    let target = get_local_mut(locals, pc);
    target.long = f(unsafe { left.long }, unsafe { right.long });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i64_partial(
    constants: &[i64],
    locals: &mut [StackValue],
    pc: &mut *const u8,
    f: impl Fn(i64, i64) -> Option<i64>,
) -> RunResult<()> {
    let right = get_local(constants, locals, pc);
    let left = get_local(constants, locals, pc);
    let target = get_local_mut(locals, pc);
    target.long = f(unsafe { left.long }, unsafe { right.long })
        .ok_or_else(|| anyhow!("Runtime exception in i64 binary"))?;
    Ok(())
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i64_test(
    constants: &[i64],
    locals: &mut [StackValue],
    pc: &mut *const u8,
    f: impl Fn(i64, i64) -> i32,
) {
    let right = get_local(constants, locals, pc);
    let left = get_local(constants, locals, pc);
    let target = get_local_mut(locals, pc);
    target.short = f(unsafe { left.long }, unsafe { right.long });
}

impl<I: TryFromImport, R: RunnableCode> Artifact<I, R> {
    /// Attempt to run the entrypoint using the supplied arguments. The
    /// arguments are
    ///
    /// - `host` - the structure that resolves calls to external, host,
    ///   functions.
    /// - `name` - the name of the entrypoint to invoke
    /// - `args` - a list of arguments to the entrypoint. The argument list must
    ///   match the declared type of the entrypoint. If this is not the case
    ///   then execution will fail with an error.
    ///
    /// Note that this method at present cannot be used to directly call a host
    /// function. Only an entrypoint defined in the Wasm module can be called.
    pub fn run<Q: std::fmt::Display + Ord + ?Sized, H: Host<I>>(
        &self,
        host: &mut H,
        name: &Q,
        args: &[Value],
    ) -> RunResult<ExecutionOutcome<H::Interrupt>>
    where
        Name: std::borrow::Borrow<Q>, {
        let start = *self.get_entrypoint_index(name)?;
        // FIXME: The next restriction could easily be lifted, but it is not a problem
        // for now.
        ensure!(start as usize >= self.imports.len(), RuntimeError::DirectlyCallImport);
        let instructions_idx = start as usize - self.imports.len();
        let outer_function = &self.code[instructions_idx]; // safe because the artifact should be well-formed.
        let num_args: u32 = args.len().try_into()?;
        ensure!(
            outer_function.num_params() == num_args,
            "The number of arguments does not match the number of parameters {} != {}.",
            num_args,
            outer_function.num_params(),
        );
        for (p, actual) in outer_function.params().iter().zip(args.iter()) {
            // the first num_params locals are arguments
            let actual_ty = ValueType::from(*actual);
            ensure!(
                *p == actual_ty,
                "Argument of incorrect type: actual {:#?}, expected {:#?}.",
                actual_ty,
                *p
            )
        }

        let globals = self.global.inits.iter().copied().map(StackValue::from).collect::<Vec<_>>();
        let mut locals: Vec<StackValue> =
            vec![unsafe { std::mem::zeroed() }; outer_function.num_registers() as usize];
        for (&arg, place) in args.iter().zip(&mut locals) {
            *place = match arg {
                Value::I32(v) => StackValue::from(v),
                Value::I64(v) => StackValue::from(v),
            };
        }
        let memory = {
            if let Some(m) = self.memory.as_ref() {
                host.tick_initial_memory(m.init_size)?;
                // This is safe since maximum initial memory is limited to 32 pages.
                let mut memory = vec![0u8; (MAX_NUM_PAGES * PAGE_SIZE) as usize];
                unsafe {
                    memory.set_len((m.init_size * PAGE_SIZE) as usize);
                }
                for data in m.init.iter() {
                    (&mut memory[data.offset as usize..]).write_all(&data.init)?;
                }
                memory
            } else {
                Vec::new()
            }
        };

        let max_memory = self.memory.as_ref().map(|x| x.max_size).unwrap_or(0) as usize;

        let pc = 0;

        let function_frames: Vec<FunctionState> = Vec::new();
        let return_type = match outer_function.return_type() {
            BlockType::EmptyType => None,
            BlockType::ValueType(vt) => Some((0, vt)),
        };
        let locals_base = 0;

        let config = RunConfig {
            pc,
            instructions_idx,
            function_frames,
            return_type,
            memory,
            locals_vec: locals,
            locals_base,
            globals,
            max_memory,
            return_value_loc: 0, // not used
        };
        self.run_config(host, config)
    }

    /// Returns the index of the given entrypoint if it exists.
    fn get_entrypoint_index<Q>(&self, name: &Q) -> RunResult<&FuncIndex>
    where
        Q: std::fmt::Display + Ord + ?Sized,
        Name: std::borrow::Borrow<Q>, {
        self.export
            .get(name)
            .ok_or_else(|| anyhow!("Trying to invoke a method that does not exist: {}.", name))
    }

    /// Returns if the given entrypoint name exists in the artifact.
    pub fn has_entrypoint<Q>(&self, name: &Q) -> bool
    where
        Q: std::fmt::Display + Ord + ?Sized,
        Name: std::borrow::Borrow<Q>, {
        self.get_entrypoint_index(name).is_ok()
    }

    /// Run a [configuration](RunConfig) using the provided `host` to resolve
    /// calls to external functions.
    ///
    /// This executes code either until
    /// - the execution terminates with a result
    /// - there is an error
    /// - the host triggers an interrupt as a result of an external call.
    pub fn run_config<H: Host<I>>(
        &self,
        host: &mut H,
        config: RunConfig,
    ) -> RunResult<ExecutionOutcome<H::Interrupt>> {
        // we deliberately deconstruct the struct here instead of having mutable
        // references to fields here to improve performance. On some benchmarks
        // instruction execution is 30% slower if we keep references to the config
        // struct instead of deconstructing it here. Why that is I don't know, but it
        // likely has to do with memory layout.
        let RunConfig {
            pc,
            mut instructions_idx,
            mut function_frames,
            mut return_type,
            mut memory,
            mut locals_vec,
            mut locals_base,
            mut globals,
            max_memory,
            return_value_loc: _,
        } = config;

        // Stack used for host function calls, to pass parameters.
        let mut stack = RuntimeStack {
            stack: vec![unsafe { std::mem::zeroed() }; 10], /* TODO: This should be max host
                                                             * function
                                                             * arguments. */
        };

        let mut locals = &mut locals_vec[locals_base..];
        // the use of get_unchecked here is safe if the caller constructs the Runconfig
        // in a protocol compliant way.
        // The only way to construct a RunConfig is in this module (since all the fields
        // are private), and the only place it is constructed is in the `run`
        // method above, where the precondition is checked.
        let code = unsafe { self.code.get_unchecked(instructions_idx) };
        let mut constants = code.constants();
        let mut instructions = code.code();
        let mut pc = unsafe { instructions.as_ptr().add(pc) };
        'outer: loop {
            let instr = unsafe { *pc };
            pc = unsafe { pc.add(1) };
            // FIXME: The unsafe here is a bit wrong, but it is much faster than using
            // InternalOpcode::try_from(instr). About 25% faster on a fibonacci test.
            // The ensure here guarantees that the transmute is safe, provided that
            // InternalOpcode stays as it is.
            // ensure!(instr <= InternalOpcode::I64ExtendI32U as u8, "Illegal opcode.");
            //             println!("{:?}", unsafe { std::mem::transmute::<_,
            // InternalOpcode>(instr) });
            match unsafe { std::mem::transmute(instr) } {
                InternalOpcode::Unreachable => bail!("Unreachable."),
                InternalOpcode::If => {
                    let condition = get_local(constants, locals, &mut pc);
                    let else_target = get_u32(&mut pc);
                    if unsafe { condition.short } == 0 {
                        // jump to the else branch.
                        pc = unsafe { instructions.as_ptr().add(else_target as usize) };
                    } // else do nothing and start executing the if branch
                }
                InternalOpcode::Br => {
                    // we could optimize this for the common case of jumping to end/beginning of a
                    // current block.
                    let target = get_u32(&mut pc);
                    pc = unsafe { instructions.as_ptr().add(target as usize) };
                }
                InternalOpcode::BrIf => {
                    // we could optimize this for the common case of jumping to end/beginning of a
                    // current block.
                    let target = get_u32(&mut pc);
                    let condition = get_local(constants, locals, &mut pc);
                    if unsafe { condition.short } != 0 {
                        pc = unsafe { instructions.as_ptr().add(target as usize) };
                    } // else do nothing
                }
                InternalOpcode::BrTable => {
                    let condition = get_local(constants, locals, &mut pc);
                    let num_labels = get_u16(&mut pc);
                    let top: u32 = unsafe { condition.short } as u32;
                    if top < u32::from(num_labels) {
                        pc = unsafe { pc.add((top as usize + 1) * 4) }; // the +1 is for the
                                                                        // default branch.
                    } // else use default branch
                    let target = get_u32(&mut pc);
                    pc = unsafe { instructions.as_ptr().add(target as usize) };
                }
                InternalOpcode::BrTableCarry => {
                    let condition = get_local(constants, locals, &mut pc);
                    let copy_source = get_local(constants, locals, &mut pc);
                    let num_labels = get_u16(&mut pc);
                    let top: u32 = unsafe { condition.short } as u32;
                    if top < u32::from(num_labels) {
                        pc = unsafe { pc.add((top as usize + 1) * 8) }; // the +1 is for the default branch.
                    } // else use default branch
                    let copy_target = get_local_mut(locals, &mut pc);
                    *copy_target = copy_source;
                    let target = get_u32(&mut pc);
                    pc = unsafe { instructions.as_ptr().add(target as usize) };
                }
                InternalOpcode::Copy => {
                    let copy_source = get_local(constants, locals, &mut pc);
                    let copy_target = get_local_mut(locals, &mut pc);
                    *copy_target = copy_source;
                }
                InternalOpcode::Return => {
                    host.track_return();
                    if let Some(top_frame) = function_frames.pop() {
                        // Make sure the return value is at the right place
                        // for the callee to continue.
                        if let Some((place, _)) = return_type {
                            locals_vec[top_frame.locals_base + place] = locals[0];
                        }
                        instructions_idx = top_frame.instructions_idx;
                        // the use of get_unchecked here is entirely safe. The only way for the
                        // index to get on the stack is if we have been
                        // executing that function already. Hence we must be able to look it up
                        // again. The only way this property would fail to
                        // hold is if somebody else was modifying the artifact's list of functions
                        // at the same time. That would lead to other
                        // problems as well and is not possible in safe Rust anyhow.
                        let code = unsafe { self.code.get_unchecked(instructions_idx) };
                        instructions = code.code();
                        pc = unsafe { instructions.as_ptr().add(top_frame.pc) };
                        constants = code.constants();
                        return_type = top_frame.return_type;
                        // truncate all the locals that are above what we need at present.
                        unsafe { locals_vec.set_len(locals_base) };
                        locals_base = top_frame.locals_base;
                        locals = &mut locals_vec[locals_base..];
                    } else {
                        break 'outer;
                    }
                }
                InternalOpcode::TickEnergy => {
                    let v = get_u32(&mut pc);
                    host.tick_energy(v as u64)?;
                }
                InternalOpcode::Call => {
                    // if we want synchronous calls we need to either
                    // 1. Just use recursion in the host. This is problematic because of stack
                    // overflow.
                    // 2. Manage storage of intermediate state
                    // ourselves. This means we have to store the state of execution, which is
                    // stored in the config structure. We handle synchronous calls by the host
                    // function interrupting execution of the current
                    // function/module. The host will then handle resumption.
                    // If the host function returns Ok(None) then the meaning of it is that
                    // execution should resume as normal.
                    let idx = get_u32(&mut pc);
                    if let Some(f) = self.imports.get(idx as usize) {
                        let params_len = f.ty().parameters.len();
                        if stack.stack.capacity() < params_len {
                            stack.stack.resize(params_len, unsafe { std::mem::zeroed() });
                        } else {
                            unsafe { stack.stack.set_len(params_len) };
                        }
                        for p in stack.stack.iter_mut().rev() {
                            *p = get_local(constants, locals, &mut pc)
                        }
                        let return_value_loc = if f.ty().result.is_some() {
                            let target = get_i32(&mut pc);
                            target as usize
                        } else {
                            0
                        };
                        // we are calling an imported function, handle the call directly.
                        if let Some(reason) = host.call(f, &mut memory, &mut stack)? {
                            return Ok(ExecutionOutcome::Interrupted {
                                reason,
                                config: RunConfig {
                                    pc: unsafe { pc.offset_from(instructions.as_ptr()) as usize }, /* TODO: Maybe use try_into? */
                                    instructions_idx,
                                    function_frames,
                                    return_type,
                                    memory,
                                    locals_vec,
                                    locals_base,
                                    globals,
                                    max_memory,
                                    return_value_loc,
                                },
                            });
                        } else if f.ty().result.is_some() {
                            locals[return_value_loc] = stack.pop();
                        }
                        assert!(stack.stack.is_empty());
                    } else {
                        host.track_call()?;
                        let local_idx = idx as usize - self.imports.len();
                        let f = self
                            .code
                            .get(local_idx)
                            .ok_or_else(|| anyhow!("Accessing non-existent code."))?;

                        // drop(locals);
                        let current_size = locals_vec.len();
                        let new_size = current_size + f.num_registers() as usize;
                        locals_vec.resize(new_size, unsafe { std::mem::zeroed() });
                        let (prefix, new_locals) = locals_vec.split_at_mut(current_size);
                        let current_locals = &mut prefix[locals_base..];

                        // Note the rev.
                        for p in new_locals[..f.num_params() as usize].iter_mut().rev() {
                            *p = get_local(constants, current_locals, &mut pc)
                        }
                        let new_return_type = match f.return_type() {
                            BlockType::EmptyType => None,
                            BlockType::ValueType(v) => Some((get_i32(&mut pc) as usize, v)),
                        };

                        let current_frame = FunctionState {
                            pc: unsafe { pc.offset_from(instructions.as_ptr()) as usize }, /* TODO: Maybe use try_into?, */
                            instructions_idx,
                            locals_base,
                            return_type,
                        };
                        function_frames.push(current_frame);
                        locals_base = current_size;

                        locals = new_locals;
                        return_type = new_return_type;
                        instructions = f.code();
                        constants = f.constants();
                        instructions_idx = local_idx;
                        pc = instructions.as_ptr();
                    }
                }
                InternalOpcode::CallIndirect => {
                    let ty_idx = get_u32(&mut pc);
                    let ty = self
                        .ty
                        .get(ty_idx as usize)
                        .ok_or_else(|| anyhow!("Non-existent type."))?;
                    let idx = get_local(constants, locals, &mut pc);
                    let idx = unsafe { idx.short } as u32;
                    if let Some(Some(f_idx)) = self.table.functions.get(idx as usize) {
                        if let Some(f) = self.imports.get(*f_idx as usize) {
                            let ty_actual = f.ty();
                            // call imported function.
                            ensure!(ty_actual == ty, "Actual type different from expected.");

                            let params_len = f.ty().parameters.len();
                            if stack.stack.capacity() < params_len {
                                stack.stack.resize(params_len, unsafe { std::mem::zeroed() });
                            } else {
                                unsafe { stack.stack.set_len(params_len) };
                            }
                            for p in stack.stack.iter_mut().rev() {
                                *p = get_local(constants, locals, &mut pc)
                            }
                            let return_value_loc = if f.ty().result.is_some() {
                                let target = get_i32(&mut pc);
                                target as usize
                            } else {
                                0
                            };

                            // we are calling an imported function, handle the call directly.
                            if let Some(reason) = host.call(f, &mut memory, &mut stack)? {
                                return Ok(ExecutionOutcome::Interrupted {
                                    reason,
                                    config: RunConfig {
                                        pc: unsafe {
                                            pc.offset_from(instructions.as_ptr()) as usize
                                        }, /* TODO: Maybe use try_into?, */
                                        instructions_idx,
                                        function_frames,
                                        return_type,
                                        memory,
                                        locals_vec,
                                        locals_base,
                                        globals,
                                        max_memory,
                                        return_value_loc,
                                    },
                                });
                            } else if f.ty().result.is_some() {
                                locals[return_value_loc] = stack.pop();
                            }
                        } else {
                            host.track_call()?;
                            let local_idx = *f_idx as usize - self.imports.len();
                            let f = self
                                .code
                                .get(local_idx)
                                .ok_or_else(|| anyhow!("Accessing non-existent code."))?;
                            let ty_actual =
                                self.ty.get(f.type_idx() as usize).ok_or_else(|| {
                                    anyhow!("Non-existent type. This should not happen.")
                                })?;
                            ensure!(
                                f.type_idx() == ty_idx || ty_actual == ty,
                                "Actual type different from expected."
                            );

                            // FIXME: Remove duplication.
                            // drop(locals);
                            let current_size = locals_vec.len();
                            let new_size = current_size + f.num_registers() as usize;
                            locals_vec.resize(new_size, unsafe { std::mem::zeroed() });
                            let (prefix, new_locals) = locals_vec.split_at_mut(current_size);
                            let current_locals = &mut prefix[locals_base..];
                            // Note the rev.
                            for p in new_locals[..f.num_params() as usize].iter_mut().rev() {
                                *p = get_local(constants, current_locals, &mut pc)
                            }
                            let new_return_type = match f.return_type() {
                                BlockType::EmptyType => None,
                                BlockType::ValueType(v) => Some((get_i32(&mut pc) as usize, v)),
                            };

                            let current_frame = FunctionState {
                                pc: unsafe { pc.offset_from(instructions.as_ptr()) as usize }, /* TODO: Maybe use try_into?, */
                                instructions_idx,
                                locals_base,
                                return_type,
                            };
                            function_frames.push(current_frame);
                            locals_base = current_size;

                            locals = new_locals;

                            return_type = new_return_type;
                            instructions = f.code();
                            constants = f.constants();
                            instructions_idx = local_idx;
                            pc = instructions.as_ptr();
                        }
                    } else {
                        bail!("Calling undefined function {}.", idx) // trap
                    }
                }
                InternalOpcode::Select => {
                    let top = get_local(constants, locals, &mut pc);
                    let t2 = get_local(constants, locals, &mut pc);
                    let t1 = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    if unsafe { top.short } == 0 {
                        *target = t2;
                    } else {
                        *target = t1;
                    }
                }
                InternalOpcode::LocalSet => {
                    let source = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    *target = source;
                }
                InternalOpcode::GlobalGet => {
                    let idx = get_u16(&mut pc);
                    let copy_target = get_local_mut(locals, &mut pc);
                    *copy_target = globals[idx as usize];
                }
                InternalOpcode::GlobalSet => {
                    let idx = get_u16(&mut pc);
                    let copy_target = get_local(constants, locals, &mut pc);
                    globals[idx as usize] = copy_target;
                }
                InternalOpcode::I32Load => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_i32(&memory, pos)?;
                    *result = StackValue::from(val);
                }
                InternalOpcode::I64Load => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_i64(&memory, pos)?;
                    *result = StackValue::from(val);
                }
                InternalOpcode::I32Load8S => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_i8(&memory, pos)?;
                    *result = StackValue::from(val as i32);
                }
                InternalOpcode::I32Load8U => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_u8(&memory, pos)?;
                    *result = StackValue::from(val as i32);
                }
                InternalOpcode::I32Load16S => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_i16(&memory, pos)?;
                    *result = StackValue::from(val as i32);
                }
                InternalOpcode::I32Load16U => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_u16(&memory, pos)?;
                    *result = StackValue::from(val as i32);
                }
                InternalOpcode::I64Load8S => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_i8(&memory, pos)?;
                    *result = StackValue::from(val as i64);
                }
                InternalOpcode::I64Load8U => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_u8(&memory, pos)?;
                    *result = StackValue::from(val as i64);
                }
                InternalOpcode::I64Load16S => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_i16(&memory, pos)?;
                    *result = StackValue::from(val as i64);
                }
                InternalOpcode::I64Load16U => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_u16(&memory, pos)?;
                    *result = StackValue::from(val as i64);
                }
                InternalOpcode::I64Load32S => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_i32(&memory, pos)?;
                    *result = StackValue::from(val as i64);
                }
                InternalOpcode::I64Load32U => {
                    let (result, pos) = memory_load(constants, locals, &mut pc);
                    let val = read_u32(&memory, pos)?;
                    *result = StackValue::from(val as i64);
                }
                InternalOpcode::I32Store => {
                    let (val, pos) = memory_store(constants, locals, &mut pc);
                    write_memory_at(&mut memory, pos, &unsafe { val.short }.to_le_bytes())?;
                }
                InternalOpcode::I64Store => {
                    let (val, pos) = memory_store(constants, locals, &mut pc);
                    write_memory_at(&mut memory, pos, &unsafe { val.long }.to_le_bytes())?;
                }
                InternalOpcode::I32Store8 => {
                    let (val, pos) = memory_store(constants, locals, &mut pc);
                    write_memory_at(&mut memory, pos, &unsafe { val.short }.to_le_bytes()[..1])?;
                }
                InternalOpcode::I32Store16 => {
                    let (val, pos) = memory_store(constants, locals, &mut pc);
                    write_memory_at(&mut memory, pos, &unsafe { val.short }.to_le_bytes()[..2])?;
                }
                InternalOpcode::I64Store8 => {
                    let (val, pos) = memory_store(constants, locals, &mut pc);
                    write_memory_at(&mut memory, pos, &unsafe { val.long }.to_le_bytes()[..1])?;
                }
                InternalOpcode::I64Store16 => {
                    let (val, pos) = memory_store(constants, locals, &mut pc);
                    write_memory_at(&mut memory, pos, &unsafe { val.long }.to_le_bytes()[..2])?;
                }
                InternalOpcode::I64Store32 => {
                    let (val, pos) = memory_store(constants, locals, &mut pc);
                    write_memory_at(&mut memory, pos, &unsafe { val.long }.to_le_bytes()[..4])?;
                }
                InternalOpcode::MemorySize => {
                    let target = get_local_mut(locals, &mut pc);
                    let l = memory.len() / PAGE_SIZE as usize;
                    *target = StackValue::from(l as i32);
                }
                InternalOpcode::MemoryGrow => {
                    let val = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    let n = unsafe { val.short } as u32;
                    let sz = memory.len() / PAGE_SIZE as usize;
                    if sz + n as usize > max_memory {
                        target.short = -1i32;
                    } else {
                        if n != 0 {
                            unsafe { memory.set_len((sz + n as usize) * PAGE_SIZE as usize) }
                        }
                        target.short = sz as i32;
                    }
                }
                InternalOpcode::I32Eqz => {
                    let source = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    let val = unsafe { source.short };
                    target.short = if val == 0 {
                        1i32
                    } else {
                        0i32
                    };
                }
                InternalOpcode::I32Eq => {
                    binary_i32(constants, locals, &mut pc, |left, right| (left == right) as i32);
                }
                InternalOpcode::I32Ne => {
                    binary_i32(constants, locals, &mut pc, |left, right| (left != right) as i32);
                }
                InternalOpcode::I32LtS => {
                    binary_i32(constants, locals, &mut pc, |left, right| (left < right) as i32);
                }
                InternalOpcode::I32LtU => {
                    binary_i32(constants, locals, &mut pc, |left, right| {
                        ((left as u32) < (right as u32)) as i32
                    });
                }
                InternalOpcode::I32GtS => {
                    binary_i32(constants, locals, &mut pc, |left, right| (left > right) as i32);
                }
                InternalOpcode::I32GtU => {
                    binary_i32(constants, locals, &mut pc, |left, right| {
                        ((left as u32) > (right as u32)) as i32
                    });
                }
                InternalOpcode::I32LeS => {
                    binary_i32(constants, locals, &mut pc, |left, right| (left <= right) as i32);
                }
                InternalOpcode::I32LeU => {
                    binary_i32(constants, locals, &mut pc, |left, right| {
                        ((left as u32) <= (right as u32)) as i32
                    });
                }
                InternalOpcode::I32GeS => {
                    binary_i32(constants, locals, &mut pc, |left, right| (left >= right) as i32);
                }
                InternalOpcode::I32GeU => {
                    binary_i32(constants, locals, &mut pc, |left, right| {
                        ((left as u32) >= (right as u32)) as i32
                    });
                }
                InternalOpcode::I64Eqz => {
                    let source = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    let val = unsafe { source.long };
                    target.short = if val == 0 {
                        1i32
                    } else {
                        0i32
                    };
                }
                InternalOpcode::I64Eq => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        (left == right) as i32
                    });
                }
                InternalOpcode::I64Ne => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        (left != right) as i32
                    });
                }
                InternalOpcode::I64LtS => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        (left < right) as i32
                    });
                }
                InternalOpcode::I64LtU => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        ((left as u64) < (right as u64)) as i32
                    });
                }
                InternalOpcode::I64GtS => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        (left > right) as i32
                    });
                }
                InternalOpcode::I64GtU => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        ((left as u64) > (right as u64)) as i32
                    });
                }
                InternalOpcode::I64LeS => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        (left <= right) as i32
                    });
                }
                InternalOpcode::I64LeU => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        ((left as u64) <= (right as u64)) as i32
                    });
                }
                InternalOpcode::I64GeS => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        (left >= right) as i32
                    });
                }
                InternalOpcode::I64GeU => {
                    binary_i64_test(constants, locals, &mut pc, |left, right| {
                        ((left as u64) >= (right as u64)) as i32
                    });
                }
                InternalOpcode::I32Clz => {
                    unary_i32(constants, locals, &mut pc, |x| x.leading_zeros() as i32);
                }
                InternalOpcode::I32Ctz => {
                    unary_i32(constants, locals, &mut pc, |x| x.trailing_zeros() as i32);
                }
                InternalOpcode::I32Popcnt => {
                    unary_i32(constants, locals, &mut pc, |x| x.count_ones() as i32);
                }
                InternalOpcode::I32Add => {
                    binary_i32(constants, locals, &mut pc, |x, y| x.wrapping_add(y));
                }
                InternalOpcode::I32Sub => {
                    binary_i32(constants, locals, &mut pc, |x, y| x.wrapping_sub(y));
                }
                InternalOpcode::I32Mul => {
                    binary_i32(constants, locals, &mut pc, |x, y| x.wrapping_mul(y));
                }
                InternalOpcode::I32DivS => {
                    binary_i32_partial(constants, locals, &mut pc, |x, y| x.checked_div(y))?;
                }
                InternalOpcode::I32DivU => {
                    binary_i32_partial(constants, locals, &mut pc, |x, y| {
                        (x as u32).checked_div(y as u32).map(|x| x as i32)
                    })?;
                }
                InternalOpcode::I32RemS => {
                    binary_i32_partial(constants, locals, &mut pc, |x, y| x.checked_rem(y))?;
                }
                InternalOpcode::I32RemU => {
                    binary_i32_partial(constants, locals, &mut pc, |x, y| {
                        (x as u32).checked_rem(y as u32).map(|x| x as i32)
                    })?;
                }
                InternalOpcode::I32And => {
                    binary_i32(constants, locals, &mut pc, |x, y| x & y);
                }
                InternalOpcode::I32Or => {
                    binary_i32(constants, locals, &mut pc, |x, y| x | y);
                }
                InternalOpcode::I32Xor => {
                    binary_i32(constants, locals, &mut pc, |x, y| x ^ y);
                }
                InternalOpcode::I32Shl => {
                    binary_i32(constants, locals, &mut pc, |x, y| x << (y as u32 % 32));
                }
                InternalOpcode::I32ShrS => {
                    binary_i32(constants, locals, &mut pc, |x, y| x >> (y as u32 % 32));
                }
                InternalOpcode::I32ShrU => {
                    binary_i32(constants, locals, &mut pc, |x, y| {
                        ((x as u32) >> (y as u32 % 32)) as i32
                    });
                }
                InternalOpcode::I32Rotl => {
                    binary_i32(constants, locals, &mut pc, |x, y| x.rotate_left(y as u32 % 32));
                }
                InternalOpcode::I32Rotr => {
                    binary_i32(constants, locals, &mut pc, |x, y| x.rotate_right(y as u32 % 32));
                }
                InternalOpcode::I64Clz => {
                    unary_i64(constants, locals, &mut pc, |x| x.leading_zeros() as i64);
                }
                InternalOpcode::I64Ctz => {
                    unary_i64(constants, locals, &mut pc, |x| x.trailing_zeros() as i64);
                }
                InternalOpcode::I64Popcnt => {
                    unary_i64(constants, locals, &mut pc, |x| x.count_ones() as i64);
                }
                InternalOpcode::I64Add => {
                    binary_i64(constants, locals, &mut pc, |x, y| x.wrapping_add(y));
                }
                InternalOpcode::I64Sub => {
                    binary_i64(constants, locals, &mut pc, |x, y| x.wrapping_sub(y));
                }
                InternalOpcode::I64Mul => {
                    binary_i64(constants, locals, &mut pc, |x, y| x.wrapping_mul(y));
                }
                InternalOpcode::I64DivS => {
                    binary_i64_partial(constants, locals, &mut pc, |x, y| x.checked_div(y))?;
                }
                InternalOpcode::I64DivU => {
                    binary_i64_partial(constants, locals, &mut pc, |x, y| {
                        (x as u64).checked_div(y as u64).map(|x| x as i64)
                    })?;
                }
                InternalOpcode::I64RemS => {
                    binary_i64_partial(constants, locals, &mut pc, |x, y| x.checked_rem(y))?;
                }
                InternalOpcode::I64RemU => {
                    binary_i64_partial(constants, locals, &mut pc, |x, y| {
                        (x as u64).checked_rem(y as u64).map(|x| x as i64)
                    })?;
                }
                InternalOpcode::I64And => {
                    binary_i64(constants, locals, &mut pc, |x, y| x & y);
                }
                InternalOpcode::I64Or => {
                    binary_i64(constants, locals, &mut pc, |x, y| x | y);
                }
                InternalOpcode::I64Xor => {
                    binary_i64(constants, locals, &mut pc, |x, y| x ^ y);
                }
                InternalOpcode::I64Shl => {
                    binary_i64(constants, locals, &mut pc, |x, y| x << (y as u64 % 64));
                }
                InternalOpcode::I64ShrS => {
                    binary_i64(constants, locals, &mut pc, |x, y| x >> (y as u64 % 64));
                }
                InternalOpcode::I64ShrU => {
                    binary_i64(constants, locals, &mut pc, |x, y| {
                        ((x as u64) >> (y as u64 % 64)) as i64
                    });
                }
                InternalOpcode::I64Rotl => {
                    binary_i64(constants, locals, &mut pc, |x, y| {
                        x.rotate_left((y as u64 % 64) as u32)
                    });
                }
                InternalOpcode::I64Rotr => {
                    binary_i64(constants, locals, &mut pc, |x, y| {
                        x.rotate_right((y as u64 % 64) as u32)
                    });
                }
                InternalOpcode::I32WrapI64 => {
                    let source = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    target.short = unsafe { source.long } as i32;
                }
                InternalOpcode::I64ExtendI32S => {
                    let source = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    target.long = unsafe { source.short } as i64;
                }
                InternalOpcode::I64ExtendI32U => {
                    let source = get_local(constants, locals, &mut pc);
                    let target = get_local_mut(locals, &mut pc);
                    // The two as' are important since the semantics of the cast in rust is that
                    // it will sign extend if the source is signed. So first we make it unsigned,
                    // and then extend, making it so that it is extended with 0's.
                    target.long = unsafe { source.short } as u32 as i64;
                }
                InternalOpcode::I32Extend8S => {
                    unary_i32(constants, locals, &mut pc, |x| x as i8 as i32)
                }
                InternalOpcode::I32Extend16S => {
                    unary_i32(constants, locals, &mut pc, |x| x as i16 as i32)
                }
                InternalOpcode::I64Extend8S => {
                    unary_i64(constants, locals, &mut pc, |x| x as i8 as i64)
                }
                InternalOpcode::I64Extend16S => {
                    unary_i64(constants, locals, &mut pc, |x| x as i16 as i64)
                }
                InternalOpcode::I64Extend32S => {
                    unary_i64(constants, locals, &mut pc, |x| x as i32 as i64)
                }
            }
        }
        match return_type {
            Some((v, ValueType::I32)) => Ok(ExecutionOutcome::Success {
                result: Some(Value::I32(unsafe { locals[v].short })),
                memory,
            }),
            Some((v, ValueType::I64)) => Ok(ExecutionOutcome::Success {
                result: Some(Value::I64(unsafe { locals[v].long })),
                memory,
            }),
            None => Ok(ExecutionOutcome::Success {
                result: None,
                memory,
            }),
        }
    }
}
