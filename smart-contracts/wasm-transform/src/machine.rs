//! An implementatio of the abstract machine that can run artifacts.

use crate::{
    artifact::{StackValue, *},
    constants::{MAX_NUM_PAGES, PAGE_SIZE},
    types::*,
};
use anyhow::{anyhow, bail, ensure};
use std::{convert::TryInto, io::Write};

/// The host that can process external functions.
pub trait Host<I> {
    /// Charge the given amount of energy for the initial memory.
    /// The argument is the number of pages.
    fn tick_initial_memory(&mut self, num_pages: u32) -> RunResult<()>;
    /// Call the specified host function, giving it access to the current memory
    /// and stack. The return value of `Ok(())` signifies that execution
    /// succeeded and the machine should proceeed, the return value of
    /// `Err(_)` signifies a trap.
    fn call(&mut self, f: &I, memory: &mut Vec<u8>, stack: &mut RuntimeStack) -> RunResult<()>;
}

/// Result of execution. Runtime exceptions are returned as `Err(_)`.
/// This includes traps, illegal memory accesses, etc.
pub type RunResult<A> = anyhow::Result<A>;

struct FunctionState<'a> {
    /// The program counter.
    pc:           usize,
    /// Instructions
    instructions: &'a [u8],
    /// Stack height
    height:       usize,
    locals_base:  usize,
    return_type:  BlockType,
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
pub struct RuntimeStack {
    /// The vector containing the whole stack.
    stack: Vec<StackValue>,
    /// The first free position. Pushing an element will
    /// insert it at this position.
    pos:   usize,
}

#[derive(Debug)]
pub enum RuntimeError {
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
    pub fn size(&self) -> usize { self.pos }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn pop(&mut self) -> StackValue {
        self.pos -= 1;
        self.stack[self.pos]
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn push(&mut self, x: StackValue) {
        if self.pos < self.stack.len() {
            self.stack[self.pos] = x;
        } else {
            self.stack.push(x)
        }
        self.pos += 1;
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn peek_mut(&mut self) -> &mut StackValue { &mut self.stack[self.pos - 1] }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn peek(&mut self) -> StackValue { self.stack[self.pos - 1] }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn set_pos(&mut self, pos: usize) { self.pos = pos; }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn push_value<F>(&mut self, f: F)
    where
        StackValue: From<F>, {
        self.push(StackValue::from(f))
    }

    /// # Safety
    /// This function is safe provided
    /// - the stack is not empty
    /// - top of the stack contains a 32-bit value.
    pub unsafe fn pop_u32(&mut self) -> u32 { self.pop().short as u32 }

    /// # Safety
    /// This function is safe provided
    /// - the stack is not empty
    /// - top of the stack contains a 32-bit value.
    pub unsafe fn peek_u32(&mut self) -> u32 { self.peek().short as u32 }

    /// # Safety
    /// This function is safe provided
    /// - the stack is not empty
    /// - top of the stack contains a 64-bit value.
    pub unsafe fn pop_u64(&mut self) -> u64 { self.pop().long as u64 }

    /// # Safety
    /// This function is safe provided
    /// - the stack is not empty
    /// - top of the stack contains a 64-bit value.
    pub unsafe fn peek_u64(&mut self) -> u64 { self.peek().long as u64 }
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_u16(bytes: &[u8], pc: &mut usize) -> u16 {
    let mut dst = [0u8; 2];
    let end = *pc + 2;
    dst.copy_from_slice(&bytes[*pc..end]);
    *pc = end;
    u16::from_le_bytes(dst)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_u32(bytes: &[u8], pc: &mut usize) -> u32 {
    let mut dst = [0u8; 4];
    let end = *pc + 4;
    dst.copy_from_slice(&bytes[*pc..end]);
    *pc = end;
    u32::from_le_bytes(dst)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_i32(bytes: &[u8], pc: &mut usize) -> i32 {
    let mut dst = [0u8; 4];
    let end = *pc + 4;
    dst.copy_from_slice(&bytes[*pc..end]);
    *pc = end;
    i32::from_le_bytes(dst)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_u64(bytes: &[u8], pc: &mut usize) -> u64 {
    let mut dst = [0u8; 8];
    let end = *pc + 8;
    dst.copy_from_slice(&bytes[*pc..end]);
    *pc = end;
    u64::from_le_bytes(dst)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_u8(bytes: &[u8], pos: usize) -> RunResult<u8> {
    bytes.get(pos).copied().ok_or_else(|| anyhow!("Memory access out of bounds."))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_u16(bytes: &[u8], pos: usize) -> RunResult<u16> {
    ensure!(pos + 2 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 2];
    dst.copy_from_slice(&bytes[pos..pos + 2]);
    Ok(u16::from_le_bytes(dst))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_u32(bytes: &[u8], pos: usize) -> RunResult<u32> {
    ensure!(pos + 4 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&bytes[pos..pos + 4]);
    Ok(u32::from_le_bytes(dst))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i8(bytes: &[u8], pos: usize) -> RunResult<i8> {
    bytes.get(pos).map(|&x| x as i8).ok_or_else(|| anyhow!("Memory access out of bounds."))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i16(bytes: &[u8], pos: usize) -> RunResult<i16> {
    ensure!(pos + 2 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 2];
    dst.copy_from_slice(&bytes[pos..pos + 2]);
    Ok(i16::from_le_bytes(dst))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i32(bytes: &[u8], pos: usize) -> RunResult<i32> {
    ensure!(pos + 4 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&bytes[pos..pos + 4]);
    Ok(i32::from_le_bytes(dst))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn read_i64(bytes: &[u8], pos: usize) -> RunResult<i64> {
    ensure!(pos + 8 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 8];
    dst.copy_from_slice(&bytes[pos..pos + 8]);
    Ok(i64::from_le_bytes(dst))
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn get_memory_pos(
    instructions: &[u8],
    stack: &mut RuntimeStack,
    pc: &mut usize,
) -> RunResult<usize> {
    let offset = get_u32(instructions, pc);
    let top = stack.pop();
    let top = unsafe { top.short } as u32;
    let pos = top as usize + offset as usize;
    Ok(pos)
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn write_memory_at(memory: &mut [u8], pos: usize, bytes: &[u8]) -> RunResult<()> {
    ensure!(pos < memory.len(), "Illegal memory access.");
    (&mut memory[pos..]).write_all(bytes)?;
    Ok(())
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn unary_i32(stack: &mut RuntimeStack, f: impl Fn(i32) -> i32) {
    let val = stack.peek_mut();
    val.short = f(unsafe { val.short });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn unary_i64(stack: &mut RuntimeStack, f: impl Fn(i64) -> i64) {
    let val = stack.peek_mut();
    val.long = f(unsafe { val.long });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i32(stack: &mut RuntimeStack, f: impl Fn(i32, i32) -> i32) {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.short = f(unsafe { left.short }, unsafe { right.short });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i32_partial(
    stack: &mut RuntimeStack,
    f: impl Fn(i32, i32) -> Option<i32>,
) -> RunResult<()> {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.short = f(unsafe { left.short }, unsafe { right.short })
        .ok_or_else(|| anyhow!("Runtime exception in i32 binary."))?;
    Ok(())
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i64(stack: &mut RuntimeStack, f: impl Fn(i64, i64) -> i64) {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.long = f(unsafe { left.long }, unsafe { right.long });
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i64_partial(
    stack: &mut RuntimeStack,
    f: impl Fn(i64, i64) -> Option<i64>,
) -> RunResult<()> {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.long = f(unsafe { left.long }, unsafe { right.long })
        .ok_or_else(|| anyhow!("Runtime exception in i64 binary"))?;
    Ok(())
}

#[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
fn binary_i64_test(stack: &mut RuntimeStack, f: impl Fn(i64, i64) -> i32) {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.short = f(unsafe { left.long }, unsafe { right.long });
}

impl<I: TryFromImport, R: RunnableCode> Artifact<I, R> {
    pub fn run<Q: std::fmt::Display + Ord + ?Sized>(
        &self,
        host: &mut impl Host<I>,
        name: &Q,
        args: &[Value],
    ) -> RunResult<(Option<Value>, Vec<u8>)>
    where
        Name: std::borrow::Borrow<Q>, {
        let start = *self
            .export
            .get(name)
            .ok_or_else(|| anyhow!("Trying to invoke a method that does not exist: {}.", name))?;
        // FIXME: The next restriction could easily be lifted, but it is not a problem
        // for now.
        ensure!(start as usize >= self.imports.len(), RuntimeError::DirectlyCallImport);
        let outer_function = &self.code[start as usize - self.imports.len()]; // safe because the artifact should be well-formed.
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

        let mut globals =
            self.global.inits.iter().copied().map(StackValue::from).collect::<Vec<_>>();
        let mut stack: RuntimeStack = RuntimeStack {
            stack: Vec::with_capacity(1000),
            pos:   0,
        };
        for &arg in args.iter() {
            match arg {
                Value::I32(short) => stack.push(StackValue::from(short)),
                Value::I64(long) => stack.push(StackValue::from(long)),
            }
        }
        for l in outer_function.locals() {
            match l {
                ValueType::I32 => stack.push(StackValue::from(0i32)),
                ValueType::I64 => stack.push(StackValue::from(0i64)),
            }
        }
        let mut memory = {
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

        let mut pc = 0;
        let mut instructions: &[u8] = outer_function.code();

        let mut function_frames: Vec<FunctionState> = Vec::new();
        let mut return_type = outer_function.return_type();
        let mut locals_base = 0;

        'outer: loop {
            let instr = instructions[pc];
            pc += 1;
            // FIXME: The unsafe here is a bit wrong, but it is much faster than using
            // InternalOpcode::try_from(instr). About 25% faster on a fibonacci test.
            // The ensure here guarantees that the transmute is safe, provided that
            // InternalOpcode stays as it is.
            // ensure!(instr <= InternalOpcode::I64ExtendI32U as u8, "Illegal opcode.");
            // println!("{:#?}", unsafe { std::mem::transmute::<_,InternalOpcode>(instr) });
            match unsafe { std::mem::transmute(instr) } {
                // InternalOpcode::try_from(instr)? {
                InternalOpcode::Unreachable => bail!("Unreachable."),
                InternalOpcode::If => {
                    let else_target = get_u32(instructions, &mut pc);
                    let top = stack.pop();
                    if unsafe { top.short } == 0 {
                        // jump to the else branch.
                        pc = else_target as usize;
                    } // else do nothing and start executing the if branch
                }
                InternalOpcode::Br => {
                    // we could optimize this for the common case of jumping to end/beginning of a
                    // current block.
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    stack.set_pos(stack.size() - diff as usize);
                    pc = target as usize;
                }
                InternalOpcode::BrCarry => {
                    let cur_size = stack.size();
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    let top = stack.pop();
                    stack.set_pos(cur_size - diff as usize);
                    stack.push(top);
                    pc = target as usize;
                }
                InternalOpcode::BrIf => {
                    // we could optimize this for the common case of jumping to end/beginning of a
                    // current block.
                    let cur_size = stack.size();
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    let top = stack.pop();
                    if unsafe { top.short } != 0 {
                        stack.set_pos(cur_size - diff as usize);
                        pc = target as usize;
                    } // else do nothing
                }
                InternalOpcode::BrIfCarry => {
                    let cur_size = stack.size();
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    let top = stack.pop();
                    if unsafe { top.short } != 0 {
                        let top = stack.pop();
                        stack.set_pos(cur_size - diff as usize);
                        stack.push(top);
                        pc = target as usize;
                    } // else do nothing
                }
                InternalOpcode::BrTable => {
                    let cur_size = stack.size();
                    let top = stack.pop();
                    let num_labels = get_u16(instructions, &mut pc);
                    let top: u32 = unsafe { top.short } as u32;
                    if top < u32::from(num_labels) {
                        pc += (top as usize + 1) * 8; // the +1 is for the
                                                      // default branch.
                    } // else use default branch
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    stack.set_pos(cur_size - diff as usize);
                    pc = target as usize;
                }
                InternalOpcode::BrTableCarry => {
                    let cur_size = stack.size();
                    let top = stack.pop();
                    let num_labels = get_u16(instructions, &mut pc);
                    let top: u32 = unsafe { top.short } as u32;
                    if top < u32::from(num_labels) {
                        pc += (top as usize + 1) * 8; // the +1 is for the
                                                      // default branch.
                    } // else use default branch
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    let top = stack.pop();
                    stack.set_pos(cur_size - diff as usize);
                    stack.push(top);
                    pc = target as usize;
                }
                InternalOpcode::Return => {
                    if let Some(top_frame) = function_frames.pop() {
                        if !return_type.is_empty() {
                            let top = stack.pop();
                            stack.set_pos(top_frame.height);
                            stack.push(top)
                        } else {
                            stack.set_pos(top_frame.height);
                        }
                        pc = top_frame.pc;
                        instructions = top_frame.instructions;
                        return_type = top_frame.return_type;
                        locals_base = top_frame.locals_base;
                    } else {
                        break 'outer;
                    }
                }
                InternalOpcode::Call => {
                    let idx = get_u32(instructions, &mut pc);
                    if let Some(f) = self.imports.get(idx as usize) {
                        // we are calling an imported function, handle the call directly.
                        host.call(f, &mut memory, &mut stack)?;
                    } else {
                        let f = self
                            .code
                            .get(idx as usize - self.imports.len())
                            .ok_or_else(|| anyhow!("Accessing non-existent code."))?;
                        let current_frame = FunctionState {
                            pc,
                            instructions,
                            locals_base,
                            height: stack.size() - f.num_params() as usize,
                            return_type,
                        };
                        locals_base = current_frame.height;
                        function_frames.push(current_frame);
                        for ty in f.locals() {
                            match ty {
                                ValueType::I32 => stack.push(StackValue::from(0u32)),
                                ValueType::I64 => stack.push(StackValue::from(0u64)),
                            }
                        }
                        instructions = f.code();
                        pc = 0;
                        return_type = f.return_type();
                    }
                }
                InternalOpcode::CallIndirect => {
                    let ty_idx = get_u32(instructions, &mut pc);
                    let ty = self
                        .ty
                        .get(ty_idx as usize)
                        .ok_or_else(|| anyhow!("Non-existent type."))?;
                    let idx = stack.pop();
                    let idx = unsafe { idx.short } as u32;
                    if let Some(Some(f_idx)) = self.table.functions.get(idx as usize) {
                        if let Some(f) = self.imports.get(*f_idx as usize) {
                            let ty_actual = f.ty();
                            // call imported function.
                            ensure!(ty_actual == ty, "Actual type different from expected.");
                            host.call(f, &mut memory, &mut stack)?;
                        } else {
                            let f = self
                                .code
                                .get(*f_idx as usize - self.imports.len())
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
                            let current_frame = FunctionState {
                                pc,
                                instructions,
                                locals_base,
                                height: stack.size() - f.num_params() as usize,
                                return_type,
                            };
                            locals_base = current_frame.height;
                            function_frames.push(current_frame);
                            for ty in f.locals() {
                                match ty {
                                    ValueType::I32 => stack.push(StackValue {
                                        short: 0,
                                    }),
                                    ValueType::I64 => stack.push(StackValue {
                                        long: 0,
                                    }),
                                }
                            }
                            instructions = f.code();
                            pc = 0;
                            return_type = f.return_type();
                        }
                    } else {
                        bail!("Calling undefined function {}.", idx) // trap
                    }
                }
                InternalOpcode::Drop => {
                    stack.pop();
                }
                InternalOpcode::Select => {
                    let top = stack.pop();
                    let t2 = stack.pop();
                    if unsafe { top.short } == 0 {
                        *stack.peek_mut() = t2;
                    } // else t1 remains on the top of the stack.
                }
                InternalOpcode::LocalGet => {
                    let idx = get_u16(instructions, &mut pc);
                    let val = stack.stack[locals_base + idx as usize];
                    stack.push(val)
                }
                InternalOpcode::LocalSet => {
                    let idx = get_u16(instructions, &mut pc);
                    let top = stack.pop();
                    stack.stack[locals_base + idx as usize] = top
                }
                InternalOpcode::LocalTee => {
                    let idx = get_u16(instructions, &mut pc);
                    let top = stack.peek();
                    stack.stack[locals_base + idx as usize] = top
                }
                InternalOpcode::GlobalGet => {
                    let idx = get_u16(instructions, &mut pc);
                    stack.push(globals[idx as usize])
                }
                InternalOpcode::GlobalSet => {
                    let idx = get_u16(instructions, &mut pc);
                    let top = stack.pop();
                    globals[idx as usize] = top
                }
                InternalOpcode::I32Load => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_i32(&memory, pos)?;
                    stack.push(StackValue::from(val))
                }
                InternalOpcode::I64Load => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_i64(&memory, pos)?;
                    stack.push(StackValue::from(val))
                }
                InternalOpcode::I32Load8S => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_i8(&memory, pos)?;
                    stack.push(StackValue::from(val as i32))
                }
                InternalOpcode::I32Load8U => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_u8(&memory, pos)?;
                    stack.push(StackValue::from(val as i32))
                }
                InternalOpcode::I32Load16S => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_i16(&memory, pos)?;
                    stack.push(StackValue::from(val as i32))
                }
                InternalOpcode::I32Load16U => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_u16(&memory, pos)?;
                    stack.push(StackValue::from(val as i32))
                }
                InternalOpcode::I64Load8S => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_i8(&memory, pos)?;
                    stack.push(StackValue::from(val as i64))
                }
                InternalOpcode::I64Load8U => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_u8(&memory, pos)?;
                    stack.push(StackValue::from(val as i64))
                }
                InternalOpcode::I64Load16S => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_i16(&memory, pos)?;
                    stack.push(StackValue::from(val as i64))
                }
                InternalOpcode::I64Load16U => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_u16(&memory, pos)?;
                    stack.push(StackValue::from(val as i64))
                }
                InternalOpcode::I64Load32S => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_i32(&memory, pos)?;
                    stack.push(StackValue::from(val as i64))
                }
                InternalOpcode::I64Load32U => {
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    let val = read_u32(&memory, pos)?;
                    stack.push(StackValue::from(val as i64))
                }
                InternalOpcode::I32Store => {
                    let val = stack.pop();
                    let val = unsafe { val.short };
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    write_memory_at(&mut memory, pos, &val.to_le_bytes())?;
                }
                InternalOpcode::I64Store => {
                    let val = stack.pop();
                    let val = unsafe { val.long };
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    write_memory_at(&mut memory, pos, &val.to_le_bytes())?;
                }
                InternalOpcode::I32Store8 => {
                    let val = stack.pop();
                    let val = unsafe { val.short };
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    write_memory_at(&mut memory, pos, &val.to_le_bytes()[..1])?;
                }
                InternalOpcode::I32Store16 => {
                    let val = stack.pop();
                    let val = unsafe { val.short };
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    write_memory_at(&mut memory, pos, &val.to_le_bytes()[..2])?;
                }
                InternalOpcode::I64Store8 => {
                    let val = stack.pop();
                    let val = unsafe { val.long };
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    write_memory_at(&mut memory, pos, &val.to_le_bytes()[..1])?;
                }
                InternalOpcode::I64Store16 => {
                    let val = stack.pop();
                    let val = unsafe { val.long };
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    write_memory_at(&mut memory, pos, &val.to_le_bytes()[..2])?;
                }
                InternalOpcode::I64Store32 => {
                    let val = stack.pop();
                    let val = unsafe { val.long };
                    let pos = get_memory_pos(instructions, &mut stack, &mut pc)?;
                    write_memory_at(&mut memory, pos, &val.to_le_bytes()[..4])?;
                }
                InternalOpcode::MemorySize => {
                    let l = memory.len() / PAGE_SIZE as usize;
                    stack.push(StackValue::from(l as i32))
                }
                InternalOpcode::MemoryGrow => {
                    let val = stack.peek_mut();
                    let n = unsafe { val.short } as u32;
                    let sz = memory.len() / PAGE_SIZE as usize;
                    if sz + n as usize > max_memory {
                        val.short = -1i32;
                    } else {
                        if n != 0 {
                            unsafe { memory.set_len((sz + n as usize) * PAGE_SIZE as usize) }
                        }
                        val.short = sz as i32;
                    }
                }
                InternalOpcode::I32Const => {
                    let val = get_i32(instructions, &mut pc);
                    stack.push(StackValue::from(val));
                }
                InternalOpcode::I64Const => {
                    let val = get_u64(instructions, &mut pc);
                    stack.push(StackValue::from(val as i64));
                }
                InternalOpcode::I32Eqz => {
                    let top = stack.peek_mut();
                    let val = unsafe { top.short };
                    top.short = if val == 0 {
                        1i32
                    } else {
                        0i32
                    };
                }
                InternalOpcode::I32Eq => {
                    binary_i32(&mut stack, |left, right| (left == right) as i32);
                }
                InternalOpcode::I32Ne => {
                    binary_i32(&mut stack, |left, right| (left != right) as i32);
                }
                InternalOpcode::I32LtS => {
                    binary_i32(&mut stack, |left, right| (left < right) as i32);
                }
                InternalOpcode::I32LtU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) < (right as u32)) as i32);
                }
                InternalOpcode::I32GtS => {
                    binary_i32(&mut stack, |left, right| (left > right) as i32);
                }
                InternalOpcode::I32GtU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) > (right as u32)) as i32);
                }
                InternalOpcode::I32LeS => {
                    binary_i32(&mut stack, |left, right| (left <= right) as i32);
                }
                InternalOpcode::I32LeU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) <= (right as u32)) as i32);
                }
                InternalOpcode::I32GeS => {
                    binary_i32(&mut stack, |left, right| (left >= right) as i32);
                }
                InternalOpcode::I32GeU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) >= (right as u32)) as i32);
                }
                InternalOpcode::I64Eqz => {
                    let top = stack.peek_mut();
                    let val = unsafe { top.long };
                    top.short = if val == 0 {
                        1i32
                    } else {
                        0i32
                    };
                }
                InternalOpcode::I64Eq => {
                    binary_i64_test(&mut stack, |left, right| (left == right) as i32);
                }
                InternalOpcode::I64Ne => {
                    binary_i64_test(&mut stack, |left, right| (left != right) as i32);
                }
                InternalOpcode::I64LtS => {
                    binary_i64_test(&mut stack, |left, right| (left < right) as i32);
                }
                InternalOpcode::I64LtU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) < (right as u64)) as i32
                    });
                }
                InternalOpcode::I64GtS => {
                    binary_i64_test(&mut stack, |left, right| (left > right) as i32);
                }
                InternalOpcode::I64GtU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) > (right as u64)) as i32
                    });
                }
                InternalOpcode::I64LeS => {
                    binary_i64_test(&mut stack, |left, right| (left <= right) as i32);
                }
                InternalOpcode::I64LeU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) <= (right as u64)) as i32
                    });
                }
                InternalOpcode::I64GeS => {
                    binary_i64_test(&mut stack, |left, right| (left >= right) as i32);
                }
                InternalOpcode::I64GeU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) >= (right as u64)) as i32
                    });
                }
                InternalOpcode::I32Clz => {
                    unary_i32(&mut stack, |x| x.leading_zeros() as i32);
                }
                InternalOpcode::I32Ctz => {
                    unary_i32(&mut stack, |x| x.trailing_zeros() as i32);
                }
                InternalOpcode::I32Popcnt => {
                    unary_i32(&mut stack, |x| x.count_ones() as i32);
                }
                InternalOpcode::I32Add => {
                    binary_i32(&mut stack, |x, y| x.wrapping_add(y));
                }
                InternalOpcode::I32Sub => {
                    binary_i32(&mut stack, |x, y| x.wrapping_sub(y));
                }
                InternalOpcode::I32Mul => {
                    binary_i32(&mut stack, |x, y| x.wrapping_mul(y));
                }
                InternalOpcode::I32DivS => {
                    binary_i32_partial(&mut stack, |x, y| x.checked_div(y))?;
                }
                InternalOpcode::I32DivU => {
                    binary_i32_partial(&mut stack, |x, y| {
                        (x as u32).checked_div(y as u32).map(|x| x as i32)
                    })?;
                }
                InternalOpcode::I32RemS => {
                    binary_i32_partial(&mut stack, |x, y| x.checked_rem(y))?;
                }
                InternalOpcode::I32RemU => {
                    binary_i32_partial(&mut stack, |x, y| {
                        (x as u32).checked_rem(y as u32).map(|x| x as i32)
                    })?;
                }
                InternalOpcode::I32And => {
                    binary_i32(&mut stack, |x, y| x & y);
                }
                InternalOpcode::I32Or => {
                    binary_i32(&mut stack, |x, y| x | y);
                }
                InternalOpcode::I32Xor => {
                    binary_i32(&mut stack, |x, y| x ^ y);
                }
                InternalOpcode::I32Shl => {
                    binary_i32(&mut stack, |x, y| x << (y as u32 % 32));
                }
                InternalOpcode::I32ShrS => {
                    binary_i32(&mut stack, |x, y| x >> (y as u32 % 32));
                }
                InternalOpcode::I32ShrU => {
                    binary_i32(&mut stack, |x, y| ((x as u32) >> (y as u32 % 32)) as i32);
                }
                InternalOpcode::I32Rotl => {
                    binary_i32(&mut stack, |x, y| x.rotate_left(y as u32 % 32));
                }
                InternalOpcode::I32Rotr => {
                    binary_i32(&mut stack, |x, y| x.rotate_right(y as u32 % 32));
                }
                InternalOpcode::I64Clz => {
                    unary_i64(&mut stack, |x| x.leading_zeros() as i64);
                }
                InternalOpcode::I64Ctz => {
                    unary_i64(&mut stack, |x| x.trailing_zeros() as i64);
                }
                InternalOpcode::I64Popcnt => {
                    unary_i64(&mut stack, |x| x.count_ones() as i64);
                }
                InternalOpcode::I64Add => {
                    binary_i64(&mut stack, |x, y| x.wrapping_add(y));
                }
                InternalOpcode::I64Sub => {
                    binary_i64(&mut stack, |x, y| x.wrapping_sub(y));
                }
                InternalOpcode::I64Mul => {
                    binary_i64(&mut stack, |x, y| x.wrapping_mul(y));
                }
                InternalOpcode::I64DivS => {
                    binary_i64_partial(&mut stack, |x, y| x.checked_div(y))?;
                }
                InternalOpcode::I64DivU => {
                    binary_i64_partial(&mut stack, |x, y| {
                        (x as u64).checked_div(y as u64).map(|x| x as i64)
                    })?;
                }
                InternalOpcode::I64RemS => {
                    binary_i64_partial(&mut stack, |x, y| x.checked_rem(y))?;
                }
                InternalOpcode::I64RemU => {
                    binary_i64_partial(&mut stack, |x, y| {
                        (x as u64).checked_rem(y as u64).map(|x| x as i64)
                    })?;
                }
                InternalOpcode::I64And => {
                    binary_i64(&mut stack, |x, y| x & y);
                }
                InternalOpcode::I64Or => {
                    binary_i64(&mut stack, |x, y| x | y);
                }
                InternalOpcode::I64Xor => {
                    binary_i64(&mut stack, |x, y| x ^ y);
                }
                InternalOpcode::I64Shl => {
                    binary_i64(&mut stack, |x, y| x << (y as u64 % 64));
                }
                InternalOpcode::I64ShrS => {
                    binary_i64(&mut stack, |x, y| x >> (y as u64 % 64));
                }
                InternalOpcode::I64ShrU => {
                    binary_i64(&mut stack, |x, y| ((x as u64) >> (y as u64 % 64)) as i64);
                }
                InternalOpcode::I64Rotl => {
                    binary_i64(&mut stack, |x, y| x.rotate_left((y as u64 % 64) as u32));
                }
                InternalOpcode::I64Rotr => {
                    binary_i64(&mut stack, |x, y| x.rotate_right((y as u64 % 64) as u32));
                }
                InternalOpcode::I32WrapI64 => {
                    let top = stack.peek_mut();
                    top.short = unsafe { top.long } as i32;
                }
                InternalOpcode::I64ExtendI32S => {
                    let top = stack.peek_mut();
                    top.long = unsafe { top.short } as i64;
                }
                InternalOpcode::I64ExtendI32U => {
                    let top = stack.peek_mut();
                    // The two as' are important since the semantics of the cast in rust is that
                    // it will sign extend if the source is signed. So first we make it unsigned,
                    // and then extend, making it so that it is extended with 0's.
                    top.long = unsafe { top.short } as u32 as i64;
                }
            }
        }
        match outer_function.return_type() {
            BlockType::ValueType(ValueType::I32) => {
                let val = stack.pop();
                Ok((Some(Value::I32(unsafe { val.short })), memory))
            }
            BlockType::ValueType(ValueType::I64) => {
                let val = stack.pop();
                Ok((Some(Value::I64(unsafe { val.long })), memory))
            }
            BlockType::EmptyType => Ok((None, memory)),
        }
    }
}
