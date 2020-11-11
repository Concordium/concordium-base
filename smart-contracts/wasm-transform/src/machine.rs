use crate::{
    artifact::{StackValue, *},
    parse::{MAX_NUM_PAGES, PAGE_SIZE},
    types::*,
};
use anyhow::{anyhow, bail, ensure};
use std::{convert::TryInto, io::Write};

/// The host that can process external functions.
pub trait Host<I> {
    fn tick_energy(x: u64) -> RunResult<()>;
    /// Call the host function.
    fn call(&mut self, f: &I, memory: &mut Vec<u8>, stack: &mut RuntimeStack) -> RunResult<()>;

    /// Call the host function, but before that check that the type
    /// is as expected.
    fn call_check_type(
        &mut self,
        f: &I,
        memory: &mut Vec<u8>,
        stack: &mut RuntimeStack,
        ty: &FunctionType,
    ) -> RunResult<()>;
}

pub type RunResult<A> = anyhow::Result<A>;

struct FunctionState<'a> {
    /// The program counter.
    pc: usize,
    /// Current values of all the locals (including parameters).
    locals: Vec<StackValue>,
    /// Instructions
    instructions: &'a [u8],
    /// Stack height
    height: usize,
    return_type: Option<ValueType>,
}

#[derive(Clone, Copy, Debug)]
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

pub struct RuntimeStack {
    /// The vector containing the whole stack.
    stack: Vec<StackValue>,
    /// The first free position. Pushing an element will
    /// insert it at this position.
    pos: usize,
}

impl RuntimeStack {
    #[inline(always)]
    pub fn size(&self) -> usize { self.pos }

    #[inline(always)]
    pub fn split_off(&mut self, mid: usize) -> &[StackValue] {
        let rest = &self.stack[mid..self.pos];
        self.pos = mid;
        rest
    }

    #[inline(always)]
    pub fn pop(&mut self) -> StackValue {
        self.pos -= 1;
        self.stack[self.pos]
    }

    #[inline(always)]
    pub fn push(&mut self, x: StackValue) {
        if self.pos < self.stack.len() {
            self.stack[self.pos] = x;
        } else {
            self.stack.push(x)
        }
        self.pos += 1;
    }

    #[inline(always)]
    pub fn peek_mut(&mut self) -> &mut StackValue { &mut self.stack[self.pos - 1] }

    #[inline(always)]
    pub fn peek(&mut self) -> StackValue { self.stack[self.pos - 1] }

    #[inline(always)]
    pub fn set_pos(&mut self, pos: usize) { self.pos = pos; }
}

#[inline(always)]
fn get_u16(bytes: &[u8], pc: &mut usize) -> u16 {
    let mut dst = [0u8; 2];
    dst.copy_from_slice(&bytes[*pc..*pc + 2]);
    *pc += 2;
    u16::from_le_bytes(dst)
}

#[inline(always)]
fn get_u32(bytes: &[u8], pc: &mut usize) -> u32 {
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&bytes[*pc..*pc + 4]);
    *pc += 4;
    u32::from_le_bytes(dst)
}

#[inline(always)]
fn get_u64(bytes: &[u8], pc: &mut usize) -> u64 {
    let mut dst = [0u8; 8];
    dst.copy_from_slice(&bytes[*pc..*pc + 8]);
    *pc += 8;
    u64::from_le_bytes(dst)
}

#[inline(always)]
fn read_u8(bytes: &[u8], pos: usize) -> RunResult<u8> {
    bytes.get(pos).copied().ok_or_else(|| anyhow!("Memory access out of bounds."))
}

#[inline(always)]
fn read_u16(bytes: &[u8], pos: usize) -> RunResult<u16> {
    ensure!(pos + 2 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 2];
    dst.copy_from_slice(&bytes[pos..pos + 2]);
    Ok(u16::from_le_bytes(dst))
}

#[inline(always)]
fn read_u32(bytes: &[u8], pos: usize) -> RunResult<u32> {
    ensure!(pos + 4 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&bytes[pos..pos + 4]);
    Ok(u32::from_le_bytes(dst))
}

#[inline(always)]
fn read_i8(bytes: &[u8], pos: usize) -> RunResult<i8> {
    bytes.get(pos).map(|&x| x as i8).ok_or_else(|| anyhow!("Memory access out of bounds."))
}

#[inline(always)]
fn read_i16(bytes: &[u8], pos: usize) -> RunResult<i16> {
    ensure!(pos + 2 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 2];
    dst.copy_from_slice(&bytes[pos..pos + 2]);
    Ok(i16::from_le_bytes(dst))
}

#[inline(always)]
fn read_i32(bytes: &[u8], pos: usize) -> RunResult<i32> {
    ensure!(pos + 4 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&bytes[pos..pos + 4]);
    Ok(i32::from_le_bytes(dst))
}

#[inline(always)]
fn read_i64(bytes: &[u8], pos: usize) -> RunResult<i64> {
    ensure!(pos + 8 <= bytes.len(), "Memory access out of bounds.");
    let mut dst = [0u8; 8];
    dst.copy_from_slice(&bytes[pos..pos + 8]);
    Ok(i64::from_le_bytes(dst))
}

#[inline(always)]
fn get_memory_pos(
    instructions: &[u8],
    stack: &mut RuntimeStack,
    pc: &mut usize,
) -> RunResult<usize> {
    let offset = get_u32(instructions, pc);
    let top = stack.pop();
    let top = unsafe { top.short };
    let pos = top as usize + offset as usize;
    Ok(pos)
}

fn write_memory_at(memory: &mut [u8], pos: usize, bytes: &[u8]) -> RunResult<()> {
    (&mut memory[pos..]).write_all(bytes)?;
    Ok(())
}

#[inline(always)]
fn unary_i32(stack: &mut RuntimeStack, f: impl Fn(i32) -> i32) -> RunResult<()> {
    let val = stack.peek_mut();
    val.short = f(unsafe { val.short });
    Ok(())
}

#[inline(always)]
fn unary_i64(stack: &mut RuntimeStack, f: impl Fn(i64) -> i64) -> RunResult<()> {
    let val = stack.peek_mut();
    val.long = f(unsafe { val.long });
    Ok(())
}

#[inline(always)]
fn binary_i32(stack: &mut RuntimeStack, f: impl Fn(i32, i32) -> i32) -> RunResult<()> {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.short = f(unsafe { left.short }, unsafe { right.short });
    Ok(())
}

#[inline(always)]
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

#[inline(always)]
fn binary_i64(stack: &mut RuntimeStack, f: impl Fn(i64, i64) -> i64) -> RunResult<()> {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.long = f(unsafe { left.long }, unsafe { right.long });
    Ok(())
}

#[inline(always)]
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

#[inline(always)]
fn binary_i64_test(stack: &mut RuntimeStack, f: impl Fn(i64, i64) -> i32) -> RunResult<()> {
    let right = stack.pop();
    let left = stack.peek_mut();
    left.short = f(unsafe { left.long }, unsafe { right.long });
    Ok(())
}

impl<I: RenameImports> Artifact<I> {
    pub fn run(
        &self,
        host: &mut impl Host<I>,
        name: &str,
        args: &[Value],
    ) -> RunResult<Option<Value>> {
        let start = *self
            .export
            .get(name)
            .ok_or_else(|| anyhow!("Trying to invoke a method that does not exist: {}.", name))?;
        let f = &self.code[start as usize]; // safe because the artifact should be well-formed.
        ensure!(
            f.num_params == args.len().try_into()?,
            "The number of arguments does not match the number of parameters."
        );
        for (p, actual) in f.locals.iter().zip(args.iter()) {
            // the first num_params locals are arguments
            ensure!(*p == ValueType::from(*actual), "Argument of incorrect type.")
        }

        let mut globals = self.global.inits.clone();

        let mut locals = Vec::with_capacity(f.locals.len());
        for &arg in args.iter() {
            match arg {
                Value::I32(short) => locals.push(StackValue::from(short)),
                Value::I64(long) => locals.push(StackValue::from(long)),
            }
        }
        for l in f.locals[args.len()..].iter() {
            match l {
                ValueType::I32 => locals.push(StackValue::from(0i32)),
                ValueType::I64 => locals.push(StackValue::from(0i64)),
            }
        }
        // FIXME: Charge for initial memory allocation.
        let mut memory = {
            if let Some(m) = self.memory.as_ref() {
                // This is safe since maximum initial memory is limited to 32 pages.
                let mut memory = vec![0u8; (m.init_size * PAGE_SIZE) as usize];
                for data in m.init.iter() {
                    (&mut memory[data.offset as usize..]).write_all(&data.init)?;
                }
                memory
            } else {
                Vec::new()
            }
        };

        let max_memory = self.memory.as_ref().map(|x| x.max_size).unwrap_or(MAX_NUM_PAGES) as usize;

        let mut pc = 0;
        let mut instructions: &[u8] = &self.code[start as usize].code.bytes;
        // TODO: We could actually allocate an exact one here.
        let mut stack: RuntimeStack = RuntimeStack {
            stack: Vec::with_capacity(1000),
            pos:   0,
        };
        let mut function_frames: Vec<FunctionState> = Vec::new();
        let mut return_type = self.code[start as usize].return_type;

        'outer: loop {
            // FIXME: This while loop here is not an ideal situation.
            // It is necessary because we can have tail calls.
            let instr = instructions[pc];
            pc += 1;
            // println!("{:?}", InternalOpcode::try_from(instr)?);
            // FIXME: The unsafe here is a bit wrong, but it is much faster than using
            // InternalOpcode::try_from(instr). About 25% faster on a fibonacci test.
            // The ensure here guarantees that the transmute is safe, provided that
            // InternalOpcode stays as it is.
            ensure!(instr <= InternalOpcode::I64ExtendI32U as u8, "Illegal opcode.");
            match unsafe { std::mem::transmute(instr) } {
                // InternalOpcode::try_from(instr)? {
                InternalOpcode::Nop => {
                    // do nothing
                }
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
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    if diff & 0x8000_0000 != 0 {
                        let top = stack.pop();
                        stack.set_pos(stack.size() - (diff & !0x8000_0000) as usize);
                        stack.push(top)
                    } else {
                        stack.set_pos(stack.size() - diff as usize);
                    }
                    pc = target as usize;
                }
                InternalOpcode::BrIf => {
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    let top = stack.pop();
                    if unsafe { top.short } != 0 {
                        if diff & 0x8000_0000 != 0 {
                            let top = stack.pop();
                            stack.set_pos(stack.size() - (diff & !0x8000_0000) as usize);
                            stack.push(top)
                        } else {
                            stack.set_pos(stack.size() - diff as usize);
                        }
                        pc = target as usize;
                    } // else do nothing
                }
                InternalOpcode::BrTable => {
                    let top = stack.pop();
                    let num_labels = get_u16(instructions, &mut pc);
                    let top: u32 = unsafe { top.short } as u32;
                    if top < u32::from(num_labels) {
                        pc += (top as usize + 1) * 8;
                    } // else use default branch
                    let diff = get_u32(instructions, &mut pc);
                    let target = get_u32(instructions, &mut pc);
                    if diff & 0x8000_0000 != 0 {
                        let top = stack.pop();
                        stack.set_pos(stack.size() - (diff & !0x8000_0000) as usize);
                        stack.push(top)
                    } else {
                        stack.set_pos(stack.size() - diff as usize);
                    }
                    pc = target as usize;
                }
                InternalOpcode::Return => {
                    // this is the same as return
                    if let Some(top_frame) = function_frames.pop() {
                        if return_type.is_some() {
                            let top = stack.pop();
                            stack.set_pos(top_frame.height);
                            stack.push(top)
                        } else {
                            stack.set_pos(top_frame.height);
                        }
                        pc = top_frame.pc;
                        locals = top_frame.locals;
                        instructions = top_frame.instructions;
                        return_type = top_frame.return_type
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
                        let current_frame = FunctionState {
                            pc,
                            locals,
                            instructions,
                            height: stack.size(),
                            return_type,
                        };
                        function_frames.push(current_frame);
                        let f = self
                            .code
                            .get(idx as usize - self.imports.len())
                            .ok_or_else(|| anyhow!("Accessing non-existent code."))?;
                        locals = Vec::with_capacity(f.locals.len());
                        locals.extend_from_slice(
                            stack.split_off(stack.size() - f.num_params as usize),
                        );

                        for ty in f.locals[f.num_params as usize..].iter() {
                            match ty {
                                ValueType::I32 => locals.push(StackValue {
                                    short: 0,
                                }),
                                ValueType::I64 => locals.push(StackValue {
                                    long: 0,
                                }),
                            }
                        }
                        instructions = &f.code.bytes;
                        pc = 0;
                        return_type = f.return_type;
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
                            // call imported function.
                            host.call_check_type(f, &mut memory, &mut stack, ty)?;
                        } else {
                            let f = self
                                .code
                                .get(*f_idx as usize - self.imports.len())
                                .ok_or_else(|| anyhow!("Accessing non-existent code."))?;
                            let ty_actual = self.ty.get(f.type_idx as usize).ok_or_else(|| {
                                anyhow!("Non-existent type. This should not happen.")
                            })?;
                            ensure!(
                                f.type_idx == ty_idx || ty_actual == ty,
                                "Actual type different from expected."
                            );
                            // FIXME: Remove duplication.

                            let current_frame = FunctionState {
                                pc,
                                locals,
                                instructions,
                                height: stack.size(),
                                return_type,
                            };
                            function_frames.push(current_frame);
                            locals = Vec::with_capacity(f.locals.len());
                            locals.extend_from_slice(
                                stack.split_off(stack.size() - f.num_params as usize),
                            );

                            for ty in f.locals[f.num_params as usize..].iter() {
                                match ty {
                                    ValueType::I32 => locals.push(StackValue {
                                        short: 0,
                                    }),
                                    ValueType::I64 => locals.push(StackValue {
                                        long: 0,
                                    }),
                                }
                            }
                            instructions = &f.code.bytes;
                            pc = 0;
                            return_type = f.return_type;
                        }
                    } else {
                        bail!("Calling undefined function.") // trap
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
                    stack.push(locals[idx as usize])
                }
                InternalOpcode::LocalSet => {
                    let idx = get_u16(instructions, &mut pc);
                    let top = stack.pop();
                    locals[idx as usize] = top
                }
                InternalOpcode::LocalTee => {
                    let idx = get_u16(instructions, &mut pc);
                    let top = stack.peek();
                    locals[idx as usize] = top
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
                        memory.resize((sz + n as usize) * PAGE_SIZE as usize, 0);
                        val.short = sz as i32;
                    }
                }
                InternalOpcode::I32Const => {
                    let val = get_u32(instructions, &mut pc);
                    stack.push(StackValue::from(val as i32));
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
                    binary_i32(&mut stack, |left, right| (left == right) as i32)?;
                }
                InternalOpcode::I32Ne => {
                    binary_i32(&mut stack, |left, right| (left != right) as i32)?;
                }
                InternalOpcode::I32LtS => {
                    binary_i32(&mut stack, |left, right| (left < right) as i32)?;
                }
                InternalOpcode::I32LtU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) < (right as u32)) as i32)?;
                }
                InternalOpcode::I32GtS => {
                    binary_i32(&mut stack, |left, right| (left > right) as i32)?;
                }
                InternalOpcode::I32GtU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) > (right as u32)) as i32)?;
                }
                InternalOpcode::I32LeS => {
                    binary_i32(&mut stack, |left, right| (left <= right) as i32)?;
                }
                InternalOpcode::I32LeU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) <= (right as u32)) as i32)?;
                }
                InternalOpcode::I32GeS => {
                    binary_i32(&mut stack, |left, right| (left >= right) as i32)?;
                }
                InternalOpcode::I32GeU => {
                    binary_i32(&mut stack, |left, right| ((left as u32) >= (right as u32)) as i32)?;
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
                    binary_i64_test(&mut stack, |left, right| (left == right) as i32)?;
                }
                InternalOpcode::I64Ne => {
                    binary_i64_test(&mut stack, |left, right| (left != right) as i32)?;
                }
                InternalOpcode::I64LtS => {
                    binary_i64_test(&mut stack, |left, right| (left < right) as i32)?;
                }
                InternalOpcode::I64LtU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) < (right as u64)) as i32
                    })?;
                }
                InternalOpcode::I64GtS => {
                    binary_i64_test(&mut stack, |left, right| (left > right) as i32)?;
                }
                InternalOpcode::I64GtU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) > (right as u64)) as i32
                    })?;
                }
                InternalOpcode::I64LeS => {
                    binary_i64_test(&mut stack, |left, right| (left <= right) as i32)?;
                }
                InternalOpcode::I64LeU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) <= (right as u64)) as i32
                    })?;
                }
                InternalOpcode::I64GeS => {
                    binary_i64_test(&mut stack, |left, right| (left >= right) as i32)?;
                }
                InternalOpcode::I64GeU => {
                    binary_i64_test(&mut stack, |left, right| {
                        ((left as u64) >= (right as u64)) as i32
                    })?;
                }
                InternalOpcode::I32Clz => {
                    unary_i32(&mut stack, |x| x.leading_zeros() as i32)?;
                }
                InternalOpcode::I32Ctz => {
                    unary_i32(&mut stack, |x| x.trailing_zeros() as i32)?;
                }
                InternalOpcode::I32Popcnt => {
                    unary_i32(&mut stack, |x| x.count_ones() as i32)?;
                }
                InternalOpcode::I32Add => {
                    binary_i32(&mut stack, |x, y| x.wrapping_add(y))?;
                }
                InternalOpcode::I32Sub => {
                    binary_i32(&mut stack, |x, y| x.wrapping_sub(y))?;
                }
                InternalOpcode::I32Mul => {
                    binary_i32(&mut stack, |x, y| x.wrapping_mul(y))?;
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
                    binary_i32(&mut stack, |x, y| x & y)?;
                }
                InternalOpcode::I32Or => {
                    binary_i32(&mut stack, |x, y| x | y)?;
                }
                InternalOpcode::I32Xor => {
                    binary_i32(&mut stack, |x, y| x ^ y)?;
                }
                InternalOpcode::I32Shl => {
                    binary_i32(&mut stack, |x, y| x << (y as u32 % 32))?;
                }
                InternalOpcode::I32ShrS => {
                    binary_i32(&mut stack, |x, y| x >> (y as u32 % 32))?;
                }
                InternalOpcode::I32ShrU => {
                    binary_i32(&mut stack, |x, y| ((x as u32) >> (y as u32 % 32)) as i32)?;
                }
                InternalOpcode::I32Rotl => {
                    binary_i32(&mut stack, |x, y| x.rotate_left(y as u32 % 32))?;
                }
                InternalOpcode::I32Rotr => {
                    binary_i32(&mut stack, |x, y| x.rotate_right(y as u32 % 32))?;
                }
                InternalOpcode::I64Clz => {
                    unary_i64(&mut stack, |x| x.leading_zeros() as i64)?;
                }
                InternalOpcode::I64Ctz => {
                    unary_i64(&mut stack, |x| x.trailing_zeros() as i64)?;
                }
                InternalOpcode::I64Popcnt => {
                    unary_i64(&mut stack, |x| x.count_ones() as i64)?;
                }
                InternalOpcode::I64Add => {
                    binary_i64(&mut stack, |x, y| x.wrapping_add(y))?;
                }
                InternalOpcode::I64Sub => {
                    binary_i64(&mut stack, |x, y| x.wrapping_sub(y))?;
                }
                InternalOpcode::I64Mul => {
                    binary_i64(&mut stack, |x, y| x.wrapping_mul(y))?;
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
                    binary_i64(&mut stack, |x, y| x & y)?;
                }
                InternalOpcode::I64Or => {
                    binary_i64(&mut stack, |x, y| x | y)?;
                }
                InternalOpcode::I64Xor => {
                    binary_i64(&mut stack, |x, y| x ^ y)?;
                }
                InternalOpcode::I64Shl => {
                    binary_i64(&mut stack, |x, y| x << (y as u64 % 64))?;
                }
                InternalOpcode::I64ShrS => {
                    binary_i64(&mut stack, |x, y| x >> (y as u64 % 64))?;
                }
                InternalOpcode::I64ShrU => {
                    binary_i64(&mut stack, |x, y| ((x as u64) >> (y as u64 % 64)) as i64)?;
                }
                InternalOpcode::I64Rotl => {
                    binary_i64(&mut stack, |x, y| x.rotate_left((y as u64 % 64) as u32))?;
                }
                InternalOpcode::I64Rotr => {
                    binary_i64(&mut stack, |x, y| x.rotate_right((y as u64 % 64) as u32))?;
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
        match f.return_type {
            Some(ValueType::I32) => {
                let val = stack.pop();
                Ok(Some(Value::I32(unsafe { val.short })))
            }
            Some(ValueType::I64) => {
                let val = stack.pop();
                Ok(Some(Value::I64(unsafe { val.long })))
            }
            None => Ok(None),
        }
    }
}
