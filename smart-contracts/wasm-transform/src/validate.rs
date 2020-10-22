use crate::{
    parse::{parse_sec_with_default, CodeSkeletonSection, OpCodeIterator, ParseResult, Skeleton},
    types::*,
};
use anyhow::{anyhow, bail, ensure};
use std::collections::BTreeSet;

pub type ValidateResult<A> = anyhow::Result<A>;

#[derive(Debug)]
pub struct OperandStack {
    pub stack: Vec<MaybeKnown>,
}

impl OperandStack {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct ControlStack {
    pub stack: Vec<ControlFrame>,
}

impl ControlStack {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
        }
    }

    /// Get the n-th element of the stack, starting at 0.
    pub fn get(&self, n: u32) -> Option<&ControlFrame> {
        let n = n as usize;
        if n >= self.stack.len() {
            None
        } else {
            self.stack.get(self.stack.len() - n - 1)
        }
    }

    pub fn get_label(&self, n: u32) -> Option<BlockType> {
        self.get(n).map(|frame| frame.label_type)
    }

    /// Get the outermost frame, target of the return.
    pub fn outermost(&self) -> Option<&ControlFrame> { self.stack.first() }
}

#[derive(Debug)]
pub struct ControlFrame {
    pub label_type:  BlockType,
    pub end_type:    BlockType,
    pub height:      usize,
    pub unreachable: bool,
}

#[derive(Debug)]
pub struct ValidationState {
    pub opds:  OperandStack,
    pub ctrls: ControlStack,
}

impl ValidationState {
    pub fn done(&self) -> bool { self.ctrls.stack.is_empty() }
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum MaybeKnown {
    Unknown,
    Known(ValueType),
}

use MaybeKnown::*;

impl MaybeKnown {
    pub fn is_unknown(self) -> bool { self == MaybeKnown::Unknown }
}

impl ValidationState {
    pub fn push_opd(&mut self, m_type: MaybeKnown) { self.opds.stack.push(m_type); }

    pub fn pop_opd(&mut self) -> ValidateResult<MaybeKnown> {
        match self.ctrls.stack.last() {
            None => bail!("Control frame exhausted."),
            Some(frame) => {
                if self.opds.stack.len() == frame.height {
                    if frame.unreachable {
                        Ok(Unknown)
                    } else {
                        bail!("Operand stack exhausted for the current block.")
                    }
                } else {
                    self.opds
                        .stack
                        .pop()
                        .ok_or_else(|| anyhow!("Stack exhausted, should not happen."))
                }
            }
        }
    }

    pub fn pop_expect_opd(&mut self, expect: MaybeKnown) -> ValidateResult<MaybeKnown> {
        let actual = self.pop_opd()?;
        if actual.is_unknown() {
            return Ok(expect);
        }
        if expect.is_unknown() {
            return Ok(actual);
        }
        ensure!(
            actual == expect,
            "Actual type different from expected {:#?} /= {:#?}.",
            actual,
            expect
        );
        Ok(actual)
    }

    pub fn push_opds(&mut self, tys: BlockType) {
        if let BlockType::ValueType(ty) = tys {
            self.push_opd(Known(ty))
        }
    }

    pub fn pop_opds(&mut self, expected: BlockType) -> ValidateResult<()> {
        if let BlockType::ValueType(ty) = expected {
            self.pop_expect_opd(Known(ty))?;
        }
        Ok(())
    }

    pub fn push_ctrl(&mut self, label_type: BlockType, end_type: BlockType) {
        let frame = ControlFrame {
            label_type,
            end_type,
            height: self.opds.stack.len(),
            unreachable: false,
        };
        self.ctrls.stack.push(frame)
    }

    // Returns the result type of the block.
    pub fn pop_ctrl(&mut self) -> ValidateResult<BlockType> {
        // We first check for the last element, and use it without removing it.
        // This is so that pop_expect_opd, which pops elements from the stack, can see
        // whether we are in the unreachable state for the stack or not.
        match self.ctrls.stack.last().map(|frame| (frame.end_type, frame.height)) {
            None => bail!("Control stack exhausted."),
            Some((end_type, height)) => {
                if let BlockType::ValueType(ty) = end_type {
                    self.pop_expect_opd(Known(ty))?;
                }
                ensure!(self.opds.stack.len() == height, "Operand stack not exhausted.");
                // Finally pop after we've made sure the stack is properly cleared.
                self.ctrls.stack.pop();
                Ok(end_type)
            }
        }
    }

    pub fn mark_unreachable(&mut self) -> ValidateResult<()> {
        match self.ctrls.stack.last_mut() {
            None => bail!("Control stack exhausted."),
            Some(frame) => {
                self.opds.stack.truncate(frame.height);
                frame.unreachable = true;
                Ok(())
            }
        }
    }
}

/// The local types, at indices start, start+1,..<end (not including end).
pub struct LocalsRange {
    pub start: LocalIndex,
    pub end:   LocalIndex,
    pub ty:    ValueType,
}

/// Context for the validation of a function.
pub struct FunctionContext<'a> {
    pub return_type: BlockType,
    pub globals:     &'a [Global],
    pub funcs:       &'a [TypeIndex],
    pub types:       &'a [FunctionType],
    pub locals:      Vec<LocalsRange>,
    // Whether memory exists or not.
    pub memory: bool,
    // Whether the table exists or not.
    pub table: bool,
}

fn make_locals(ty: &FunctionType, locals: &[Local]) -> Vec<LocalsRange> {
    let mut out = Vec::with_capacity(ty.parameters.len() + locals.len());
    let mut start = 0;
    for &ty in ty.parameters.iter() {
        let end = start + 1;
        out.push(LocalsRange {
            start,
            end,
            ty,
        });
        start = end;
    }
    for local in locals.iter() {
        let end = start + local.multiplicity;
        out.push(LocalsRange {
            start,
            end,
            ty: local.ty,
        });
        start = end;
    }
    out
}

impl<'a> FunctionContext<'a> {
    pub fn get_local(&self, idx: LocalIndex) -> ValidateResult<ValueType> {
        let res = self.locals.binary_search_by(|locals| {
            if locals.end <= idx {
                std::cmp::Ordering::Less
            } else if idx < locals.start {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        match res {
            Ok(idx) => Ok(self.locals[idx].ty),
            Err(_) => bail!("Local index out of range."),
        }
    }

    /// Get a global together with its mutability.
    pub fn get_global(&self, idx: GlobalIndex) -> ValidateResult<(ValueType, bool)> {
        if let Some(global) = self.globals.get(idx as usize) {
            Ok((global.init.ty(), global.mutable))
        } else {
            bail!("Global index out of range.")
        }
    }

    pub fn memory_exists(&self) -> bool { self.memory }

    pub fn table_exists(&self) -> bool { self.table }

    pub fn get_func(&self, idx: FuncIndex) -> ValidateResult<&FunctionType> {
        if let Some(&type_idx) = self.funcs.get(idx as usize) {
            self.get_type(type_idx)
        } else {
            bail!("Function index out of range.")
        }
    }

    pub fn get_type(&self, idx: TypeIndex) -> ValidateResult<&FunctionType> {
        self.types.get(idx as usize).ok_or_else(|| anyhow!("Type index out of range."))
    }
}

enum Type {
    I8,
    I16,
    I32,
    I64,
}
/// Ensure that the alignment is valid for the given type.
fn ensure_alignment(num: u32, align: Type) -> ValidateResult<()> {
    match align {
        Type::I8 => {
            ensure!(num <= 0, "Type I8 alignment must be less than 0, but is {}.", num);
        }
        Type::I16 => {
            ensure!(num <= 1, "Type I16 alignment must be less than 1, but is {}.", num);
        }
        Type::I32 => {
            ensure!(num <= 2, "Type I32 alignment must be less than 2, but is {}", num);
        }
        Type::I64 => {
            ensure!(num <= 3, "Type I64 alignment must be less than 3, but is {}.", num);
        }
    }
    Ok(())
}

pub fn validate<'a>(
    context: &FunctionContext<'a>,
    mut opcodes: impl Iterator<Item = ParseResult<OpCode>>,
) -> ValidateResult<Vec<OpCode>> {
    let mut state = ValidationState {
        opds:  OperandStack::new(),
        ctrls: ControlStack::new(),
    };
    state.push_ctrl(context.return_type, context.return_type);
    let mut instructions = Vec::new();
    while let Some(opcode) = opcodes.next() {
        let next_opcode = opcode?;
        match &next_opcode {
            OpCode::End => {
                let res = state.pop_ctrl()?;
                state.push_opds(res);
            }
            OpCode::Nop => {
                // do nothing.
            }
            OpCode::Unreachable => {
                state.mark_unreachable()?;
            }
            OpCode::Block(ty) => {
                state.push_ctrl(*ty, *ty);
            }
            OpCode::Loop(ty) => {
                state.push_ctrl(BlockType::EmptyType, *ty);
            }
            OpCode::If {
                ty,
            } => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_ctrl(*ty, *ty);
            }
            OpCode::Else => {
                let res = state.pop_ctrl()?;
                state.push_ctrl(res, res);
            }
            OpCode::Br(label) => {
                if let Some(label_type) = state.ctrls.get_label(*label) {
                    state.pop_opds(label_type)?;
                    state.mark_unreachable()?;
                } else {
                    bail!("Jump to a non-existent label.")
                }
            }
            OpCode::BrIf(label) => {
                if let Some(label_type) = state.ctrls.get_label(*label) {
                    state.pop_expect_opd(Known(ValueType::I32))?;
                    state.pop_opds(label_type)?;
                    state.push_opds(label_type);
                } else {
                    bail!("Conditional jump to non-existent label.")
                }
            }
            OpCode::BrTable {
                labels,
                default,
            } => {
                if let Some(default_label_type) = state.ctrls.get_label(*default) {
                    for &label in labels.iter() {
                        if let Some(target_frame) = state.ctrls.get(label) {
                            ensure!(
                                default_label_type == target_frame.label_type,
                                "Different targets have different label types."
                            );
                        } else {
                            bail!("Table jump to non-existent label.")
                        }
                    }
                    state.pop_expect_opd(Known(ValueType::I32))?;
                    state.pop_opds(default_label_type)?;
                    state.mark_unreachable()?;
                } else {
                    bail!("Table jump to non-existent label.")
                }
            }
            OpCode::Return => {
                if let Some(label_type) = state.ctrls.outermost().map(|frame| frame.label_type) {
                    state.pop_opds(label_type)?;
                    state.mark_unreachable()?;
                }
            }
            OpCode::Call(idx) => {
                let func = context.get_func(*idx)?;
                for &ty in func.parameters.iter().rev() {
                    state.pop_expect_opd(Known(ty))?;
                }
                for &ty in func.result.iter() {
                    state.push_opd(Known(ty))
                }
            }
            OpCode::CallIndirect(idx) => {
                ensure!(context.table_exists(), "Table with index 0 must exist.");
                // the table type is valid by construction, there is only one.
                let func = context.get_type(*idx)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                for &ty in func.parameters.iter().rev() {
                    state.pop_expect_opd(Known(ty))?;
                }
                for &ty in func.result.iter() {
                    state.push_opd(Known(ty))
                }
            }
            OpCode::Drop => {
                state.pop_opd()?;
            }
            OpCode::Select => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                let t1 = state.pop_opd()?;
                let t2 = state.pop_expect_opd(t1)?;
                state.push_opd(t2);
            }
            OpCode::LocalGet(idx) => {
                let ty = context.get_local(*idx)?;
                state.push_opd(Known(ty));
            }
            OpCode::LocalSet(idx) => {
                let ty = context.get_local(*idx)?;
                state.pop_expect_opd(Known(ty))?;
            }
            OpCode::LocalTee(idx) => {
                let ty = context.get_local(*idx)?;
                let stack_ty = state.pop_expect_opd(Known(ty))?;
                state.push_opd(stack_ty);
            }
            OpCode::GlobalGet(idx) => {
                let ty = context.get_global(*idx)?.0;
                state.push_opd(Known(ty));
            }
            OpCode::GlobalSet(idx) => {
                let (ty, mutable) = context.get_global(*idx)?;
                ensure!(mutable, "Trying to set a const global.");
                state.pop_expect_opd(Known(ty))?;
            }
            OpCode::I32Load(memarg) => {
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Load(memarg) => {
                ensure_alignment(memarg.align, Type::I64)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I32Load8S(memarg) => {
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Load8U(memarg) => {
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Load16S(memarg) => {
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Load16U(memarg) => {
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Load8S(memarg) => {
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load8U(memarg) => {
                ensure_alignment(memarg.align, Type::I8)?;
                ensure!(memarg.align <= 0, "Alignment out of range");
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load16S(memarg) => {
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load16U(memarg) => {
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load32S(memarg) => {
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load32U(memarg) => {
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I32Store(memarg) => {
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store(memarg) => {
                ensure_alignment(memarg.align, Type::I64)?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I32Store8(memarg) => {
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I32Store16(memarg) => {
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store8(memarg) => {
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store16(memarg) => {
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store32(memarg) => {
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::MemorySize => {
                ensure!(context.memory_exists(), "Memory should exist.");
                state.push_opd(Known(ValueType::I32))
            }
            OpCode::MemoryGrow => {
                ensure!(context.memory_exists(), "Memory should exist.");
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32))
            }
            OpCode::I32Const(_) => {
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Const(_) => {
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I32Eqz => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Eq
            | OpCode::I32Ne
            | OpCode::I32LtS
            | OpCode::I32LtU
            | OpCode::I32GtS
            | OpCode::I32GtU
            | OpCode::I32LeS
            | OpCode::I32LeU
            | OpCode::I32GeS
            | OpCode::I32GeU => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Eqz => {
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Eq
            | OpCode::I64Ne
            | OpCode::I64LtS
            | OpCode::I64LtU
            | OpCode::I64GtS
            | OpCode::I64GtU
            | OpCode::I64LeS
            | OpCode::I64LeU
            | OpCode::I64GeS
            | OpCode::I64GeU => {
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Clz | OpCode::I32Ctz | OpCode::I32Popcnt => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Add
            | OpCode::I32Sub
            | OpCode::I32Mul
            | OpCode::I32DivS
            | OpCode::I32DivU
            | OpCode::I32RemS
            | OpCode::I32RemU
            | OpCode::I32And
            | OpCode::I32Or
            | OpCode::I32Xor
            | OpCode::I32Shl
            | OpCode::I32ShrS
            | OpCode::I32ShrU
            | OpCode::I32Rotl
            | OpCode::I32Rotr => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Clz | OpCode::I64Ctz | OpCode::I64Popcnt => {
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Add
            | OpCode::I64Sub
            | OpCode::I64Mul
            | OpCode::I64DivS
            | OpCode::I64DivU
            | OpCode::I64RemS
            | OpCode::I64RemU
            | OpCode::I64And
            | OpCode::I64Or
            | OpCode::I64Xor
            | OpCode::I64Shl
            | OpCode::I64ShrS
            | OpCode::I64ShrU
            | OpCode::I64Rotl
            | OpCode::I64Rotr => {
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I32WrapI64 => {
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64ExtendI32S | OpCode::I64ExtendI32U => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
        }
        instructions.push(next_opcode);
    }
    if state.done() {
        Ok(instructions)
    } else {
        bail!("Improperly terminated instruction sequence.")
    }
}

pub fn validate_module<'a>(skeleton: &Skeleton<'a>) -> ValidateResult<Module> {
    // The type section is valid as long as it's well-formed.
    let ty: TypeSection = parse_sec_with_default(&skeleton.ty)?;
    // Imports are valid as long as they parse, and all the indices exist.
    let import: ImportSection = parse_sec_with_default(&skeleton.import)?;
    for i in import.imports.iter() {
        match i.description {
            ImportDescription::Func {
                type_idx,
            } => ensure!(ty.get(type_idx).is_some(), "Import refers to a non-existent type."),
        }
    }
    // The table section is valid as long as it's well-formed.
    // We already check the limits at parse time.
    let table: TableSection = parse_sec_with_default(&skeleton.table)?;

    // The memory section is valid as long as it's well-formed.
    // We already check the limits at parse time.
    let memory: MemorySection = parse_sec_with_default(&skeleton.memory)?;

    // The global section is valid as long as it's well-formed.
    // We already check that all the globals are initialized with
    // correct expressions.
    let global: GlobalSection = parse_sec_with_default(&skeleton.global)?;

    // The start section is valid as long as it parses correctly.
    // We make sure that there is no content in the start section during parsing.
    let start = parse_sec_with_default(&skeleton.start)?;

    // The function type section is valid if it parses properly, and all the indices
    // of types are valid.
    // The code section then needs to match.
    let func: FunctionSection = parse_sec_with_default(&skeleton.func)?;
    for &type_idx in func.types.iter() {
        ensure!(ty.get(type_idx).is_some(), "Function refers to a type that does not exist.")
    }

    // Number of functions that can be referred to.
    // Since all imports must be functions we could just use length, but
    // in the interest of being more robust to changes we count imported functions
    // instead.
    let total_funcs =
        import.imports.iter().filter(|&x| Import::is_func(x)).count() + func.types.len();

    let code: CodeSkeletonSection = parse_sec_with_default(&skeleton.code)?;
    ensure!(
        func.types.len() == code.impls.len(),
        "The number of functions in the function and code sections must match."
    );
    // an index of function types, merging imported and declared functions.
    let funcs = import
        .imports
        .iter()
        .filter_map(|i| match i.description {
            ImportDescription::Func {
                type_idx,
            } => Some(type_idx),
        })
        .chain(func.types.iter().copied())
        .collect::<Vec<TypeIndex>>();

    let mut parsed_code = Vec::with_capacity(code.impls.len());
    for (&f, c) in func.types.iter().zip(code.impls) {
        match ty.get(f) {
            Some(func_ty) => {
                let ctx = FunctionContext {
                    return_type: BlockType::from(func_ty.result),
                    globals:     &global.globals,
                    funcs:       &funcs,
                    types:       &ty.types,
                    locals:      make_locals(func_ty, &c.locals),
                    memory:      memory.memory_type.is_some(),
                    table:       table.table_type.is_some(),
                };
                let opcodes = validate(&ctx, &mut OpCodeIterator::new(c.expr_bytes))?;
                parsed_code.push(Code {
                    locals: c.locals,
                    expr:   Expression {
                        instrs: opcodes,
                    },
                })
            }
            None => bail!("Function has a type that does not exist."),
        }
    }
    // Exports are mostly valid by parsing, but we need to make sure that
    // they are all distinct.
    let export: ExportSection = parse_sec_with_default(&skeleton.export)?;
    let mut export_names = BTreeSet::new();
    for e in export.exports.iter() {
        // ensure the name is unique.
        ensure!(export_names.insert(&e.name), "Duplicate exports {}.", e.name);

        match e.description {
            ExportDescription::Func {
                index,
            } => {
                ensure!(
                    (index as usize) < total_funcs,
                    "Trying to export a function that does not exist."
                );
            }
            ExportDescription::Table => {
                ensure!(
                    table.table_type.is_some(),
                    "Trying to export a table, but no table is declared."
                );
            }
            ExportDescription::Memory => {
                ensure!(
                    memory.memory_type.is_some(),
                    "Trying to export a memory, but no memory is declared."
                );
            }
            ExportDescription::Global {
                index,
            } => {
                ensure!(
                    global.get(index).is_some(),
                    "Trying to export a global that does not exist."
                );
            }
        }
    }

    // The element section is almost well-formed by parsing.
    // Parsing already ensures that limits are well-formed, that
    // the offset expression is of the correct type and constant.
    // We additionally need to check that all the functions referred
    // to in the table are defined.
    let element: ElementSection = parse_sec_with_default(&skeleton.element)?;
    for elem in element.elements.iter() {
        for &init in elem.inits.iter() {
            ensure!(
                (init as usize) < total_funcs,
                "Index in the element segment refers to a non-existent function."
            );
        }
    }

    // The data section is valid by parsing, provided that a memory.
    // is declared in the module.
    let data: DataSection = parse_sec_with_default(&skeleton.data)?;
    // Make sure that if there are any data segments then a memory exists.
    // By parsing we already ensure that all the references are to a single memory.
    ensure!(
        data.sections.is_empty() || memory.memory_type.is_some(),
        "There are some data sections, but no declared memory."
    );
    Ok(Module {
        ty,
        import,
        func,
        table,
        memory,
        global,
        export,
        start,
        element,
        code: CodeSection {
            impls: parsed_code,
        },
        data,
    })
}
