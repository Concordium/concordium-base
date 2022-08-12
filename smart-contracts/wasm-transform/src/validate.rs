//! Utilities for Wasm module validation.
//!
//! The specification that is taken as the basis is [wasm-core-1-20191205](https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/),
//! but we have further restrictions to accommodate our use on the chain.
//! Some of these are already ensured by parsing, others are ensured by
//! validation.
//!
//! The basic code validation algorithm used here is a straighforward transcript
//! of the validation algorithm described in the appendix of the linked Wasm
//! specification.

use crate::{
    constants::*,
    parse::{
        parse_custom, parse_sec_with_default, CodeSkeletonSection, OpCodeIterator, ParseResult,
        Skeleton, EMPTY_CTX,
    },
    types::*,
};
use anyhow::{anyhow, bail, ensure};
use std::{borrow::Borrow, collections::BTreeSet, convert::TryInto, rc::Rc};

#[derive(Debug)]
pub enum ValidationError {
    TooManyLocals {
        actual: u32,
        max:    u32,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::TooManyLocals {
                actual,
                max,
            } => write!(f, "The number of locals ({}) is more than allowed ({}).", actual, max),
        }
    }
}

/// Result type of validation.
pub type ValidateResult<A> = anyhow::Result<A>;

#[derive(Debug, Default)]
/// The operand stack containing either known or unknown types.
/// Unknown types appear on the stack by the use of parametric instructions
/// after an unreachable section of the code.
///
/// The default instance produces an empty operator stack.
pub(crate) struct OperandStack {
    pub(crate) stack: Vec<MaybeKnown>,
}

#[derive(Debug, Default)]
/// The stack of "control frames". A control frame is a block of code, e.g., a
/// `block ... end` section.
///
/// The default instance produces an empty control stack.
pub(crate) struct ControlStack {
    pub(crate) stack: Vec<ControlFrame>,
}

impl ControlStack {
    /// Get the n-th element of the stack, starting at 0.
    pub fn get(&self, n: u32) -> Option<&ControlFrame> {
        let n = n as usize;
        if n >= self.stack.len() {
            None
        } else {
            self.stack.get(self.stack.len() - n - 1)
        }
    }

    /// Get the label type of the `n`-th label. This is the type
    /// that is used when jumping to the label.
    pub fn get_label(&self, n: u32) -> Option<BlockType> {
        self.get(n).map(|frame| frame.label_type)
    }

    /// Get the outermost frame, target of the return jump.
    pub fn outermost(&self) -> Option<&ControlFrame> { self.stack.first() }
}

#[derive(Debug)]
/// A single control frame. This indicates what the types are for jumping to the
/// label of this block, or normally exiting the block, as well as some metadata
/// with reference to the ControlStack
pub(crate) struct ControlFrame {
    /// Whether the current control frame is started by an if.
    pub(crate) is_if:       bool,
    /// Label type of the block, this is the type that is used when
    /// jumping to the label of the block.
    pub(crate) label_type:  BlockType,
    /// end type of the block, this is the type that is used when
    /// ending the block in a normal way.
    pub(crate) end_type:    BlockType,
    /// height of the stack at the entry of this block.
    pub(crate) height:      usize,
    /// whether we are in the unreachable part of this block or not.
    /// the unreachable part is any part after an unconditional jump or
    /// a trap instruction.
    pub(crate) unreachable: bool,
}

#[derive(Debug)]
/// The validation state contains the control frames and a stack of operands.
/// this is the same state as described by the validation algorithm of the wasm
/// specification appendix.
pub struct ValidationState {
    pub(crate) opds:                 OperandStack,
    pub(crate) ctrls:                ControlStack,
    /// Maximum reachable stack height.
    pub(crate) max_reachable_height: usize,
}

impl ValidationState {
    /// Check whether we are done, meaning that the control stack is
    /// exhausted.
    pub fn done(&self) -> bool { self.ctrls.stack.is_empty() }
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
/// A possibly known type. Unknown types appear on the stack after
/// we enter an unreachable part of the code. This part must still be
/// type-checked, but the stack at that point is arbitrary.
pub(crate) enum MaybeKnown {
    Unknown,
    Known(ValueType),
}

use MaybeKnown::*;

impl MaybeKnown {
    pub(crate) fn is_unknown(self) -> bool { self == MaybeKnown::Unknown }
}

impl ValidationState {
    /// Push a new type to the stack.
    fn push_opd(&mut self, m_type: MaybeKnown) {
        self.opds.stack.push(m_type);
        if let Some(ur) = self.ctrls.stack.last().map(|frame| frame.unreachable) {
            if !ur {
                self.max_reachable_height =
                    std::cmp::max(self.max_reachable_height, self.opds.stack.len());
            }
        }
    }

    /// Pop a type from the stack and, if successful, return it.
    fn pop_opd(&mut self) -> ValidateResult<MaybeKnown> {
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

    /// Pop an operand from the stack, checking that it is as expected.
    ///
    /// If successful, return the more precise type of the two, expected and
    /// actual. The type in the stack can be marked as unknown if it is in
    /// an unreachable part of the code.
    fn pop_expect_opd(&mut self, expect: MaybeKnown) -> ValidateResult<MaybeKnown> {
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

    /// Push zero or one operands to the current stack.
    fn push_opds(&mut self, tys: BlockType) {
        if let BlockType::ValueType(ty) = tys {
            self.push_opd(Known(ty))
        }
    }

    /// Pop zero or one operands from the stack, and check that it
    /// has expected type.
    fn pop_opds(&mut self, expected: BlockType) -> ValidateResult<()> {
        if let BlockType::ValueType(ty) = expected {
            self.pop_expect_opd(Known(ty))?;
        }
        Ok(())
    }

    /// Push a new control frame with the given label and end types.
    ///
    /// The label type is the type that will be at the top of the stack
    /// when a jump to this label is executed.
    /// The end type is the type that is at the top of the stack when normal
    /// execution of the block reaches its end.
    ///
    /// For blocks the label type and end type are the same, for loops the label
    /// type is empty, and the end type is potentially not.
    fn push_ctrl(&mut self, is_if: bool, label_type: BlockType, end_type: BlockType) {
        let frame = ControlFrame {
            is_if,
            label_type,
            end_type,
            height: self.opds.stack.len(),
            unreachable: false,
        };
        self.ctrls.stack.push(frame)
    }

    /// Pop the current control frame and return its result type, together
    /// with a flag signalling whether the frame was started with an `if`.
    fn pop_ctrl(&mut self) -> ValidateResult<(BlockType, bool)> {
        // We first check for the last element, and use it without removing it.
        // This is so that pop_expect_opd, which pops elements from the stack, can see
        // whether we are in the unreachable state for the stack or not.
        match self.ctrls.stack.last().map(|frame| (frame.end_type, frame.height, frame.is_if)) {
            None => bail!("Control stack exhausted."),
            Some((end_type, height, opcode)) => {
                if let BlockType::ValueType(ty) = end_type {
                    self.pop_expect_opd(Known(ty))?;
                }
                ensure!(self.opds.stack.len() == height, "Operand stack not exhausted.");
                // Finally pop after we've made sure the stack is properly cleared.
                self.ctrls.stack.pop();
                Ok((end_type, opcode))
            }
        }
    }

    fn mark_unreachable(&mut self) -> ValidateResult<()> {
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
pub(crate) struct LocalsRange {
    pub(crate) start: LocalIndex,
    pub(crate) end:   LocalIndex,
    pub(crate) ty:    ValueType,
}

/// Context for the validation of a function.
pub(crate) struct FunctionContext<'a> {
    pub(crate) return_type: BlockType,
    pub(crate) globals:     &'a [Global],
    pub(crate) funcs:       &'a [TypeIndex],
    pub(crate) types:       &'a [Rc<FunctionType>],
    pub(crate) locals:      Vec<LocalsRange>,
    // Whether memory exists or not.
    pub(crate) memory:      bool,
    // Whether the table exists or not.
    pub(crate) table:       bool,
}

/// Make a locals structure used to validate a function body.
/// This function additionally ensures that there are no more than
/// ALLOWED_LOCALS local variables. Note that function parameters are included
/// in locals.
fn make_locals(ty: &FunctionType, locals: &[Local]) -> ValidateResult<(Vec<LocalsRange>, u32)> {
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
        let end =
            start.checked_add(local.multiplicity).ok_or_else(|| anyhow!("Too many locals"))?;
        out.push(LocalsRange {
            start,
            end,
            ty: local.ty,
        });
        start = end;
    }
    let num_locals = start;
    ensure!(num_locals <= ALLOWED_LOCALS, ValidationError::TooManyLocals {
        actual: num_locals,
        max:    ALLOWED_LOCALS,
    });
    Ok((out, num_locals))
}

/// The trait used used to parametrize the validation algorithm so that it can
/// be used for other applications than mere validation. In particular the
/// validation algorithm maintains useful state during its run, e.g., current
/// and maximum stack height, which is useful during compilation.
pub trait HasValidationContext {
    /// Get the local of a function at the given index.
    /// Note that function parameters define implicit locals.
    fn get_local(&self, idx: LocalIndex) -> ValidateResult<ValueType>;

    /// Get a global together with its mutability. `true` for mutable, `false`
    /// for constant.
    fn get_global(&self, idx: GlobalIndex) -> ValidateResult<(ValueType, bool)>;

    /// Return whether the module has memory.
    fn memory_exists(&self) -> bool;

    /// Return whether the module has the table.
    fn table_exists(&self) -> bool;

    /// Get the type of the function at the given index.
    fn get_func(&self, idx: FuncIndex) -> ValidateResult<&Rc<FunctionType>>;

    /// Get the type at the given index.
    fn get_type(&self, idx: TypeIndex) -> ValidateResult<&Rc<FunctionType>>;

    /// Return the return type of the function.
    fn return_type(&self) -> BlockType;
}

impl<'a> HasValidationContext for FunctionContext<'a> {
    fn get_local(&self, idx: LocalIndex) -> ValidateResult<ValueType> {
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
    fn get_global(&self, idx: GlobalIndex) -> ValidateResult<(ValueType, bool)> {
        if let Some(global) = self.globals.get(idx as usize) {
            Ok((global.init.ty(), global.mutable))
        } else {
            bail!("Global index out of range.")
        }
    }

    fn memory_exists(&self) -> bool { self.memory }

    fn table_exists(&self) -> bool { self.table }

    fn get_func(&self, idx: FuncIndex) -> ValidateResult<&Rc<FunctionType>> {
        if let Some(&type_idx) = self.funcs.get(idx as usize) {
            self.get_type(type_idx)
        } else {
            bail!("Function index out of range.")
        }
    }

    fn get_type(&self, idx: TypeIndex) -> ValidateResult<&Rc<FunctionType>> {
        self.types.get(idx as usize).ok_or_else(|| anyhow!("Type index out of range."))
    }

    fn return_type(&self) -> BlockType { self.return_type }
}

/// A helper type used to ensure alignment.
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
            ensure!(num == 0, "Type I8 alignment must be less than 0, but is {}.", num);
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

/// Trait to handle the results of validation.
/// The type parameter should be instantiated with an opcode. The reason it is a
/// type parameter is to support both opcodes and references to opcodes as
/// parameters. The latter is useful because opcodes are not copyable.
pub trait Handler<O> {
    type Outcome: Sized;

    /// Handle the opcode. This function is called __after__ the `validate`
    /// function itself processes the opcode. Hence the validation state is
    /// already updated. However the function does get access to the stack
    /// height __before__ the opcode is processed.
    fn handle_opcode(
        &mut self,
        state: &ValidationState,
        stack_heigh: usize,
        opcode: O,
    ) -> anyhow::Result<()>;

    /// Finish processing the code. This function is called after the code body
    /// has been successfully validated.
    fn finish(self, state: &ValidationState) -> anyhow::Result<Self::Outcome>;
}

impl Handler<OpCode> for Vec<OpCode> {
    type Outcome = (Self, usize);

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn handle_opcode(
        &mut self,
        _state: &ValidationState,
        _stack_height: usize,
        opcode: OpCode,
    ) -> anyhow::Result<()> {
        self.push(opcode);
        Ok(())
    }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn finish(self, state: &ValidationState) -> anyhow::Result<Self::Outcome> {
        Ok((self, state.max_reachable_height))
    }
}

/// Validate a single function. In order that this function is as flexible as
/// possible it takes as input just an iterator over opcodes. The function will
/// terminate at the first opcode it fails to read. Validation will ensure that
/// the iterator is fully consumed and properly terminated by an `End` opcode.
/// The return value is the outcome determined by the handler, as well as
/// the maximum reachable stack height in this function.
pub fn validate<O: Borrow<OpCode>, H: Handler<O>>(
    context: &impl HasValidationContext,
    opcodes: impl Iterator<Item = ParseResult<O>>,
    mut handler: H,
) -> ValidateResult<H::Outcome> {
    let mut state = ValidationState {
        opds:                 OperandStack::default(),
        ctrls:                ControlStack::default(),
        max_reachable_height: 0,
    };
    state.push_ctrl(false, context.return_type(), context.return_type());
    for opcode in opcodes {
        let next_opcode = opcode?;
        let old_stack_height = state.opds.stack.len();
        match next_opcode.borrow() {
            OpCode::End => {
                let (res, is_if) = state.pop_ctrl()?;
                if is_if {
                    ensure!(
                        res == BlockType::EmptyType,
                        "If without an else must have empty return type"
                    )
                }
                state.push_opds(res);
            }
            OpCode::Nop => {
                // do nothing.
            }
            OpCode::Unreachable => {
                state.mark_unreachable()?;
            }
            OpCode::Block(ty) => {
                state.push_ctrl(false, *ty, *ty);
            }
            OpCode::Loop(ty) => {
                state.push_ctrl(false, BlockType::EmptyType, *ty);
            }
            OpCode::If {
                ty,
            } => {
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_ctrl(true, *ty, *ty);
            }
            OpCode::Else => {
                let (res, is_if) = state.pop_ctrl()?;
                ensure!(is_if, "Else can only come after an if");
                state.push_ctrl(false, res, res);
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
                ensure!(
                    labels.len() <= MAX_SWITCH_SIZE,
                    "Size of switch statement exceeds maximum."
                );
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
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Load(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I64)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I32Load8S(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Load8U(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Load16S(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I32Load16U(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I32));
            }
            OpCode::I64Load8S(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load8U(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I8)?;
                ensure!(memarg.align == 0, "Alignment out of range");
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load16S(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load16U(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load32S(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I64Load32U(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.push_opd(Known(ValueType::I64));
            }
            OpCode::I32Store(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I32)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I64)?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I32Store8(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I32Store16(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I32))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store8(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I8)?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store16(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
                ensure_alignment(memarg.align, Type::I16)?;
                state.pop_expect_opd(Known(ValueType::I64))?;
                state.pop_expect_opd(Known(ValueType::I32))?;
            }
            OpCode::I64Store32(memarg) => {
                ensure!(context.memory_exists(), "Memory should exist.");
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
        handler.handle_opcode(&state, old_stack_height, next_opcode)?;
    }
    if state.done() {
        handler.finish(&state)
    } else {
        bail!("Improperly terminated instruction sequence.")
    }
}

/// Validate an import according to the specific logic of the host.
pub trait ValidateImportExport {
    /// Validate an imported function signature.
    /// The second argument indicates whether this import has a duplicate name.
    fn validate_import_function(
        &self,
        duplicate: bool,
        mod_name: &Name,
        item_name: &Name,
        ty: &FunctionType,
    ) -> bool;

    /// Validate an imported function signature.
    /// The second argument indicates whether this import has a duplicate name.
    fn validate_export_function(&self, item_name: &Name, ty: &FunctionType) -> bool;
}

/// Validate the module. This function parses and validates the module at the
/// same time, failing at the first encountered error.
pub fn validate_module<'a>(
    imp: &impl ValidateImportExport,
    skeleton: &Skeleton<'a>,
) -> ValidateResult<Module> {
    // This is a technicality, but we need to parse the custom sections to ensure
    // that they are valid. Validity consists only of checking that the name part
    // is properly encoded.
    for cs in skeleton.custom.iter() {
        parse_custom(cs)?;
    }

    // The type section is valid as long as it's well-formed.
    let ty: TypeSection = parse_sec_with_default(EMPTY_CTX, &skeleton.ty)?;
    // Imports are valid as long as they parse, and all the indices exist.
    let import: ImportSection = parse_sec_with_default(EMPTY_CTX, &skeleton.import)?;
    {
        let mut seen_imports = BTreeSet::new();
        for i in import.imports.iter() {
            match i.description {
                ImportDescription::Func {
                    type_idx,
                } => {
                    if let Some(ty) = ty.get(type_idx) {
                        let is_new = seen_imports.insert((&i.mod_name, &i.item_name));
                        ensure!(
                            imp.validate_import_function(!is_new, &i.mod_name, &i.item_name, ty),
                            "Disallowed import."
                        );
                    } else {
                        bail!("Import refers to a non-existent type.");
                    }
                }
            }
        }
    }
    // The table section is valid as long as it's well-formed.
    // We already check the limits at parse time.
    let table: TableSection = parse_sec_with_default(EMPTY_CTX, &skeleton.table)?;

    // The memory section is valid as long as it's well-formed.
    // We already check the limits at parse time.
    let memory: MemorySection = parse_sec_with_default(EMPTY_CTX, &skeleton.memory)?;

    // The global section is valid as long as it's well-formed.
    // We already check that all the globals are initialized with
    // correct expressions.
    let global: GlobalSection = parse_sec_with_default(EMPTY_CTX, &skeleton.global)?;
    ensure!(
        global.globals.len() <= MAX_NUM_GLOBALS,
        "The number of globals must not exceed {}.",
        MAX_NUM_GLOBALS
    );

    // The start section is valid as long as it parses correctly.
    // We make sure that there is no content in the start section during parsing.
    let start = parse_sec_with_default(EMPTY_CTX, &skeleton.start)?;

    // The function type section is valid if it parses properly, and all the indices
    // of types are valid.
    // The code section then needs to match.
    let func: FunctionSection = parse_sec_with_default(EMPTY_CTX, &skeleton.func)?;
    for &type_idx in func.types.iter() {
        ensure!(ty.get(type_idx).is_some(), "Function refers to a type that does not exist.")
    }

    // Number of functions that can be referred to.
    // Since all imports must be functions we could just use length, but
    // in the interest of being more robust to changes we count imported functions
    // instead.
    let total_funcs =
        import.imports.iter().filter(|&x| Import::is_func(x)).count() + func.types.len();

    let code: CodeSkeletonSection = parse_sec_with_default(EMPTY_CTX, &skeleton.code)?;
    ensure!(
        func.types.len() == code.impls.len(),
        "The number of functions in the function and code sections must match."
    );
    // an index of function types, merging imported and declared functions.
    let funcs = import
        .imports
        .iter()
        .map(|i| match i.description {
            ImportDescription::Func {
                type_idx,
            } => type_idx,
        })
        .chain(func.types.iter().copied())
        .collect::<Vec<TypeIndex>>();

    let mut parsed_code = Vec::with_capacity(code.impls.len());
    for (&f, c) in func.types.iter().zip(code.impls) {
        match ty.get(f) {
            Some(func_ty) => {
                let (locals, num_locals) = make_locals(func_ty, &c.locals)?;
                let ctx = FunctionContext {
                    return_type: BlockType::from(func_ty.result),
                    globals: &global.globals,
                    funcs: &funcs,
                    types: &ty.types,
                    locals,
                    memory: memory.memory_type.is_some(),
                    table: table.table_type.is_some(),
                };
                let (opcodes, max_height) =
                    validate(&ctx, &mut OpCodeIterator::new(c.expr_bytes), Vec::new())?;
                ensure!(
                    num_locals as usize + max_height <= MAX_ALLOWED_STACK_HEIGHT,
                    "Stack height would exceed allowed limits."
                );

                let code = Code {
                    ty: func_ty.clone(),
                    ty_idx: f,
                    num_locals,
                    locals: c.locals,
                    expr: Expression {
                        instrs: opcodes,
                    },
                };
                parsed_code.push(code)
            }
            None => bail!("Function has a type that does not exist."),
        }
    }
    // Exports are mostly valid by parsing, but we need to make sure that
    // they are all distinct.
    let export: ExportSection = parse_sec_with_default(EMPTY_CTX, &skeleton.export)?;
    let mut export_names = BTreeSet::new();
    ensure!(export.exports.len() <= MAX_NUM_EXPORTS, "Module exceeds maximum number of exports.");
    for e in export.exports.iter() {
        // ensure the name is unique.
        ensure!(export_names.insert(&e.name), "Duplicate exports {}.", e.name);

        match e.description {
            ExportDescription::Func {
                index,
            } => {
                if let Some(ty) = funcs.get(index as usize).and_then(|ty_idx| ty.get(*ty_idx)) {
                    ensure!(imp.validate_export_function(&e.name, ty), "Export function not valid.")
                } else {
                    bail!("Trying to export a function that does not exist.")
                }
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
    let element: ElementSection = parse_sec_with_default(&global, &skeleton.element)?;
    ensure!(
        element.elements.is_empty() || table.table_type.is_some(),
        "There is an elements section, but no table."
    );
    for elem in element.elements.iter() {
        let inits_len: u32 = elem.inits.len().try_into()?;
        ensure!(
            inits_len <= MAX_INIT_TABLE_SIZE,
            "Number of initial elements is more than the table size."
        );
        if let Some(table_type) = table.table_type.as_ref() {
            let offset = elem.offset as u32;
            // since we provide no way to grow the table the initial minimum size
            // is the size of the table, as specified in the allocation section of the
            // Wasm semantics.
            // The as u32 is safe beca
            let end = offset
                .checked_add(inits_len)
                .ok_or_else(|| anyhow!("The end of the table exceeds u32 max bound."))?;
            ensure!(
                end <= table_type.limits.min,
                "Initialization expression for the table exceeds table size {} > {}.",
                end,
                table_type.limits.min
            );
        }
        for &init in elem.inits.iter() {
            ensure!(
                (init as usize) < total_funcs,
                "Index in the element segment refers to a non-existent function."
            );
        }
    }

    // The data section is almost well-formed by parsing.
    // Parsing already ensures that limits are well-formed, that
    // the offset expression is of the correct type and constant.
    // We additionally need to check that all the locations referred
    // to in the table are defined.
    let data: DataSection = parse_sec_with_default(&global, &skeleton.data)?;
    // Make sure that if there are any data segments then a memory exists.
    // By parsing we already ensure that all the references are to a single memory
    // and that the initial memory is limited by MAX_INIT_MEMORY_SIZE.
    if let Some(memory_type) = memory.memory_type.as_ref() {
        for data in data.sections.iter() {
            let inits_len: u32 = data.init.len().try_into()?;
            ensure!(
                // this cannot overflow because we've already ensured limits.min <
                // MAX_INIT_MEMORY_SIZE
                inits_len <= memory_type.limits.min * PAGE_SIZE,
                "Number of initial elements is more than the initial memory size."
            );
            let offset: u32 = data.offset.try_into()?;
            let end = offset
                .checked_add(inits_len)
                .ok_or_else(|| anyhow!("The end of the memory exceeds u32 max bound."))?;
            ensure!(
                // by validation we have that memory_type.limits.min <= MAX_INIT_MEMORY_SIZE <
                // 2^16, so this cannot overflow but we're still being safe
                memory_type.limits.min.checked_mul(PAGE_SIZE).map_or(false, |l| end <= l),
                "Initialization expression for the data segment exceeds initial memory size {} > \
                 {}.",
                end,
                memory_type.limits.min * PAGE_SIZE
            );
        }
    } else {
        // There is no memory, so there should be no data section.
        ensure!(data.sections.is_empty(), "There are data sections, but no declared memory.");
    }
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
