// AST definition of Wasm modules.
// Based on the Wasm specification Release 1.1, July 21st, 2020.

use crate::*;

pub struct Module {
    // TODO
}

pub struct Function {
    func_type: FuncIndex,
    locals:    Vec<ValueType>,
    body:      Expression,
    // TODO This is supposed to be an optional annotation, that will only be used
    // for our source code transformation, and not be used for source generation.
    // An alternative is to parametrize `Function` over the type to use here,
    // but maybe `Option` is actually cleaner.
    /// The maximum stack height this function can use. See cost specification.
    max_stack_size: Option<StackSize>,
}

// Special annotations

pub type StackSize = u64;
/// A number of operands on the stack.
pub type StackHeight = u64;

// Indices
pub type TypeIndex = u32;
pub type FuncIndex = u32;
pub type TableIndex = u32;
pub type MemIndex = u32;
pub type GlobalIndex = u32;
pub type LocalIndex = u32;
pub type LabelIndex = u32;

pub enum ValueType {
    I32,
    I64,
}

pub enum BlockType {
    TypeIndex(TypeIndex),
    ValueType(ValueType),
}

pub type LocalsType = u64;

pub type InstrSeq = Vec<Instruction>;

/// An expression is a sequence of instructions followed by the "end" delimiter,
/// which is also present in the binary format (see 5.4.6).
pub type Expression = InstrSeq;

pub enum Instruction {
    // Numeric instructions
    // TODO

    // Parametric instructions
    Drop,
    Select,

    // Variable instructions
    LocalGet(LocalIndex),
    LocalSet(LocalIndex),
    LocalTee(LocalIndex),
    GlobalGet(GlobalIndex),
    GlobalSet(GlobalIndex),

    // Memory instructions
    // TODO

    // Control instructions
    Nop,
    Unreachable,
    Block(BlockType, InstrSeq),
    Loop(BlockType, InstrSeq),
    If(BlockType, Box<Instruction>, Box<Instruction>),
    Br(LabelIndex),
    BrIf(LabelIndex),
    BrTable(Vec<LabelIndex>, LabelIndex),
    Return,
    Call(FuncIndex),
    CallIndirect(TypeIndex),
}
