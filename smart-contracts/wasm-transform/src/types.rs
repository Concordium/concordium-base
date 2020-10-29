// AST definition of Wasm modules.
// Based on the Wasm specification Release 1.1, July 21st, 2020.

// NOTE: As most parts of the module are actually not changed by our
// transformation, we do not have to parse and reencode all parts (even though
// we have to visit them for validation). The only parts we want to change
// should be imports, the memory definition (to set the limits) and the body
// expressions of functions (included in the code section). We could therefore
// read most module sections without parsing and store them in the binary
// format, and only parse and reencode the import section, memory section and
// code section. Alternatively, if we have to parse for validation anyway, we
// can still only store the tokens and at least do not have to build a more
// structured AST for these parts. As a consequence, some of the below
// definitions might eventually not be needed, as we'd just use the token format
// the parser provides.
pub struct Module {
    // TODO
}

impl Module {
    // TODO implement
    // pub fn get_function(idx: FuncIndex) -> &Function {
    //     // TODO implement
    //     panic!("Not yet implemented.");
    // }

    /// Get the arity (number of values) of the given block type.
    pub fn get_arity(&self, bt: &BlockType) -> usize {
        match bt {
            BlockType::EmptyType => 0,
            BlockType::ValueType(_) => 1,
            BlockType::TypeIndex(idx) => 10000000000, // TODO lookup in module
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Function {
    pub func_type: TypeIndex,
    // TODO might want retain compact representations of multiple locals of same type
    pub locals: Vec<ValueType>,
    pub body: Expression,
    // TODO Storing the maximum stack size here is probably unnecessary if, for simplicity,
    // we calculate it on the ready AST of the body expression, instead of during parsing.
    // TODO This is supposed to be an optional annotation, that will only be used
    // for our source code transformation, and not be used for source generation.
    // An alternative is to parametrize `Function` over the type to use here,
    // but maybe `Option` is actually cleaner.
    /// The maximum stack size this function can use. See cost specification.
    /// Note that this should include a constant base size for the frame,
    /// the size for the locals and the size the body can use during execution.
    pub max_stack_size: Option<StackSize>,
}

// Special annotations

/// Stack size in bytes.
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

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ValueType {
    I32,
    I64,
}

#[derive(Clone, PartialEq, Debug)]
pub enum BlockType {
    EmptyType,
    ValueType(ValueType),
    TypeIndex(TypeIndex),
}

pub type LocalsType = u64;

#[derive(Clone, PartialEq, Debug)]
pub struct MemArg {
    offset: u32,
    align: u32,
}

pub type InstrSeq = Vec<Instruction>;

/// An expression is a sequence of instructions followed by the "end" delimiter,
/// which is also present in the binary format (see 5.4.6).
pub type Expression = InstrSeq;

#[derive(Clone, PartialEq, Debug)]
pub enum Instruction {
    // Control instructions
    Nop,
    Unreachable,
    Block(BlockType, InstrSeq),
    Loop(BlockType, InstrSeq),
    If(BlockType, InstrSeq, InstrSeq),
    Br(LabelIndex),
    BrIf(LabelIndex),
    BrTable(Vec<LabelIndex>, LabelIndex),
    Return,
    Call(FuncIndex),
    CallIndirect(TypeIndex),

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
    I32Load(MemArg),
    I64Load(MemArg),
    I32Load8S(MemArg),
    I32Load8U(MemArg),
    I32Load16S(MemArg),
    I32Load16U(MemArg),
    I64Load8S(MemArg),
    I64Load8U(MemArg),
    I64Load16S(MemArg),
    I64Load16U(MemArg),
    I64Load32S(MemArg),
    I64Load32U(MemArg),
    I32Store(MemArg),
    I64Store(MemArg),
    I32Store8(MemArg),
    I32Store16(MemArg),
    I64Store8(MemArg),
    I64Store16(MemArg),
    I64Store32(MemArg),
    MemorySize,
    MemoryGrow,

    // Numeric instructions
    I32Const(i32),
    I64Const(i64),

    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU, // With this instruction, the contract gets 2^32-4294967296 GTU.
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    I64Eqz,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU, // With this instruction, the contract gets 2^64-18446744073709551616 GTU.
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,

    I32Clz,
    I32Ctz,
    I32Popcnt,
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    I64Clz,
    I64Ctz,
    I64Popcnt,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,

    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
}

/// Lookup an element in the given vector, using backwards indexing.
pub fn lookup_label(labels: &Vec<usize>, idx: LabelIndex) -> usize {
    let i = labels.len() - 1 - (idx as usize);
    labels[i]
}
