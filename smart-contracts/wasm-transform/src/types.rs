//! AST definition of Wasm modules, as well as supporting datatypes.
//! Based on the [W3C Wasm specification](https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-import)
//!
//! The main type is [Module](./struct.Module.html), which defines a Wasm
//! module, either validated or not validated. Some of the properties that are
//! stated as validity conditions in the Wasm specification are already
//! guaranteed automatically by the AST definition of the Module, and the
//! parsing functions.

use anyhow::bail;
use derive_more::{Display, From};
use std::{convert::TryFrom, rc::Rc};

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Display)]
/// A webassembly Name. We choose to have it be an owned value rather than a
/// reference into the original module. Names are also used in the parsed AST,
/// and we don't want to retain references to the original bytes just because of
/// a few names.
#[display(fmt = "{}", name)]
pub struct Name {
    /// Names in Wasm are utf8 encoded.
    pub name: String,
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str { &self.name }
}

impl<'a> From<&'a str> for Name {
    fn from(s: &'a str) -> Self {
        Self {
            name: s.to_string(),
        }
    }
}

impl std::borrow::Borrow<str> for Name {
    fn borrow(&self) -> &str { &self.name }
}

#[derive(Debug)]
/// A single import description.
pub enum ImportDescription {
    /// Import a function with the given type. The other import types, Table,
    /// Memory, Global, are not supported by Concordium.
    Func {
        type_idx: TypeIndex,
    },
}

#[derive(Debug)]
/// Import of an item from another module.
pub struct Import {
    /// The name of the module the item is imported from.
    pub mod_name:    Name,
    /// The name of the item that is to be imported.
    pub item_name:   Name,
    /// And the description of the item.
    pub description: ImportDescription,
}

impl Import {
    /// Return whether the import is a function.
    pub fn is_func(&self) -> bool {
        match self.description {
            ImportDescription::Func {
                ..
            } => true,
        }
    }
}

#[derive(Debug, Default)]
/// The Default instance for this type produces an empty section.
pub struct ImportSection {
    pub imports: Vec<Import>,
}

#[derive(Debug, Default)]
/// The Default instance for this type produces an empty function section.
pub struct FunctionSection {
    pub types: Vec<TypeIndex>,
}

impl FunctionSection {
    pub fn get(&self, idx: FuncIndex) -> Option<TypeIndex> { self.types.get(idx as usize).copied() }
}

#[derive(Debug, Default)]
/// The Default instance for this type produces an empty table section.
pub struct TableSection {
    /// We only support at most one section for now, as in Wasm MVP, hence an
    /// Option as opposed to the vector.
    ///
    /// If present, the table type limits ensure that min <= 2^16.
    pub table_type: Option<TableType>,
}

#[derive(Debug)]
/// An exported item description. Since it is inconsequential whether extra
/// definitions are exported we allow all of them to be flexible with respect to
/// the external tooling.
pub enum ExportDescription {
    /// An exported function with the given type.
    Func {
        index: FuncIndex,
    },
    /// An exported table. Since only table with index 0 is currently supported
    /// there is no explicit index.
    Table,
    /// Exported memory. Since only memory with index 0 is currently supported
    /// there is no explicit index.
    Memory,
    /// An exported global.
    Global {
        index: GlobalIndex,
    },
}

#[derive(Debug)]
/// An exported item.
pub struct Export {
    /// Name of the exported item.
    pub name:        Name,
    /// And its type.
    pub description: ExportDescription,
}

#[derive(Debug, Default)]
/// The Default instance of this type returns an empty section.
pub struct ExportSection {
    pub exports: Vec<Export>,
}

#[derive(Debug, Default)]
/// We do not support start sections, so this type has exactly one value, the
/// empty start section, which is of course also the value returned by the
/// Default instance.
pub struct StartSection {}

#[derive(Debug)]
/// An element description, describing how to initialize the table.
/// The table index 0 is implicit, so we don't record it in the struct.
pub struct Element {
    /// The offset to start the initialization.
    pub offset: i32,
    /// Functions to define in the table, starting at the offset.
    pub inits:  Vec<FuncIndex>,
}

#[derive(Debug, Default)]
/// The Default instance of this produces an empty Element section.
pub struct ElementSection {
    pub elements: Vec<Element>,
}

#[derive(Debug, Copy, Clone)]
/// The initial global value with its type.
/// Because we do not allow imported globals, the initialization expression
/// must consist of a single constant value of the right type, which we
/// short-circuit into the single constant.
pub enum GlobalInit {
    I32(i32),
    I64(i64),
}

impl From<GlobalInit> for i64 {
    fn from(g: GlobalInit) -> Self {
        match g {
            GlobalInit::I64(x) => x,
            GlobalInit::I32(x) => i64::from(x),
        }
    }
}

impl From<&Global> for ValueType {
    fn from(g: &Global) -> Self {
        match g.init {
            GlobalInit::I32(_) => ValueType::I32,
            GlobalInit::I64(_) => ValueType::I64,
        }
    }
}

impl GlobalInit {
    ///  Type of this global
    pub fn ty(self) -> ValueType {
        match self {
            GlobalInit::I32(_) => ValueType::I32,
            GlobalInit::I64(_) => ValueType::I64,
        }
    }
}

#[derive(Debug)]
/// A single Global declaration, with initial value.
pub struct Global {
    /// The type of the value with the initial value.
    pub init:    GlobalInit,
    pub mutable: bool,
}

#[derive(Debug, Default)]
/// The Default instance of this type returns an empty section.
pub struct GlobalSection {
    pub globals: Vec<Global>,
}

impl GlobalSection {
    pub fn get(&self, idx: GlobalIndex) -> Option<&Global> { self.globals.get(idx as usize) }
}

#[derive(Debug, Clone, Copy)]
/// A local variable declaration in a function.
pub struct Local {
    /// The number of variables of this type.
    pub multiplicity: u32,
    /// The type of the local.
    pub ty:           ValueType,
}

#[derive(Debug)]
/// The body of a function.
pub struct Code {
    /// Type of the function, this is added here to avoid more error cases.
    /// in processing (e.g., after validation we know that the number of code
    /// and function sections match).
    pub ty:         Rc<FunctionType>,
    /// Type index carried over from the source. This should match the ty type
    /// above.
    pub ty_idx:     TypeIndex,
    /// The number of locals of a function. NB: This includes parameters and
    /// locals declared inside the function.
    pub num_locals: u32,
    /// Declaration of the locals. This does not include parameters.
    pub locals:     Vec<Local>,
    /// And a sequence of instructions.
    pub expr:       Expression,
}

#[derive(Debug, Default)]
/// The Default instance of this type returns an empty code section.
pub struct CodeSection {
    pub impls: Vec<Code>,
}

#[derive(Debug)]
/// The initialization of memory. The memory index is implicitly 0.
pub struct Data {
    /// Where to start initializing.
    pub offset: i32,
    /// The bytes to initialize with.
    pub init:   Vec<u8>,
}

#[derive(Debug, Default)]
/// The Default instance of this type returns an empty data section.
pub struct DataSection {
    pub sections: Vec<Data>,
}

#[derive(Debug, Default)]
/// The Default instance for this type produces an empty memory section.
pub struct MemorySection {
    /// Since we only support the memory with index 0 we use an Option as
    /// opposed to a vector. In the version of Wasm we support
    pub memory_type: Option<MemoryType>,
}

#[derive(Debug)]
/// A processed custom section. By specification all custom sections have a
/// name, followed by uninterpreted bytes.
pub struct CustomSection<'a> {
    pub name:     Name,
    pub contents: &'a [u8],
}

#[derive(Debug, Default)]
/// The default instance for type produces an empty type section.
pub struct TypeSection {
    /// A list of types. We use an Rc here so that we can avoid cloning the
    /// FunctionType, which could be used to use-up resources when we
    /// add this type to each of the code sections.
    pub types: Vec<Rc<FunctionType>>,
}

impl TypeSection {
    pub fn get(&self, idx: TypeIndex) -> Option<&Rc<FunctionType>> { self.types.get(idx as usize) }
}

#[derive(Debug)]
/// A parsed Wasm module. This no longer has custom sections since they are not
/// needed for further processing.
pub struct Module {
    pub ty:      TypeSection,
    pub import:  ImportSection,
    pub func:    FunctionSection,
    pub table:   TableSection,
    pub memory:  MemorySection,
    pub global:  GlobalSection,
    pub export:  ExportSection,
    pub start:   StartSection,
    pub element: ElementSection,
    pub code:    CodeSection,
    pub data:    DataSection,
}

pub type StackSize = u64;
/// A number of operands on the stack.
pub type StackHeight = u64;

/// Indices
pub type TypeIndex = u32;
pub type FuncIndex = u32;
pub type TableIndex = u32;
pub type MemIndex = u32;
pub type GlobalIndex = u32;
pub type LocalIndex = u32;
pub type LabelIndex = u32;

/// Supported Wasm value types (i.e., no floats). We use a very low-level
/// encoding which we make use of to remove some needless allocations. In
/// particular the tags must be as specified by the Wasm specification and must
/// match the binary serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ValueType {
    I32 = 0x7F,
    I64 = 0x7E,
}

/// Try to decode a value type from a single byte, the bytes being as specified
/// by the Wasm specification.
impl TryFrom<u8> for ValueType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x7F => Ok(ValueType::I32),
            0x7E => Ok(ValueType::I64),
            _ => bail!("Unknown value type byte {:#04x}", value),
        }
    }
}

/// Try to decode a value type from a single byte, the bytes being as specified
/// by the Wasm specification.
impl From<ValueType> for u8 {
    fn from(from: ValueType) -> Self {
        match from {
            ValueType::I32 => 0x7F,
            ValueType::I64 => 0x7E,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// We only support the empty block type and a single value type. Type indices
/// are not supported in the MVP version of Wasm.
pub enum BlockType {
    EmptyType,
    ValueType(ValueType),
}

impl From<Option<ValueType>> for BlockType {
    fn from(opt: Option<ValueType>) -> Self {
        match opt {
            Some(x) => BlockType::ValueType(x),
            None => BlockType::EmptyType,
        }
    }
}

impl BlockType {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    pub fn is_empty(self) -> bool {
        match self {
            BlockType::EmptyType => true,
            BlockType::ValueType(_) => false,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TableType {
    pub limits: Limits,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryType {
    pub limits: Limits,
}

#[derive(Debug, Clone, Eq, PartialEq)]
/// The immediate memory argument. Since all operations are on memory index 0
/// the index is implicit.
pub struct MemArg {
    /// The offest into the linear memory.
    pub offset: u32,
    /// Alignment. This is ignored by the Wasm semantics, but may be used as a
    /// hint. We will simply ignore it.
    pub align:  u32,
}

#[derive(Debug, Copy, Clone)]
pub struct Limits {
    pub min: u32,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A function type with at most one return value. The MVP version of Wasm does
/// not support multiple return values, and thus we don't either.
pub struct FunctionType {
    pub parameters: Vec<ValueType>,
    pub result:     Option<ValueType>,
}

impl FunctionType {
    /// A function type with no arguments and no results.
    pub fn empty() -> Self {
        Self {
            parameters: Vec::new(),
            result:     None,
        }
    }
}

/// A sequence of instructions.
pub type InstrSeq = Vec<OpCode>;

/// An expression is a sequence of instructions followed by the "end" delimiter,
/// which is also present in the binary format (see 5.4.6).
#[derive(Debug, Default, From)]
pub struct Expression {
    pub instrs: InstrSeq,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpCode {
    // Control instructions
    End,
    Nop,
    Unreachable,
    Block(BlockType),
    Loop(BlockType),
    If {
        ty: BlockType,
    },
    Else,
    Br(LabelIndex),
    BrIf(LabelIndex),
    BrTable {
        labels:  Vec<LabelIndex>,
        default: LabelIndex,
    },
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
    I32GtU,
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
    I64GtU,
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
}
