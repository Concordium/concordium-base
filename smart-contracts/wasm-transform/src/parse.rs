//! This module defines a parser for the Web assembly binary format conforming
//! to the specification in [wasm-core-1-20191205](https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/) but with further
//! restrictions to ensure suitability for the Concordium blockchain.
//!
//! In particular all floating point types and instructions are removed and will
//! cause a parsing error. The reason for this is that we currently do not
//! support floating point types to ensure determinism, and to simplify the
//! validator and further stages we simply remove those instructions at the
//! parsing stage.
//!
//! Parsing is organized into two stages. In the first stage bytes are parsed
//! into a Skeleton, which is simply a list of sections, the sections themselves
//! being unparsed. This structure is useful for some operations, such as
//! pruning and embedding additional metadata into the module.
//!
//! In the second stage each section can be parsed into a proper structure.
use crate::{constants::*, types::*};
use anyhow::{bail, ensure};
use std::{
    convert::TryFrom,
    io::{Cursor, Read, Seek, SeekFrom},
    rc::Rc,
};

/// # Core datatypes.

/// Type alias used in the Wasm specification.
pub type Byte = u8;

#[derive(Debug)]
/// A section carved out of a module, but with no further processing.
/// It can be serialized back by writing the section ID and bytes together with
/// the length. The lifetime is the lifetime of the original byte array this
/// section was carved from.
pub struct UnparsedSection<'a> {
    pub section_id: SectionId,
    pub bytes:      &'a [u8],
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Debug)]
/// All supported section IDs as specified by the Web assembly specification.
pub enum SectionId {
    Custom = 0,
    Type,
    Import,
    Function,
    Table,
    Memory,
    Global,
    Export,
    Start,
    Element,
    Code,
    Data,
}

#[derive(Debug)]
/// Skeleton of a module, which is a list of sections that are minimally
/// processed.
pub struct Skeleton<'a> {
    /// Type section.
    pub ty: Option<UnparsedSection<'a>>,
    /// Import section.
    pub import: Option<UnparsedSection<'a>>,
    /// Function section.
    pub func: Option<UnparsedSection<'a>>,
    /// Table section.
    pub table: Option<UnparsedSection<'a>>,
    /// Memory section.
    pub memory: Option<UnparsedSection<'a>>,
    /// Global section.
    pub global: Option<UnparsedSection<'a>>,
    /// Export section.
    pub export: Option<UnparsedSection<'a>>,
    /// Start section.
    pub start: Option<UnparsedSection<'a>>,
    /// Element section.
    pub element: Option<UnparsedSection<'a>>,
    /// Code section.
    pub code: Option<UnparsedSection<'a>>,
    /// Data section.
    pub data: Option<UnparsedSection<'a>>,
    /// A list of custom sections in the order they appeared in the input.
    pub custom: Vec<UnparsedSection<'a>>,
}

/// Auxiliary type alias used by all the parsing functions.
pub type ParseResult<A> = anyhow::Result<A>;

/// A trait for parsing data. The lifetime is useful when we want to parse
/// data without copying, which is useful to avoid copying all the unparsed
/// sections.
pub trait Parseable<'a, Ctx = ()>: Sized {
    /// Read a value from the cursor, or signal error.
    /// This function is responsible for advancing the cursor in-line with the
    /// data it has read.
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self>;
}

/// A helper trait for more convenient use. The difference from the above is
/// that typically the result type is determined by the context, which we take
/// advantage of to reduce the need for typing annotations which would be needed
/// by the Parseable trait.
///
/// The reason for that is that this trait defines a new method on the type,
/// giving us access to all of the convenience features of Rust that come with
/// it.
pub trait GetParseable<A> {
    /// Parse an item. Analogous to 'parse', but with the reversed roles for
    /// types of input and output. In the 'Parseable' trait the trait is defined
    /// for the type that is to be parsed and the source is fixed, whereas here
    /// the trait is parameterized by the type to be parsed, and the trait is
    /// implemented for the source type.
    fn next(self) -> ParseResult<A>;
}

/// A generic implementation for a cursor.
impl<'a, 'b, A: Parseable<'a>> GetParseable<A> for &'b mut Cursor<&'a [u8]> {
    #[inline(always)]
    fn next(self) -> ParseResult<A> { A::parse(self) }
}

/// Another generic implementation, but this time the input is not directly a
/// readable type. Instead this instance additionally ensures that all of the
/// input data is used by the parser.
impl<'a, A: Parseable<'a>> GetParseable<A> for &'a [u8] {
    #[inline(always)]
    fn next(self) -> ParseResult<A> {
        let mut cursor = Cursor::new(self);
        let res = A::parse(&mut cursor)?;
        ensure!(cursor.position() == self.len() as u64, "Not all of the contents was consumed.");
        Ok(res)
    }
}

/// Implementation for u32 according to the Wasm specification.
impl<'a> Parseable<'a> for u32 {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // 5 is ceil(32 / 7)
        let res = leb128::read::unsigned(&mut cursor.take(5))?;
        Ok(u32::try_from(res)?)
    }
}

/// Implementation for u64 according to the Wasm specification.
impl<'a> Parseable<'a> for u64 {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // 10 is ceil(64 / 7)
        let res = leb128::read::unsigned(&mut cursor.take(10))?;
        Ok(res)
    }
}

/// Implementation for i32 according to the Wasm specification.
impl<'a> Parseable<'a> for i32 {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // 5 is ceil(32 / 7)
        let res = leb128::read::signed(&mut cursor.take(5))?;
        Ok(i32::try_from(res)?)
    }
}

/// Implementation for i64 according to the Wasm specification.
impl<'a> Parseable<'a> for i64 {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let res = leb128::read::signed(&mut cursor.take(10))?;
        Ok(res)
    }
}

/// Parsing of the section ID according to the linked Wasm specification.
impl<'a> Parseable<'a> for SectionId {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf)?;
        use SectionId::*;
        match buf[0] {
            0 => Ok(Custom),
            1 => Ok(Type),
            2 => Ok(Import),
            3 => Ok(Function),
            4 => Ok(Table),
            5 => Ok(Memory),
            6 => Ok(Global),
            7 => Ok(Export),
            8 => Ok(Start),
            9 => Ok(Element),
            10 => Ok(Code),
            11 => Ok(Data),
            id => bail!("Unknown section id {}", id),
        }
    }
}

/// Parse a vector of elements according to the Wasm specification.
/// Specifically this is parsed by reading the length as a u32 and then reading
/// that many elements.
impl<'a, A: Parseable<'a>> Parseable<'a> for Vec<A> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(cursor)?;
        let max_initial_capacity =
            MAX_PREALLOCATED_BYTES / std::cmp::max(1, std::mem::size_of::<A>());
        let mut out = Vec::with_capacity(std::cmp::min(len as usize, max_initial_capacity));
        for _ in 0..len {
            out.push(cursor.next()?)
        }
        Ok(out)
    }
}

/// Same as the instance for Vec<u8>, with the difference that no data is copied
/// and the result is a reference to the initial byte array.
impl<'a> Parseable<'a> for &'a [u8] {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(cursor)?;
        let pos = cursor.position() as usize;
        let end = pos + len as usize;
        ensure!(end <= cursor.get_ref().len(), "Malformed byte array");
        cursor.seek(SeekFrom::Current(i64::from(len)))?;
        Ok(&cursor.get_ref()[pos..end])
    }
}

/// Special case of a vector where we only expect 0 or 1 elements.
impl<'a, A: Parseable<'a>> Parseable<'a> for Option<A> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(cursor)? {
            0u8 => Ok(None),
            1u8 => Ok(Some(cursor.next()?)),
            tag => bail!("Unsupported option tag: {:#04x}", tag),
        }
    }
}

/// Same as the instance for Vec<u8>, with the difference that no data is copied
/// and the result is a reference to the initial byte array.
impl<'a> Parseable<'a> for &'a [ValueType] {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(cursor)?;
        let pos = cursor.position() as usize;
        let end = pos + len as usize;
        ensure!(end <= cursor.get_ref().len(), "Malformed byte array");
        cursor.seek(SeekFrom::Current(i64::from(len)))?;
        let bytes = &cursor.get_ref()[pos..end];
        for byte in bytes {
            if let Err(e) = ValueType::try_from(*byte) {
                bail!("Unknown value type array: {}", e)
            }
        }
        Ok(unsafe { &*(bytes as *const [u8] as *const [ValueType]) })
    }
}

/// Parse a section skeleton, which consists of parsing the section ID
/// and recording the boundaries of it.
impl<'a> Parseable<'a> for UnparsedSection<'a> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let section_id = cursor.next()?;
        let bytes = cursor.next()?;
        Ok(UnparsedSection {
            section_id,
            bytes,
        })
    }
}

/// Try to parse the input as a Wasm module in binary format. This function
/// ensures
///
/// - the magic hash at the beginning is correct
/// - version is correct
/// - sections are in the correct order
/// - all input is consumed.
pub fn parse_skeleton<'a>(input: &'a [u8]) -> ParseResult<Skeleton<'a>> {
    let cursor = &mut Cursor::new(input);
    {
        // check magic hash and version
        let mut buf = [0u8; 4];
        cursor.read_exact(&mut buf)?;
        // ensure magic hash
        ensure!(buf == MAGIC_HASH, "Unknown magic hash");
        cursor.read_exact(&mut buf)?;
        // ensure module version.
        ensure!(buf == VERSION, "Unsupported version.");
    }
    let mut last_section = SectionId::Custom;

    let mut ty = None;
    let mut import = None;
    let mut func = None;
    let mut table = None;
    let mut memory = None;
    let mut global = None;
    let mut export = None;
    let mut start = None;
    let mut element = None;
    let mut code = None;
    let mut data = None;
    let mut custom = Vec::new();

    // since read_section advances the cursor by at least one byte this loop will
    // terminate
    while cursor.position() < input.len() as u64 {
        let section = UnparsedSection::parse(cursor)?;
        ensure!(
            section.section_id == SectionId::Custom || section.section_id > last_section,
            "Section out of place."
        );
        if section.section_id != SectionId::Custom {
            last_section = section.section_id
        }
        match section.section_id {
            SectionId::Custom => custom.push(section),
            SectionId::Type => ty = Some(section),
            SectionId::Import => import = Some(section),
            SectionId::Function => func = Some(section),
            SectionId::Table => table = Some(section),
            SectionId::Memory => memory = Some(section),
            SectionId::Global => global = Some(section),
            SectionId::Export => export = Some(section),
            SectionId::Start => start = Some(section),
            SectionId::Element => element = Some(section),
            SectionId::Code => code = Some(section),
            SectionId::Data => data = Some(section),
        }
    }
    // make sure we've read all the input
    ensure!(cursor.position() as usize == input.len(), "Leftover bytes.");
    Ok(Skeleton {
        ty,
        import,
        func,
        table,
        memory,
        global,
        export,
        start,
        element,
        code,
        data,
        custom,
    })
}

/// Parse a name as specified by the Wasm specification, with our own
/// restrictions. The restriction we impose is that the name consists solely of
/// ASCII characters.
impl<'a> Parseable<'a> for Name {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let name_bytes = cursor.next()?;
        let name = std::str::from_utf8(name_bytes)?.to_string();
        ensure!(name.is_ascii(), "Only ASCII names are allowed.");
        Ok(Name {
            name,
        })
    }
}

/// Parse a custom section.
pub fn parse_custom<'a>(sec: &UnparsedSection<'a>) -> ParseResult<CustomSection<'a>> {
    let mut cursor = Cursor::new(sec.bytes);
    let name = cursor.next()?;
    let contents = &sec.bytes[cursor.position() as usize..];
    Ok(CustomSection {
        name,
        contents,
    })
}

/// Parse a single byte.
impl<'a> Parseable<'a> for Byte {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

/// Parse a value type. The Wasm version we support does not have floating point
/// types, so we disallow them already at the parsing stage.
impl<'a> Parseable<'a> for ValueType {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        ValueType::try_from(Byte::parse(cursor)?)
    }
}

/// Parse a limit, and additionally ensure that, if given, the upper bound is
/// no less than lower bound.
impl<'a> Parseable<'a> for Limits {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(cursor)? {
            0x00 => {
                let min = cursor.next()?;
                Ok(Limits {
                    min,
                    max: None,
                })
            }
            0x01 => {
                let min = cursor.next()?;
                let mmax = cursor.next()?;
                ensure!(min <= mmax, "Lower limit must be no greater than the upper limit.");
                Ok(Limits {
                    min,
                    max: Some(mmax),
                })
            }
            tag => bail!("Incorrect limits tag {:#04x}.", tag),
        }
    }
}

/// Read a single byte and compare it to the given one, failing if they do not
/// match.
fn expect_byte<'a>(cursor: &mut Cursor<&'a [u8]>, byte: Byte) -> ParseResult<()> {
    let b = Byte::parse(cursor)?;
    ensure!(b == byte, "Unexpected byte {:#04x}. Expected {:#04x}", b, byte);
    Ok(())
}

/// Parse a function type. Since we do not support multiple return values we
/// ensure at parse time that there are no more than one return values.
impl<'a> Parseable<'a> for FunctionType {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        expect_byte(cursor, 0x60)?;
        let parameters = cursor.next()?;
        let result_vec = Vec::<ValueType>::parse(cursor)?;
        ensure!(result_vec.len() <= 1, "Only single return value is supported.");
        let result = result_vec.first().copied();
        Ok(FunctionType {
            parameters,
            result,
        })
    }
}

/// Parse a table type. In the version we support there is a single table type,
/// the funcref, so this only records the resulting table limits.
/// This instance additionally ensures that the limits are valid, i.e., in range
/// 2^32. Since the bounds are 32-bit integers, this is true by default.
impl<'a> Parseable<'a> for TableType {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        expect_byte(cursor, 0x70)?;
        let limits = Limits::parse(cursor)?;
        ensure!(limits.min <= MAX_INIT_TABLE_SIZE, "Initial table size exceeds allowed limits.");
        Ok(TableType {
            limits,
        })
    }
}

/// Memory types are just limits on the size of the memory.
/// This also ensures that limits are within range 2^16.
impl<'a> Parseable<'a> for MemoryType {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let limits = Limits::parse(cursor)?;
        match limits.max {
            Some(x) => ensure!(x <= 1 << 16, "Memory limits must be in range 2^16."),
            None => ensure!(limits.min <= 1 << 16, "Memory limits must be in range 2^16."),
        }
        Ok(MemoryType {
            limits,
        })
    }
}

impl<'a, X: Parseable<'a>> Parseable<'a> for Rc<X> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> { Ok(Rc::new(X::parse(cursor)?)) }
}

impl<'a> Parseable<'a> for TypeSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let types = cursor.next()?;
        Ok(TypeSection {
            types,
        })
    }
}

impl<'a> Parseable<'a> for ImportDescription {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(cursor)? {
            0x00 => {
                let type_idx = cursor.next()?;
                Ok(ImportDescription::Func {
                    type_idx,
                })
            }
            tag => bail!("Unsupported import type {:#04x}. Only functions can be imported.", tag),
        }
    }
}

impl<'a> Parseable<'a> for Import {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let mod_name = cursor.next()?;
        let item_name = cursor.next()?;
        let description = cursor.next()?;
        Ok(Import {
            mod_name,
            item_name,
            description,
        })
    }
}

impl<'a> Parseable<'a> for ImportSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let imports = cursor.next()?;
        Ok(ImportSection {
            imports,
        })
    }
}

impl<'a> Parseable<'a> for FunctionSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let types = cursor.next()?;
        Ok(FunctionSection {
            types,
        })
    }
}

/// Attempt to read a constant expression of given type.
/// Since we do not allow imported globals, the only constant expressions are
/// single constant instruction.
fn read_constant_expr<'a>(cursor: &mut Cursor<&'a [u8]>, ty: ValueType) -> ParseResult<GlobalInit> {
    let res = match ty {
        ValueType::I32 => match decode_opcode(cursor)? {
            OpCode::I32Const(n) => GlobalInit::I32(n),
            _ => bail!("Unexpected instruction. Expected `I32Const`"),
        },
        ValueType::I64 => match decode_opcode(cursor)? {
            OpCode::I64Const(n) => GlobalInit::I64(n),
            _ => bail!("Unexpected instruction. Expected `I64Const`"),
        },
    };
    // end parsing the expression
    expect_byte(cursor, END)?;
    Ok(res)
}

impl<'a> Parseable<'a> for TableSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let table_type_vec: Vec<TableType> = cursor.next()?;
        ensure!(table_type_vec.len() <= 1, "Only table with index 0 is supported.");
        Ok(TableSection {
            table_type: table_type_vec.first().copied(),
        })
    }
}

impl<'a> Parseable<'a> for MemorySection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let memory_types_vec: Vec<MemoryType> = cursor.next()?;
        ensure!(memory_types_vec.len() <= 1, "Only memory with index 1 is supported.");
        Ok(MemorySection {
            memory_type: memory_types_vec.first().copied(),
        })
    }
}

impl<'a> Parseable<'a> for ExportDescription {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(cursor)? {
            0x00 => {
                let index = FuncIndex::parse(cursor)?;
                Ok(ExportDescription::Func {
                    index,
                })
            }
            0x01 => {
                let index = TableIndex::parse(cursor)?;
                ensure!(index == 0, "Only table with index 0 is supported.");
                Ok(ExportDescription::Table)
            }
            0x02 => {
                let index = MemIndex::parse(cursor)?;
                ensure!(index == 0, "Only memory with index 0 is supported.");
                Ok(ExportDescription::Memory)
            }
            0x03 => {
                let index = GlobalIndex::parse(cursor)?;
                Ok(ExportDescription::Global {
                    index,
                })
            }
            byte => bail!("Unsupported export tag {:#04x}.", byte),
        }
    }
}

impl<'a> Parseable<'a> for Export {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let name = cursor.next()?;
        let description = cursor.next()?;
        Ok(Export {
            name,
            description,
        })
    }
}

impl<'a> Parseable<'a> for ExportSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let exports = cursor.next()?;
        Ok(ExportSection {
            exports,
        })
    }
}

impl<'a> Parseable<'a> for StartSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let idxs: Vec<FuncIndex> = cursor.next()?;
        ensure!(idxs.is_empty(), "Start functions are not supported.");
        Ok(StartSection {})
    }
}

impl<'a> Parseable<'a> for Element {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let table_index = TableIndex::parse(cursor)?;
        ensure!(table_index == 0, "Only table index 0 is supported.");
        let offset = read_constant_expr(cursor, ValueType::I32)?;
        let inits = cursor.next()?;
        if let GlobalInit::I32(offset) = offset {
            Ok(Element {
                offset,
                inits,
            })
        } else {
            bail!("Internal error, parsed a constant of type I32 that is not an I32.");
        }
    }
}

impl<'a> Parseable<'a> for ElementSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let elements = cursor.next()?;
        Ok(ElementSection {
            elements,
        })
    }
}

impl<'a> Parseable<'a> for Global {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let ty = cursor.next()?;
        let mutable = match Byte::parse(cursor)? {
            0x00 => false,
            0x01 => true,
            flag => bail!("Unsupported mutability flag {:#04x}", flag),
        };
        let init = read_constant_expr(cursor, ty)?;
        Ok(Global {
            init,
            mutable,
        })
    }
}

impl<'a> Parseable<'a> for GlobalSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let globals = cursor.next()?;
        Ok(GlobalSection {
            globals,
        })
    }
}

/// The byte used to signal the end of an instruction sequence.
const END: Byte = 0x0B;

/// The version of Wasm we support only has the empty block type, the I32, and
/// I64 types. Type indices are not supported.
impl<'a> Parseable<'a> for BlockType {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(cursor)? {
            0x40 => Ok(BlockType::EmptyType),
            0x7F => Ok(BlockType::ValueType(ValueType::I32)),
            0x7E => Ok(BlockType::ValueType(ValueType::I64)),
            x => bail!("Unsupported block type {}", x),
        }
    }
}

impl<'a> Parseable<'a> for MemArg {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let align = cursor.next()?;
        let offset = cursor.next()?;
        Ok(MemArg {
            offset,
            align,
        })
    }
}

impl<'a> Parseable<'a> for Local {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let multiplicity = cursor.next()?;
        let ty = cursor.next()?;
        Ok(Local {
            multiplicity,
            ty,
        })
    }
}

impl<'a> Parseable<'a> for Data {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let index = u32::parse(cursor)?;
        ensure!(index == 0, "Only memory index 0 is supported.");
        let offset = read_constant_expr(cursor, ValueType::I32)?;
        let init = cursor.next()?;
        if let GlobalInit::I32(offset) = offset {
            Ok(Data {
                offset,
                init,
            })
        } else {
            bail!("Internal error, a constant expression of type I32 is not an I32");
        }
    }
}

impl<'a> Parseable<'a> for DataSection {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let sections = cursor.next()?;
        Ok(DataSection {
            sections,
        })
    }
}

pub fn parse_sec_with_default<'a, A: Parseable<'a> + Default>(
    sec: &Option<UnparsedSection<'a>>,
) -> ParseResult<A> {
    match sec.as_ref() {
        None => Ok(Default::default()),
        Some(sec) => sec.bytes.next(),
    }
}

// /// Try to parse all the non-custom sections of a Skeleton into a Module.
// pub fn parse_module<'a>(skeleton: &Skeleton<'a>) -> ParseResult<Module> {
//     let ty = parse_sec_with_default(&skeleton.ty)?;
//     let import = parse_sec_with_default(&skeleton.import)?;
//     let func = parse_sec_with_default(&skeleton.func)?;
//     let table = parse_sec_with_default(&skeleton.table)?;
//     let memory = parse_sec_with_default(&skeleton.memory)?;
//     let global = parse_sec_with_default(&skeleton.global)?;
//     let export = parse_sec_with_default(&skeleton.export)?;
//     let start = parse_sec_with_default(&skeleton.start)?;
//     let element = parse_sec_with_default(&skeleton.element)?;
//     let code = parse_sec_with_default(&skeleton.code)?;
//     let data = parse_sec_with_default(&skeleton.data)?;
//     Ok(Module {
//         ty,
//         import,
//         func,
//         table,
//         memory,
//         global,
//         export,
//         start,
//         element,
//         code,
//         data,
//     })
// }

/// Decode the next opcode directly from the cursor.
pub fn decode_opcode<'a>(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<OpCode> {
    match Byte::parse(cursor)? {
        END => Ok(OpCode::End),
        0x00 => Ok(OpCode::Unreachable),
        0x01 => Ok(OpCode::Nop),
        0x02 => {
            let bt = cursor.next()?;
            Ok(OpCode::Block(bt))
        }
        0x03 => {
            let bt = cursor.next()?;
            Ok(OpCode::Loop(bt))
        }
        0x04 => {
            let ty = cursor.next()?;
            Ok(OpCode::If {
                ty,
            })
        }
        0x05 => Ok(OpCode::Else),
        0x0C => {
            let l = cursor.next()?;
            Ok(OpCode::Br(l))
        }
        0x0D => {
            let l = cursor.next()?;
            Ok(OpCode::BrIf(l))
        }
        0x0E => {
            let labels = cursor.next()?;
            let default = cursor.next()?;
            Ok(OpCode::BrTable {
                labels,
                default,
            })
        }
        0x0F => Ok(OpCode::Return),
        0x10 => {
            let idx = cursor.next()?;
            Ok(OpCode::Call(idx))
        }
        0x11 => {
            let ty = cursor.next()?;
            expect_byte(cursor, 0x00)?;
            Ok(OpCode::CallIndirect(ty))
        }
        // parametric instructions
        0x1A => Ok(OpCode::Drop),
        0x1B => Ok(OpCode::Select),
        // variable instructions
        0x20 => {
            let idx = cursor.next()?;
            Ok(OpCode::LocalGet(idx))
        }
        0x21 => {
            let idx = cursor.next()?;
            Ok(OpCode::LocalSet(idx))
        }
        0x22 => {
            let idx = cursor.next()?;
            Ok(OpCode::LocalTee(idx))
        }
        0x23 => {
            let idx = cursor.next()?;
            Ok(OpCode::GlobalGet(idx))
        }
        0x24 => {
            let idx = cursor.next()?;
            Ok(OpCode::GlobalSet(idx))
        }
        // memory instructions
        0x28 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Load(memarg))
        }
        0x29 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Load(memarg))
        }
        0x2C => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Load8S(memarg))
        }
        0x2D => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Load8U(memarg))
        }
        0x2E => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Load16S(memarg))
        }
        0x2F => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Load16U(memarg))
        }
        0x30 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Load8S(memarg))
        }
        0x31 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Load8U(memarg))
        }
        0x32 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Load16S(memarg))
        }
        0x33 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Load16U(memarg))
        }
        0x34 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Load32S(memarg))
        }
        0x35 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Load32U(memarg))
        }
        0x36 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Store(memarg))
        }
        0x37 => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Store(memarg))
        }
        0x3A => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Store8(memarg))
        }
        0x3B => {
            let memarg = cursor.next()?;
            Ok(OpCode::I32Store16(memarg))
        }
        0x3C => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Store8(memarg))
        }
        0x3D => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Store16(memarg))
        }
        0x3E => {
            let memarg = cursor.next()?;
            Ok(OpCode::I64Store32(memarg))
        }
        0x3F => {
            expect_byte(cursor, 0x00)?;
            Ok(OpCode::MemorySize)
        }
        0x40 => {
            expect_byte(cursor, 0x00)?;
            Ok(OpCode::MemoryGrow)
        }
        // constants
        0x41 => {
            let n = cursor.next()?;
            Ok(OpCode::I32Const(n))
        }
        0x42 => {
            let n = cursor.next()?;
            Ok(OpCode::I64Const(n))
        }
        // numeric instructions
        0x45 => Ok(OpCode::I32Eqz),
        0x46 => Ok(OpCode::I32Eq),
        0x47 => Ok(OpCode::I32Ne),
        0x48 => Ok(OpCode::I32LtS),
        0x49 => Ok(OpCode::I32LtU),
        0x4A => Ok(OpCode::I32GtS),
        0x4B => Ok(OpCode::I32GtU),
        0x4C => Ok(OpCode::I32LeS),
        0x4D => Ok(OpCode::I32LeU),
        0x4E => Ok(OpCode::I32GeS),
        0x4F => Ok(OpCode::I32GeU),

        0x50 => Ok(OpCode::I64Eqz),
        0x51 => Ok(OpCode::I64Eq),
        0x52 => Ok(OpCode::I64Ne),
        0x53 => Ok(OpCode::I64LtS),
        0x54 => Ok(OpCode::I64LtU),
        0x55 => Ok(OpCode::I64GtS),
        0x56 => Ok(OpCode::I64GtU),
        0x57 => Ok(OpCode::I64LeS),
        0x58 => Ok(OpCode::I64LeU),
        0x59 => Ok(OpCode::I64GeS),
        0x5A => Ok(OpCode::I64GeU),

        0x67 => Ok(OpCode::I32Clz),
        0x68 => Ok(OpCode::I32Ctz),
        0x69 => Ok(OpCode::I32Popcnt),
        0x6A => Ok(OpCode::I32Add),
        0x6B => Ok(OpCode::I32Sub),
        0x6C => Ok(OpCode::I32Mul),
        0x6D => Ok(OpCode::I32DivS),
        0x6E => Ok(OpCode::I32DivU),
        0x6F => Ok(OpCode::I32RemS),
        0x70 => Ok(OpCode::I32RemU),
        0x71 => Ok(OpCode::I32And),
        0x72 => Ok(OpCode::I32Or),
        0x73 => Ok(OpCode::I32Xor),
        0x74 => Ok(OpCode::I32Shl),
        0x75 => Ok(OpCode::I32ShrS),
        0x76 => Ok(OpCode::I32ShrU),
        0x77 => Ok(OpCode::I32Rotl),
        0x78 => Ok(OpCode::I32Rotr),

        0x79 => Ok(OpCode::I64Clz),
        0x7A => Ok(OpCode::I64Ctz),
        0x7B => Ok(OpCode::I64Popcnt),
        0x7C => Ok(OpCode::I64Add),
        0x7D => Ok(OpCode::I64Sub),
        0x7E => Ok(OpCode::I64Mul),
        0x7F => Ok(OpCode::I64DivS),
        0x80 => Ok(OpCode::I64DivU),
        0x81 => Ok(OpCode::I64RemS),
        0x82 => Ok(OpCode::I64RemU),
        0x83 => Ok(OpCode::I64And),
        0x84 => Ok(OpCode::I64Or),
        0x85 => Ok(OpCode::I64Xor),
        0x86 => Ok(OpCode::I64Shl),
        0x87 => Ok(OpCode::I64ShrS),
        0x88 => Ok(OpCode::I64ShrU),
        0x89 => Ok(OpCode::I64Rotl),
        0x8A => Ok(OpCode::I64Rotr),

        0xA7 => Ok(OpCode::I32WrapI64),

        0xAC => Ok(OpCode::I64ExtendI32S),
        0xAD => Ok(OpCode::I64ExtendI32U),
        byte => bail!("Unsupported instruction {:#04x}", byte),
    }
}

pub struct OpCodeIterator<'a> {
    state: Cursor<&'a [u8]>,
}

impl<'a> OpCodeIterator<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            state: Cursor::new(bytes),
        }
    }
}

impl<'a> Iterator for OpCodeIterator<'a> {
    type Item = ParseResult<OpCode>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.position() == self.state.get_ref().len() as u64 {
            None
        } else {
            Some(decode_opcode(&mut self.state))
        }
    }
}

#[derive(Debug)]
/// The body of a function.
pub struct CodeSkeleton<'a> {
    /// Declaration of the locals.
    pub locals: Vec<Local>,
    /// And uninterpreter instructions.
    pub expr_bytes: &'a [u8],
}

#[derive(Debug, Default)]
/// The Default instance of this type returns an empty code section.
pub struct CodeSkeletonSection<'a> {
    pub impls: Vec<CodeSkeleton<'a>>,
}

impl<'a> Parseable<'a> for CodeSkeleton<'a> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let size: u32 = cursor.next()?;
        let cur_pos = cursor.position();
        let locals = cursor.next()?;
        let end_pos = cursor.position();
        ensure!(
            u64::from(size) >= end_pos - cur_pos,
            "We've already read too many bytes, module is malformed."
        );
        let remaining = u64::from(size) - (end_pos - cur_pos);
        ensure!(
            ((end_pos + remaining) as usize) <= cursor.get_ref().len(),
            "We would need to read beyond the end of the input."
        );
        let expr_bytes = &cursor.get_ref()[end_pos as usize..(end_pos + remaining) as usize];
        cursor.set_position(end_pos + remaining);
        Ok(CodeSkeleton {
            locals,
            expr_bytes,
        })
    }
}

impl<'a> Parseable<'a> for CodeSkeletonSection<'a> {
    fn parse(cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let impls = cursor.next()?;
        Ok(CodeSkeletonSection {
            impls,
        })
    }
}
