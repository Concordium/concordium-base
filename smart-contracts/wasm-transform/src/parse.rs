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
    pub ty:      Option<UnparsedSection<'a>>,
    /// Import section.
    pub import:  Option<UnparsedSection<'a>>,
    /// Function section.
    pub func:    Option<UnparsedSection<'a>>,
    /// Table section.
    pub table:   Option<UnparsedSection<'a>>,
    /// Memory section.
    pub memory:  Option<UnparsedSection<'a>>,
    /// Global section.
    pub global:  Option<UnparsedSection<'a>>,
    /// Export section.
    pub export:  Option<UnparsedSection<'a>>,
    /// Start section.
    pub start:   Option<UnparsedSection<'a>>,
    /// Element section.
    pub element: Option<UnparsedSection<'a>>,
    /// Code section.
    pub code:    Option<UnparsedSection<'a>>,
    /// Data section.
    pub data:    Option<UnparsedSection<'a>>,
    /// A list of custom sections in the order they appeared in the input.
    pub custom:  Vec<UnparsedSection<'a>>,
}

/// Auxiliary type alias used by all the parsing functions.
pub type ParseResult<A> = anyhow::Result<A>;

/// A trait for parsing data. The lifetime is useful when we want to parse
/// data without copying, which is useful to avoid copying all the unparsed
/// sections.
pub trait Parseable<'a, Ctx>: Sized {
    /// Read a value from the cursor, or signal error.
    /// This function is responsible for advancing the cursor in-line with the
    /// data it has read.
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self>;
}

/// An empty context used when we can parse data without an additional context.
pub(crate) const EMPTY_CTX: () = ();

/// A helper trait for more convenient use. The difference from the above is
/// that typically the result type is determined by the context, which we take
/// advantage of to reduce the need for typing annotations which would be needed
/// by the Parseable trait.
///
/// The reason for that is that this trait defines a new method on the type,
/// giving us access to all of the convenience features of Rust that come with
/// it.
pub trait GetParseable<A, Ctx> {
    /// Parse an item. Analogous to 'parse', but with the reversed roles for
    /// types of input and output. In the 'Parseable' trait the trait is defined
    /// for the type that is to be parsed and the source is fixed, whereas here
    /// the trait is parameterized by the type to be parsed, and the trait is
    /// implemented for the source type.
    fn next(self, ctx: Ctx) -> ParseResult<A>;
}

/// A generic implementation for a cursor.
impl<'a, 'b, Ctx, A: Parseable<'a, Ctx>> GetParseable<A, Ctx> for &'b mut Cursor<&'a [u8]> {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn next(self, ctx: Ctx) -> ParseResult<A> { A::parse(ctx, self) }
}

/// Another generic implementation, but this time the input is not directly a
/// readable type. Instead this instance additionally ensures that all of the
/// input data is used by the parser.
impl<'a, Ctx, A: Parseable<'a, Ctx>> GetParseable<A, Ctx> for &'a [u8] {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn next(self, ctx: Ctx) -> ParseResult<A> {
        let mut cursor = Cursor::new(self);
        let res = A::parse(ctx, &mut cursor)?;
        ensure!(cursor.position() == self.len() as u64, "Not all of the contents was consumed.");
        Ok(res)
    }
}

/// Implementation for u16 according to the Wasm specification.
impl<'a, Ctx> Parseable<'a, Ctx> for u16 {
    fn parse(_ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // 3 is ceil(16 / 7)
        let res = leb128::read::unsigned(&mut cursor.take(3))?;
        Ok(u16::try_from(res)?)
    }
}

/// Implementation for u32 according to the Wasm specification.
impl<'a, Ctx> Parseable<'a, Ctx> for u32 {
    fn parse(_ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // 5 is ceil(32 / 7)
        let res = leb128::read::unsigned(&mut cursor.take(5))?;
        Ok(u32::try_from(res)?)
    }
}

/// Implementation for u64 according to the Wasm specification.
impl<'a, Ctx> Parseable<'a, Ctx> for u64 {
    fn parse(_ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // 10 is ceil(64 / 7)
        let res = leb128::read::unsigned(&mut cursor.take(10))?;
        Ok(res)
    }
}

/// Implementation for i32 according to the Wasm specification.
impl<'a, Ctx> Parseable<'a, Ctx> for i32 {
    fn parse(_ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // 5 is ceil(32 / 7)
        let res = leb128::read::signed(&mut cursor.take(5))?;
        Ok(i32::try_from(res)?)
    }
}

/// Implementation for i64 according to the Wasm specification.
impl<'a, Ctx> Parseable<'a, Ctx> for i64 {
    fn parse(_ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let res = leb128::read::signed(&mut cursor.take(10))?;
        Ok(res)
    }
}

/// Parsing of the section ID according to the linked Wasm specification.
impl<'a, Ctx> Parseable<'a, Ctx> for SectionId {
    fn parse(_ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
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
impl<'a, Ctx: Copy, A: Parseable<'a, Ctx>> Parseable<'a, Ctx> for Vec<A> {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(ctx, cursor)?;
        let max_initial_capacity =
            MAX_PREALLOCATED_BYTES / std::cmp::max(1, std::mem::size_of::<A>());
        let mut out = Vec::with_capacity(std::cmp::min(len as usize, max_initial_capacity));
        for _ in 0..len {
            out.push(cursor.next(ctx)?)
        }
        Ok(out)
    }
}

/// Same as the instance for Vec<u8>, with the difference that no data is copied
/// and the result is a reference to the initial byte array.
impl<'a, Ctx> Parseable<'a, Ctx> for &'a [u8] {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(ctx, cursor)?;
        let pos = cursor.position() as usize;
        let end = pos + len as usize;
        ensure!(end <= cursor.get_ref().len(), "Malformed byte array");
        cursor.seek(SeekFrom::Current(i64::from(len)))?;
        Ok(&cursor.get_ref()[pos..end])
    }
}

/// Special case of a vector where we only expect 0 or 1 elements.
impl<'a, Ctx: Copy, A: Parseable<'a, Ctx>> Parseable<'a, Ctx> for Option<A> {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(ctx, cursor)? {
            0u8 => Ok(None),
            1u8 => Ok(Some(cursor.next(ctx)?)),
            tag => bail!("Unsupported option tag: {:#04x}", tag),
        }
    }
}

/// Same as the instance for Vec<u8>, with the difference that no data is copied
/// and the result is a reference to the initial byte array.
impl<'a, Ctx> Parseable<'a, Ctx> for &'a [ValueType] {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let len = u32::parse(ctx, cursor)?;
        let pos = cursor.position() as usize;
        let end = pos + len as usize;
        ensure!(end <= cursor.get_ref().len(), "Malformed byte array");
        cursor.seek(SeekFrom::Current(i64::from(len)))?;
        let bytes = &cursor.get_ref()[pos..end];
        for &byte in bytes {
            if ValueType::try_from(byte).is_err() {
                bail!(ParseError::UnsupportedValueType {
                    byte
                })
            }
        }
        Ok(unsafe { &*(bytes as *const [u8] as *const [ValueType]) })
    }
}

/// Parse a section skeleton, which consists of parsing the section ID
/// and recording the boundaries of it.
impl<'a, Ctx: Copy> Parseable<'a, Ctx> for UnparsedSection<'a> {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let section_id = cursor.next(ctx)?;
        let bytes = cursor.next(ctx)?;
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
pub fn parse_skeleton(input: &[u8]) -> ParseResult<Skeleton<'_>> {
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
        let section = UnparsedSection::parse(EMPTY_CTX, cursor)?;
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
impl<'a, Ctx> Parseable<'a, Ctx> for Name {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let name_bytes: &[u8] = cursor.next(ctx)?;
        ensure!(name_bytes.len() <= MAX_NAME_SIZE, ParseError::NameTooLong);
        let name = std::str::from_utf8(name_bytes)?.to_string();
        ensure!(name.is_ascii(), ParseError::OnlyASCIINames);
        Ok(Name {
            name,
        })
    }
}

/// Parse a custom section.
pub fn parse_custom<'a>(sec: &UnparsedSection<'a>) -> ParseResult<CustomSection<'a>> {
    let mut cursor = Cursor::new(sec.bytes);
    let name = cursor.next(EMPTY_CTX)?;
    let contents = &sec.bytes[cursor.position() as usize..];
    Ok(CustomSection {
        name,
        contents,
    })
}

/// Parse a single byte.
impl<'a, Ctx> Parseable<'a, Ctx> for Byte {
    fn parse(_ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

/// Parse a value type. The Wasm version we support does not have floating point
/// types, so we disallow them already at the parsing stage.
impl<'a, Ctx> Parseable<'a, Ctx> for ValueType {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let byte = Byte::parse(ctx, cursor)?;
        if let Ok(x) = ValueType::try_from(byte) {
            Ok(x)
        } else {
            bail!(ParseError::UnsupportedValueType {
                byte
            })
        }
    }
}

/// Parse a limit, and additionally ensure that, if given, the upper bound is
/// no less than lower bound.
impl<'a, Ctx: Copy> Parseable<'a, Ctx> for Limits {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(ctx, cursor)? {
            0x00 => {
                let min = cursor.next(ctx)?;
                Ok(Limits {
                    min,
                    max: None,
                })
            }
            0x01 => {
                let min = cursor.next(ctx)?;
                let mmax = cursor.next(ctx)?;
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
fn expect_byte(cursor: &mut Cursor<&[u8]>, byte: Byte) -> ParseResult<()> {
    let b = Byte::parse(EMPTY_CTX, cursor)?;
    ensure!(b == byte, "Unexpected byte {:#04x}. Expected {:#04x}", b, byte);
    Ok(())
}

/// Parse a function type. Since we do not support multiple return values we
/// ensure at parse time that there are no more than one return values.
impl<'a, Ctx: Copy> Parseable<'a, Ctx> for FunctionType {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        expect_byte(cursor, 0x60)?;
        let parameters = cursor.next(ctx)?;
        let result_vec = Vec::<ValueType>::parse(ctx, cursor)?;
        ensure!(result_vec.len() <= 1, ParseError::OnlySingleReturn);
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
impl<'a, Ctx: Copy> Parseable<'a, Ctx> for TableType {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        expect_byte(cursor, 0x70)?;
        let limits = Limits::parse(ctx, cursor)?;
        ensure!(limits.min <= MAX_INIT_TABLE_SIZE, "Initial table size exceeds allowed limits.");
        Ok(TableType {
            limits,
        })
    }
}

/// Memory types are just limits on the size of the memory.
/// This also ensures that limits are within range 2^16.
impl<'a, Ctx: Copy> Parseable<'a, Ctx> for MemoryType {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let limits = Limits::parse(ctx, cursor)?;
        ensure!(
            limits.min <= MAX_INIT_MEMORY_SIZE,
            "Initial memory allocation of {} pages exceeds maximum of {}.",
            limits.min,
            MAX_INIT_MEMORY_SIZE
        );
        match limits.max {
            Some(x) => ensure!(x <= 1 << 16, "Memory limits must be in range 2^16."),
            None => ensure!(limits.min <= 1 << 16, "Memory limits must be in range 2^16."),
        }
        Ok(MemoryType {
            limits,
        })
    }
}

impl<'a, Ctx, X: Parseable<'a, Ctx>> Parseable<'a, Ctx> for Rc<X> {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        Ok(Rc::new(X::parse(ctx, cursor)?))
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for TypeSection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let types = cursor.next(ctx)?;
        Ok(TypeSection {
            types,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ImportDescription {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(ctx, cursor)? {
            0x00 => {
                let type_idx = cursor.next(ctx)?;
                Ok(ImportDescription::Func {
                    type_idx,
                })
            }
            tag => bail!(ParseError::UnsupportedImportType {
                tag
            }),
        }
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for Import {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let mod_name = cursor.next(ctx)?;
        let item_name = cursor.next(ctx)?;
        let description = cursor.next(ctx)?;
        Ok(Import {
            mod_name,
            item_name,
            description,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ImportSection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let imports = cursor.next(ctx)?;
        Ok(ImportSection {
            imports,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for FunctionSection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let types = cursor.next(ctx)?;
        Ok(FunctionSection {
            types,
        })
    }
}

/// Attempt to read a constant expression of given type (see section 3.3.7.2).
/// The `ty` argument specifies the expected type of the expression.
/// For the version of the standard we use this is always a single value type,
/// and thus any constant expression will be a single instruction.
///
/// Constant expressions appear in three places in the wasm specification we
/// support.
///
/// - As initializers for globals. In that case the format of constant
/// expressions is more restricted. They are not allowed to refer to globals
/// defined in the current modules. This prevents circularity, although a more
/// relaxed condition could be used. The function supports this mode of constant
/// expressions by using `None` as the last argument.
/// - As offset expressions in element and data segments. In these contexts the
///   constant expressions are allowed to refer to `GlobalGet` instructions for
///   `const` globals of the right type.
fn read_constant_expr<'a>(
    cursor: &mut Cursor<&'a [u8]>,
    ty: ValueType,
    globals_allowed: Option<&GlobalSection>,
) -> ParseResult<GlobalInit> {
    let instr = decode_opcode(cursor)?;
    let res = match instr {
        OpCode::I32Const(n) => {
            ensure!(ty == ValueType::I32, "Constant instruction of type I64, but I32 expected.");
            GlobalInit::I32(n)
        }
        OpCode::I64Const(n) => {
            ensure!(ty == ValueType::I64, "Constant instruction of type I32, but I64 expected.");
            GlobalInit::I64(n)
        }
        OpCode::GlobalGet(idx) => match globals_allowed {
            None => bail!("GlobalGet not allowed in this constant expression."),
            Some(globals) => {
                let global = globals.get(idx).ok_or_else(|| {
                    anyhow::anyhow!("Reference to non-existent global in constant expression.")
                })?;
                ensure!(
                    global.init.ty() == ty,
                    "Global in constant expression of incorrect type: {:?} != {:?}",
                    global.init.ty(),
                    ty
                );
                ensure!(
                    !global.mutable,
                    "Only references to constant globals can appear in constant expressions."
                );
                global.init
            }
        },
        _ => bail!("Not a constant instruction {:?}.", instr),
    };
    // end parsing the expression
    expect_byte(cursor, END)?;
    Ok(res)
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for TableSection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let table_type_vec: Vec<TableType> = cursor.next(ctx)?;
        ensure!(table_type_vec.len() <= 1, "Only table with index 0 is supported.");
        Ok(TableSection {
            table_type: table_type_vec.first().copied(),
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for MemorySection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let memory_types_vec: Vec<MemoryType> = cursor.next(ctx)?;
        ensure!(memory_types_vec.len() <= 1, "Only memory with index 1 is supported.");
        Ok(MemorySection {
            memory_type: memory_types_vec.first().copied(),
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ExportDescription {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(ctx, cursor)? {
            0x00 => {
                let index = FuncIndex::parse(ctx, cursor)?;
                Ok(ExportDescription::Func {
                    index,
                })
            }
            0x01 => {
                let index = TableIndex::parse(ctx, cursor)?;
                ensure!(index == 0, "Only table with index 0 is supported.");
                Ok(ExportDescription::Table)
            }
            0x02 => {
                let index = MemIndex::parse(ctx, cursor)?;
                ensure!(index == 0, "Only memory with index 0 is supported.");
                Ok(ExportDescription::Memory)
            }
            0x03 => {
                let index = GlobalIndex::parse(ctx, cursor)?;
                Ok(ExportDescription::Global {
                    index,
                })
            }
            byte => bail!("Unsupported export tag {:#04x}.", byte),
        }
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for Export {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let name: Name = cursor.next(ctx)?;
        let description = cursor.next(ctx)?;

        if let ExportDescription::Func {
            ..
        } = description
        {
            ensure!(
                name.name.len() <= concordium_contracts_common::constants::MAX_FUNC_NAME_SIZE,
                ParseError::FuncNameTooLong
            );
        }

        Ok(Export {
            name,
            description,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for ExportSection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let exports = cursor.next(ctx)?;
        Ok(ExportSection {
            exports,
        })
    }
}

impl<'a, Ctx> Parseable<'a, Ctx> for StartSection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        // We deliberately try to parse the index before failing
        // in order that the error message is more precise.
        let _idxs: FuncIndex = cursor.next(ctx)?;
        bail!(ParseError::StartFunctionsNotSupported);
    }
}

impl<'a> Parseable<'a, &GlobalSection> for Element {
    fn parse(ctx: &GlobalSection, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let table_index = TableIndex::parse(ctx, cursor)?;
        ensure!(table_index == 0, "Only table index 0 is supported.");
        let offset = read_constant_expr(cursor, ValueType::I32, Some(ctx))?;
        let inits = cursor.next(ctx)?;
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

impl<'a> Parseable<'a, &GlobalSection> for ElementSection {
    fn parse(ctx: &GlobalSection, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let elements = cursor.next(ctx)?;
        Ok(ElementSection {
            elements,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for Global {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let ty = cursor.next(ctx)?;
        let mutable = match Byte::parse(ctx, cursor)? {
            0x00 => false,
            0x01 => true,
            flag => bail!("Unsupported mutability flag {:#04x}", flag),
        };
        // Globals initialization expressions cannot refer to other (in-module) globals.
        let init = read_constant_expr(cursor, ty, None)?;
        Ok(Global {
            init,
            mutable,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for GlobalSection {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let globals = cursor.next(ctx)?;
        Ok(GlobalSection {
            globals,
        })
    }
}

/// The byte used to signal the end of an instruction sequence.
const END: Byte = 0x0B;

/// The version of Wasm we support only has the empty block type, the I32, and
/// I64 types. Type indices are not supported.
impl<'a, Ctx> Parseable<'a, Ctx> for BlockType {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        match Byte::parse(ctx, cursor)? {
            0x40 => Ok(BlockType::EmptyType),
            0x7F => Ok(BlockType::ValueType(ValueType::I32)),
            0x7E => Ok(BlockType::ValueType(ValueType::I64)),
            x => bail!("Unsupported block type {}", x),
        }
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for MemArg {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let align = cursor.next(ctx)?;
        let offset = cursor.next(ctx)?;
        Ok(MemArg {
            offset,
            align,
        })
    }
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for Local {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let multiplicity = cursor.next(ctx)?;
        let ty = cursor.next(ctx)?;
        Ok(Local {
            multiplicity,
            ty,
        })
    }
}

impl<'a> Parseable<'a, &GlobalSection> for Data {
    fn parse(ctx: &GlobalSection, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let index = u32::parse(ctx, cursor)?;
        ensure!(index == 0, "Only memory index 0 is supported.");
        let offset = read_constant_expr(cursor, ValueType::I32, Some(ctx))?;
        let init = cursor.next(ctx)?;
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

impl<'a> Parseable<'a, &GlobalSection> for DataSection {
    fn parse(ctx: &GlobalSection, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let sections = cursor.next(ctx)?;
        Ok(DataSection {
            sections,
        })
    }
}

pub fn parse_sec_with_default<'a, Ctx, A: Parseable<'a, Ctx> + Default>(
    ctx: Ctx,
    sec: &Option<UnparsedSection<'a>>,
) -> ParseResult<A> {
    match sec.as_ref() {
        None => Ok(Default::default()),
        Some(sec) => sec.bytes.next(ctx),
    }
}

#[derive(Debug)]
pub enum ParseError {
    UnsupportedInstruction {
        opcode: Byte,
    },
    UnsupportedValueType {
        byte: Byte,
    },
    UnsupportedImportType {
        tag: Byte,
    },
    OnlySingleReturn,
    OnlyASCIINames,
    NameTooLong,
    FuncNameTooLong,
    StartFunctionsNotSupported,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnsupportedInstruction {
                opcode,
            } => write!(f, "Unsupported instruction {:#04x}", opcode),
            ParseError::UnsupportedValueType {
                byte,
            } => write!(f, "Unknown value type byte {:#04x}", byte),
            ParseError::UnsupportedImportType {
                tag,
            } => write!(f, "Unsupported import type {:#04x}. Only functions can be imported.", tag),
            ParseError::OnlySingleReturn => write!(f, "Only single return value is supported."),
            ParseError::OnlyASCIINames => write!(f, "Only ASCII names are allowed."),
            ParseError::NameTooLong => write!(f, "Names are limited to {} bytes.", MAX_NAME_SIZE),
            ParseError::FuncNameTooLong => write!(
                f,
                "Names of functions are limited to {} bytes.",
                concordium_contracts_common::constants::MAX_FUNC_NAME_SIZE
            ),
            ParseError::StartFunctionsNotSupported => {
                write!(f, "Start functions are not supported.")
            }
        }
    }
}

/// Decode the next opcode directly from the cursor.
pub fn decode_opcode(cursor: &mut Cursor<&[u8]>) -> ParseResult<OpCode> {
    match Byte::parse(EMPTY_CTX, cursor)? {
        END => Ok(OpCode::End),
        0x00 => Ok(OpCode::Unreachable),
        0x01 => Ok(OpCode::Nop),
        0x02 => {
            let bt = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::Block(bt))
        }
        0x03 => {
            let bt = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::Loop(bt))
        }
        0x04 => {
            let ty = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::If {
                ty,
            })
        }
        0x05 => Ok(OpCode::Else),
        0x0C => {
            let l = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::Br(l))
        }
        0x0D => {
            let l = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::BrIf(l))
        }
        0x0E => {
            let labels = cursor.next(EMPTY_CTX)?;
            let default = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::BrTable {
                labels,
                default,
            })
        }
        0x0F => Ok(OpCode::Return),
        0x10 => {
            let idx = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::Call(idx))
        }
        0x11 => {
            let ty = cursor.next(EMPTY_CTX)?;
            expect_byte(cursor, 0x00)?;
            Ok(OpCode::CallIndirect(ty))
        }
        // parametric instructions
        0x1A => Ok(OpCode::Drop),
        0x1B => Ok(OpCode::Select),
        // variable instructions
        0x20 => {
            let idx = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::LocalGet(idx))
        }
        0x21 => {
            let idx = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::LocalSet(idx))
        }
        0x22 => {
            let idx = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::LocalTee(idx))
        }
        0x23 => {
            let idx = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::GlobalGet(idx))
        }
        0x24 => {
            let idx = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::GlobalSet(idx))
        }
        // memory instructions
        0x28 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Load(memarg))
        }
        0x29 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Load(memarg))
        }
        0x2C => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Load8S(memarg))
        }
        0x2D => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Load8U(memarg))
        }
        0x2E => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Load16S(memarg))
        }
        0x2F => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Load16U(memarg))
        }
        0x30 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Load8S(memarg))
        }
        0x31 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Load8U(memarg))
        }
        0x32 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Load16S(memarg))
        }
        0x33 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Load16U(memarg))
        }
        0x34 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Load32S(memarg))
        }
        0x35 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Load32U(memarg))
        }
        0x36 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Store(memarg))
        }
        0x37 => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Store(memarg))
        }
        0x3A => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Store8(memarg))
        }
        0x3B => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Store16(memarg))
        }
        0x3C => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Store8(memarg))
        }
        0x3D => {
            let memarg = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I64Store16(memarg))
        }
        0x3E => {
            let memarg = cursor.next(EMPTY_CTX)?;
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
            let n = cursor.next(EMPTY_CTX)?;
            Ok(OpCode::I32Const(n))
        }
        0x42 => {
            let n = cursor.next(EMPTY_CTX)?;
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
        byte => bail!(ParseError::UnsupportedInstruction {
            opcode: byte,
        }),
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
    pub locals:     Vec<Local>,
    /// And uninterpreted instructions.
    pub expr_bytes: &'a [u8],
}

#[derive(Debug, Default)]
/// The Default instance of this type returns an empty code section.
pub struct CodeSkeletonSection<'a> {
    pub impls: Vec<CodeSkeleton<'a>>,
}

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for CodeSkeleton<'a> {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let size: u32 = cursor.next(ctx)?;
        let cur_pos = cursor.position();
        let locals = cursor.next(ctx)?;
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

impl<'a, Ctx: Copy> Parseable<'a, Ctx> for CodeSkeletonSection<'a> {
    fn parse(ctx: Ctx, cursor: &mut Cursor<&'a [u8]>) -> ParseResult<Self> {
        let impls = cursor.next(ctx)?;
        Ok(CodeSkeletonSection {
            impls,
        })
    }
}
