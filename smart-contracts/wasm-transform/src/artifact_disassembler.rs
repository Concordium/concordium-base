//! A disassembler for the compiled [`Artifact`].
//!
//! This module renders an [`Artifact`] in a human-readable, textual form. It
//! prints the artifact metadata (version, types, imports, table, memory,
//! globals, exports and per-function headers) and disassembles the compiled,
//! register-based internal bytecodes of every function.
//!
//! ## Caution
//!
//! This code is purely AI generated and is not thoroughly reviewed. Use it for
//! debugging purposes only.

use crate::{
    artifact::{Artifact, InternalOpcode, RunnableCode, TryFromImport},
    types::{BlockType, FuncIndex, FunctionType, GlobalInit, ValueType},
};
use std::{collections::BTreeMap, convert::TryInto, fmt::Write};

/// Disassemble an [`Artifact`] into a human-readable string.
///
/// ## Caution
///
/// This code is purely AI generated and is not thoroughly reviewed. Use it for
/// debugging purposes only.
pub fn disassemble_artifact<I, C>(artifact: &Artifact<I, C>) -> String
where
    I: TryFromImport + std::fmt::Display,
    C: RunnableCode,
{
    let mut out = String::new();

    // A reverse lookup from function index to the export names pointing at it,
    // so that we can annotate exported functions in their headers.
    let mut exports_by_func: BTreeMap<FuncIndex, Vec<&str>> = BTreeMap::new();
    for (name, idx) in artifact.export.iter() {
        exports_by_func.entry(*idx).or_default().push(name.as_ref());
    }

    write_header(&mut out, artifact, &exports_by_func);

    let num_imports = artifact.imports.len();
    for (i, func) in artifact.code.iter().enumerate() {
        let func_index = (num_imports + i) as FuncIndex;
        let _ = writeln!(out);
        write_function(&mut out, artifact, func_index, func, &exports_by_func);
    }

    out
}

/// Write the artifact-level metadata (everything except the function bodies).
fn write_header<I, C>(
    out: &mut String,
    artifact: &Artifact<I, C>,
    exports_by_func: &BTreeMap<FuncIndex, Vec<&str>>,
) where
    I: TryFromImport + std::fmt::Display,
    C: RunnableCode,
{
    let _ = writeln!(out, "=== Artifact ===");
    let _ = writeln!(out, "version: {:?}", artifact.version);

    // Types.
    let _ = writeln!(out, "\ntypes ({}):", artifact.ty.len());
    for (i, ty) in artifact.ty.iter().enumerate() {
        let _ = writeln!(out, "  type[{}]: {}", i, fmt_functype(ty));
    }

    // Imports. Imported functions occupy the lowest function indices.
    let _ = writeln!(out, "\nimports ({}):", artifact.imports.len());
    for (i, import) in artifact.imports.iter().enumerate() {
        let _ = writeln!(
            out,
            "  func[{}]: {} : {}",
            i,
            import,
            fmt_functype(import.ty())
        );
    }

    // Table.
    let table = &artifact.table;
    let _ = writeln!(out, "\ntable ({} slots):", table.functions.len());
    for (i, slot) in table.functions.iter().enumerate() {
        if let Some(func_idx) = slot {
            let _ = writeln!(out, "  [{}] -> func[{}]", i, func_idx);
        }
    }

    // Memory.
    match &artifact.memory {
        Some(mem) => {
            let _ = writeln!(
                out,
                "\nmemory: init {} page(s), max {} page(s), {} data segment(s):",
                mem.init_size,
                mem.max_size,
                mem.init.len()
            );
            for (i, data) in mem.init.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "  data[{}]: offset {}, {} byte(s)",
                    i,
                    data.offset,
                    data.init.len()
                );
            }
        }
        None => {
            let _ = writeln!(out, "\nmemory: none");
        }
    }

    // Globals.
    let _ = writeln!(out, "\nglobals ({}):", artifact.global.inits.len());
    for (i, g) in artifact.global.inits.iter().enumerate() {
        let _ = writeln!(out, "  global[{}]: {}", i, fmt_global_init(*g));
    }

    // Exports.
    let _ = writeln!(out, "\nexports ({}):", artifact.export.len());
    for (name, idx) in artifact.export.iter() {
        let _ = writeln!(out, "  {:?} -> func[{}]", name.as_ref(), idx);
    }

    // A short listing of the defined functions and their exported names (if
    // any), before the detailed disassembly below.
    let num_imports = artifact.imports.len();
    let _ = writeln!(out, "\nfunctions ({} defined):", artifact.code.len());
    for (i, func) in artifact.code.iter().enumerate() {
        let func_index = (num_imports + i) as FuncIndex;
        let exported = exports_by_func
            .get(&func_index)
            .map(|names| format!("  exported as {:?}", names))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  func[{}]: type[{}]{}",
            func_index,
            func.type_idx(),
            exported
        );
    }
}

/// Write the header and disassembly of a single function.
fn write_function<I, C>(
    out: &mut String,
    artifact: &Artifact<I, C>,
    func_index: FuncIndex,
    func: &C,
    exports_by_func: &BTreeMap<FuncIndex, Vec<&str>>,
) where
    I: TryFromImport + std::fmt::Display,
    C: RunnableCode,
{
    let code = func.code();
    let constants = func.constants();

    let _ = writeln!(out, "--- func[{}] ---", func_index);
    if let Some(names) = exports_by_func.get(&func_index) {
        let _ = writeln!(out, "  exported as: {:?}", names);
    }
    let ty = artifact.ty.get(func.type_idx() as usize);
    match ty {
        Some(ty) => {
            let _ = writeln!(out, "  type[{}]: {}", func.type_idx(), fmt_functype(ty));
        }
        None => {
            let _ = writeln!(out, "  type[{}]: <unknown type>", func.type_idx());
        }
    }
    let _ = writeln!(
        out,
        "  params: [{}]",
        func.params()
            .iter()
            .map(|t| fmt_valtype(*t))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(
        out,
        "  locals ({}): [{}]",
        func.num_locals(),
        func.locals()
            .map(fmt_valtype)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(out, "  return: {}", fmt_blocktype(func.return_type()));
    let _ = writeln!(out, "  registers: {}", func.num_registers());
    if constants.is_empty() {
        let _ = writeln!(out, "  constants: none");
    } else {
        let _ = writeln!(
            out,
            "  constants: [{}]",
            constants
                .iter()
                .enumerate()
                .map(|(i, c)| format!("{}={}", i, c))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let _ = writeln!(out, "  code ({} bytes):", code.len());
    disassemble_code(out, artifact, func, code, constants);
}

/// Decode and print the instruction stream of a function.
fn disassemble_code<I, C>(
    out: &mut String,
    artifact: &Artifact<I, C>,
    _func: &C,
    code: &[u8],
    constants: &[i64],
) where
    I: TryFromImport + std::fmt::Display,
    C: RunnableCode,
{
    let mut reader = Reader { code, pc: 0 };
    loop {
        let offset = reader.pc;
        let byte = match reader.u8() {
            Some(b) => b,
            None => break, // Clean end of stream.
        };
        match decode_instruction(&mut reader, artifact, byte, constants) {
            Ok(text) => {
                let _ = writeln!(out, "    0x{:04x}: {}", offset, text);
            }
            Err(msg) => {
                let _ = writeln!(out, "    0x{:04x}: ; <decode error: {}>", offset, msg);
                break;
            }
        }
    }
}

/// Decode a single instruction, given its already-read opcode byte, into a
/// rendered string. `reader` is positioned just after the opcode byte and is
/// advanced past the instruction's immediate operands.
fn decode_instruction<I, C>(
    reader: &mut Reader,
    artifact: &Artifact<I, C>,
    opcode_byte: u8,
    constants: &[i64],
) -> Result<String, String>
where
    I: TryFromImport + std::fmt::Display,
    C: RunnableCode,
{
    use InternalOpcode::*;

    let op = InternalOpcode::try_from(opcode_byte)
        .map_err(|_| format!("unknown opcode byte 0x{:02x}", opcode_byte))?;
    // The mnemonic is the Debug name of the opcode variant.
    let mnemonic = format!("{:?}", op);

    // Read a register/constant operand and render it symbolically.
    let reg = |reader: &mut Reader| -> Result<String, String> {
        let slot = reader.i32()?;
        Ok(fmt_reg(slot, constants))
    };

    let text = match op {
        Unreachable | Return => mnemonic,

        // Unary: source -> target.
        I32Eqz | I64Eqz | I32Clz | I32Ctz | I32Popcnt | I64Clz | I64Ctz | I64Popcnt
        | I32WrapI64 | I64ExtendI32S | I64ExtendI32U | I32Extend8S | I32Extend16S | I64Extend8S
        | I64Extend16S | I64Extend32S | MemoryGrow => {
            let source = reg(reader)?;
            let target = reg(reader)?;
            format!("{} {} -> {}", mnemonic, source, target)
        }

        // Binary: a, b -> target.
        I32Eq | I32Ne | I32LtS | I32LtU | I32GtS | I32GtU | I32LeS | I32LeU | I32GeS | I32GeU
        | I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU | I64LeS | I64LeU | I64GeS | I64GeU
        | I32Add | I32Sub | I32Mul | I32DivS | I32DivU | I32RemS | I32RemU | I32And | I32Or
        | I32Xor | I32Shl | I32ShrS | I32ShrU | I32Rotl | I32Rotr | I64Add | I64Sub | I64Mul
        | I64DivS | I64DivU | I64RemS | I64RemU | I64And | I64Or | I64Xor | I64Shl | I64ShrS
        | I64ShrU | I64Rotl | I64Rotr => {
            let a = reg(reader)?;
            let b = reg(reader)?;
            let target = reg(reader)?;
            format!("{} {}, {} -> {}", mnemonic, a, b, target)
        }

        // Ternary: op1, op2, op3 -> target.
        Select => {
            let a = reg(reader)?;
            let b = reg(reader)?;
            let c = reg(reader)?;
            let target = reg(reader)?;
            format!("{} {}, {}, {} -> {}", mnemonic, a, b, c, target)
        }

        // Memory loads: [base + offset] -> target.
        I32Load | I64Load | I32Load8S | I32Load8U | I32Load16S | I32Load16U | I64Load8S
        | I64Load8U | I64Load16S | I64Load16U | I64Load32S | I64Load32U => {
            let offset = reader.u32()?;
            let base = reg(reader)?;
            let target = reg(reader)?;
            format!("{} [{} + {}] -> {}", mnemonic, base, offset, target)
        }

        // Memory stores: value -> [base + offset].
        I32Store | I64Store | I32Store8 | I32Store16 | I64Store8 | I64Store16 | I64Store32 => {
            let offset = reader.u32()?;
            let value = reg(reader)?;
            let base = reg(reader)?;
            format!("{} {} -> [{} + {}]", mnemonic, value, base, offset)
        }

        MemorySize => {
            let target = reg(reader)?;
            format!("{} -> {}", mnemonic, target)
        }

        GlobalGet => {
            let idx = reader.u16()?;
            let target = reg(reader)?;
            format!("{} global[{}] -> {}", mnemonic, idx, target)
        }
        GlobalSet => {
            let idx = reader.u16()?;
            let source = reg(reader)?;
            format!("{} {} -> global[{}]", mnemonic, source, idx)
        }

        Copy => {
            let from = reg(reader)?;
            let to = reg(reader)?;
            format!("{} {} -> {}", mnemonic, from, to)
        }

        // Control flow. Jump targets are absolute byte offsets into this
        // function's code stream.
        If => {
            let cond = reg(reader)?;
            let target = reader.u32()?;
            format!("{} {} else -> @0x{:04x}", mnemonic, cond, target)
        }
        Br => {
            let target = reader.u32()?;
            format!("{} @0x{:04x}", mnemonic, target)
        }
        BrIf => {
            let target = reader.u32()?;
            let cond = reg(reader)?;
            format!("{} {} -> @0x{:04x}", mnemonic, cond, target)
        }
        BrTable => {
            let cond = reg(reader)?;
            let count = reader.u16()?;
            let default = reader.u32()?;
            let mut labels = Vec::with_capacity(count as usize);
            for _ in 0..count {
                labels.push(format!("@0x{:04x}", reader.u32()?));
            }
            format!(
                "{} {} default @0x{:04x} [{}]",
                mnemonic,
                cond,
                default,
                labels.join(", ")
            )
        }
        BrTableCarry => {
            let cond = reg(reader)?;
            let copy_source = reg(reader)?;
            let count = reader.u16()?;
            // Default target, then one entry per label. Each entry is a copy
            // destination register followed by the absolute jump target.
            let default_to = reg(reader)?;
            let default_target = reader.u32()?;
            let mut labels = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let to = reg(reader)?;
                let target = reader.u32()?;
                labels.push(format!("(copy -> {} @0x{:04x})", to, target));
            }
            format!(
                "{} {} copy {} default (copy -> {} @0x{:04x}) [{}]",
                mnemonic,
                cond,
                copy_source,
                default_to,
                default_target,
                labels.join(", ")
            )
        }

        TickEnergy => {
            let cost = reader.u32()?;
            format!("{} {}", mnemonic, cost)
        }

        Call => {
            let idx = reader.u32()?;
            let ty = resolve_func_type(artifact, idx)
                .ok_or_else(|| format!("call to unknown function {}", idx))?;
            let mut args = Vec::with_capacity(ty.parameters.len());
            for _ in 0..ty.parameters.len() {
                args.push(reg(reader)?);
            }
            let ret = if ty.result.is_some() {
                Some(reg(reader)?)
            } else {
                None
            };
            format!(
                "{} func[{}] ({}){}",
                mnemonic,
                idx,
                args.join(", "),
                ret.map(|r| format!(" -> {}", r)).unwrap_or_default()
            )
        }
        CallIndirect => {
            let type_idx = reader.u32()?;
            let table_entry = reg(reader)?;
            let ty = artifact
                .ty
                .get(type_idx as usize)
                .ok_or_else(|| format!("call_indirect with unknown type {}", type_idx))?;
            let mut args = Vec::with_capacity(ty.parameters.len());
            for _ in 0..ty.parameters.len() {
                args.push(reg(reader)?);
            }
            let ret = if ty.result.is_some() {
                Some(reg(reader)?)
            } else {
                None
            };
            format!(
                "{} type[{}] table[{}] ({}){}",
                mnemonic,
                type_idx,
                table_entry,
                args.join(", "),
                ret.map(|r| format!(" -> {}", r)).unwrap_or_default()
            )
        }
    };
    Ok(text)
}

/// Resolve the [`FunctionType`] of a function referenced by a `Call`, given its
/// combined function index (imports occupy the lowest indices, followed by the
/// defined functions in `code`).
fn resolve_func_type<'a, I, C>(
    artifact: &'a Artifact<I, C>,
    idx: FuncIndex,
) -> Option<&'a FunctionType>
where
    I: TryFromImport,
    C: RunnableCode,
{
    let num_imports = artifact.imports.len();
    let i = idx as usize;
    if i < num_imports {
        Some(artifact.imports[i].ty())
    } else {
        let func = artifact.code.get(i - num_imports)?;
        artifact.ty.get(func.type_idx() as usize)
    }
}

/// A cursor over the instruction stream that reads little-endian integers, as
/// the interpreter does. Each read either advances the position and returns the
/// value or reports that the stream is truncated.
struct Reader<'a> {
    code: &'a [u8],
    pc: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.code.get(self.pc)?;
        self.pc += 1;
        Some(b)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let bytes = self
            .code
            .get(self.pc..self.pc + 2)
            .ok_or("truncated u16 operand")?;
        self.pc += 2;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self
            .code
            .get(self.pc..self.pc + 4)
            .ok_or("truncated u32 operand")?;
        self.pc += 4;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn i32(&mut self) -> Result<i32, String> {
        let bytes = self
            .code
            .get(self.pc..self.pc + 4)
            .ok_or("truncated i32 operand")?;
        self.pc += 4;
        Ok(i32::from_le_bytes(bytes.try_into().unwrap()))
    }
}

/// Render a register operand slot. Non-negative slots are register locations
/// (parameters, locals and dynamic registers). Negative slots encode a constant
/// with index `-(slot + 1)` into the function's constant table, whose value is
/// resolved for readability.
fn fmt_reg(slot: i32, constants: &[i64]) -> String {
    if slot >= 0 {
        format!("r{}", slot)
    } else {
        let idx = (-(slot as i64) - 1) as usize;
        match constants.get(idx) {
            Some(value) => format!("const[{}]={}", idx, value),
            None => format!("const[{}]=<out of range>", idx),
        }
    }
}

fn fmt_valtype(ty: ValueType) -> &'static str {
    match ty {
        ValueType::I32 => "i32",
        ValueType::I64 => "i64",
    }
}

fn fmt_functype(ty: &FunctionType) -> String {
    let params = ty
        .parameters
        .iter()
        .map(|t| fmt_valtype(*t))
        .collect::<Vec<_>>()
        .join(", ");
    let result = match ty.result {
        Some(t) => fmt_valtype(t),
        None => "()",
    };
    format!("({}) -> {}", params, result)
}

fn fmt_blocktype(ty: BlockType) -> String {
    match ty {
        BlockType::EmptyType => "()".to_string(),
        BlockType::ValueType(t) => fmt_valtype(t).to_string(),
    }
}

fn fmt_global_init(g: GlobalInit) -> String {
    match g {
        GlobalInit::I32(x) => format!("i32 {}", x),
        GlobalInit::I64(x) => format!("i64 {}", x),
    }
}
