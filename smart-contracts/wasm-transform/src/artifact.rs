//! This module defines the notion of the artifact.
//! This is a processed and instantiated module that can have its exposed
//! methods invoked.
//!
//! The module in this section is in a format where serialization and
//! deserialization are straightforward and cheap.

use crate::{
    parse::MAX_NUM_PAGES,
    types::*,
    validate::{validate, Handler, HasValidationContext, ValidationState},
};
use anyhow::{anyhow, bail, ensure};
use std::{collections::BTreeMap, convert::TryInto, io::Write};

#[derive(Copy, Clone)]
/// Either a short or long integer. The use of repr(C) is crucial to guarantee
/// that offsets of both fields are 0, i.e., that we can read the short field if
/// the long field is stored. This only works on little endian platforms.
pub union StackValue {
    pub short: i32,
    pub long:  i64,
}

impl std::fmt::Debug for StackValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StackValue")
        // write!(f, "{}", unsafe { self.short })
    }
}

impl From<i32> for StackValue {
    #[inline(always)]
    fn from(short: i32) -> Self {
        Self {
            short,
        }
    }
}

impl From<u32> for StackValue {
    #[inline(always)]
    fn from(short: u32) -> Self {
        Self {
            short: short as i32,
        }
    }
}

impl From<i64> for StackValue {
    #[inline(always)]
    fn from(long: i64) -> Self {
        Self {
            long,
        }
    }
}

impl From<u64> for StackValue {
    #[inline(always)]
    fn from(long: u64) -> Self {
        Self {
            long: long as i64,
        }
    }
}

impl From<GlobalInit> for StackValue {
    #[inline(always)]
    fn from(g: GlobalInit) -> Self {
        match g {
            GlobalInit::I32(short) => Self {
                short,
            },
            GlobalInit::I64(long) => Self {
                long,
            },
        }
    }
}

#[derive(Debug)]
pub struct InstantiatedTable {
    pub functions: Vec<Option<FuncIndex>>,
}

#[derive(Debug)]
pub struct InstantiatedGlobals {
    pub inits: Vec<GlobalInit>,
}

#[derive(Debug)]
pub struct ArtifactData {
    /// Where to start initializing.
    pub offset: i32,
    /// The bytes to initialize with.
    pub init: Vec<u8>,
}

impl From<Data> for ArtifactData {
    fn from(d: Data) -> Self {
        Self {
            offset: d.offset,
            init:   d.init,
        }
    }
}

#[derive(Debug)]
pub struct ArtifactMemory {
    pub init_size: u32,
    pub max_size:  u32,
    pub init:      Vec<ArtifactData>,
}

#[derive(Debug)]
pub struct CompiledFunction {
    num_params: u32,
    type_idx: TypeIndex,
    return_type: BlockType,
    /// Vector of types of locals. This includes function parameters at the
    /// beginning.
    locals: Vec<ValueType>,
    code: Instructions,
}

#[derive(Debug)]
pub struct CompiledFunctionBytes<'a> {
    pub num_params: u32,
    pub type_idx: TypeIndex,
    pub return_type: BlockType,
    /// Vector of types of locals. This includes function parameters at the
    /// beginning.
    pub locals: &'a [ValueType],
    pub code: &'a [u8],
}

pub trait TryFromImport: Sized {
    fn try_from_import(ty: &[FunctionType], import: Import) -> CompileResult<Self>;
    fn ty(&self) -> &FunctionType;
}

pub struct ArtifactNamedImport {
    pub(crate) mod_name:  Name,
    pub(crate) item_name: Name,
    pub(crate) ty:        FunctionType,
}

impl TryFromImport for ArtifactNamedImport {
    fn try_from_import(ty: &[FunctionType], import: Import) -> CompileResult<Self> {
        match import.description {
            ImportDescription::Func {
                type_idx,
            } => {
                let ty = ty
                    .get(type_idx as usize)
                    .ok_or_else(|| anyhow!("Unknown type index."))?
                    .clone();
                Ok(Self {
                    mod_name: import.mod_name,
                    item_name: import.item_name,
                    ty,
                })
            }
        }
    }

    fn ty(&self) -> &FunctionType { &self.ty }
}

pub trait RunnableCode {
    fn num_params(&self) -> u32;
    fn type_idx(&self) -> TypeIndex;
    fn return_type(&self) -> BlockType;
    /// Vector of types of locals. This includes function parameters at the
    /// beginning.
    fn locals(&self) -> &[ValueType];
    fn code(&self) -> &[u8];
}

impl RunnableCode for CompiledFunction {
    #[inline(always)]
    fn num_params(&self) -> u32 { self.num_params }

    #[inline(always)]
    fn type_idx(&self) -> TypeIndex { self.type_idx }

    #[inline(always)]
    fn return_type(&self) -> BlockType { self.return_type }

    #[inline(always)]
    fn locals(&self) -> &[ValueType] { &self.locals }

    #[inline(always)]
    fn code(&self) -> &[u8] { &self.code.bytes }
}

impl<'a> RunnableCode for CompiledFunctionBytes<'a> {
    #[inline(always)]
    fn num_params(&self) -> u32 { self.num_params }

    #[inline(always)]
    fn type_idx(&self) -> TypeIndex { self.type_idx }

    #[inline(always)]
    fn return_type(&self) -> BlockType { self.return_type }

    #[inline(always)]
    fn locals(&self) -> &[ValueType] { self.locals }

    #[inline(always)]
    fn code(&self) -> &[u8] { self.code }
}

/// A parsed Wasm module. This no longer has custom sections since they are not
/// needed for further processing.
#[derive(Debug)]
pub struct Artifact<ImportFunc, CompiledCode> {
    /// Imports by (module name, item name).
    pub imports: Vec<ImportFunc>,
    /// Types of the module. These are needed for dynamic dispatch, i.e.,
    /// call-indirect.
    pub ty: Vec<FunctionType>,
    /// A fully instantiated table.
    pub table: InstantiatedTable,
    /// The memory of the artifact.
    pub memory: Option<ArtifactMemory>,
    /// Globals initialized with initial values.
    pub global: InstantiatedGlobals,
    /// The exported functions.
    /// Validation should ensure that an exported function is a defined one,
    /// and not one of the imported ones.
    /// Thus the index refers to the index in the code section.
    pub export: BTreeMap<Name, FuncIndex>,
    pub code: Vec<CompiledCode>,
}

/// Internal opcode. This is mostly the same as OpCode, but with control
/// instructions resolved to jumps in the instruction sequence, and function
/// calls processed.
#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive)]
pub enum InternalOpcode {
    // Control instructions
    Unreachable = 0u8,
    If,
    Br,
    BrCarry,
    BrIf,
    BrIfCarry,
    BrTable,
    BrTableCarry,
    Return,
    Call,
    CallIndirect,

    // Parametric instructions
    Drop,
    Select,

    // Variable instructions
    LocalGet,
    LocalSet,
    LocalTee,
    GlobalGet,
    GlobalSet,

    // Memory instructions
    I32Load,
    I64Load,
    I32Load8S,
    I32Load8U,
    I32Load16S,
    I32Load16U,
    I64Load8S,
    I64Load8U,
    I64Load16S,
    I64Load16U,
    I64Load32S,
    I64Load32U,
    I32Store,
    I64Store,
    I32Store8,
    I32Store16,
    I64Store8,
    I64Store16,
    I64Store32,
    MemorySize,
    MemoryGrow,

    // Numeric instructions
    I32Const,
    I64Const,

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

pub type CompileResult<A> = anyhow::Result<A>;

#[derive(Default, Debug)]
pub struct Instructions {
    pub(crate) bytes: Vec<u8>,
}

impl Instructions {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
        }
    }

    pub fn push(&mut self, opcode: InternalOpcode) { self.bytes.push(opcode as u8) }

    pub fn push_u16(&mut self, x: u16) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    pub fn push_u32(&mut self, x: u32) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    pub fn push_i32(&mut self, x: i32) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    pub fn push_i64(&mut self, x: i64) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    pub fn current_offset(&self) -> usize { self.bytes.len() }

    pub fn back_patch(&mut self, back_loc: usize, to_write: u32) -> CompileResult<()> {
        let mut place: &mut [u8] = &mut self.bytes[back_loc..];
        place.write_all(&to_write.to_le_bytes())?;
        Ok(())
    }
}

enum JumpTarget {
    Known {
        pos: usize,
    },
    Unknown {
        backpatch_locations: Vec<usize>,
    },
}

impl JumpTarget {
    pub fn new_unknown() -> Self {
        JumpTarget::Unknown {
            backpatch_locations: Vec::new(),
        }
    }

    pub fn new_unknown_loc(pos: usize) -> Self {
        JumpTarget::Unknown {
            backpatch_locations: vec![pos],
        }
    }

    pub fn new_known(pos: usize) -> Self {
        JumpTarget::Known {
            pos,
        }
    }
}

#[derive(Default)]
struct BackPatchStack {
    stack: Vec<JumpTarget>,
}

impl BackPatchStack {
    pub fn push(&mut self, target: JumpTarget) { self.stack.push(target) }

    pub fn pop(&mut self) -> CompileResult<JumpTarget> {
        self.stack.pop().ok_or_else(|| anyhow!("Attempt to pop from an empty stack."))
    }

    pub fn get_mut(&mut self, n: LabelIndex) -> CompileResult<&mut JumpTarget> {
        ensure!(
            (n as usize) < self.stack.len(),
            "Attempt to access label beyond the size of the stack."
        );
        let lookup_idx = self.stack.len() - n as usize - 1;
        self.stack.get_mut(lookup_idx).ok_or_else(|| anyhow!("Attempt to access unknown label."))
    }
}

struct BackPatch {
    out:       Instructions,
    backpatch: BackPatchStack,
}

impl BackPatch {
    fn new() -> Self {
        Self {
            out:       Default::default(),
            backpatch: BackPatchStack {
                stack: vec![JumpTarget::new_unknown()],
            },
        }
    }

    pub fn push_jump(
        &mut self,
        label_idx: LabelIndex,
        state: &ValidationState,
        instruction: Option<(InternalOpcode, InternalOpcode)>,
    ) -> CompileResult<()> {
        let target = self.backpatch.get_mut(label_idx)?;
        let target_frame = state
            .ctrls
            .get(label_idx)
            .ok_or_else(|| anyhow!("Could not get jump target frame."))?;
        let target_height = target_frame.height;
        let current_height = state.opds.stack.len();
        ensure!(
            current_height >= target_height,
            "Current height must be at least as much as the target."
        );
        let diff = if let BlockType::EmptyType = target_frame.label_type {
            if let Some((l, _)) = instruction {
                self.out.push(l);
            }
            (current_height - target_height).try_into()?
        } else {
            if let Some((_, r)) = instruction {
                self.out.push(r);
            }
            (current_height - target_height).try_into()?
        };
        // output the difference in stack heights.
        self.out.push_u32(diff);
        match target {
            JumpTarget::Known {
                pos,
            } => {
                self.out.push_u32(*pos as u32);
            }
            JumpTarget::Unknown {
                backpatch_locations,
            } => {
                // output instruction
                backpatch_locations.push(self.out.current_offset());
                // output a dummy value
                self.out.push_u32(0u32);
            }
        }
        Ok(())
    }
}

impl Handler<&OpCode> for BackPatch {
    type Outcome = Instructions;

    fn handle_opcode(&mut self, state: &ValidationState, opcode: &OpCode) -> CompileResult<()> {
        use InternalOpcode::*;
        match opcode {
            OpCode::End => {
                if let JumpTarget::Unknown {
                    backpatch_locations,
                } = self.backpatch.pop()?
                {
                    // As u32 would be safe here since module sizes are much less than 4GB, but
                    // we are being extra careful.
                    let current_pos: u32 = self.out.bytes.len().try_into()?;
                    for pos in backpatch_locations {
                        self.out.back_patch(pos, current_pos)?;
                    }
                }
                // do not emit any code, since end is implicit in generated
                // code.
            }
            OpCode::Block(_) => {
                self.backpatch.push(JumpTarget::new_unknown());
            }
            OpCode::Loop(_) => {
                self.backpatch.push(JumpTarget::new_known(self.out.current_offset()))
            }
            OpCode::If {
                ..
            } => {
                self.out.push(If);
                self.backpatch.push(JumpTarget::new_unknown_loc(self.out.bytes.len()));
                self.out.push_u32(0);
            }
            OpCode::Else => {
                // If we reached the else normally, after executing the if branch, we just break
                // to the end of else.
                self.push_jump(0, state, Some((Br, BrCarry)))?;
                // Because the module is well-formed this can only happen after an if
                // We do not backpatch the code now, apart from the initial jump to the else
                // branch. The effect of this will be that any break out of the if statement
                // will jump to the end of else, as intended.
                if let JumpTarget::Unknown {
                    backpatch_locations,
                } = self.backpatch.get_mut(0)?
                {
                    // As u32 would be safe here since module sizes are much less than 4GB, but
                    // we are being extra careful.
                    let current_pos: u32 = self.out.bytes.len().try_into()?;
                    ensure!(
                        !backpatch_locations.is_empty(),
                        "Backpatch should contain at least the If start."
                    );
                    let first = backpatch_locations.remove(0);
                    self.out.back_patch(first, current_pos)?;
                } else {
                    bail!("Invariant violation in else branch.")
                }
            }
            OpCode::Br(label_idx) => {
                self.push_jump(*label_idx, state, Some((Br, BrCarry)))?;
            }
            OpCode::BrIf(label_idx) => {
                self.push_jump(*label_idx, state, Some((BrIf, BrIfCarry)))?;
            }
            OpCode::BrTable {
                labels,
                default,
            } => {
                let target_frame = state
                    .ctrls
                    .get(*default)
                    .ok_or_else(|| anyhow!("Could not get jump target frame."))?;
                if let BlockType::EmptyType = target_frame.label_type {
                    self.out.push(BrTable);
                } else {
                    self.out.push(BrTableCarry);
                }
                // the try_into is not needed because MAX_SWITCH_SIZE is small enough
                // but it does not hurt.
                let labels_len: u16 = labels.len().try_into()?;
                self.out.push_u16(labels_len);
                self.push_jump(*default, state, None)?;
                // The label types are the same for the default as well all the other
                // labels.
                for label_idx in labels {
                    self.push_jump(*label_idx, state, None)?;
                }
            }
            OpCode::Return => {
                // The interpreter will know that return means terminate execution of the
                // function and from the result type of the function it will be
                // clear whether anything needs to be returned.
                self.out.push(Return)
            }
            OpCode::Call(idx) => {
                self.out.push(Call);
                self.out.push_u32(*idx);
            }
            OpCode::CallIndirect(x) => {
                self.out.push(CallIndirect);
                self.out.push_u32(*x);
            }
            OpCode::Nop => {
                // do nothing, we don't need an opcode for that since we don't
                // care about alignment.
            }
            OpCode::Unreachable => {
                self.out.push(Unreachable);
            }
            OpCode::Drop => {
                self.out.push(Drop);
            }
            OpCode::Select => {
                self.out.push(Select);
            }
            OpCode::LocalGet(idx) => {
                self.out.push(LocalGet);
                // the as u16 is safe because idx < NUM_ALLOWED_LOCALS <= 2^15
                self.out.push_u16(*idx as u16);
            }
            OpCode::LocalSet(idx) => {
                self.out.push(LocalSet);
                // the as u16 is safe because idx < NUM_ALLOWED_LOCALS <= 2^15
                self.out.push_u16(*idx as u16);
            }
            OpCode::LocalTee(idx) => {
                self.out.push(LocalTee);
                // the as u16 is safe because idx < NUM_ALLOWED_LOCALS <= 2^15
                self.out.push_u16(*idx as u16);
            }
            OpCode::GlobalGet(idx) => {
                self.out.push(GlobalGet);
                // the as u16 is safe because idx < MAX_NUM_GLOBALS <= 2^16
                self.out.push_u16(*idx as u16);
            }
            OpCode::GlobalSet(idx) => {
                self.out.push(GlobalSet);
                // the as u16 is safe because idx < MAX_NUM_GLOBALS <= 2^16
                self.out.push_u16(*idx as u16);
            }
            OpCode::I32Load(memarg) => {
                self.out.push(I32Load);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Load(memarg) => {
                self.out.push(I64Load);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I32Load8S(memarg) => {
                self.out.push(I32Load8S);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I32Load8U(memarg) => {
                self.out.push(I32Load8U);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I32Load16S(memarg) => {
                self.out.push(I32Load16S);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I32Load16U(memarg) => {
                self.out.push(I32Load16U);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Load8S(memarg) => {
                self.out.push(I64Load8S);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Load8U(memarg) => {
                self.out.push(I64Load8U);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Load16S(memarg) => {
                self.out.push(I64Load16S);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Load16U(memarg) => {
                self.out.push(I64Load16U);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Load32S(memarg) => {
                self.out.push(I64Load32S);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Load32U(memarg) => {
                self.out.push(I64Load32U);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I32Store(memarg) => {
                self.out.push(I32Store);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Store(memarg) => {
                self.out.push(I64Store);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I32Store8(memarg) => {
                self.out.push(I32Store8);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I32Store16(memarg) => {
                self.out.push(I32Store16);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Store8(memarg) => {
                self.out.push(I64Store8);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Store16(memarg) => {
                self.out.push(I64Store16);
                self.out.push_u32(memarg.offset);
            }
            OpCode::I64Store32(memarg) => {
                self.out.push(I64Store32);
                self.out.push_u32(memarg.offset);
            }
            OpCode::MemorySize => self.out.push(MemorySize),
            OpCode::MemoryGrow => self.out.push(MemoryGrow),
            OpCode::I32Const(c) => {
                self.out.push(I32Const);
                self.out.push_i32(*c);
            }
            OpCode::I64Const(c) => {
                self.out.push(I64Const);
                self.out.push_i64(*c);
            }
            OpCode::I32Eqz => {
                self.out.push(I32Eqz);
            }
            OpCode::I32Eq => {
                self.out.push(I32Eq);
            }
            OpCode::I32Ne => {
                self.out.push(I32Ne);
            }
            OpCode::I32LtS => {
                self.out.push(I32LtS);
            }
            OpCode::I32LtU => {
                self.out.push(I32LtU);
            }
            OpCode::I32GtS => {
                self.out.push(I32GtS);
            }
            OpCode::I32GtU => {
                self.out.push(I32GtU);
            }
            OpCode::I32LeS => {
                self.out.push(I32LeS);
            }
            OpCode::I32LeU => {
                self.out.push(I32LeU);
            }
            OpCode::I32GeS => {
                self.out.push(I32GeS);
            }
            OpCode::I32GeU => {
                self.out.push(I32GeU);
            }
            OpCode::I64Eqz => {
                self.out.push(I64Eqz);
            }
            OpCode::I64Eq => {
                self.out.push(I64Eq);
            }
            OpCode::I64Ne => {
                self.out.push(I64Ne);
            }
            OpCode::I64LtS => {
                self.out.push(I64LtS);
            }
            OpCode::I64LtU => {
                self.out.push(I64LtU);
            }
            OpCode::I64GtS => {
                self.out.push(I64GtS);
            }
            OpCode::I64GtU => {
                self.out.push(I64GtU);
            }
            OpCode::I64LeS => {
                self.out.push(I64LeS);
            }
            OpCode::I64LeU => {
                self.out.push(I64LeU);
            }
            OpCode::I64GeS => {
                self.out.push(I64GeS);
            }
            OpCode::I64GeU => {
                self.out.push(I64GeU);
            }
            OpCode::I32Clz => {
                self.out.push(I32Clz);
            }
            OpCode::I32Ctz => {
                self.out.push(I32Ctz);
            }
            OpCode::I32Popcnt => {
                self.out.push(I32Popcnt);
            }
            OpCode::I32Add => {
                self.out.push(I32Add);
            }
            OpCode::I32Sub => {
                self.out.push(I32Sub);
            }
            OpCode::I32Mul => {
                self.out.push(I32Mul);
            }
            OpCode::I32DivS => {
                self.out.push(I32DivS);
            }
            OpCode::I32DivU => {
                self.out.push(I32DivU);
            }
            OpCode::I32RemS => {
                self.out.push(I32RemS);
            }
            OpCode::I32RemU => {
                self.out.push(I32RemU);
            }
            OpCode::I32And => {
                self.out.push(I32And);
            }
            OpCode::I32Or => {
                self.out.push(I32Or);
            }
            OpCode::I32Xor => {
                self.out.push(I32Xor);
            }
            OpCode::I32Shl => {
                self.out.push(I32Shl);
            }
            OpCode::I32ShrS => {
                self.out.push(I32ShrS);
            }
            OpCode::I32ShrU => {
                self.out.push(I32ShrU);
            }
            OpCode::I32Rotl => {
                self.out.push(I32Rotl);
            }
            OpCode::I32Rotr => {
                self.out.push(I32Rotr);
            }
            OpCode::I64Clz => {
                self.out.push(I64Clz);
            }
            OpCode::I64Ctz => {
                self.out.push(I64Ctz);
            }
            OpCode::I64Popcnt => {
                self.out.push(I64Popcnt);
            }
            OpCode::I64Add => {
                self.out.push(I64Add);
            }
            OpCode::I64Sub => {
                self.out.push(I64Sub);
            }
            OpCode::I64Mul => {
                self.out.push(I64Mul);
            }
            OpCode::I64DivS => {
                self.out.push(I64DivS);
            }
            OpCode::I64DivU => {
                self.out.push(I64DivU);
            }
            OpCode::I64RemS => {
                self.out.push(I64RemS);
            }
            OpCode::I64RemU => {
                self.out.push(I64RemU);
            }
            OpCode::I64And => {
                self.out.push(I64And);
            }
            OpCode::I64Or => {
                self.out.push(I64Or);
            }
            OpCode::I64Xor => {
                self.out.push(I64Xor);
            }
            OpCode::I64Shl => {
                self.out.push(I64Shl);
            }
            OpCode::I64ShrS => {
                self.out.push(I64ShrS);
            }
            OpCode::I64ShrU => {
                self.out.push(I64ShrU);
            }
            OpCode::I64Rotl => {
                self.out.push(I64Rotl);
            }
            OpCode::I64Rotr => {
                self.out.push(I64Rotr);
            }
            OpCode::I32WrapI64 => {
                self.out.push(I32WrapI64);
            }
            OpCode::I64ExtendI32S => {
                self.out.push(I64ExtendI32S);
            }
            OpCode::I64ExtendI32U => {
                self.out.push(I64ExtendI32U);
            }
        }
        Ok(())
    }

    fn finish(self) -> CompileResult<Self::Outcome> {
        ensure!(self.backpatch.stack.is_empty(), "There are still jumps to backpatch.");
        Ok(self.out)
    }
}

struct ModuleContext<'a> {
    module: &'a Module,
    locals: &'a [ValueType],
    code:   &'a Code,
}

impl<'a> HasValidationContext for ModuleContext<'a> {
    fn get_local(&self, idx: u32) -> CompileResult<ValueType> {
        self.locals.get(idx as usize).copied().ok_or_else(|| anyhow!("Local does not exist."))
    }

    fn get_global(&self, idx: crate::types::GlobalIndex) -> CompileResult<(ValueType, bool)> {
        match self.module.global.globals.get(idx as usize) {
            Some(g) => Ok((ValueType::from(g), g.mutable)),
            None => bail!("Attempting to access non-existing global."),
        }
    }

    fn memory_exists(&self) -> bool { self.module.memory.memory_type.is_some() }

    fn table_exists(&self) -> bool { self.module.table.table_type.is_some() }

    fn get_func(&self, idx: FuncIndex) -> CompileResult<&std::rc::Rc<FunctionType>> {
        if (idx as usize) < self.module.import.imports.len() {
            match self.module.import.imports[idx as usize].description {
                ImportDescription::Func {
                    type_idx,
                } => self
                    .module
                    .ty
                    .get(type_idx)
                    .ok_or_else(|| anyhow!("Attempting to get type that does not exist")),
            }
        } else {
            self.module
                .code
                .impls
                .get(idx as usize - self.module.import.imports.len())
                .map(|c| &c.ty)
                .ok_or_else(|| anyhow!("Attempting to get type of function that does not exist."))
        }
    }

    fn get_type(&self, idx: TypeIndex) -> CompileResult<&std::rc::Rc<FunctionType>> {
        self.module
            .ty
            .types
            .get(idx as usize)
            .ok_or_else(|| anyhow!("Attempting to get non-existing type."))
    }

    fn return_type(&self) -> BlockType { BlockType::from(self.code.ty.result) }
}

pub fn compile_module<I: TryFromImport>(
    input: Module,
) -> CompileResult<Artifact<I, CompiledFunction>> {
    let mut code_out = Vec::with_capacity(input.code.impls.len());

    for code in input.code.impls.iter() {
        let mut locals = code.ty.parameters.iter().copied().collect::<Vec<_>>();
        for local in code.locals.iter() {
            locals.extend((0..local.multiplicity).map(|_| local.ty));
        }

        let context = ModuleContext {
            module: &input,
            locals: &locals,
            code,
        };

        let mut exec_code =
            validate(&context, code.expr.instrs.iter().map(Result::Ok), BackPatch::new())?;
        // We add a return instruction at the end so we have an easier time in the
        // interpreter since there is no implicit return.
        exec_code.push(InternalOpcode::Return);

        let result = CompiledFunction {
            type_idx: code.ty_idx,
            locals,
            num_params: code.ty.parameters.len().try_into()?,
            return_type: BlockType::from(code.ty.result),
            code: exec_code,
        };
        code_out.push(result)
    }

    let ty = input.ty.types.into_iter().map(|x| (*x).clone()).collect::<Vec<FunctionType>>();
    let table = {
        if let Some(tt) = input.table.table_type {
            let mut functions = vec![None; tt.limits.min as usize];
            for init in input.element.elements.iter() {
                // validation has already ensured that inits are within bounds.
                for (place, value) in
                    functions[init.offset as usize..].iter_mut().zip(init.inits.iter())
                {
                    *place = Some(*value)
                }
            }
            InstantiatedTable {
                functions,
            }
        } else {
            InstantiatedTable {
                functions: Vec::new(),
            }
        }
    };
    let memory = {
        if let Some(mt) = input.memory.memory_type {
            Some(ArtifactMemory {
                init_size: mt.limits.min,
                max_size:  mt
                    .limits
                    .max
                    .map(|x| std::cmp::min(x, MAX_NUM_PAGES))
                    .unwrap_or(MAX_NUM_PAGES),
                init:      input
                    .data
                    .sections
                    .into_iter()
                    .map(ArtifactData::from)
                    .collect::<Vec<_>>(),
            })
        } else {
            None
        }
    };
    let global = InstantiatedGlobals {
        inits: input.global.globals.iter().map(|x| x.init).collect::<Vec<_>>(),
    };
    let export = input
        .export
        .exports
        .into_iter()
        .filter_map(|export| {
            if let ExportDescription::Func {
                index,
            } = export.description
            {
                Some((export.name, index))
            } else {
                None
            }
        })
        .collect::<BTreeMap<_, _>>();
    let imports = input
        .import
        .imports
        .into_iter()
        .map(|i| I::try_from_import(&ty, i))
        .collect::<CompileResult<_>>()?;
    Ok(Artifact {
        imports,
        ty,
        table,
        memory,
        global,
        export,
        code: code_out,
    })
}
