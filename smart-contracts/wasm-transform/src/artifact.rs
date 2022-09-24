//! This module defines the notion of the artifact.
//! This is a processed and instantiated module that can have its exposed
//! methods invoked.
//!
//! The module in this section is in a format where serialization and
//! deserialization are straightforward and cheap.

use crate::{
    constants::MAX_NUM_PAGES,
    types::*,
    validate::{validate, Handler, HasValidationContext, LocalsRange, ValidationState},
};
use anyhow::{anyhow, bail, ensure};
use derive_more::{Display, From, Into};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    io::Write,
    sync::Arc,
};

#[derive(Copy, Clone)]
/// Either a short or long integer.
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
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn from(short: i32) -> Self {
        Self {
            short,
        }
    }
}

impl From<u32> for StackValue {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn from(short: u32) -> Self {
        Self {
            short: short as i32,
        }
    }
}

impl From<i64> for StackValue {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn from(long: i64) -> Self {
        Self {
            long,
        }
    }
}

impl From<u64> for StackValue {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn from(long: u64) -> Self {
        Self {
            long: long as i64,
        }
    }
}

impl From<GlobalInit> for StackValue {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
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

#[derive(Debug, Clone)]
/// A fully instantiated table. This is possible because in the Wasm
/// specification we have, the only way to write functions to the table is via
/// the elements section of the module. Since we ensure the table is small
/// enough we can afford to initialize it at compile time.
pub struct InstantiatedTable {
    pub functions: Vec<Option<FuncIndex>>,
}

#[derive(Debug, Clone)]
/// Fully instantiated globals with initial values.
pub struct InstantiatedGlobals {
    pub inits: Vec<GlobalInit>,
}

#[derive(Debug, Clone)]
/// The data segment of the artifact. This is a slightly processed
/// data segment of the module. In contrast to the table we cannot use
/// the same trick of initializing it here. In practice data segments
/// are at high offsets, which would lead to big artifacts. Thus we
/// store it pretty much in the same way that it was when it was part
/// of the source, except we have resolved the offset.
pub struct ArtifactData {
    /// Where to start initializing.
    pub offset: i32,
    /// The bytes to initialize with.
    pub init:   Vec<u8>,
}

impl From<Data> for ArtifactData {
    fn from(d: Data) -> Self {
        Self {
            offset: d.offset,
            init:   d.init,
        }
    }
}

#[derive(Debug, Clone)]
/// Memory of the artifact, with initial size, as well as maximum size set.
/// If the maximum size is not part of the original module we set it to the
/// [constants::MAX_NUM_PAGES](../constants/constant.MAX_NUM_PAGES.html)
pub struct ArtifactMemory {
    pub init_size: u32,
    pub max_size:  u32,
    pub init:      Vec<ArtifactData>,
}

/// A local variable declaration in a function.
/// Because we know there are not going to be more than 2^16-1 locals we can
/// store multiplicity more efficiently.
#[derive(Debug, Clone, Copy)]
pub struct ArtifactLocal {
    pub(crate) multiplicity: u16,
    pub(crate) ty:           ValueType,
}

impl From<ValueType> for ArtifactLocal {
    fn from(ty: ValueType) -> Self {
        Self {
            ty,
            multiplicity: 1,
        }
    }
}

impl TryFrom<Local> for ArtifactLocal {
    type Error = anyhow::Error;

    fn try_from(value: Local) -> Result<Self, Self::Error> {
        let multiplicity = value.multiplicity.try_into()?;
        Ok(Self {
            ty: value.ty,
            multiplicity,
        })
    }
}

#[derive(Debug, Clone)]
/// A function which has been processed into a form suitable for execution.
pub struct CompiledFunction {
    type_idx:    TypeIndex,
    return_type: BlockType,
    /// Parameters of the function.
    params:      Vec<ValueType>,
    /// Number of locals, cached, but should match what is in the
    /// locals vector below.
    num_locals:  u32,
    /// Vector of types of locals. This __does not__ include function
    /// parameters.
    locals:      Vec<ArtifactLocal>,
    code:        Instructions,
}

#[derive(Debug)]
/// A borrowed variant of [CompiledFunction](./struct.CompiledFunction.html)
/// that does not own the body and locals. This is used to make deserialization
/// of artifacts cheaper.
pub struct CompiledFunctionBytes<'a> {
    pub(crate) type_idx:    TypeIndex,
    pub(crate) return_type: BlockType,
    pub(crate) params:      &'a [ValueType],
    /// Vector of types of locals. This __does not__ include
    /// parameters.
    /// FIXME: It would be ideal to have this as a zero-copy structure,
    /// but it likely does not matter, and it would be more error-prone.
    pub(crate) num_locals:  u32,
    pub(crate) locals:      Vec<ArtifactLocal>,
    pub(crate) code:        &'a [u8],
}

impl<'a> From<CompiledFunctionBytes<'a>> for CompiledFunction {
    fn from(cfb: CompiledFunctionBytes<'a>) -> Self {
        Self {
            type_idx:    cfb.type_idx,
            return_type: cfb.return_type,
            params:      cfb.params.to_vec(),
            num_locals:  cfb.num_locals,
            locals:      cfb.locals,
            code:        cfb.code.to_vec().into(),
        }
    }
}

/// Try to process an import into something that is perhaps more suitable for
/// execution, i.e., quicker to resolve.
pub trait TryFromImport: Sized {
    fn try_from_import(ty: &[FunctionType], import: Import) -> CompileResult<Self>;
    fn ty(&self) -> &FunctionType;
}

/// An example of a processed import with minimal processing. Useful for testing
/// and experimenting, but not for efficient execution.
#[derive(Debug, Clone, Display)]
#[display(fmt = "{}.{}", mod_name, item_name)]
pub struct ArtifactNamedImport {
    pub(crate) mod_name:  Name,
    pub(crate) item_name: Name,
    pub(crate) ty:        FunctionType,
}

impl ArtifactNamedImport {
    pub fn matches(&self, mod_name: &str, item_name: &str) -> bool {
        self.mod_name.as_ref() == mod_name && self.item_name.as_ref() == item_name
    }
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

pub struct LocalsIterator<'a> {
    /// Number of locals that are still going to be yielded from the iterator.
    remaining_items:      u32,
    pub(crate) locals:    &'a [ArtifactLocal],
    /// Current position in the locals list.
    current_item:         usize,
    /// Current multiplicity of the current_item.
    current_multiplicity: u16,
}

impl<'a> LocalsIterator<'a> {
    pub fn new(num_locals: u32, locals: &'a [ArtifactLocal]) -> Self {
        Self {
            remaining_items: num_locals,
            locals,
            current_item: 0,
            current_multiplicity: 0,
        }
    }
}

impl<'a> Iterator for LocalsIterator<'a> {
    type Item = ValueType;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining_items.checked_sub(1)?;
        let al = self.locals.get(self.current_item)?;
        if self.current_multiplicity < al.multiplicity {
            self.current_multiplicity += 1;
            Some(al.ty)
        } else {
            self.current_item += 1;
            self.current_multiplicity = 0;
            self.next()
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_items as usize, Some(self.remaining_items as usize))
    }
}

impl<'a> ExactSizeIterator for LocalsIterator<'a> {
    fn len(&self) -> usize { self.remaining_items as usize }
}

/// A trait encapsulating the properties that are needed to run a function.
pub trait RunnableCode {
    fn num_params(&self) -> u32;
    fn type_idx(&self) -> TypeIndex;
    fn return_type(&self) -> BlockType;
    /// Vector of types of locals. This includes function parameters at the
    /// beginning.
    fn params(&self) -> &[ValueType];
    fn num_locals(&self) -> u32;
    fn locals(&self) -> LocalsIterator<'_>;
    fn code(&self) -> &[u8];
}

impl RunnableCode for CompiledFunction {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn num_params(&self) -> u32 { self.params.len() as u32 }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn type_idx(&self) -> TypeIndex { self.type_idx }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn return_type(&self) -> BlockType { self.return_type }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn params(&self) -> &[ValueType] { &self.params }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn num_locals(&self) -> u32 { self.num_locals }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn locals(&self) -> LocalsIterator { LocalsIterator::new(self.num_locals, &self.locals) }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn code(&self) -> &[u8] { &self.code.bytes }
}

impl<'a> RunnableCode for CompiledFunctionBytes<'a> {
    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn num_params(&self) -> u32 { self.params.len() as u32 }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn type_idx(&self) -> TypeIndex { self.type_idx }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn return_type(&self) -> BlockType { self.return_type }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn params(&self) -> &[ValueType] { self.params }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn num_locals(&self) -> u32 { self.num_locals }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn locals(&self) -> LocalsIterator { LocalsIterator::new(self.num_locals, &self.locals) }

    #[cfg_attr(not(feature = "fuzz-coverage"), inline(always))]
    fn code(&self) -> &[u8] { self.code }
}

/// A parsed Wasm module. This no longer has custom sections since they are not
/// needed for further processing.
/// The type parameter `ImportFunc` is instantiated with the representation of
/// host functions. To efficiently and relatively safely execute the module we
/// preprocess imported functions into an enum. However for testing we sometimes
/// just use raw imports. This type parameter allows us flexibility.
/// The type parameter `RunnableCode` is used to allow flexibility in code
/// representation. For testing uses it is convenient that the type is
/// "owned", in the sense of it being a vector of instructions. For efficient
/// execution, and to avoid deserialization, the code is represented as a byte
/// array (i.e., as as slice of bytes `&[u8]`) when we execute it on the node.
#[derive(Debug, Clone)]
pub struct Artifact<ImportFunc, CompiledCode> {
    /// Imports by (module name, item name).
    pub imports: Vec<ImportFunc>,
    /// Types of the module. These are needed for dynamic dispatch, i.e.,
    /// call-indirect.
    pub ty:      Vec<FunctionType>,
    /// A fully instantiated table.
    pub table:   InstantiatedTable,
    /// The memory of the artifact.
    pub memory:  Option<ArtifactMemory>,
    /// Globals initialized with initial values.
    pub global:  InstantiatedGlobals,
    /// The exported functions.
    /// Validation should ensure that an exported function is a defined one,
    /// and not one of the imported ones.
    /// Thus the index refers to the index in the code section.
    pub export:  BTreeMap<Name, FuncIndex>,
    pub code:    Vec<CompiledCode>,
}

/// Ar artifact which does not own the code to run. The code is only a reference
/// to a byte array.
pub type BorrowedArtifact<'a, ImportFunc> = Artifact<ImportFunc, CompiledFunctionBytes<'a>>;
/// An artifact that owns the code to run.
pub type OwnedArtifact<ImportFunc> = Artifact<ImportFunc, CompiledFunction>;

/// Convert a borrowed artifact to an owned one. This allocates memory for all
/// the code of the artifact so it should be used sparingly.
impl<'a, ImportFunc> From<BorrowedArtifact<'a, ImportFunc>> for OwnedArtifact<ImportFunc> {
    fn from(a: BorrowedArtifact<'a, ImportFunc>) -> Self {
        let Artifact {
            imports,
            ty,
            table,
            memory,
            global,
            export,
            code,
        } = a;
        Self {
            imports,
            ty,
            table,
            memory,
            global,
            export,
            code: code.into_iter().map(CompiledFunction::from).collect::<Vec<_>>(),
        }
    }
}

/// Convert a borrowed artifact to an owned one inside an `Arc`. This allocates
/// memory for all the code of the artifact so it should be used sparingly.
impl<'a, ImportFunc> From<BorrowedArtifact<'a, ImportFunc>> for Arc<OwnedArtifact<ImportFunc>> {
    fn from(a: BorrowedArtifact<'a, ImportFunc>) -> Self { Arc::new(a.into()) }
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

/// Result of compilation. Either Ok(_) or an error indicating the reason.
pub type CompileResult<A> = anyhow::Result<A>;

#[derive(Default, Debug, Clone, From, Into)]
/// A sequence of internal opcodes, followed by any immediate arguments.
pub struct Instructions {
    pub(crate) bytes: Vec<u8>,
}

impl Instructions {
    fn push(&mut self, opcode: InternalOpcode) { self.bytes.push(opcode as u8) }

    fn push_u16(&mut self, x: u16) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    fn push_u32(&mut self, x: u32) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    fn push_i32(&mut self, x: i32) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    fn push_i64(&mut self, x: i64) { self.bytes.extend_from_slice(&x.to_le_bytes()); }

    fn current_offset(&self) -> usize { self.bytes.len() }

    fn back_patch(&mut self, back_loc: usize, to_write: u32) -> CompileResult<()> {
        let mut place: &mut [u8] = &mut self.bytes[back_loc..];
        place.write_all(&to_write.to_le_bytes())?;
        Ok(())
    }
}

/// Target of a jump that we need to keep track of temporarily.
enum JumpTarget {
    /// We know the position in the instruction sequence where the jump should
    /// resolve to. This is used in the case of loops.
    Known {
        pos: usize,
    },
    /// We do not yet know where in the instruction sequence we will jump to.
    /// We record the list of places at which we need to back-patch the location
    /// when we get to it.
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
/// Stack of jump targets
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
/// An intermediate structure of the instruction sequence plus any pending
/// backpatch locations we need to resolve.
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
        old_stack_height: usize, // stack height before the jump
        instruction: Option<(InternalOpcode, InternalOpcode)>,
    ) -> CompileResult<()> {
        let target_frame = state
            .ctrls
            .get(label_idx)
            .ok_or_else(|| anyhow!("Could not get jump target frame."))?;
        let target_height = target_frame.height;
        ensure!(
            old_stack_height >= target_height,
            "Current height must be at least as much as the target, {} >= {}",
            old_stack_height,
            target_height
        );
        let diff = if let BlockType::EmptyType = target_frame.label_type {
            if let Some((l, _)) = instruction {
                self.out.push(l);
            }
            (old_stack_height - target_height).try_into()?
        } else {
            if let Some((_, r)) = instruction {
                self.out.push(r);
            }
            (old_stack_height - target_height).try_into()?
        };
        // output the difference in stack heights.
        self.out.push_u32(diff);
        let target = self.backpatch.get_mut(label_idx)?;
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

    fn handle_opcode(
        &mut self,
        state: &ValidationState,
        stack_height: usize,
        opcode: &OpCode,
    ) -> CompileResult<()> {
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
                self.push_jump(0, state, stack_height, Some((Br, BrCarry)))?;
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
                self.push_jump(*label_idx, state, stack_height, Some((Br, BrCarry)))?;
            }
            OpCode::BrIf(label_idx) => {
                self.push_jump(*label_idx, state, stack_height, Some((BrIf, BrIfCarry)))?;
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
                self.push_jump(*default, state, stack_height, None)?;
                // The label types are the same for the default as well all the other
                // labels.
                for label_idx in labels {
                    self.push_jump(*label_idx, state, stack_height, None)?;
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

    fn finish(self, _state: &ValidationState) -> CompileResult<Self::Outcome> {
        ensure!(self.backpatch.stack.is_empty(), "There are still jumps to backpatch.");
        Ok(self.out)
    }
}

struct ModuleContext<'a> {
    module: &'a Module,
    locals: &'a [LocalsRange],
    code:   &'a Code,
}

impl<'a> HasValidationContext for ModuleContext<'a> {
    fn get_local(&self, idx: u32) -> CompileResult<ValueType> {
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

/// Compile a module into an artifact, failing if there are problems.
/// Problems should not arise if the module is well-formed, and all the imports
/// are supported by the `I` type.
impl Module {
    pub fn compile<I: TryFromImport>(self) -> CompileResult<Artifact<I, CompiledFunction>> {
        let mut code_out = Vec::with_capacity(self.code.impls.len());

        for code in self.code.impls.iter() {
            let mut ranges = Vec::with_capacity(code.ty.parameters.len() + code.locals.len());
            let mut locals = Vec::with_capacity(code.ty.parameters.len() + code.locals.len());
            let mut start = 0;
            for &param in code.ty.parameters.iter() {
                let end = start + 1;
                ranges.push(LocalsRange {
                    start,
                    end,
                    ty: param,
                });
                start = end;
            }
            for &local in code.locals.iter() {
                locals.push(ArtifactLocal::try_from(local)?);
                let end = start + local.multiplicity;
                ranges.push(LocalsRange {
                    start,
                    end,
                    ty: local.ty,
                });
                start = end;
            }

            let context = ModuleContext {
                module: &self,
                locals: &ranges,
                code,
            };

            let mut exec_code =
                validate(&context, code.expr.instrs.iter().map(Result::Ok), BackPatch::new())?;
            // We add a return instruction at the end so we have an easier time in the
            // interpreter since there is no implicit return.
            exec_code.push(InternalOpcode::Return);

            let num_params: u32 = code.ty.parameters.len().try_into()?;

            let result = CompiledFunction {
                type_idx: code.ty_idx,
                params: code.ty.parameters.clone(),
                num_locals: start - num_params,
                locals,
                return_type: BlockType::from(code.ty.result),
                code: exec_code,
            };
            code_out.push(result)
        }

        let ty = self.ty.types.into_iter().map(|x| (*x).clone()).collect::<Vec<FunctionType>>();
        let table = {
            if let Some(tt) = self.table.table_type {
                let mut functions = vec![None; tt.limits.min as usize];
                for init in self.element.elements.iter() {
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
            if let Some(mt) = self.memory.memory_type {
                Some(ArtifactMemory {
                    init_size: mt.limits.min,
                    max_size:  mt
                        .limits
                        .max
                        .map(|x| std::cmp::min(x, MAX_NUM_PAGES))
                        .unwrap_or(MAX_NUM_PAGES),
                    init:      self
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
            inits: self.global.globals.iter().map(|x| x.init).collect::<Vec<_>>(),
        };
        let export = self
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
        let imports = self
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
}
