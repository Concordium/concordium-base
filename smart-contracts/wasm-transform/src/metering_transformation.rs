//! A program transformation that inserts metering instructions into
//! a Wasm module.

use crate::types::*;
use anyhow::{anyhow, bail};
use std::{convert::TryInto, rc::Rc};

/// TODO set these indices to the imports of the respective accounting host
/// functions. They should be given by the specification.
/// The type of this function should be i64 -> ()
pub const FN_IDX_ACCOUNT_ENERGY: FuncIndex = 0;
/// Dynamically track calls to enable us to limit the number of active
/// frames.
/// The type of this function should be unit to unit.
pub const FN_IDX_TRACK_CALL: FuncIndex = 1;
/// Track returns so that we can keep the count correctly.
/// The type of this function should be () -> ().
pub const FN_IDX_TRACK_RETURN: FuncIndex = 2;
/// Charge for memory allocation. The type of this
/// function should be i32 -> i32.
pub const FN_IDX_MEMORY_ALLOC: FuncIndex = 3;

/// The number of added functions. All functions that are in the source module
/// will have the indices shifted by this amount.
/// The table as well must be updated by increasing all the function indices by
/// this constant.
pub const NUM_ADDED_FUNCTIONS: FuncIndex = 4;

/// Result of a transformation. The transformation should generally not fail on
/// a well-formed module, i.e., one that has been validated. But we might want
/// to put additional restrictions on a module, in which case we have the
/// freedom to fail.
pub type TransformationResult<A> = anyhow::Result<A>;

/// Return the arity of the label, i.e., 0 or 1.
fn lookup_label(labels: &[BlockType], idx: LabelIndex) -> TransformationResult<usize> {
    if (idx as usize) < labels.len() {
        let i = labels.len() - 1 - idx as usize;
        match labels[i] {
            BlockType::EmptyType => Ok(0),
            BlockType::ValueType(_) => Ok(1),
        }
    } else {
        bail!("Label {} not found.", idx)
    }
}

/// Definition of energy costs of instructions.
pub mod cost {
    pub type Energy = u64;
    use super::*;

    /// Part of a cost of a function call related to allocating
    /// a new function frame and storing values of locals, etc.
    pub const FUNC_FRAME_BASE: Energy = 10;

    /// Cost of a jump (either Br, Loop, or analogous).
    pub const JUMP: Energy = 8;

    /// Read n elements from the stack.
    pub const fn read_stack(n: u32) -> Energy { n as Energy }

    /// Write n elements to the stack.
    pub const fn write_stack(n: u32) -> Energy { n as Energy }

    /// Copy n elements from one place in the stack to another.
    /// Used by jumps and function returns.
    pub const fn copy_stack(n: usize) -> Energy { n as Energy }

    /// Cost of a boolean test.
    pub const TEST: Energy = 2;
    /// Cost of a bounds check in, for example, BrTable, and memory loads
    /// and stores.
    pub const BOUNDS: Energy = 2;

    /// # Numeric instructions
    /// Base cost of a unary instruction.
    pub const UNOP: Energy = read_stack(1) + write_stack(1);
    /// Base cost of a binary instruction.
    pub const BINOP: Energy = read_stack(2) + write_stack(1);
    /// Cost of a `const` instruction.
    pub const CONST: Energy = 1 + write_stack(1);

    /// Cost of a simple unary instruction. Which at present contains
    /// all unary numeric instructions.
    pub const SIMPLE_UNOP: Energy = UNOP + 1;

    /// Cost of a simple binary instruction. This includes all bit
    /// operations, and addition and subtraction.
    pub const SIMPLE_BINOP: Energy = BINOP + 1;
    /// See for example <https://streamhpc.com/blog/2012-07-16/how-expensive-is-an-operation-on-a-cpu/>
    /// The cost of `MUL`, `DIV` and `REM` is in general more, so we account for
    /// that. However the ratio compared to add is not that much more since our
    /// current implementation is an interpreter, and consequently there are
    /// overheads in argument handling that dominate the costs.
    pub const MUL: Energy = BINOP + 2;
    pub const DIV: Energy = BINOP + 2;
    pub const REM: Energy = BINOP + 2;

    /// Parametric instructions
    pub const DROP: Energy = 2;
    pub const SELECT: Energy = TEST + copy_stack(1);

    /// Local variable instructions are cheap. We treat them as stack
    /// operations.
    pub const GET_LOCAL: Energy = 1 + read_stack(1) + write_stack(1);
    pub const SET_LOCAL: Energy = 1 + read_stack(1) + write_stack(1);
    pub const TEE_LOCAL: Energy = 1 + read_stack(1) + write_stack(1);
    /// Looking up globals is cheap compared to linear memory.
    /// They are essentially the same as locals, except they are in a different
    /// array.
    pub const GET_GLOBAL: Energy = 1 + read_stack(1) + write_stack(1);
    pub const SET_GLOBAL: Energy = 1 + read_stack(1) + write_stack(1);

    /// # Memory instructions.
    /// Load either an i32 or i64 from linear memory.
    /// In practice the cost does not dependn on the number of bytes.
    pub const LOAD_WORD: Energy = 4;

    /// Store n bytes in linear memory.
    pub const fn store(n: usize) -> Energy { BOUNDS + 2 + n as Energy }

    /// Checking memory size is pretty cheap, it is just a vec.len() call.
    pub const MEMSIZE: Energy = write_stack(1) + 3;
    /// Constant part for the memory grow instruction. The variable part is
    /// charged for by the host function.
    pub const MEMGROW: Energy = read_stack(1) + write_stack(1) + 8;

    /// Control instructions
    ///
    /// A Nop really does not cost anything, but it does take up space, so we
    /// give it the least possible cost
    pub const NOP: Energy = 1;

    /// The if statement boils down to a test and a jump afterwards.
    /// Jumps are simply setting the instruction pointer.
    pub const IF_STATEMENT: Energy = TEST + JUMP;

    /// Cost of an unconditional jump with the given label arity.
    /// The label arity for us is either 0 or 1, since we do not support
    /// multiple return values.
    pub const fn branch(label_arity: usize) -> Energy { JUMP + copy_stack(label_arity) }

    /// BR_IF is almost the same as an IF statement, so we price it the same.
    pub const BR_IF: Energy = IF_STATEMENT;

    /// Cost of a branch with table (switch statement). This involves bounds
    /// checking on the array of labels, and then a normal branch.
    pub const fn br_table(label_arity: usize) -> Energy { BOUNDS + branch(label_arity) }

    /// Cost for invoking a function __before__ the entering the function.
    /// This excludes the cost incurred by the number of locals the function
    /// defines (for the latter, see `invoke_after`).
    pub const fn invoke_before(num_args: usize, num_res: usize) -> Energy {
        // Enter frame
        FUNC_FRAME_BASE + copy_stack(num_args) + JUMP
         // Leave frame
         + copy_stack(num_res) + JUMP
    }

    /// Cost incurred by the number of locals when invoking a function (to be
    /// charged after invocation). The number of locals is only the number of
    /// declared locals, not including function parameters.
    pub const fn invoke_after(num_locals: u32) -> Energy {
        // Enter frame and allocate the given number of locals.
        // Each local takes 8 bytes.
        4 * (num_locals as Energy)
    }

    /// Cost of call_indirect with the given number of arguments and results.
    /// This is expensive since it involves a dynamic type check.
    pub const fn call_indirect(num_args: usize, num_res: usize) -> Energy {
        BOUNDS + type_check(num_args + num_res) + invoke_before(num_args, num_res)
    }

    /// Cost of a dynamic type check. The argument is the number of types
    /// i.e., parameters + results that need to be checked.
    pub const fn type_check(len: usize) -> Energy { len as Energy }

    /// Get the cost of the given instruction in the context of the stack of
    /// labels, and the module.
    pub fn get_cost<C: HasTransformationContext>(
        instr: &OpCode,
        labels: &[BlockType],
        module: &C,
    ) -> TransformationResult<Energy> {
        use crate::types::OpCode::*;
        let res = match instr {
            // Control instructions
            Nop => NOP,
            Unreachable => 0,
            Block(_) => 0,
            Loop(_) => 0,
            If {
                ..
            } => IF_STATEMENT,
            Br(idx) => branch(lookup_label(labels, *idx)?),
            BrIf(_) => BR_IF,
            BrTable {
                default,
                ..
            } => br_table(lookup_label(labels, *default)?),
            Return => {
                // Return has the same cost as Br to the outermost branch.
                let return_ty = labels
                    .first()
                    .ok_or_else(|| anyhow!("Invariant violation, labels should not be empty."))?;
                branch(
                    if *return_ty == BlockType::EmptyType {
                        0
                    } else {
                        1
                    },
                )
            }
            Call(idx) => {
                let (num_args, num_res) = module.get_func_type_len(*idx)?;
                invoke_before(num_args, num_res)
            }
            CallIndirect(ty_idx) => {
                let (num_args, num_res) = module.get_type_len(*ty_idx)?;
                call_indirect(num_args, num_res)
            }
            End => 0,
            Else => 0,

            // Parametric instructions
            Drop => DROP,
            Select => SELECT,

            //Variable instructions
            LocalGet(_) => GET_LOCAL,
            LocalSet(_) => SET_LOCAL,
            LocalTee(_) => TEE_LOCAL,
            GlobalGet(_) => GET_GLOBAL,
            GlobalSet(_) => SET_GLOBAL,

            // Memory instructions
            I32Load(_) => LOAD_WORD,
            I64Load(_) => LOAD_WORD,
            I32Load8S(_) => LOAD_WORD,
            I32Load8U(_) => LOAD_WORD,
            I32Load16S(_) => LOAD_WORD,
            I32Load16U(_) => LOAD_WORD,
            I64Load8S(_) => LOAD_WORD,
            I64Load8U(_) => LOAD_WORD,
            I64Load16S(_) => LOAD_WORD,
            I64Load16U(_) => LOAD_WORD,
            I64Load32S(_) => LOAD_WORD,
            I64Load32U(_) => LOAD_WORD,
            I32Store(_) => BOUNDS + 2 + 4,
            I64Store(_) => BOUNDS + 2 + 6,
            I32Store8(_) => BOUNDS + 2 + 1,
            I32Store16(_) => BOUNDS + 2 + 4,
            I64Store8(_) => BOUNDS + 2 + 1 + 2,
            I64Store16(_) => BOUNDS + 2 + 2 + 3,
            I64Store32(_) => BOUNDS + 2 + 2 + 4,
            MemorySize => MEMSIZE,
            MemoryGrow => MEMGROW,

            // Numeric instructions
            I32Const(_) => CONST,
            I64Const(_) => CONST,

            I32Eqz => SIMPLE_UNOP,
            I32Eq => SIMPLE_BINOP,
            I32Ne => SIMPLE_BINOP,
            I32LtS => SIMPLE_BINOP,
            I32LtU => SIMPLE_BINOP,
            I32GtS => SIMPLE_BINOP,
            I32GtU => SIMPLE_BINOP,
            I32LeS => SIMPLE_BINOP,
            I32LeU => SIMPLE_BINOP,
            I32GeS => SIMPLE_BINOP,
            I32GeU => SIMPLE_BINOP,
            I64Eqz => SIMPLE_UNOP,
            I64Eq => SIMPLE_BINOP,
            I64Ne => SIMPLE_BINOP,
            I64LtS => SIMPLE_BINOP,
            I64LtU => SIMPLE_BINOP,
            I64GtS => SIMPLE_BINOP,
            I64GtU => SIMPLE_BINOP,
            I64LeS => SIMPLE_BINOP,
            I64LeU => SIMPLE_BINOP,
            I64GeS => SIMPLE_BINOP,
            I64GeU => SIMPLE_BINOP,

            I32Clz => SIMPLE_UNOP,
            I32Ctz => SIMPLE_UNOP,
            I32Popcnt => SIMPLE_UNOP,
            I32Add => SIMPLE_BINOP,
            I32Sub => SIMPLE_BINOP,
            I32Mul => MUL,
            I32DivS => DIV,
            I32DivU => DIV,
            I32RemS => REM,
            I32RemU => REM,
            I32And => SIMPLE_BINOP,
            I32Or => SIMPLE_BINOP,
            I32Xor => SIMPLE_BINOP,
            I32Shl => SIMPLE_BINOP,
            I32ShrS => SIMPLE_BINOP,
            I32ShrU => SIMPLE_BINOP,
            I32Rotl => SIMPLE_BINOP,
            I32Rotr => SIMPLE_BINOP,
            I64Clz => SIMPLE_UNOP,
            I64Ctz => SIMPLE_UNOP,
            I64Popcnt => SIMPLE_UNOP,
            I64Add => SIMPLE_BINOP,
            I64Sub => SIMPLE_BINOP,
            I64Mul => MUL,
            I64DivS => DIV,
            I64DivU => DIV,
            I64RemS => REM,
            I64RemU => REM,
            I64And => SIMPLE_BINOP,
            I64Or => SIMPLE_BINOP,
            I64Xor => SIMPLE_BINOP,
            I64Shl => SIMPLE_BINOP,
            I64ShrS => SIMPLE_BINOP,
            I64ShrU => SIMPLE_BINOP,
            I64Rotl => SIMPLE_BINOP,
            I64Rotr => SIMPLE_BINOP,

            I32WrapI64 => SIMPLE_UNOP,
            I64ExtendI32S => SIMPLE_UNOP,
            I64ExtendI32U => SIMPLE_UNOP,
        };
        Ok(res)
    }
}

use cost::Energy;

// // TODO: Add stack accounting instructions.
// fn account_stack_size(exp: &mut InstrSeq, size: i64) {
//     exp.push(OpCode::I64Const(size));
//     exp.push(OpCode::Call(FN_IDX_ACCOUNT_STACK_SIZE));
// }

///Metadata needed for transformation.
struct InstrSeqTransformer<'a, C> {
    /// Reference to the original module to get the right context.
    module:               &'a C,
    /// Current label stack (in the form of the labels' arities).
    /// The last item in the vector is the innermost block label.
    labels:               Vec<BlockType>,
    /// The transformed sequence with accounting instructions inserded.
    new_seq:              InstrSeq,
    /// Accumulator for energy to be charged for the pending (and currently to
    /// be added) instructions.
    energy:               Energy,
    /// Pending instructions that are going to be inserted after the energy
    /// charging instruction. This is a temporary cache.
    pending_instructions: InstrSeq,
}

impl<'b, C: HasTransformationContext> InstrSeqTransformer<'b, C> {
    fn lookup_label(&mut self, idx: LabelIndex) -> TransformationResult<usize> {
        lookup_label(&self.labels, idx)
    }

    fn account_energy(&mut self, e: Energy) {
        // TODO the current specification says we use an I64Const. Decide what is
        // actually the best also regarding conversion etc. Probably i64 is actually
        // fine. NB: The u64 energy value is written as is, and will be
        // reinterpreted as u64 again in the host function call.
        self.new_seq.push(OpCode::I64Const(e as i64));
        self.new_seq.push(OpCode::Call(FN_IDX_ACCOUNT_ENERGY));
    }

    // TODO fn account_stack_size(&mut self, size: i64) { account_stack_size(&mut
    // self.new_seq, size) }

    fn add_energy(&mut self, e: Energy) { self.energy += e; }

    /// Account for all of the pending energy and drain the pending OpCodes to
    /// the new output sequence.
    fn account_energy_push_pending(&mut self) {
        // If there is nothing to account for, do not insert accounting instructions.
        // This case can occur for example with nested loop instructions, or nested
        // blocks followed by a loop.
        if self.energy > 0 {
            self.account_energy(self.energy);
            self.energy = 0;
        }
        // Move the pending instructions for which we just accounted to new_seq.
        // NB: This leaves pending_instructions empty, and correctness relies on it.
        self.new_seq.append(&mut self.pending_instructions);
    }

    /// Account for all the pending energy, and push the given OpCode to the
    /// output list.
    fn add_instr_account_energy(&mut self, instr: &OpCode) {
        self.account_energy_push_pending();
        self.add_to_new(instr);
    }

    /// Add the OpCode to the pending sequence.
    fn add_to_pending(&mut self, instr: &OpCode) { self.pending_instructions.push(instr.clone()); }

    /// Add the OpCode to the output sequence.
    fn add_to_new(&mut self, instr: &OpCode) { self.new_seq.push(instr.clone()); }

    /// Injects accounting instructions into a sequence of instructions,
    /// returning the energy to charge for the first instructions that will
    /// be unconditionally executed. This energy has to be charged for
    /// before.
    fn run(
        &mut self,
        input_instructions: impl Iterator<Item = &'b OpCode>,
    ) -> TransformationResult<()> {
        use crate::types::OpCode::*;

        for instr in input_instructions {
            // First add the energy to be charged for this instruction to the accumulated
            // energy.
            self.add_energy(cost::get_cost(instr, &self.labels, self.module)?);

            // Then determine whether the current unconditional instruction sequence stops
            // (in which case the amount to charge for the collected instructions is now
            // collected in `energy`) or what other accounting instructions have to be
            // inserted.
            match instr {
                Block(bt) => {
                    // For block, the energy cost of the first instructions can be combined with
                    // that for previous instructions.
                    // So we do not do anything other than continue processing the  the
                    // instructions.
                    self.labels.push(*bt);
                    self.add_to_pending(instr);
                }
                Loop(_) => {
                    // account for all the pending instructions up to this point since a loop can be
                    // entered multiple times.
                    self.account_energy_push_pending();
                    // A loop's label type is its argument type.
                    self.labels.push(BlockType::EmptyType);
                    self.add_to_new(instr);
                }
                If {
                    ty,
                } => {
                    // Since there are two branches we need to charge for all the instructions
                    // before we enter either of them, and start afresh.
                    self.account_energy_push_pending();
                    // An if-block's label type is its end type.
                    self.labels.push(*ty);
                    self.add_to_new(instr);
                }
                Return => {
                    // First charge for all pending instructions and execute all pending
                    // instructions.
                    self.account_energy_push_pending();
                    // Finally account for stack size by reducing it by the same value it was
                    // increased when entering the function, then return.
                    // TODO self.account_stack_size(-self.max_stack_size);
                    // The return instruction.
                    self.add_to_new(instr);
                }
                End => {
                    self.account_energy_push_pending();
                    self.labels.pop();
                    self.add_to_new(instr);
                }
                Else => {
                    self.account_energy_push_pending();
                    if let Some(ty) = self.labels.pop() {
                        self.labels.push(ty)
                    } else {
                        bail!(
                            "Instruction sequence malformed: Else branch that does not have a \
                             label."
                        )
                    }
                    self.add_to_new(instr);
                }
                MemoryGrow => {
                    // The memory allocation accounting call can for energy accounting also be
                    // combined with other instructions.
                    self.add_to_pending(&Call(FN_IDX_MEMORY_ALLOC));
                    self.add_to_pending(instr);
                }
                Unreachable => self.add_instr_account_energy(instr),
                Br(_) => {
                    self.add_instr_account_energy(instr);
                }
                BrIf(idx) => {
                    self.account_energy_push_pending();
                    let label_arity = self.lookup_label(*idx)?;
                    // If the target of the `br_if` instruction is the end of a block that returns
                    // nothing, we can replace the `br_if` instruction with an
                    // `if` block that includes metering instructions and a `br`. Example:
                    //
                    // block $b
                    //   ...
                    //   br_if $b1
                    // end
                    //
                    // gets transformed into
                    //
                    // block $b1
                    //   ...
                    //   if
                    //     ...metering code...
                    //     br $b1
                    //   end
                    // end
                    //
                    // However, if the target block $b1 returns a value, then this transformation
                    // would result in a type error because the typechecking of the contents of the
                    // if block happens without access to typing information of the stack variables
                    // that precede the block.
                    // As a result, the type checker cannot ensure that the contents of the if block
                    // produce the same type as the target block.
                    // Therefore, in case that the target block returns a type, we transform
                    // the above code as follows:
                    //
                    // block $b1
                    //   ...
                    //   if
                    //     ...metering code...
                    //     i32.const 1
                    //   else
                    //     i32.const 0
                    //   end
                    //   br_if $b1
                    // end
                    //
                    // Here, we insert the metering code before the `br_if` instruction,
                    // but immediately restore the "boolean" value of the preceding instruction
                    // through `i32.const 1` in the "then" branch and `i32.const 0` in the "else"
                    // branch. We thus avoid additional nesting of the `br_if` instruction
                    // while preserving the semantics of the program.
                    match label_arity {
                        0 => {
                            // Target block returns nothing
                            self.add_to_new(&If {
                                ty: BlockType::EmptyType,
                            });
                            self.account_energy(cost::branch(label_arity));
                            // In the replacement instruction, the label moves out by one index and
                            // therefore the index has to be incremented.
                            self.add_to_new(&Br(idx + 1));
                            self.add_to_new(&End);
                            // We do not need to update the labels vector for
                            // this non-recursive
                            // replacement. Therefore,
                            // the original label index is still
                            // valid here.
                        }
                        1 => {
                            // Target block returns a value
                            self.add_to_new(&If {
                                ty: BlockType::ValueType(ValueType::I32),
                            });
                            self.account_energy(cost::branch(label_arity));
                            self.add_to_new(&I32Const(1));
                            self.add_to_new(&Else);
                            self.add_to_new(&I32Const(0));
                            self.add_to_new(&End);
                            self.add_to_new(&BrIf(*idx));
                        }
                        n => bail!(
                            "Block must have either no or one return value. {} return values are \
                             not supported.",
                            n
                        ),
                    }
                }
                BrTable {
                    ..
                } => self.add_instr_account_energy(instr),
                // We need to change which function we call since we've inserted NUM_ADDED_FUNCTIONS
                // functions at the beginning of the module, for cost accounting.
                Call(idx) => {
                    self.add_to_pending(&Call(FN_IDX_TRACK_CALL));
                    self.add_instr_account_energy(&Call(idx + NUM_ADDED_FUNCTIONS));
                    self.add_to_new(&Call(FN_IDX_TRACK_RETURN));
                }
                // The call indirect function does not have to be reindexed since the table is.
                CallIndirect(_) => {
                    self.add_to_pending(&Call(FN_IDX_TRACK_CALL));
                    self.add_instr_account_energy(instr);
                    self.add_to_new(&Call(FN_IDX_TRACK_RETURN));
                }
                _ => {
                    // In all other cases, just add the instruction to the pending instructions.
                    self.add_to_pending(instr);
                }
            }
        }
        if !self.pending_instructions.is_empty() {
            self.account_energy_push_pending();
        }
        Ok(())
    }
}

/// A helper trait so that we can use the transformation on different datatypes.
/// In particular we use it in tests which have their own notion of context to
/// make it possible to specify modules in a compact way.
pub trait HasTransformationContext {
    /// Get the number of arguments and return values of a function type at the
    /// given index.
    fn get_type_len(&self, idx: TypeIndex) -> TransformationResult<(usize, usize)>;

    /// Get the number of parameters and return values of a function.
    /// In our version of Wasm there is at most one return value.
    fn get_func_type_len(&self, idx: FuncIndex) -> TransformationResult<(usize, usize)>;
}

impl HasTransformationContext for Module {
    fn get_type_len(&self, idx: TypeIndex) -> TransformationResult<(usize, usize)> {
        self.ty
            .get(idx)
            .map(|ty| {
                (
                    ty.parameters.len(),
                    if ty.result.is_some() {
                        1
                    } else {
                        0
                    },
                )
            })
            .ok_or_else(|| anyhow!("Type with index {} not found.", idx))
    }

    fn get_func_type_len(&self, idx: FuncIndex) -> TransformationResult<(usize, usize)> {
        let ty_idx =
            self.func.get(idx).ok_or_else(|| anyhow!("Function with index {} not found.", idx))?;
        self.get_type_len(ty_idx)
    }
}

/// Inject cost accounting into the function, according to cost
/// specification version XXX.
pub fn inject_accounting<C: HasTransformationContext>(
    function: &Code,
    module: &C,
) -> TransformationResult<Code> {
    // At the beginning of a function, we charge for its invocation and the first
    // unconditionally executed instructions of the body and account for its maximum
    // stack size.
    let num_params: u32 = function.ty.parameters.len().try_into()?;
    let energy =
        cost::invoke_after(function.num_locals.checked_sub(num_params).ok_or_else(|| {
            anyhow!(
                "Precondition violation. Number of locals is less than the number of parameters."
            )
        })?);

    let labels = vec![BlockType::from(function.ty.result)];
    let mut transformer = InstrSeqTransformer {
        module,
        labels,
        new_seq: InstrSeq::new(),
        energy,
        pending_instructions: Vec::new(),
    };

    transformer.run(function.expr.instrs.iter())?;

    Ok(Code {
        ty: function.ty.clone(),
        expr: Expression::from(transformer.new_seq),
        locals: function.locals.clone(),
        ..*function
    })
}

/// A context derived from a Wasm module.
struct ModuleContext<'a> {
    types:    &'a [Rc<FunctionType>],
    imported: &'a [Import],
    funcs:    &'a [TypeIndex],
}

impl<'a> HasTransformationContext for ModuleContext<'a> {
    fn get_type_len(&self, idx: TypeIndex) -> TransformationResult<(usize, usize)> {
        self.types
            .get(idx as usize)
            .map(|ty| {
                (
                    ty.parameters.len(),
                    if ty.result.is_some() {
                        1
                    } else {
                        0
                    },
                )
            })
            .ok_or_else(|| anyhow!("Type with index {} not found.", idx))
    }

    fn get_func_type_len(&self, idx: FuncIndex) -> TransformationResult<(usize, usize)> {
        let ty_idx = self
            .imported
            .get(idx as usize)
            .map(|i| match i.description {
                ImportDescription::Func {
                    type_idx,
                } => type_idx,
            })
            .or_else(|| self.funcs.get(idx as usize - self.imported.len()).copied())
            .ok_or_else(|| anyhow!("Function with index {} not found.", idx))?;
        self.get_type_len(ty_idx)
    }
}

impl Module {
    /// Add metering instructions to the module.
    pub fn inject_metering(&mut self) -> TransformationResult<()> {
        // Update the elements to account for the inserted imports.
        for elem in self.element.elements.iter_mut() {
            for init in elem.inits.iter_mut() {
                *init += NUM_ADDED_FUNCTIONS;
            }
        }
        let ctx = ModuleContext {
            types:    &self.ty.types,
            funcs:    &self.func.types,
            imported: &self.import.imports,
        };
        for code in self.code.impls.iter_mut() {
            let injected_code = inject_accounting(code, &ctx)?;
            *code = injected_code;
        }

        let num_types_originally: u32 = self.ty.types.len().try_into()?;
        // insert a new type for the new imports
        let mut new_types = Vec::with_capacity(self.ty.types.len() + NUM_ADDED_FUNCTIONS as usize);
        new_types.extend_from_slice(&self.ty.types);
        // account energy
        new_types.push(Rc::new(FunctionType {
            parameters: vec![ValueType::I64],
            result:     None,
        }));
        // account call/return
        new_types.push(Rc::new(FunctionType {
            parameters: Vec::new(),
            result:     None,
        }));
        // account memory alloc
        new_types.push(Rc::new(FunctionType {
            parameters: vec![ValueType::I32],
            result:     Some(ValueType::I32),
        }));
        self.ty.types = new_types;

        // Add functions to the beginning of the import list.
        let mut new_imports =
            Vec::with_capacity(NUM_ADDED_FUNCTIONS as usize + self.import.imports.len());
        new_imports.push(Import {
            mod_name:    Name {
                name: "concordium_metering".to_owned(),
            },
            item_name:   Name {
                name: "account_energy".to_owned(),
            },
            description: ImportDescription::Func {
                type_idx: num_types_originally,
            },
        });
        new_imports.push(Import {
            mod_name:    Name {
                name: "concordium_metering".to_owned(),
            },
            item_name:   Name {
                name: "track_call".to_owned(),
            },
            description: ImportDescription::Func {
                type_idx: num_types_originally + 1,
            },
        });
        new_imports.push(Import {
            mod_name:    Name {
                name: "concordium_metering".to_owned(),
            },
            item_name:   Name {
                name: "track_return".to_owned(),
            },
            description: ImportDescription::Func {
                type_idx: num_types_originally + 1,
            },
        });
        new_imports.push(Import {
            mod_name:    Name {
                name: "concordium_metering".to_owned(),
            },
            item_name:   Name {
                name: "account_memory".to_owned(),
            },
            description: ImportDescription::Func {
                type_idx: num_types_originally + 2,
            },
        });
        new_imports.append(&mut self.import.imports);
        self.import.imports = new_imports;
        for export in self.export.exports.iter_mut() {
            if let ExportDescription::Func {
                ref mut index,
            } = export.description
            {
                *index += NUM_ADDED_FUNCTIONS;
            }
        }
        Ok(())
    }
}
