pub use crate::types::*;

// TODO set these indices to the imports of the respective accounting host
// functions. They should be given by the specification.
const FN_IDX_ACCOUNT_ENERGY: FuncIndex = 0;
const FN_IDX_ACCOUNT_STACK_SIZE: FuncIndex = 1;
const FN_IDX_MEMORY_ALLOC: FuncIndex = 2;

/// Definition of energy costs of instructions. See cost specification.
/// TODO The concrete factors between different costs are not specified in the specification yet,
/// and the values chosen here are rather exemplary; they still have to be carefully determined.
pub mod cost {
    pub type Energy = u64; // TODO import type from elsewhere
    use crate::types::*;

    // General costs
    pub const FUNC_FRAME_BASE: Energy = 10;
    pub const LOOKUP: Energy = 10;
    pub const JUMP: Energy = 1;
    pub const JUMP_STACK: Energy = 1;

    pub const fn read_stack(n: usize) -> Energy {
        (n as Energy) * 2
    }

    pub const fn write_stack(n: usize) -> Energy {
        (n as Energy) * 2
    }

    pub const fn copy_stack(n: usize) -> Energy {
        (n as Energy) * 8
    }

    pub const TEST: Energy = 2;
    pub const BOUNDS: Energy = 10;

    pub const fn read_mem(n: usize) -> Energy {
        100 + (n as Energy) * 5
    }

    pub const fn write_mem(n: usize) -> Energy {
        100 + (n as Energy) * 5
    }

    // Numeric instructions
    pub const UNOP: Energy = read_stack(1) + write_stack(1);
    pub const BINOP: Energy = read_stack(1) + write_stack(1);
    pub const CONST: Energy = write_stack(1);
    pub const SIMPLE_UNOP: Energy = UNOP + 1;
    pub const SIMPLE_BINOP: Energy = BINOP + 1;
    // See for example https://streamhpc.com/blog/2012-07-16/how-expensive-is-an-operation-on-a-cpu/
    pub const MUL: Energy = BINOP + 4;
    pub const DIV: Energy = BINOP + 10;
    pub const REM: Energy = BINOP + 10;


    // Parametric instructions
    pub const DROP: Energy = JUMP_STACK;
    pub const SELECT: Energy = TEST + JUMP_STACK + copy_stack(1);

    // Variable instructions
    pub const GET_LOCAL: Energy = read_stack(1) + write_stack(1);
    pub const SET_LOCAL: Energy = read_stack(1) + write_stack(1);
    pub const TEE_LOCAL: Energy = read_stack(1) + write_stack(1);
    // TODO: The current specification distinguishes between 4 or 8 bytes, but to simplify implementation
    // (we would need to lookup the type of the global index) we might not want to change this
    // to not distinguish.
    pub const GET_GLOBAL: Energy = read_mem(8);
    pub const SET_GLOBAL: Energy = write_mem(8); // NB: We do not distinguish between 4 or 8 bytes.

    // Memory instructions
    pub const fn load(n: usize) -> Energy {
        SIMPLE_BINOP + BOUNDS + read_mem(n)
    }

    pub const fn store(n: usize) -> Energy {
        SIMPLE_BINOP + BOUNDS + write_mem(n)
    }

    pub const MEMSIZE: Energy = 100;
    // Constant part for the memory grow instruction.
    pub const MEMGROW: Energy = 1000;

    // Control instructions
    pub const NOP: Energy = JUMP;

    pub const IF: Energy = TEST + JUMP;

    pub const fn branch(label_arity: usize) -> Energy {
        JUMP + copy_stack(label_arity)
    }

    // This is only the cost to be charged before the replacement instruction.
    pub const BR_IF: Energy = IF;

    pub const fn br_table(label_arity: usize) -> Energy {
        BOUNDS + LOOKUP + branch(label_arity)
    }

    // Cost for invoking a function (to be charged before invocation), excluding the
    // cost incurred by the number of locals the function defines (for the latter,
    // see `invoke_after`).
    pub const fn invoke_before(num_args: usize, num_res: usize) -> Energy {
        // Enter frame
        FUNC_FRAME_BASE + copy_stack(num_args) + JUMP
         // Leave frame
         + copy_stack(num_res) + JUMP
    }

    // Cost incurred by the number of locals when invoking a function (to be charged
    // after invocation).
    pub const fn invoke_after(num_locals: usize) -> Energy {
        // Enter frame
        write_stack(num_locals)
    }

    pub fn get_cost(instr: &Instruction, labels: &Vec<usize>, module: &Module) -> Energy {
        use crate::types::Instruction::*;
        match instr {
            // Control instructions
            Nop => NOP,
            Unreachable => 0,
            Block(_, _) => 0,
            Loop(_, _) => 0,
            If(_, _, _) => IF,
            Br(idx) => branch(lookup_label(labels, *idx)),
            BrIf(_) => BR_IF,
            BrTable(_, idx_default) => br_table(lookup_label(labels, *idx_default)),
            Return => 0,
            Call(idx) => {
                let (num_args, num_res) = module.get_func_type_len(*idx);
                invoke_before(num_args, num_res)
            }
            CallIndirect(ty_idx) => {
                let (num_args, num_res) = module.get_type_len(*ty_idx);
                invoke_before(num_args, num_res)
            }

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
            // NB: The cost is currently always based on whether it is an I32 or an I64 instruction.
            I32Load(_) => load(4),
            I64Load(_) => load(8),
            I32Load8S(_) => load(4),
            I32Load8U(_) => load(4),
            I32Load16S(_) => load(4),
            I32Load16U(_) => load(4),
            I64Load8S(_) => load(8),
            I64Load8U(_) => load(8),
            I64Load16S(_) => load(8),
            I64Load16U(_) => load(8),
            I64Load32S(_) => load(8),
            I64Load32U(_) => load(8),
            I32Store(_) => store(4),
            I64Store(_) => store(8),
            I32Store8(_) => store(4),
            I32Store16(_) => store(4),
            I64Store8(_) => store(8),
            I64Store16(_) => store(8),
            I64Store32(_) => store(8),
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
            I32GtU  => SIMPLE_BINOP,// With this instruction, the contract gets 2^32-4294967296 GTU.
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
            I64GtU  => SIMPLE_BINOP,// With this instruction, the contract gets 2^64-18446744073709551616 GTU.
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
            I32Extend8S => SIMPLE_UNOP,
            I32Extend16S => SIMPLE_UNOP,
            I64Extend8S => SIMPLE_UNOP,
            I64Extend16S => SIMPLE_UNOP,
            I64Extend32S => SIMPLE_UNOP,
        }
    }
}

use cost::Energy;

// Add energy accounting instructions.
fn account_energy(exp: &mut InstrSeq, e: Energy) {
    // TODO the current specification says we use an I32Const. Decide what is actually the best also regarding conversion etc. Probably i64 is actually fine.
    // NB: The u64 energy value is written as is, and will be reinterpreted as u64 again in the host function call.
    exp.push(Instruction::I64Const(e as i64));
    exp.push(Instruction::Call(FN_IDX_ACCOUNT_ENERGY));
}

// Add stack accounting instructions.
fn account_stack_size(exp: &mut InstrSeq, size: i64) {
    exp.push(Instruction::I64Const(size));
    exp.push(Instruction::Call(FN_IDX_ACCOUNT_STACK_SIZE));
}

// Metadata needed for transformation.
struct InstrSeqTransformer<'a> {
    module: &'a Module,
    max_stack_size: i64,
    // Current label stack (in the form of the labels' arities).
    labels: Vec<usize>,
    // `seq` with injected accounting.
    new_seq: InstrSeq,
    // Whether to add an accounting instruction at the beginning of the sequence for the first
    // instructions in the sequence. Otherwise the energy for these first instructions is returned
    // with the result.
    insert_account_energy_beginning: bool,
    // Amount to charge for the first instructions in the sequence, before the first injected
    // accounting instruction. This can be added to an earlier charging instruction.
    energy_first_part: Option<Energy>,
    // Accumulator for energy to be charged for the pending instructions.
    energy: Energy,
    // NOTE: Performance could be improved with adding charging instructions directly,
    // updating the energy value in-place after it has been determined.
    pending_instructions: InstrSeq,
    // Original sequence
    seq: &'a InstrSeq,
}

impl<'b> InstrSeqTransformer<'b> {
    /// Inject cost accounting into the function, according to cost
    /// specification version XXX.
    /// This requires function.max_stack_size to be present.
    pub fn inject_accounting(function: &Function, module: &Module) -> Function {
        let mut transformer = InstrSeqTransformer {
            module,
            max_stack_size: function.max_stack_size.unwrap() as i64,
            labels: Vec::new(),
            new_seq: InstrSeq::new(),
            insert_account_energy_beginning: false,
            energy_first_part: None,
            energy: 0,
            pending_instructions: InstrSeq::new(),
            seq: &function.body,
        };

        // We create a new body expression, as in-place modification (as far as
        // possible) will probably not be cheaper anyway.
        let mut new_body: InstrSeq = InstrSeq::new();

        // At the beginning of a function, we charge for its invocation and the first
        // unconditionally executed instructions of the body and account for its maximum
        // stack size.
        let (energy_body_first_part, mut injected) = transformer.run();
        let mut first_energy_accounting = cost::invoke_after(function.locals.len());
        if let Some(e) = energy_body_first_part {
            first_energy_accounting += e;
        }
        account_energy(&mut new_body, first_energy_accounting);
        account_stack_size(&mut new_body, transformer.max_stack_size);

        new_body.append(&mut injected);

        // At the end of the function (in addition to before every return statement), we
        // have to account and for stack size again (subtract the previously added stack
        // size for this function).
        account_stack_size(&mut new_body, -transformer.max_stack_size);

        Function {
            body: new_body,
            locals: function.locals.clone(),
            ..*function
        }
    }

    /// Run a "sub transformer" on the given sequence.
    /// the given label arity is pushed on top of the label stack.
    fn run_sub(
        &self,
        seq: &'b InstrSeq,
        label_arity: usize,
        insert_account_energy_beginning: bool,
    ) -> (Option<Energy>, InstrSeq) {
        let mut sub_transformer = InstrSeqTransformer {
            module: self.module,
            // Max stack size is that of the current function.
            max_stack_size: self.max_stack_size,
            labels: self.labels.clone(),
            new_seq: InstrSeq::new(),
            insert_account_energy_beginning,
            energy_first_part: None,
            energy: 0,
            pending_instructions: InstrSeq::new(),
            seq,
        };
        sub_transformer.labels.push(label_arity);
        sub_transformer.run()
    }

    fn lookup_label(&mut self, idx: LabelIndex) -> usize {
        lookup_label(&mut self.labels, idx)
    }

    fn get_block_type_len(&self, bt: &BlockType) -> usize {
        self.module.get_block_type_len(bt)
    }

    fn account_energy(&mut self, e: Energy) {
        account_energy(&mut self.new_seq, e)
    }

    fn account_stack_size(&mut self, size: i64) {
        account_stack_size(&mut self.new_seq, size)
    }

    fn add_energy(&mut self, e: Energy) {
        self.energy += e;
    }

    fn account_energy_push_pending(&mut self) {
        if self.insert_account_energy_beginning {
            self.account_energy(self.energy);
        } else {
            // Depending on the cost factors, `energy` could be 0. But as this should only
            // happen in very unsual cases, we should probably not add a check to optimizing
            // in this case.
            if self.energy_first_part.is_none() {
                self.energy_first_part = Some(self.energy);
            } else {
                self.account_energy(self.energy);
            }
        }
        self.energy = 0;
        // Move the pending instructions for which the last two instructions charge to
        // new_body.
        println!(
            "On {:?}: Moving pending to new: {:?}",
            self.seq, self.pending_instructions
        );
        self.new_seq.append(&mut self.pending_instructions);
    }

    fn add_instr_account_energy(&mut self, instr: &Instruction) {
        self.account_energy_push_pending();
        self.add_to_new(instr);
    }

    fn add_to_pending(&mut self, instr: &Instruction) {
        println!("On {:?}: Adding to pending: {:?}", self.seq, *instr);
        self.pending_instructions.push(instr.clone());
    }

    fn add_to_new(&mut self, instr: &Instruction) {
        println!("On {:?}: Adding to new: {:?}", self.seq, *instr);
        self.new_seq.push(instr.clone());
    }

    // Injects accounting instructions into a sequence of instructions, returning
    // the energy to charge for the first instructions that will be unconditionally
    // executed. This energy has to be charged for before.
    fn run(&mut self) -> (Option<Energy>, InstrSeq) {
        use crate::types::Instruction::*;

        for instr in self.seq.iter() {
            // First add the energy to be charged for this instruction to the accumulated
            // energy.
            self.add_energy(cost::get_cost(instr, &self.labels, &self.module));

            // Then determine whether the current unconditional instruction sequence stops
            // (in which case the amount to charge for the collected instructions is now
            // collected in `energy`) or what other accounting instructions have to be
            // inserted.
            match instr {
                Block(bt, bseq) => {
                    // For block, the energy cost of the first instructions can be combined with
                    // that for previous instructions.
                    let (energy_first_part, bseq_new) =
                        self.run_sub(&bseq, self.get_block_type_len(bt), false);
                    if let Some(e) = energy_first_part {
                        self.add_energy(e);
                    }
                    // Charge for the current sequence including the first insstructions of the
                    // block.
                    self.account_energy_push_pending();
                    self.add_to_new(&Block(bt.clone(), bseq_new));
                }
                Loop(bt, bseq) => {
                    // For "loop", we have to charge as the first instruction of the loop.
                    let (_, bseq_new) = self.run_sub(&bseq, self.get_block_type_len(bt), true);
                    self.account_energy_push_pending();
                    self.add_to_new(&Loop(bt.clone(), bseq_new));
                }
                If(bt, seq1, seq2) => {
                    let (_, seq1_new) = self.run_sub(&seq1, self.get_block_type_len(bt), true);
                    let (_, seq2_new) = self.run_sub(&seq2, self.get_block_type_len(bt), true);
                    self.account_energy_push_pending();
                    self.add_to_new(&If(bt.clone(), seq1_new, seq2_new));
                }
                Return => {
                    // First charge for all pending instructions and execute all pending
                    // instructions.
                    self.account_energy_push_pending();
                    // Finally account for stack size by reducing it by the same value it was
                    // increased when entering the function, then return.
                    self.account_stack_size(-self.max_stack_size);
                    // The return instruction.
                    self.add_to_new(instr);
                }
                MemoryGrow => {
                    // The memory allocation accounting call can for energy accounting also be
                    // combined with other instructions.
                    self.add_to_pending(&Call(FN_IDX_MEMORY_ALLOC));
                    self.add_to_pending(instr);
                }
                Unreachable => self.add_instr_account_energy(instr),
                Br(_) => self.add_instr_account_energy(instr),
                BrIf(idx) => {
                    // NB: We must not add the original instruction - it is replaced with a new
                    // instruction.
                    self.account_energy_push_pending();
                    let mut bseq1 = InstrSeq::new();
                    // We do not need to update the labels vector for this non-recursive
                    // replacement. Therefore, the original label index is still
                    // valid here.
                    account_energy(&mut bseq1, cost::branch(self.lookup_label(*idx)));
                    // In the replacement instruction, the lable moves out by one index and
                    // therefore the index has to be incremented.
                    bseq1.push(Br(idx + 1));
                    // NB: The cost for "if" has already been added by `get_cost`.
                    self.add_to_new(&If(BlockType::EmptyType, bseq1, vec![Nop]));
                }
                BrTable(_, _) => self.add_instr_account_energy(instr),
                Call(_) => self.add_instr_account_energy(instr),
                CallIndirect(_) => self.add_instr_account_energy(instr),

                _ => {
                    // In all other cases, just add the instruction to the pending instructions.
                    self.add_to_pending(instr);
                }
            }
        }
        if !self.pending_instructions.is_empty() {
            self.account_energy_push_pending();
        }
        // TODO is there an alternative to cloning here? Returning reference does not
        // work directly.
        (self.energy_first_part, self.new_seq.clone())
    }
}

#[cfg(test)]
#[path = "./transformations_test.rs"]
mod transformations_test;
