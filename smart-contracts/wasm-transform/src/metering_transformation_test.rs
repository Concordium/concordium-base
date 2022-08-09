/**
Notes on the tests:
- Note: that the tests currently do not cover all instructions: for instructions that are handled identically by the transformation, only representatives are used.
- Not all test expressions might actually be valid Wasm; But for testing the accounting transformation this should not hurt and it can still be a useful test.

For further tests:
- Do some randomized tests, embedding chunks with known transformation results into each other / sequencing them will give more assurance.
- We should also have tests running the generated code and testing for semantical equivalence (apart from the semantical changes accounting introduces).
- Another way of testing is transforming and running programs and asserting the expected total energy accounted.
*/
use crate::types::*;
use std::rc::Rc;

use crate::{
    metering_transformation::{cost::*, *},
    types::{
        BlockType::{EmptyType, ValueType as BlockValue},
        OpCode::*,
        ValueType::*,
    },
};

macro_rules! flatten {
        ( $( $a:expr ),* ) => {
            {
                let mut temp_vec = Vec::<OpCode>::new();
                $(
                    for i in $a.iter() {
                        temp_vec.push(i.clone());
                    }
                )*
                temp_vec
            }
        };
    }

macro_rules! energy {
    ($e:expr) => {
        [I64Const($e as i64), Call(FN_IDX_ACCOUNT_ENERGY)]
    };
}

macro_rules! stack {
    ($e:expr) => {
        Vec::<OpCode>::new() // FIXME: I64Const($e as i64),
                             // Call(FN_IDX_ACCOUNT_STACK_SIZE)]
    };
}

macro_rules! mem_alloc {
    () => {
        [Call(FN_IDX_MEMORY_ALLOC)]
    };
}

fn mk_locals(tys: &[ValueType]) -> Vec<Local> {
    tys.iter()
        .copied()
        .map(|ty| Local {
            multiplicity: 1,
            ty,
        })
        .collect()
}

struct TransformationContext {
    types: Vec<FunctionType>,
    funcs: Vec<FunctionType>,
}

impl TransformationContext {
    pub fn empty() -> Self {
        Self {
            types: Vec::new(),
            funcs: Vec::new(),
        }
    }
}

impl HasTransformationContext for TransformationContext {
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
            .ok_or_else(|| anyhow::anyhow!("Type with index {} not found.", idx))
    }

    fn get_func_type_len(&self, idx: FuncIndex) -> TransformationResult<(usize, usize)> {
        self.funcs
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
            .ok_or_else(|| anyhow::anyhow!("Function with index {} not found.", idx))
    }
}

// Example MemArg
const MEMARG: MemArg = MemArg {
    offset: 0,
    align:  0,
};

/// Examplary function's stack size for `test_body` test cases.
// const S: i64 = 456;
/// Number of locals for `test_body` test cases.
const TEST_BODY_N_LOCALS: u32 = 2;
/// Energy for function entry for `test_body` test cases.
const ENTRY: Energy = invoke_after(TEST_BODY_N_LOCALS);

fn test_body(ty: FunctionType, body_orig: InstrSeq, body_expect: InstrSeq) {
    test_body_ctx(TransformationContext::empty(), ty, body_orig, body_expect)
}

fn test_body_ctx(
    ctx: TransformationContext,
    ty: FunctionType,
    body_orig: InstrSeq,
    body_expect: InstrSeq,
) {
    // TODO Add type 0 with type lengths (3,2) (this is used in testing below)
    // TODO Add type 1 = [i32 i32] -> [i32] (lengths (2,1)) (this is used in testing
    // below) TODO Add function with index 0 and type 1 (this is used in
    // testing below)
    let f = Code {
        locals:     mk_locals(&[I32, I64]),
        ty_idx:     0,
        /* For testing the transformation of the body, we always use these exemplary locals. */
        expr:       Expression {
            instrs: body_orig,
        },
        ty:         Rc::new(ty),
        num_locals: 2,
    };
    assert_eq!(inject_accounting(&f, &ctx).unwrap().expr.instrs, body_expect);
}

// Tests with different locals
#[test]
fn test_locals_1() {
    let ctx = TransformationContext::empty();
    let f = Code {
        locals:     vec![],
        ty:         Rc::new(FunctionType::empty()),
        ty_idx:     0,
        expr:       Expression::from(vec![End]),
        num_locals: 0,
    };
    let expected = flatten![stack!(123), stack!(-123), [End]];

    assert_eq!(inject_accounting(&f, &ctx).unwrap().expr.instrs, expected);
}

#[test]
fn test_locals_2() {
    let ctx = TransformationContext::empty();
    let f = Code {
        locals:     mk_locals(&[I32, I64]),
        ty_idx:     0,
        expr:       Expression {
            instrs: vec![End],
        },
        ty:         Rc::new(FunctionType::empty()),
        num_locals: 2,
    };
    let expected = flatten![energy!(invoke_after(2)), stack!(123), stack!(-123), [End]];
    assert_eq!(inject_accounting(&f, &ctx).unwrap().expr.instrs, expected);
}

#[test]
fn test_locals_3() {
    let ctx = TransformationContext::empty();
    let f = Code {
        ty:         Rc::new(FunctionType::empty()), // irrelevant
        ty_idx:     0,
        locals:     mk_locals(&[I64, I64]),
        expr:       Expression::from(vec![End]),
        num_locals: 2,
        // NOTE: this is a random value and does not correspond to the body
    };
    let expected = flatten![energy!(invoke_after(2)), stack!(123), stack!(-123), [End]];
    assert_eq!(inject_accounting(&f, &ctx).unwrap().expr.instrs, expected);
}

// Tests for function bodies.

#[test]
fn test_empty() {
    test_body(FunctionType::empty(), vec![End], flatten![energy!(ENTRY), stack!(S), stack!(-S), [
        End
    ]])
}

#[test]
fn test_simple_1() {
    test_body(FunctionType::empty(), vec![I64Const(1234567890), End], flatten![
        energy!(ENTRY + CONST),
        stack!(S),
        [I64Const(1234567890)],
        stack!(-S),
        [End]
    ])
}

#[test]
fn test_num_1() {
    test_body(
        FunctionType::empty(),
        vec![I64Const(1234567890), I32Const(43), I32Const(50), I32DivS, I32WrapI64, I64Sub],
        flatten![
            energy!(ENTRY + 3 * CONST + SIMPLE_UNOP + SIMPLE_BINOP + DIV),
            stack!(S),
            [I64Const(1234567890), I32Const(43), I32Const(50), I32DivS, I32WrapI64, I64Sub],
            stack!(-S)
        ],
    )
}

#[test]
fn test_num_2() {
    test_body(
        FunctionType::empty(),
        vec![I64Const(1234567890), I64Const(0), I64RemU, End],
        flatten![
            energy!(ENTRY + 2 * CONST + REM),
            stack!(S),
            [I64Const(1234567890), I64Const(0), I64RemU],
            stack!(-S),
            [End]
        ],
    )
}

#[test]
fn test_num_3() {
    test_body(
        FunctionType::empty(),
        vec![I64Const(1234567890), I64Const(0), I64Const(1), I64Const(2), I64Mul, I64Mul, End],
        flatten![
            energy!(ENTRY + 4 * CONST + 2 * MUL),
            stack!(S),
            [I64Const(1234567890), I64Const(0), I64Const(1), I64Const(2), I64Mul, I64Mul],
            stack!(-S),
            [End]
        ],
    )
}

#[test]
fn test_return() {
    test_body(
        FunctionType::empty(),
        vec![I32Const(10), I32Const(20), I32Add, Return, I32Const(30), End],
        flatten![
            energy!(ENTRY + 2 * CONST + SIMPLE_BINOP + branch(0)),
            stack!(S),
            [I32Const(10), I32Const(20), I32Add],
            stack!(-S),
            [Return],
            energy!(CONST),
            [I32Const(30)],
            stack!(-S),
            [End]
        ],
    )
}

#[test]
fn test_call() {
    test_body_ctx(
        TransformationContext {
            types: vec![],
            funcs: vec![FunctionType {
                parameters: vec![I32, I32],
                result:     Some(I32),
            }],
        },
        FunctionType::empty(),
        vec![I32Const(10), I32Const(20), Call(0), I32Const(40), I32Sub, End],
        flatten![
            energy!(ENTRY + 2 * CONST + invoke_before(2, 1)),
            stack!(S),
            [
                I32Const(10),
                I32Const(20),
                Call(FN_IDX_TRACK_CALL),
                Call(NUM_ADDED_FUNCTIONS),
                Call(FN_IDX_TRACK_RETURN)
            ],
            energy!(CONST + SIMPLE_BINOP),
            [I32Const(40), I32Sub],
            stack!(-S),
            [End]
        ],
    )
}

#[test]
fn test_call_indirect() {
    test_body_ctx(
        TransformationContext {
            types: vec![
                FunctionType {
                    parameters: vec![I32, I32],
                    result:     Some(I32),
                },
                FunctionType {
                    parameters: vec![I32, I32],
                    result:     Some(I32),
                },
            ],
            funcs: vec![],
        },
        FunctionType::empty(),
        vec![I32Const(10), I32Const(20), I32Const(0), CallIndirect(1), I32Const(40), I32Sub, End],
        flatten![
            energy!(ENTRY + 3 * CONST + call_indirect(2, 1)),
            stack!(S),
            [
                I32Const(10),
                I32Const(20),
                I32Const(0),
                Call(FN_IDX_TRACK_CALL),
                CallIndirect(1),
                Call(FN_IDX_TRACK_RETURN)
            ],
            energy!(CONST + SIMPLE_BINOP),
            [I32Const(40), I32Sub],
            stack!(-S),
            [End]
        ],
    )
}

#[test]
fn test_unreachable_1() {
    test_body(FunctionType::empty(), vec![Unreachable], flatten![
        energy!(ENTRY),
        stack!(S),
        [Unreachable],
        stack!(-S)
    ])
}

#[test]
fn test_unreachable_2() {
    test_body(
        FunctionType::empty(),
        vec![I32Const(10), I32Const(20), I32Add, Unreachable, I32Const(30)],
        flatten![
            energy!(ENTRY + 2 * CONST + SIMPLE_BINOP),
            stack!(S),
            [I32Const(10), I32Const(20), I32Add],
            [Unreachable],
            energy!(CONST),
            [I32Const(30)],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_empty() {
    test_body(FunctionType::empty(), vec![Block(EmptyType), End], flatten![
        energy!(ENTRY),
        stack!(S),
        [Block(EmptyType), End],
        stack!(-S)
    ])
}

#[test]
fn test_loop_empty() {
    test_body(FunctionType::empty(), vec![Loop(EmptyType), End], flatten![
        energy!(ENTRY),
        stack!(S),
        [Loop(EmptyType), End],
        stack!(-S)
    ])
}

#[test]
fn test_block_simple() {
    test_body(FunctionType::empty(), vec![Block(BlockValue(I64)), I64Const(0), End, End], flatten![
        energy!(ENTRY + CONST),
        stack!(S),
        [Block(BlockValue(I64)), I64Const(0), End],
        stack!(-S),
        [End]
    ])
}

#[test]
fn test_loop_simple() {
    test_body(FunctionType::empty(), vec![Loop(BlockValue(I64)), I64Const(0), End], flatten![
        energy!(ENTRY),
        stack!(S),
        [Loop(BlockValue(I64))],
        energy!(CONST),
        [I64Const(0), End],
        stack!(-S)
    ])
}

#[test]
fn test_block_branch() {
    test_body(FunctionType::empty(), vec![Block(EmptyType), Br(0), End], flatten![
        energy!(ENTRY + branch(0)),
        stack!(S),
        [Block(EmptyType), Br(0), End],
        stack!(-S)
    ])
}

#[test]
fn test_loop_branch() {
    test_body(FunctionType::empty(), vec![Loop(EmptyType), Br(0), End], flatten![
        energy!(ENTRY),
        stack!(S),
        [Loop(EmptyType)],
        energy!(branch(0)),
        [Br(0), End],
        stack!(-S)
    ])
}

#[test]
fn test_block_branch_2() {
    test_body(
        FunctionType::empty(),
        vec![Block(BlockValue(I64)), I64Const(0), Br(0), End],
        flatten![
            energy!(ENTRY + CONST + branch(1)),
            stack!(S),
            [Block(BlockValue(I64))],
            [I64Const(0), Br(0), End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_loop_branch_2() {
    test_body(
        FunctionType::empty(),
        vec![Loop(BlockValue(I64)), I64Const(0), Br(0), End],
        flatten![
            energy!(ENTRY),
            stack!(S),
            [Loop(BlockValue(I64))],
            energy!(CONST + branch(0)), // The loop has 0 arguments
            [I64Const(0), Br(0), End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_br_if() {
    test_body(
        FunctionType::empty(),
        vec![Block(EmptyType), I32Const(9), BrIf(0), End, End],
        flatten![
            energy!(ENTRY + CONST + BR_IF),
            stack!(S),
            [Block(EmptyType)],
            flatten![
                [I32Const(9), If {
                    ty: EmptyType,
                }],
                energy!(branch(0)),
                [Br(1), End]
            ],
            [End],
            stack!(-S),
            [End]
        ],
    )
}

fn br_if_substitute(label: LabelIndex) -> Vec<OpCode> {
    flatten![
        [If {
            ty: BlockValue(I32),
        }],
        energy!(branch(1)),
        [I32Const(1), Else, I32Const(0), End, BrIf(label),]
    ]
}

#[test]
fn test_typed_block_br_if() {
    test_body(
        FunctionType::empty(),
        vec![Block(BlockValue(I32)), I32Const(1), I32Const(1), BrIf(0), End],
        flatten![
            energy!(ENTRY + CONST * 2 + BR_IF),
            stack!(S),
            [Block(BlockValue(I32)), I32Const(1), I32Const(1)],
            br_if_substitute(0),
            [End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_typed_outer_block_br_if() {
    test_body(
        FunctionType::empty(),
        vec![
            Block(BlockValue(I32)),
            Block(EmptyType),
            I32Const(1),
            I32Const(2),
            BrIf(1),
            Drop,
            End,
            I32Const(3),
            End,
        ],
        flatten![
            energy!(ENTRY + CONST * 2 + BR_IF),
            stack!(S),
            [Block(BlockValue(I32)), Block(EmptyType), I32Const(1), I32Const(2)],
            br_if_substitute(1),
            energy!(DROP),
            [Drop, End],
            energy!(CONST),
            [I32Const(3), End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_loop_br_if() {
    test_body(FunctionType::empty(), vec![Loop(EmptyType), I32Const(9), BrIf(0), End], flatten![
        energy!(ENTRY),
        stack!(S),
        [Loop(EmptyType)],
        energy!(CONST + BR_IF),
        [I32Const(9), If {
            ty: EmptyType,
        }],
        energy!(branch(0)),
        [Br(1), End, End],
        stack!(-S)
    ])
}

#[test]
fn test_block_br_if_2() {
    test_body(
        FunctionType::empty(),
        vec![Block(BlockValue(I64)), I64Const(5), I32Const(9), BrIf(0), I64Const(5), End],
        flatten![
            energy!(ENTRY + 2 * CONST + BR_IF),
            stack!(S),
            [Block(BlockValue(I64)), I64Const(5), I32Const(9)],
            br_if_substitute(0),
            energy!(CONST),
            [I64Const(5), End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_loop_br_if_2() {
    test_body(
        FunctionType::empty(),
        vec![Loop(BlockValue(I64)), I64Const(5), I32Const(9), BrIf(0), End, I64Const(5), End],
        flatten![
            energy!(ENTRY),
            stack!(S),
            [Loop(BlockValue(I64))],
            flatten![
                energy!(2 * CONST + BR_IF),
                [I64Const(5), I32Const(9), If {
                    ty: EmptyType,
                }],
                energy!(branch(0)), // The loop has 0 arguments
                [Br(1), End, End],
                energy!(CONST),
                [I64Const(5), End]
            ],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_nested() {
    test_body(FunctionType::empty(), vec![Block(EmptyType), Block(EmptyType), End, End], flatten![
        energy!(ENTRY),
        stack!(S),
        [Block(EmptyType), Block(EmptyType), End, End],
        stack!(-S)
    ])
}

#[test]
fn test_loop_nested() {
    test_body(FunctionType::empty(), vec![Loop(EmptyType), Loop(EmptyType), End, End], flatten![
        energy!(ENTRY),
        stack!(S),
        [Loop(EmptyType), Loop(EmptyType), End, End],
        stack!(-S)
    ])
}

#[test]
fn test_block_nested_2() {
    test_body(
        FunctionType::empty(),
        vec![Block(BlockValue(I64)), Block(BlockValue(I64)), I64Const(4), End, End],
        flatten![
            energy!(ENTRY + CONST),
            stack!(S),
            [Block(BlockValue(I64)), Block(BlockValue(I64)), I64Const(4), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_loop_nested_2() {
    test_body(
        FunctionType::empty(),
        vec![Loop(EmptyType), Loop(EmptyType), I64Const(4), End, End],
        flatten![
            energy!(ENTRY),
            stack!(S),
            [Loop(EmptyType), Loop(EmptyType)],
            energy!(CONST),
            [I64Const(4), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_nested_branch() {
    test_body(
        FunctionType::empty(),
        vec![Block(EmptyType), Block(EmptyType), Br(1), End, End],
        flatten![
            energy!(ENTRY + branch(0)),
            stack!(S),
            [Block(EmptyType), Block(EmptyType), Br(1), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_loop_nested_branch() {
    test_body(
        FunctionType::empty(),
        vec![Loop(EmptyType), Loop(EmptyType), Br(1), End, End],
        flatten![
            energy!(ENTRY),
            stack!(S),
            [Loop(EmptyType), Loop(EmptyType)],
            energy!(branch(0)),
            [Br(1), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_nested_branch_table_1() {
    test_body(
        FunctionType::empty(),
        vec![Block(EmptyType), Block(EmptyType), BrTable {
            labels:  vec![0, 1],
            default: 0,
        }],
        flatten![
            energy!(ENTRY + br_table(0)),
            stack!(S),
            [Block(EmptyType), Block(EmptyType), BrTable {
                labels:  vec![0, 1],
                default: 0,
            }],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_nested_branch_table_2() {
    test_body(
        FunctionType::empty(),
        vec![
            Block(BlockValue(I64)),
            Block(BlockValue(I64)),
            I64Const(7),
            BrTable {
                labels:  vec![0, 1],
                default: 0,
            },
            End,
            End,
        ],
        flatten![
            energy!(ENTRY + CONST + br_table(1)),
            stack!(S),
            [
                Block(BlockValue(I64)),
                Block(BlockValue(I64)),
                I64Const(7),
                BrTable {
                    labels:  vec![0, 1],
                    default: 0,
                },
                End,
                End
            ],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_nested_branch_l0() {
    test_body(
        FunctionType::empty(),
        vec![Block(BlockValue(I64)), Block(BlockValue(I32)), Br(0), End, End],
        flatten![
            energy!(ENTRY + branch(1)),
            stack!(S),
            [Block(BlockValue(I64)), Block(BlockValue(I32)), Br(0), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_block_nested_branch_l1() {
    test_body(
        FunctionType::empty(),
        vec![Block(BlockValue(I64)), Block(BlockValue(I32)), Br(1)],
        flatten![
            energy!(ENTRY + branch(1)),
            stack!(S),
            [Block(BlockValue(I64)), Block(BlockValue(I32)), Br(1)],
            stack!(-S)
        ],
    )
}

#[test]
fn test_loop_nested_branch_l0() {
    test_body(
        FunctionType::empty(),
        vec![Loop(BlockValue(I64)), Loop(BlockValue(I32)), Br(0), End, End],
        flatten![
            energy!(ENTRY),
            stack!(S),
            [Loop(BlockValue(I64)), Loop(BlockValue(I32))],
            energy!(branch(0)), // The loop label has no arguments.
            [Br(0), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_loop_nested_branch_l1() {
    test_body(
        FunctionType::empty(),
        vec![Loop(BlockValue(I64)), Loop(BlockValue(I32)), Br(1), End, End],
        flatten![
            energy!(ENTRY),
            stack!(S),
            [Loop(BlockValue(I64)), Loop(BlockValue(I32))],
            energy!(branch(0)), // The outer loop has 0 arguments
            [Br(1), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_if_1() {
    test_body(
        FunctionType::empty(),
        vec![
            If {
                ty: EmptyType,
            },
            Nop,
            Else,
            Nop,
            Nop,
            End,
        ],
        flatten![
            energy!(ENTRY + IF_STATEMENT),
            stack!(S),
            [If {
                ty: EmptyType,
            }],
            energy!(NOP),
            [Nop, Else],
            energy!(2 * NOP),
            [Nop, Nop, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_if_2() {
    test_body(
        FunctionType::empty(),
        vec![
            If {
                ty: EmptyType,
            },
            Nop,
            If {
                ty: EmptyType,
            },
            Nop,
            Else,
            Nop,
            Nop,
            End,
            End,
        ],
        flatten![
            energy!(ENTRY + IF_STATEMENT),
            stack!(S),
            [If {
                ty: EmptyType,
            }],
            energy!(NOP + IF_STATEMENT),
            [Nop],
            [If {
                ty: EmptyType,
            }],
            energy!(NOP),
            [Nop, Else],
            energy!(2 * NOP),
            [Nop, Nop, End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_if_branch_0() {
    test_body(
        FunctionType::empty(),
        vec![
            If {
                ty: BlockValue(I64),
            },
            I64Const(9),
            Br(0),
            Else,
            I64Const(7),
            If {
                ty: EmptyType,
            },
            Br(0),
            Else,
            Nop,
            Br(0),
            End,
            End,
        ],
        flatten![
            energy!(ENTRY + IF_STATEMENT),
            stack!(S),
            [If {
                ty: BlockValue(I64),
            }],
            energy!(CONST + branch(1)),
            [I64Const(9), Br(0), Else],
            energy!(CONST + IF_STATEMENT),
            [I64Const(7), If {
                ty: EmptyType,
            }],
            energy!(branch(0)),
            [Br(0), Else],
            energy!(NOP + branch(0)),
            [Nop, Br(0), End, End],
            stack!(-S)
        ],
    )
}

#[test]
fn test_if_branch_1() {
    test_body(
        FunctionType::empty(),
        vec![
            If {
                ty: BlockValue(I64),
            },
            I64Const(9),
            Br(0),
            Else,
            I64Const(7),
            If {
                ty: EmptyType,
            },
            Br(1),
            Else,
            Nop,
            Br(1),
            End,
            End,
            End,
        ],
        flatten![
            energy!(ENTRY + IF_STATEMENT),
            stack!(S),
            [If {
                ty: BlockValue(I64),
            }],
            energy!(CONST + branch(1)),
            [I64Const(9), Br(0), Else],
            energy!(CONST + IF_STATEMENT),
            [I64Const(7), If {
                ty: EmptyType,
            }],
            energy!(branch(1)),
            [Br(1), Else],
            energy!(NOP + branch(1)),
            [Nop, Br(1), End, End],
            stack!(-S),
            [End]
        ],
    )
}

#[test]
fn test_drop() {
    test_body(FunctionType::empty(), vec![I32Const(10), I64Const(20), Drop, Drop], flatten![
        energy!(ENTRY + 2 * CONST + 2 * DROP),
        stack!(S),
        [I32Const(10), I64Const(20), Drop, Drop],
        stack!(-S)
    ])
}

#[test]
fn test_select() {
    test_body(
        FunctionType::empty(),
        vec![I32Const(10), I64Const(20), I32Const(0), Select],
        flatten![
            energy!(ENTRY + 3 * CONST + SELECT),
            stack!(S),
            [I32Const(10), I64Const(20), I32Const(0), Select],
            stack!(-S)
        ],
    )
}

#[test]
fn test_local_get_set_1() {
    test_body(
        FunctionType::empty(),
        vec![LocalGet(0), I64Const(20), I64Add, LocalSet(0)],
        flatten![
            energy!(ENTRY + CONST + GET_LOCAL + SET_LOCAL + SIMPLE_BINOP),
            stack!(S),
            [LocalGet(0), I64Const(20), I64Add, LocalSet(0)],
            stack!(-S)
        ],
    )
}

#[test]
fn test_local_get_set_2() {
    test_body(FunctionType::empty(), vec![I64Const(20), LocalSet(0)], flatten![
        energy!(ENTRY + CONST + SET_LOCAL),
        stack!(S),
        [I64Const(20), LocalSet(0)],
        stack!(-S)
    ])
}

#[test]
fn test_local_tee() {
    test_body(FunctionType::empty(), vec![I64Const(20), LocalTee(0), LocalTee(1)], flatten![
        energy!(ENTRY + CONST + 2 * TEE_LOCAL),
        stack!(S),
        [I64Const(20), LocalTee(0), LocalTee(1)],
        stack!(-S)
    ])
}

#[test]
fn test_global_get_set_1() {
    test_body(
        FunctionType::empty(),
        vec![GlobalGet(0), I64Const(20), I64Add, GlobalSet(0)],
        flatten![
            energy!(ENTRY + CONST + GET_GLOBAL + SET_GLOBAL + SIMPLE_BINOP),
            stack!(S),
            [GlobalGet(0), I64Const(20), I64Add, GlobalSet(0)],
            stack!(-S)
        ],
    )
}

#[test]
fn test_global_get_set_2() {
    test_body(FunctionType::empty(), vec![I64Const(20), GlobalSet(0)], flatten![
        energy!(ENTRY + CONST + SET_GLOBAL),
        stack!(S),
        [I64Const(20), GlobalSet(0)],
        stack!(-S)
    ])
}

#[test]
fn test_memory_load_store_1() {
    test_body(
        FunctionType::empty(),
        vec![
            I32Const(128),
            I64Load(MEMARG),
            I32Const(128),
            I64Load(MEMARG),
            I64Add,
            I32Const(128),
            I64Store(MEMARG),
        ],
        flatten![
            energy!(ENTRY + 3 * CONST + 2 * 3 + SIMPLE_BINOP + store(8)),
            stack!(S),
            [
                I32Const(128),
                I64Load(MEMARG),
                I32Const(128),
                I64Load(MEMARG),
                I64Add,
                I32Const(128),
                I64Store(MEMARG)
            ],
            stack!(-S)
        ],
    )
}

#[test]
fn test_memory_load_store_2() {
    test_body(
        FunctionType::empty(),
        vec![
            I32Const(44),
            I32Const(44),
            I32Const(128),
            I32Store(MEMARG),
            I32Const(64),
            I32Store(MEMARG),
        ],
        flatten![
            energy!(ENTRY + 4 * CONST + 2 * store(4)),
            stack!(S),
            [
                I32Const(44),
                I32Const(44),
                I32Const(128),
                I32Store(MEMARG),
                I32Const(64),
                I32Store(MEMARG),
            ],
            stack!(-S)
        ],
    )
}

#[test]
fn test_memory_size() {
    test_body(FunctionType::empty(), vec![MemorySize], flatten![
        energy!(ENTRY + MEMSIZE),
        stack!(S),
        [MemorySize],
        stack!(-S)
    ])
}

#[test]
fn test_memory_grow() {
    test_body(
        FunctionType::empty(),
        vec![I32Const(64), MemoryGrow, I64Const(0), I64Const(1)],
        flatten![
            energy!(ENTRY + MEMGROW + 3 * CONST),
            stack!(S),
            [I32Const(64)],
            mem_alloc!(),
            [MemoryGrow, I64Const(0), I64Const(1)],
            stack!(-S)
        ],
    )
}
