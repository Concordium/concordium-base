/*
Notes on the tests:
- Note that the tests currently do not cover all instructions: for instructions that are handled identically by the transformation, only representatives are used.
- Not all test expressions might actually be valid Wasm; But for testing the accounting transformation this should not hurt and it can still be a useful test.

For further tests:
- Do some randomized tests, embedding chunks with known transformation results into each other / sequencing them will give more assurance.
- We should also have tests running the generated code and testing for semantical equivalence (apart from the semantical changes accounting introduces).
- Another way of testing is transforming and running programs and asserting the expected total energy accounted.
*/
mod transformation_tests {
    use crate::transformations::*;
    use crate::types::{BlockType::*, Instruction::*, ValueType::*};
    use cost::*;

    macro_rules! energy {
        ($e:expr) => {
            [I64Const($e as i64), Call(FN_IDX_ACCOUNT_ENERGY)]
        };
    }

    macro_rules! stack {
        ($e:expr) => {
            [I64Const($e as i64), Call(FN_IDX_ACCOUNT_STACK_SIZE)]
        };
    }

    macro_rules! mem_alloc {
        () => {
            [Call(FN_IDX_MEMORY_ALLOC)]
        };
    }

    macro_rules! to_vec {
        ( $( $a:expr ),* ) => {
            {
                let mut temp_vec = Vec::<Instruction>::new();
                $(
                    for i in $a.iter() {
                        temp_vec.push(i.clone());
                    }
                )*
                    temp_vec
            }
        };
    }

    // Example MemArg
    const MEMARG: MemArg = MemArg {
        offset: 0,
        align: 0,
    };

    /// Examplary function's stack size for `test_body` test cases.
    const S: i64 = 456;
    /// Number of locals for `test_body` test cases.
    const TEST_BODY_N_LOCALS: usize = 2;
    /// Energy for function entry for `test_body` test cases.
    const ENTRY: Energy = invoke_after(TEST_BODY_N_LOCALS);

    fn test_body(body_orig: InstrSeq, body_expect: InstrSeq) {
        // TODO Add type 0 with type lengths (3,2) (this is used in testing below)
        // TODO Add type 1 = [i32 i32] -> [i32] (lengths (2,1)) (this is used in testing below)
        // TODO Add function with index 0 and type 1 (this is used in testing below)
        let m = Module {};
        let f = Function {
            func_type: 0,              // irrelevant
            locals:    vec![I32, I64], /* For testing the transformation of the body, we always
                                        * use these exemplary locals. */
            body:      body_orig.clone(),
            // NOTE: This is just an exemplary value that does not have to correspond to the actual
            // body.
            max_stack_size: Some(S as StackSize),
        };
        let f_ = Function {
            func_type:      0,
            locals:         vec![I32, I64],
            body:           body_expect.clone(),
            max_stack_size: Some(S as StackSize),
        };
        assert_eq!(inject_accounting(&f, &m), f_);
    }

    // Tests with different locals

    #[test]
    fn test_locals_1() {
        let m = Module {};
        let f = Function {
            func_type: 0, // irrelevant
            locals:    vec![],
            body:      vec![],
            // NOTE: this is a random value and does not correspond to the body
            max_stack_size: Some(123),
        };
        let f_ = Function {
            func_type:      0,
            locals:         vec![],
            body:           to_vec![energy!(invoke_after(0)), stack!(123), stack!(-123)],
            max_stack_size: Some(123),
        };
        assert_eq!(inject_accounting(&f, &m), f_);
    }

    #[test]
    fn test_locals_2() {
        let m = Module {};
        let f = Function {
            func_type: 0, // irrelevant
            locals:    vec![I32, I64],
            body:      vec![],
            // NOTE: this is a random value and does not correspond to the body
            max_stack_size: Some(123),
        };
        let f_ = Function {
            func_type:      0,
            locals:         vec![I32, I64],
            body:           to_vec![energy!(invoke_after(2)), stack!(123), stack!(-123)],
            max_stack_size: Some(123),
        };
        assert_eq!(inject_accounting(&f, &m), f_);
    }

    #[test]
    fn test_locals_3() {
        let m = Module {};
        let f = Function {
            func_type: 0, // irrelevant
            locals: vec![I64, I64],
            body: vec![],
            // NOTE: this is a random value and does not correspond to the body
            max_stack_size: Some(123),

        };
        let f_ = Function {
            func_type: 0,
            locals: vec![I64, I64],
            body: to_vec![
                energy!(invoke_after(2)),
                stack!(123),
                stack!(-123)
            ],
            max_stack_size: Some(123),

        };
        assert_eq!(inject_accounting(&f, &m), f_);
    }

    // Tests for function bodies.

    #[test]
    fn test_empty() {
        test_body(vec![], to_vec![
            energy!(ENTRY),
            stack!(S),
            stack!(-S)
        ])
    }

    #[test]
    fn test_simple_1() {
        test_body(vec![I64Const(1234567890)], to_vec![
            energy!(ENTRY + CONST),
            stack!(S),
            [I64Const(1234567890)],
            stack!(-S)
        ])
    }

    #[test]
    fn test_num_1() {
        test_body(vec![
            I64Const(1234567890),
            I32Const(43),
            I32Const(50),
            I32DivS,
            I32WrapI64,
            I64Sub
        ], to_vec![
            energy!(ENTRY + 3*CONST + 2*SIMPLE_BINOP + DIV),
            stack!(S),
            [I64Const(1234567890),
             I32Const(43),
             I32Const(50),
             I32DivS,
             I32WrapI64,
             I64Sub
            ],
            stack!(-S)
        ])
    }

    #[test]
    fn test_num_2() {
        test_body(vec![
            I64Const(1234567890),
            I64Const(0),
            I64RemU
        ], to_vec![
            energy!(ENTRY + 2*CONST + REM),
            stack!(S),
            [I64Const(1234567890),
             I64Const(0),
             I64RemU
            ],
            stack!(-S)
        ])
    }

    #[test]
    fn test_num_3() {
        test_body(vec![
            I64Const(1234567890),
            I64Const(0),
            I64Const(1),
            I64Const(2),
            I64Mul,
            I64Mul
        ], to_vec![
            energy!(ENTRY + 4*CONST + 2*MUL),
            stack!(S),
            [I64Const(1234567890),
             I64Const(0),
             I64Const(1),
             I64Const(2),
             I64Mul,
             I64Mul
            ],
            stack!(-S)
        ])
    }

    #[test]
    fn test_return() {
        test_body(
            vec![
                I32Const(10),
                I32Const(20),
                I32Add,
                Return,
                I32Const(30),
            ],
            to_vec![
                energy!(ENTRY + 2*CONST + SIMPLE_BINOP),
                stack!(S),
                [ I32Const(10),
                  I32Const(20),
                  I32Add,
                ],
                stack!(-S),
                [ Return ],
                energy!(CONST),
                [ I32Const(30) ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_call() {
        test_body(
            vec![
                I32Const(10),
                I32Const(20),
                Call(0),
                I32Const(40),
                I32Sub
            ],
            to_vec![
                energy!(ENTRY + 2*CONST + invoke_before(2,1)),
                stack!(S),
                [ I32Const(10),
                  I32Const(20),
                  Call(0),
                ],
                energy!(CONST + SIMPLE_BINOP),
                [ I32Const(40),
                  I32Sub
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_call_indirect() {
        test_body(
            vec![
                I32Const(10),
                I32Const(20),
                I32Const(0),
                CallIndirect(1),
                I32Const(40),
                I32Sub
            ],
            to_vec![
                energy!(ENTRY + 3*CONST + call_indirect(2,1)),
                stack!(S),
                [ I32Const(10),
                  I32Const(20),
                  I32Const(0),
                  CallIndirect(1),
                ],
                energy!(CONST + SIMPLE_BINOP),
                [ I32Const(40),
                  I32Sub
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_unreachable_1() {
        test_body(vec![Unreachable], to_vec![
            energy!(ENTRY),
            stack!(S),
            [ Unreachable ],
            stack!(-S)
        ])
    }

    #[test]
    fn test_unreachable_2() {
        test_body(
            vec![
                I32Const(10),
                I32Const(20),
                I32Add,
                Unreachable,
                I32Const(30),
            ],
            to_vec![
                energy!(ENTRY + 2*CONST + SIMPLE_BINOP),
                stack!(S),
                [ I32Const(10),
                  I32Const(20),
                  I32Add,
                ],
                [ Unreachable ],
                energy!(CONST),
                [ I32Const(30) ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_empty() {
        test_body(
            vec![
                Block(EmptyType, vec![])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Block(EmptyType, vec![])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_empty() {
        test_body(
            vec![
                Loop(EmptyType, vec![])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(EmptyType, vec!
                       [ // An empty body does not cause any accounting.
                       ])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_simple() {
        test_body(
            vec![
                Block(ValueType(I64), vec![I64Const(0)])
            ],
            to_vec![
                energy!(ENTRY + CONST),
                stack!(S),
                [ Block(ValueType(I64), vec![I64Const(0)])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_simple() {
        test_body(
            vec![
                Loop(ValueType(I64), vec![I64Const(0)])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(ValueType(I64), to_vec!
                       [ energy!(CONST),
                         [I64Const(0)]
                       ])
                ],
                stack!(-S)
            ])
    }


    #[test]
    fn test_block_branch() {
        test_body(
            vec![
                Block(EmptyType, vec![Br(0)])
            ],
            to_vec![
                energy!(ENTRY + branch(0)),
                stack!(S),
                [ Block(EmptyType, vec![Br(0)])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_branch() {
        test_body(
            vec![
                Loop(EmptyType, vec![Br(0)])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(EmptyType, to_vec!
                       [ energy!(branch(0)),
                         [Br(0)]
                       ])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_branch_2() {
        test_body(
            vec![
                Block(ValueType(I64), vec![I64Const(0), Br(0)])
            ],
            to_vec![
                energy!(ENTRY + CONST + branch(1)),
                stack!(S),
                [ Block(ValueType(I64), vec![I64Const(0), Br(0)])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_branch_2() {
        test_body(
            vec![
                Loop(ValueType(I64), vec![I64Const(0), Br(0)])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(ValueType(I64), to_vec!
                       [ energy!(CONST + branch(0)), // The loop has 0 arguments
                         [I64Const(0), Br(0)]
                       ])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_br_if() {
        test_body(
            vec![
                Block(EmptyType, vec![I32Const(9), BrIf(0)])
            ],
            to_vec![
                energy!(ENTRY + CONST + BR_IF),
                stack!(S),
                [ Block(EmptyType, vec!
                        [ I32Const(9),
                          If(EmptyType,
                             to_vec!
                             [ energy!(branch(0)),
                               [Br(1)]
                             ],
                             vec![Nop]
                          ),
                        ])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_br_if() {
        test_body(
            vec![
                Loop(EmptyType, vec![I32Const(9), BrIf(0)])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(EmptyType, to_vec!
                       [ energy!(CONST + BR_IF),
                         [I32Const(9)],
                         [If(EmptyType,
                             to_vec!
                             [ energy!(branch(0)),
                               [Br(1)]
                             ],
                             vec![Nop]
                         )]
                       ])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_br_if_2() {
        test_body(
            vec![
                Block(ValueType(I64), vec![I64Const(5), I32Const(9), BrIf(0), I64Const(5)])
            ],
            to_vec![
                energy!(ENTRY + 2*CONST + BR_IF),
                stack!(S),
                [ Block(ValueType(I64), to_vec!
                        [ [I64Const(5)],
                          [I32Const(9)],
                          [If(EmptyType,
                              to_vec!
                              [ energy!(branch(1)),
                                [Br(1)]
                              ],
                              vec![Nop]
                          )],
                          energy!(CONST),
                          [I64Const(5)]
                        ])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_br_if_2() {
        test_body(
            vec![
                Loop(ValueType(I64), vec![I64Const(5), I32Const(9), BrIf(0), I64Const(5)])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(ValueType(I64), to_vec!
                       [ energy!(2*CONST + BR_IF),
                         [I64Const(5)],
                         [I32Const(9)],
                         [If(EmptyType,
                             to_vec!
                             [ energy!(branch(0)), // The loop has 0 arguments
                               [Br(1)]
                             ],
                             vec![Nop]
                         )],
                         energy!(CONST),
                         [I64Const(5)]
                       ])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_nested() {
        test_body(
            vec![
                Block(EmptyType, vec![Block(EmptyType, vec![])])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Block(EmptyType, vec![Block(EmptyType, vec![])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_nested() {
        test_body(
            vec![
                Loop(EmptyType, vec![Loop(EmptyType, vec![])])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(EmptyType, vec![Loop(EmptyType, vec![])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_nested_2() {
        test_body(
            vec![
                Block(ValueType(I64), vec![Block(ValueType(I64), vec![I64Const(4)])])
            ],
            to_vec![
                energy!(ENTRY + CONST),
                stack!(S),
                [ Block(ValueType(I64), vec![Block(ValueType(I64), vec![I64Const(4)])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_nested_2() {
        test_body(
            vec![
                Loop(EmptyType, vec![Loop(EmptyType, vec![I64Const(4)])])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(EmptyType, vec![Loop(EmptyType, to_vec!
                                            [ energy!(CONST),
                                              [I64Const(4)]
                                            ])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_nested_branch() {
        test_body(
            vec![
                Block(EmptyType, vec![Block(EmptyType, vec![Br(1)])])
            ],
            to_vec![
                energy!(ENTRY + branch(0)),
                stack!(S),
                [ Block(EmptyType, vec![Block(EmptyType, vec![Br(1)])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_nested_branch() {
        test_body(
            vec![
                Loop(EmptyType, vec![Loop(EmptyType, vec![Br(1)])])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(EmptyType, vec![Loop(EmptyType, to_vec!
                                            [ energy!(branch(0)),
                                              [Br(1)]
                                            ])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_nested_branch_table_1() {
        test_body(
            vec![
                Block(EmptyType, vec![Block(EmptyType, vec![BrTable(vec![0,1], 0)])])
            ],
            to_vec![
                energy!(ENTRY + br_table(0)),
                stack!(S),
                [ Block(EmptyType, vec![Block(EmptyType, vec![BrTable(vec![0,1], 0)])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_nested_branch_table_2() {
        test_body(
            vec![
                Block(ValueType(I64), vec![Block(ValueType(I64), vec![I64Const(7), BrTable(vec![0,1], 0)])])
            ],
            to_vec![
                energy!(ENTRY + CONST + br_table(1)),
                stack!(S),
                [ Block(ValueType(I64), vec![Block(ValueType(I64), vec![I64Const(7), BrTable(vec![0,1], 0)])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_nested_branch_l0() {
        test_body(
            vec![
                Block(ValueType(I64), vec![Block(TypeIndex(0), vec![Br(0)])])
            ],
            to_vec![
                energy!(ENTRY + branch(2)),
                stack!(S),
                [ Block(ValueType(I64), vec![Block(TypeIndex(0), vec![Br(0)])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_block_nested_branch_l1() {
        test_body(
            vec![
                Block(ValueType(I64), vec![Block(TypeIndex(0), vec![Br(1)])])
            ],
            to_vec![
                energy!(ENTRY + branch(1)),
                stack!(S),
                [ Block(ValueType(I64), vec![Block(TypeIndex(0), vec![Br(1)])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_nested_branch_l0() {
        test_body(
            vec![
                Loop(ValueType(I64), vec![Loop(TypeIndex(0), vec![Br(0)])])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(ValueType(I64), vec![Loop(TypeIndex(0), to_vec!
                                                 [ energy!(branch(3)), // The inner loop has 3 arguments
                                                   [Br(0)]
                                                 ])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_loop_nested_branch_l1() {
        test_body(
            vec![
                Loop(ValueType(I64), vec![Loop(TypeIndex(0), vec![Br(1)])])
            ],
            to_vec![
                energy!(ENTRY),
                stack!(S),
                [ Loop(ValueType(I64), vec![Loop(TypeIndex(0), to_vec!
                                                 [ energy!(branch(0)), // The outer loop has 0 arguments
                                                   [Br(1)]
                                                 ])])
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_if_1() {
        test_body(
            vec![
                If(EmptyType,vec![Nop],vec![Nop, Nop])
            ],
            to_vec![
                energy!(ENTRY + IF),
                stack!(S),
                [If(
                    EmptyType,
                    to_vec![
                        energy!(NOP),
                        [Nop]
                    ],
                    to_vec![
                        energy!(2*NOP),
                        [Nop, Nop]
                    ],
                )],
                stack!(-S)
            ])
    }

    #[test]
    fn test_if_2() {
        test_body(
            vec![
                If(EmptyType,vec![Nop],vec![If(EmptyType,vec![Nop],vec![Nop, Nop])])
            ],
            to_vec![
                energy!(ENTRY + IF),
                stack!(S),
                [If(
                    EmptyType,
                    to_vec![
                        energy!(NOP),
                        [Nop]
                    ],
                    to_vec![
                        energy!(IF),
                        [If(EmptyType,
                            to_vec![energy!(NOP), [Nop]],
                            to_vec![energy!(2*NOP), [Nop, Nop]]
                        )]
                    ],
                )],
                stack!(-S)
            ])
    }

    #[test]
    fn test_if_branch_0() {
        test_body(
            vec![
                If(ValueType(I64),
                   vec![I64Const(9), Br(0)],
                   vec![I64Const(7), If(EmptyType,vec![Br(0)],vec![Nop, Br(0)])])
            ],
            to_vec![
                energy!(ENTRY + IF),
                stack!(S),
                [If(
                    ValueType(I64),
                    to_vec![
                        energy!(CONST + branch(1)),
                        [I64Const(9), Br(0)]
                    ],
                    to_vec![
                        energy!(CONST + IF),
                        [ I64Const(7),
                          If(EmptyType,
                             to_vec![energy!(branch(0)), [Br(0)]],
                             to_vec![energy!(NOP + branch(0)), [Nop, Br(0)]]
                          )
                        ]
                    ],
                )],
                stack!(-S)
            ])
    }

    #[test]
    fn test_if_branch_1() {
        test_body(
            vec![
                If(ValueType(I64),
                   vec![I64Const(9), Br(0)],
                   vec![I64Const(7), If(EmptyType,vec![Br(1)],vec![Nop, Br(1)])])
            ],
            to_vec![
                energy!(ENTRY + IF),
                stack!(S),
                [If(
                    ValueType(I64),
                    to_vec![
                        energy!(CONST + branch(1)),
                        [I64Const(9), Br(0)]
                    ],
                    to_vec![
                        energy!(CONST + IF),
                        [ I64Const(7),
                          If(EmptyType,
                             to_vec![energy!(branch(1)), [Br(1)]],
                             to_vec![energy!(NOP + branch(1)), [Nop, Br(1)]]
                          )
                        ]
                    ],
                )],
                stack!(-S)
            ])
    }

    #[test]
    fn test_drop() {
        test_body(
            vec![
                I32Const(10),
                I64Const(20),
                Drop,
                Drop,
            ],
            to_vec![
                energy!(ENTRY + 2*CONST + 2*DROP),
                stack!(S),
                [ I32Const(10),
                  I64Const(20),
                  Drop,
                  Drop,
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_select() {
        test_body(
            vec![
                I32Const(10),
                I64Const(20),
                I32Const(0),
                Select
            ],
            to_vec![
                energy!(ENTRY + 3*CONST + SELECT),
                stack!(S),
                [ I32Const(10),
                  I64Const(20),
                  I32Const(0),
                  Select
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_local_get_set_1() {
        test_body(
            vec![
                LocalGet(0),
                I64Const(20),
                I64Add,
                LocalSet(0)
            ],
            to_vec![
                energy!(ENTRY + CONST + GET_LOCAL + SET_LOCAL + SIMPLE_BINOP),
                stack!(S),
                [LocalGet(0),
                 I64Const(20),
                 I64Add,
                 LocalSet(0)
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_local_get_set_2() {
        test_body(
            vec![
                I64Const(20),
                LocalSet(0)
            ],
            to_vec![
                energy!(ENTRY + CONST + SET_LOCAL),
                stack!(S),
                [I64Const(20),
                 LocalSet(0)
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_local_tee() {
        test_body(
            vec![
                I64Const(20),
                LocalTee(0),
                LocalTee(1),
            ],
            to_vec![
                energy!(ENTRY + CONST + 2*TEE_LOCAL),
                stack!(S),
                [I64Const(20),
                 LocalTee(0),
                 LocalTee(1),
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_global_get_set_1() {
        test_body(
            vec![
                GlobalGet(0),
                I64Const(20),
                I64Add,
                GlobalSet(0)
            ],
            to_vec![
                energy!(ENTRY + CONST + GET_GLOBAL + SET_GLOBAL + SIMPLE_BINOP),
                stack!(S),
                [GlobalGet(0),
                 I64Const(20),
                 I64Add,
                 GlobalSet(0)
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_global_get_set_2() {
        test_body(
            vec![
                I64Const(20),
                GlobalSet(0)
            ],
            to_vec![
                energy!(ENTRY + CONST + SET_GLOBAL),
                stack!(S),
                [I64Const(20),
                 GlobalSet(0)
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_memory_load_store_1() {
        test_body(
            vec![
                I32Const(128),
                I64Load(MEMARG),
                I32Const(128),
                I64Load(MEMARG),
                I64Add,
                I32Const(128),
                I64Store(MEMARG),
            ],
            to_vec![
                energy!(ENTRY + 3*CONST + 2*load(8) + SIMPLE_BINOP + store(8)),
                stack!(S),
                [I32Const(128),
                 I64Load(MEMARG),
                 I32Const(128),
                 I64Load(MEMARG),
                 I64Add,
                 I32Const(128),
                 I64Store(MEMARG),
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_memory_load_store_2() {
        test_body(
            vec![
                I32Const(44),
                I32Const(44),
                I32Const(128),
                I32Store(MEMARG),
                I32Const(64),
                I32Store(MEMARG),
            ],
            to_vec![
                energy!(ENTRY + 4*CONST + 2*store(4)),
                stack!(S),
                [I32Const(44),
                 I32Const(44),
                 I32Const(128),
                 I32Store(MEMARG),
                 I32Const(64),
                 I32Store(MEMARG),
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_memory_size() {
        test_body(
            vec![
                MemorySize
            ],
            to_vec![
                energy!(ENTRY + MEMSIZE),
                stack!(S),
                [MemorySize
                ],
                stack!(-S)
            ])
    }

    #[test]
    fn test_memory_grow() {
        test_body(
            vec![
                I32Const(64),
                MemoryGrow,
                I64Const(0),
                I64Const(1),
            ],
            to_vec![
                energy!(ENTRY + MEMGROW + 3*CONST),
                stack!(S),
                [I32Const(64)],
                mem_alloc!(),
                [MemoryGrow,
                 I64Const(0),
                 I64Const(1)
                ],
                stack!(-S)
            ])
    }

}
