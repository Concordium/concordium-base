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

    /// Examplary function's stack size for `test_body` test cases.
    const S: i64 = 456;
    /// Number of locals for `test_body` test cases.
    const TEST_BODY_N_LOCALS: usize = 2;
    /// Energy for function entry for `test_body` test cases.
    const ENTRY: Energy = invoke_after(TEST_BODY_N_LOCALS);

    fn test_body(body_orig: InstrSeq, body_expect: InstrSeq) {
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
        assert_eq!(InstrSeqTransformer::inject_accounting(&f, &m), f_);
    }

    // Tests with different locals

    #[test]
    fn test_inject_locals_1() {
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
        assert_eq!(InstrSeqTransformer::inject_accounting(&f, &m), f_);
    }

    #[test]
    fn test_inject_locals_2() {
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
        assert_eq!(InstrSeqTransformer::inject_accounting(&f, &m), f_);
    }

    #[test]
    fn test_inject_locals_3() {
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
        assert_eq!(InstrSeqTransformer::inject_accounting(&f, &m), f_);
    }

    #[test]
    fn test_inject_body_1() {
        test_body(vec![], to_vec![
            energy!(ENTRY),
            stack!(S),
            stack!(-S)
        ])
    }

    #[test]
    fn test_inject_body_2() {
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
    fn test_inject_body_3() {
        test_body(
            vec![
                I32Const(10),
                I32Const(20),
                I32Add,
                Return,
                I32Const(30),
            ],
            to_vec![
                energy!(ENTRY + 2*COST_CONST + COST_SIMPLE_BIN),
                stack!(S),
                [ I32Const(10),
                  I32Const(20),
                  I32Add,
                ],
                stack!(-S),
                [ Return ],
                energy!(COST_CONST),
                [ I32Const(30) ],
                stack!(-S)
            ])
    }
}
