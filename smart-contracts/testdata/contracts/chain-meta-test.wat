(module
    (; This module provides a number of init functions that are designed to test whether 
       various contexts are passed correctly by the scheduler to the smart contracts. ;)
    (type (;0;) (func (result i64))) (; type of simple accessors ;)
    (type (;1;) (func (param i64) (result i32))) (;type of the init/receive method;)
    (type (;2;) (func (result i32))) (; type of the accept method ;)
    (type (;3;) (func (param i32 i32 i32) (result i32))) (; type of the write_state function ;)
    (type (;4;) (func (param i32)))
    (import "concordium" "get_slot_time" (func $get_slot_time (type 0)))
    (import "concordium" "get_init_origin" (func $get_init_origin (type 4)))
    (import "concordium" "accept" (func (;1;) $accept (type 2)))
    (import "concordium" "write_state" (func $write_state (type 3)))
    (; check that slot time is 444, accept if so, reject otherwise ;)
    (func (;5;) $init_check_slot_time (type 1)
        (if (i64.eq (call $get_slot_time) (i64.const 444))
            (then (return (i32.const 0)))
            (else (return (i32.const -1)))
        )
        unreachable
    )
     
    (; write the init origin address to the contract's state, 
       fail if state cannot be written, otherwise just accept ;)
    (func (;6;) $init_origin (type 1)
        (if (i32.eq (i32.const -1) (memory.grow (i32.const 1)))
            (then unreachable) 
            (else nop))
        (call $get_init_origin (i32.const 0))
        (; write the address to contract's state ;)
        (; write at the beginning of contract state, automatically growing it ;)
        (; account address length is 32, and it starts at offset 32 of the init context ;)
        (if (i32.ne (call $write_state (i32.const 0) (i32.const 32) (i32.const 0)) (i32.const 32))
            (then (return (i32.const -1)))
            (else nop))
        (i32.const 0)
    )

    (memory (;0;) 1)
    (export "init_check_slot_time" (func $init_check_slot_time))
    (export "init_origin" (func $init_origin))
)