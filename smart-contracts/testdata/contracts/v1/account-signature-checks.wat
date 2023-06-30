;; This module contains a single contract with entrypoints for checking account signatures, functionality introduced in P6.
(module

 ;; Imports
 (import "concordium" "get_parameter_size" (func $get_parameter_size (param $index i32) (result i32)))
 (import "concordium" "get_parameter_section" (func $get_parameter_section (param $index i32) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "invoke" (func $invoke (param $tag i32) (param $start i32) (param $length i32) (result i64)))
 (import "concordium" "write_output" (func $write_output (param $start i32) (param $length i32) (param $offset i32) (result i32)))

 ;; Helper functions

 (func $assert_eq (param $actual i32) (param $expected i32)
       (if (i32.eq (local.get $actual) (local.get $expected))
           (then nop)
           (else unreachable)))

 (func $assert_eq_64 (param $actual i64) (param $expected i64)
       (if (i64.eq (local.get $actual) (local.get $expected))
           (then nop)
           (else unreachable)))

 ;; Contract

 ;; Initialize contract.
 (func $init (export "init_contract") (param i64) (result i32)
       (return (i32.const 0))) ;; Successful init

 ;; Retrieve the parameter (an account address) and get the account keys for the parameter. Then return the keys.
 (func $receive_name (export "contract.get_keys") (param i64) (result i32)
      ;; Assume the parameter is an account address. 
      (call $get_parameter_section (i32.const 0) (i32.const 0) (i32.const 32) (i32.const 0))
      ;; query account keys, tag of the operation is 6.
      (call $invoke (i32.const 6) (i32.const 0) (i32.const 32))
      ;; The keys are output as parameter 1. Read them into linear memory.
      (call $get_parameter_section (i32.const 1) (i32.const 0) (call $get_parameter_size (i32.const 1)) (i32.const 0))
      ;; Output 4 bytes from linear memory
      (call $write_output (i32.const 0) (call $get_parameter_size (i32.const 1)) (i32.const 0))
      (return (i32.const 0)))

 ;; Get the signature and data from the parameter, and invoke the check signature operation. Then return the signature check result.
 (func $receive_upgrade (export "contract.check_signature") (param $amount i64) (result i32)
      (local $res i64)
      ;; get the entire parameter.
      (call $get_parameter_section (i32.const 0) (i32.const 0) (call $get_parameter_size (i32.const 0)) (i32.const 0))
      ;; check signature, tag of the operation is 5
      (local.set $res (call $invoke (i32.const 5) (i32.const 0) (call $get_parameter_size (i32.const 0))))
      (i64.store (i32.const 0) (local.get $res))
      ;; Output the return value from the invoke call as a return value of this entrypoint.
      (call $write_output (i32.const 0) (i32.const 8) (i32.const 0))
       ;; Return success
       (return (i32.const 0)))
 (memory 1))
