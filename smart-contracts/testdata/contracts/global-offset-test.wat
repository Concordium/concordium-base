(module

  ;; This module tests the use of global.get for offsets
  ;; in data and elem sections.

  (import "concordium" "accept" (func $accept (result i32)))

  (global $g0 i32 (i32.const 0))
  (global $g1 i32 (i32.const 1))
  (global $g3 i32 (i32.const 7))

  (data (offset (global.get $g0)) "Hello, ")
  (data (offset (global.get $g3)) "world!")

  (table 2 funcref)
  (elem (offset (global.get $g0)) $f_i32)
  (elem (offset (global.get $g1)) $f_i64)

  (func $f_i32 (result i32)
    (i32.const 32))

  (func $f_i64 (result i64)
    (i64.const 64))

  (func $assert_eq (param $actual i32) (param $expected i32)
    (if (i32.eq (local.get $actual) (local.get $expected))
      (then nop)
      (else unreachable)))

  (func $assert_eq_i64 (param $actual i64) (param $expected i64)
    (if (i64.eq (local.get $actual) (local.get $expected))
      (then nop)
      (else unreachable)))

  (func (export "init_test") (param i64) (result i32)
    (i32.const 0) ;; Successful init
  )

  (func (export "test.receive") (param i64) (result i32)

    (call $assert_eq
      (call_indirect (result i32) (global.get $g0)) ;; Call $f_i32
      (i32.const 32))

    (call $assert_eq_i64
      (call_indirect (result i64) (global.get $g1)) ;; Call $f_i64
      (i64.const 64))

    (call $accept)
  )

  (memory 1)
)
