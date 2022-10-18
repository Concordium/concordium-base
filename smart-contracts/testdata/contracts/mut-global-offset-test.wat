(module

  ;; This module is invalid because it tries to use a mutable global
  ;; as an offset in the data and elem section.
  ;;
  ;; To compile with wat2wasm, use the --no-check option.

  (import "concordium" "accept" (func $accept (result i32)))

  (global $g0 (mut i32) (i32.const 0)) ;; mut global created

  (data (offset (global.get $g0)) "Hello, ") ;; mut global used for offset

  (table 1 funcref)
  (elem (offset (global.get $g0)) $f_i32) ;; mut global used for offset

  (func $f_i32 (result i32)
    (i32.const 32))

  (func $assert_eq (param $actual i32) (param $expected i32)
    (if (i32.eq (local.get $actual) (local.get $expected))
      (then nop)
      (else unreachable)))

  (func (export "init_test") (param i64) (result i32)
    (i32.const 0) ;; Successful init
  )

  (func (export "test.receive") (param i64) (result i32)

    (call $assert_eq
      (call_indirect (result i32) (global.get $g0)) ;; Call $f_i32
      (i32.const 32))

    (call $accept)
  )

  (memory 1)
)
