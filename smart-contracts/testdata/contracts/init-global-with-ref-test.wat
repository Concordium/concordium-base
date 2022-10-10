(module

  ;; This module is invalid because it tries to initialize
  ;; a global with the reference of another global.
  ;;
  ;; To compile with wat2wasm, use the --no-check option.

  (import "concordium" "accept" (func $accept (result i32)))

  (global $g0 i32 (i32.const 0))
  (global $g1 i32 (global.get $g0)) ;; The use of global.get here is invalid

  (func (export "init_test") (param i64) (result i32)
    (i32.const 0) ;; Successful init
  )

  (func (export "test.receive") (param i64) (result i32)
    (call $accept) ;; Successful receive
  )

  (memory 1)
)
