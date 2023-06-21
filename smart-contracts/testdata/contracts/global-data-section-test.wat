(module

  ;; This module is used to be valid, but has then been
  ;; made invalid by stricter rules for appearance of globals
  ;; in data sections.
  ;; 
  ;; To compile with wat2wasm, use the --no-check option.

  (global $g0 i32 (i32.const 0))

  (func (export "init_test") (param i64) (result i32)
    (i32.const 0) ;; Successful init
  )

  (func (export "test.receive") (param i64) (result i32)
    (i32.const 0) ;; success
  )

  (data (offset (global.get $g0)) "Hello, ")

  (memory 1)
)
