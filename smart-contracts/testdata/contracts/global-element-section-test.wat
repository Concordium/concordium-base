(module

  ;; This module used to be valid, but has then been
  ;; made invalid by stricter rules for appearance of globals
  ;; in element sections.
  ;; 
  ;; To compile with wat2wasm, use the --no-check option.

  (global $g0 i32 (i32.const 0))

  (func $init (export "init_test") (param i64) (result i32)
    (i32.const 0) ;; Successful init
  )

  (func (export "test.receive") (param i64) (result i32)
    (i32.const 0) ;; success
  )

  (table 1 funcref)
  ;; This is the invalid part. Globals cannot be used for offsets in the element section.
  (elem (offset (global.get $g0)) $init)

  (memory 1)
)
