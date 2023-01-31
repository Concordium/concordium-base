(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func (param i32)))
  (type (;2;) (func (param i64) (result i32)))
  (import "concordium" "get_receive_owner" (func (;0;) (type 1)))
  (func (;1;) (type 0) (param i32)
    (local i64))
  (func (;2;) (type 2) (param i64) (result i32)
    i32.const 0
    call 0
    i32.const 0)
  (table (;0;) 460 funcref)
  (memory (;0;) 0)
  (global (;0;) i32 (i32.const 0))
  (export ".AA" (func 2))
  (export "init_AA" (func 2))
  (elem (;0;) (i32.const 0) func 0)
  (data (;0;) (i32.const 0) ""))

(;
  thread 'main' panicked at 'range end index 32 out of range for slice of length 0', src/lib.rs:509:23
;)