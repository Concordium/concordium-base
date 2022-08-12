(module
  (type $external (func (param i32)))
  (func $foo (type $external) (param i32)
    (loop $loop
      ;; allocate memory until no longer able to, or until
      ;; the counter reaches 0
      (local.set 0 (i32.sub (local.get 0) (i32.const 1)))
      (if (i32.and (i32.gt_s (local.get 0) (i32.const 0)) (i32.ge_s (memory.grow (i32.const 1)) (i32.const 0)))
          (br $loop)
      )
    )
  )
  (func $write_u32 (type $external) (param i32)
    (drop (memory.grow (i32.const 512)))
    (loop $loop
      (i32.store (local.get 0) (i32.const 17))
      (local.set 0 (i32.sub (local.get 0) (i32.const 4)))
      (if (i32.ge_s (local.get 0) (i32.const 0))
          (br $loop)
      )
    )
  )
  (func $write_u64 (type $external) (param i32)
    (drop (memory.grow (i32.const 512)))
    (loop $loop
      (i64.store (local.get 0) (i64.const 17))
      (local.set 0 (i32.sub (local.get 0) (i32.const 8)))
      (if (i32.ge_s (local.get 0) (i32.const 0))
          (br $loop)
      )
    )
  )
  (func $write_u32_u8 (type $external) (param i32)
    (drop (memory.grow (i32.const 512)))
    (loop $loop
      (i32.store8 (local.get 0) (i32.const 17))
      (local.set 0 (i32.sub (local.get 0) (i32.const 1)))
      (if (i32.ge_s (local.get 0) (i32.const 0))
          (br $loop)
      )
    )
  )
  (func $write_u64_u8 (type $external) (param i32)
    (drop (memory.grow (i32.const 512)))
    (loop $loop
      (i64.store8 (local.get 0) (i64.const 17))
      (local.set 0 (i32.sub (local.get 0) (i32.const 1)))
      (if (i32.ge_s (local.get 0) (i32.const 0))
          (br $loop)
      )
    )
  )
  (table (;0;) 1 1 funcref)
  (memory (;0;) 0 1024)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "foo_extern" (func $foo))
  (export "write_u32" (func $write_u32))
  (export "write_u64" (func $write_u64))
  (export "write_u32_u8" (func $write_u32_u8))
  (export "write_u64_u8" (func $write_u64_u8))
)