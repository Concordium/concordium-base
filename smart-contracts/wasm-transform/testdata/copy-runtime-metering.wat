(module
  (func (export "add_and_copy")
    (local i64 i32)
    local.get 1
    i32.const 1
    i32.add
    local.set 1
    (local.set 0 (i64.const 123))
  )
  (func (export "add_and_copy_10")
      (local i64 i32)
      local.get 1
      i32.const 1
      i32.add
      local.set 1
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
  )
  (func (export "only_copy")
    (local i64)
    (local.set 0 (i64.const 123))
  )
  (func (export "only_copy_10")
    (local i64)
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
    (local.set 0 (i64.const 123))
  )
  (func (export "loop_copy")
    (local i64 i32)
    (loop $loop
      (local.set 0 (i64.const 123))

      local.get 1
      i32.const 1
      i32.add
      local.set 1

      local.get 1
      i32.const 10
      i32.lt_s
      br_if $loop
    )
  )
  (func (export "loop_copy_10")
    (local i64 i32)
    (loop $loop
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))
      (local.set 0 (i64.const 123))

      local.get 1
      i32.const 1
      i32.add
      local.set 1

      local.get 1
      i32.const 10
      i32.lt_s
      br_if $loop
    )
  )

  (memory (export "memory") 10)
)
