(module
  (type $external (func (param i32)))
  (type $empty (func))
  (func $loop (type $external) (param i32)
    (loop $loop
      (local.set 0 (i32.mul (local.get 0) (i32.const 17)))
      (br $loop)
    )
  )
  (func $empty_loop (type $empty)
    (loop $loop
      (br $loop)
    )
  )
  (func $empty_loop_if (type $empty)
    (loop $loop
      (i32.const 1)
      (br_if $loop)
    )
  )
  (export "loop" (func $loop))
  (export "empty_loop" (func $empty_loop))
  (export "empty_loop_if" (func $empty_loop_if))
)