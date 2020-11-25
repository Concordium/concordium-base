(module
  (type $external (func (param i32)))
  (func $loop (type $external) (param i32)
    (loop $loop
      (local.set 0 (i32.mul (local.get 0) (i32.const 17)))
      (br $loop)
    )
  )
  (export "loop" (func $loop))
)