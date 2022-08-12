(module
  (type $external (func (param i64) (result i32)))
  (func $init (type $external) (param i64) (result i32)
    (i32.const 0)
  )
  (export "init_" (func $init))
  (export "." (func $init))
)