(module
  ;; execute n iterations of the loop, where n is the given parameter.
  (func $loop (export "loop") (param i32)
    (loop $loop
      (local.set 0 (i32.mul (local.get 0) (i32.const 17)))
      (br $loop)
    )
  )

  ;; infinite empty loop
  (func (export "empty_loop")
    (loop $loop
      (br $loop)
    )
  )

  ;; a function with no arguments that immediately returns.
  (func $just_return)

  ;; call the previous function in an infinite loop
  (func (export "call_empty_function")
     (loop $loop
       (call $just_return)
       (br $loop)
     )
  )

  ;; infinite loop with a nested block
  (func (export "block")
    (loop $loop
      (block $block
        (br $loop)
      )
    )
  )
)