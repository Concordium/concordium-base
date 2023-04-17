;; A fibonacci contract that uses the state.
;; Matches the behaviour and API of the fib example contract in concordium-rust-smart-contracts.
(module

 ;; Imports

 (import "concordium" "get_parameter_section" (func $host_get_parameter_section (param $index i32) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "invoke" (func $host_invoke (param $tag i32) (param $start i32) (param $length i32) (result i64)))

 (import "concordium" "state_lookup_entry" (func $state_lookup_entry (param $key_start i32) (param $key_length i32) (result i64)))
 (import "concordium" "state_create_entry" (func $state_create_entry (param $key_start i32) (param $key_length i32) (result i64)))
 (import "concordium" "state_entry_read" (func $state_entry_read (param $entry i64) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "state_entry_write" (func $state_entry_write (param $entry i64) (param $read_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "write_output" (func $write_output (param $read_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "get_receive_self_address" (func $get_receive_self_address (param $start i32)))

 ;; Helper functions

 ;; Cause a runtime error if the two provided numbers are not equal.
 (func $assert_eq (param $actual i32) (param $expected i32)
       (if (i32.eq (local.get $actual) (local.get $expected))
           (then nop)
           (else unreachable)))

 ;; Cause a runtime error if the two provided numbers are not equal.
 (func $assert_eq_64 (param $actual i64) (param $expected i64)
       (if (i64.eq (local.get $actual) (local.get $expected))
           (then nop)
           (else unreachable)))

 ;; Read the parameter into memory.
 (func $get_parameter (param $write_offset i32) (param $length i32) (param $read_offset i32) (result i32)
       (return
         (call $host_get_parameter_section
               (i32.const 0)
               (local.get $write_offset) ;; Write offset in memory.
               (local.get $length) ;; Write length.
               (local.get $read_offset)))) ;; Offset to read from.

 ;; Write a u64 to the [] entry in the state and assert that it succeeded.
 (func $set_state (param $val i64)
    (local $entry i64)
    ;; Get the id for the entry at [].
    (local.set $entry (call $state_lookup_entry (i32.const 0) (i32.const 0)))
    ;; Store the input value at memory location 0.
    (i64.store (i32.const 0) (local.get $val))
    ;; Then write the u64 to the state from the position 0 in memory. Also check that writing succeeded.
    (call $assert_eq
      (call $state_entry_write (local.get $entry) (i32.const 0) (i32.const 8) (i32.const 0))
      (i32.const 8)) ;; Eight bytes should have been written.
    )

 ;; Read the u64 state to wasm memory location 0 and assert that 8 bytes were read.
 (func $get_state (result i64)
    (local $entry i64)
    ;; Get the id for the entry at [].
    (local.set $entry (call $state_lookup_entry (i32.const 0) (i32.const 0)))
    ;; Read to memory position 0.
    (call $assert_eq
        (call $state_entry_read (local.get $entry) (i32.const 0) (i32.const 8) (i32.const 0))
        (i32.const 8)
    )
    ;; Return the state value.
    (i64.load (i32.const 0)))

 ;; Set the provided u64 as the return value, by using the `write_output` host function. Asserts that it succeeded.
 (func $set_return_value (param $val i64)
    ;; Store the value at memory location 16.
    (i64.store (i32.const 0) (local.get $val))
    ;; Then write the u64 to the output from the position 0 in memory. Also check that writing succeeded.
    (call $assert_eq
      (call $write_output (i32.const 0) (i32.const 8) (i32.const 0))
      (i32.const 8)) ;; Eight bytes should have been written.
    )

   ;; Assert that an invocation resulted in success.
  (func $assert_invoke_success (param $rv i64)
      (call $assert_eq_64
            ;; First 24 bits may have some parameter-related data.
            ;; So we shift those away and check whether the result is 0,
            ;; which means that the invoke succeeded.
            (i64.shl (local.get $rv) (i64.const 24))
            (i64.const 0)))

  ;; Extracts the parameter index part from a (assumed successful) result of a invoke call.
  (func $extract_param_index (param $rv i64) (result i32)
        (local $out i32)
        ;; Shift 40 right.
        (local.set $rv (i64.shr_u (local.get $rv) (i64.const 40)))
        ;; Convert to i32.
        (local.set $out (i32.wrap_i64 (local.get $rv)))
        ;; Then set the first bit to zero, as it indicates state changes, and we just need the parameter index.
        ;; Use a mask for it:
        ;; The numeric value 8388607 is the mask 0b0111_1111_1111_1111_1111_1111.
        (local.set $out (i32.and
                         (i32.const 8388607)
                         (local.get $out)))
        ;; Return the result.
        (local.get $out))

 ;; Invoke the receive entrypoint on the contract itself with the provided parameter.
 (func $invoke_self_receive (param $n i64) (result i64)
    (local $invoke_res i64)
    (local $parameter_index i32)
    ;; Prepare the wasm memory with the parameter to be used in the invoke.
    (call $get_receive_self_address (i32.const 0)) ;; 0..16: self address.
    (i32.store16 (i32.const 16) (i32.const 8)) ;; 16..18: parameter size
    (i64.store (i32.const 18) (local.get $n)) ;; 18..26: parameter (`n`)
    (i32.store16 (i32.const 26) (i32.const 7)) ;; 26..28: entrypoint size ("receive" = 7)
    ;; 28..35: "receive" = [114, 101, 99, 101, 105, 118, 101]
    (i32.store8 (i32.const 28) (i32.const 114)) ;; r
    (i32.store8 (i32.const 29) (i32.const 101)) ;; e
    (i32.store8 (i32.const 30) (i32.const 99))  ;; c
    (i32.store8 (i32.const 31) (i32.const 101)) ;; e
    (i32.store8 (i32.const 32) (i32.const 105)) ;; i
    (i32.store8 (i32.const 33) (i32.const 118)) ;; v
    (i32.store8 (i32.const 34) (i32.const 101)) ;; e
    (i64.store (i32.const 35) (i64.const 0)) ;; 35..43: amount (0)

    (local.set $invoke_res
       (call $host_invoke
          (i32.const 1)    ;; Calling a contract
          (i32.const 0)    ;; Start of parameter in wasm memory
          (i32.const 43))) ;; Length of parameter

    ;; Assert that the invoke succeeded.
    (call $assert_invoke_success (local.get $invoke_res))

    ;; Get parameter index
    (local.set $parameter_index (call $extract_param_index (local.get $invoke_res)))

    ;; Get the return value (save to wasm memory location 0).
    ;; And ensure that eight bytes were read.
    (call $assert_eq
          (call $host_get_parameter_section (local.get $parameter_index) (i32.const 0) (i32.const 8) (i32.const 0))
          (i32.const 8))
    ;; Return the u64 at wasm memory location 0.
    (i64.load (i32.const 0))
   )

 ;; Contract

 ;; Initialize contract.
 (func $init (export "init_fib") (param i64) (result i32)
       ;; Create an entry at [].
       (call $state_create_entry (i32.const 0) (i32.const 0))
       ;; Ignoring the return value, as $set_state also looks it up.
       (drop)
       ;; Set the initial state to be 0.
       (call $set_state (i64.const 0))
       ;; Return success.
       (i32.const 0))

 ;; Receive method
 (func $receive_method (export "fib.receive") (param i64) (result i32)
       ;; Declare some local variables.
       (local $n i64)
       (local $n2 i64)
       (local $n1 i64)
       (local $cv2 i64)
       (local $cv1 i64)
       (local $res i64)

       ;; Read the parameter $n (u64) into memory and check that we successfully read it.
       (call $assert_eq
         (call $get_parameter
           (i32.const 0) ;; Write offset in memory
           (i32.const 8) ;; Length.
           (i32.const 0)) ;; Read offset.
         (i32.const 8))
       ;; Set $n.
       (local.set $n (i64.load (i32.const 0)))

       (if
        (i64.le_u (local.get $n) (i64.const 1))
        ;; If $n <= 1, end recursion.
        (then
          (call $set_state (i64.const 1))
          (call $set_return_value (i64.const 1))
         )
        (else
          ;; Invoke self with n - 2 and save in $n2.
          (local.set $n2 (call $invoke_self_receive (i64.sub (local.get $n) (i64.const 2))))
          ;; Read state and save in $cv2.
          (local.set $cv2 (call $get_state))
          ;; Assert that $n2 == $cv2.
          (call $assert_eq_64 (local.get $n2) (local.get $cv2))

          ;; Invoke self with n -1 and save in $n1.
          (local.set $n1 (call $invoke_self_receive (i64.sub (local.get $n) (i64.const 1))))
          ;; Read state and save in $cv1.
          (local.set $cv1 (call $get_state))
          ;; Assert that $n1 == $cv1.
          (call $assert_eq_64 (local.get $n1) (local.get $cv1))

          ;; Set state to $cv1 + $cv2.
          (local.set $res (i64.add (local.get $cv1) (local.get $cv2)))
          (call $set_state (local.get $res))

          ;; Return $cv1 + $cv2.
          (call $set_return_value (local.get $res))
         ))

       ;; Return success
       (i32.const 0)
       )

 ;; View method
 (func $view_method (export "fib.view") (param i64) (result i32)
    ;; Set the current state as the return value.
    (call $set_return_value (call $get_state))
    ;; Return success.
    (i32.const 0))

 (memory 1))
