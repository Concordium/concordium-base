;; Two flows are supported in this test, b and c.
;; Both start by calling entrypoint 'a' and passing in a parameter, b'b' (98 in ASCII) or b'c' (99).
;;
;; b flow:
;; - Invoke entrypoint 'a'
;;   - Set state = 112
;;   - Invoke entrypoint 'b'
;;     - Query own balance
;;     - Set state = 113
;;     - Fail with error -1
;;   - Assert state == 112 (rollback occurred)
;;
;; c flow:
;; - Invoke entrypoint 'a'
;;   - Set state = 112
;;   - Invoke entrypoint 'c'
;;     - Invoke entrypoint 'd'
;;       - Return success
;;     - Set state = 113
;;     - Fail with error -1
;;   - Assert state == 112 (rollback occurred)
(module

 ;; Imports

 (import "concordium" "get_parameter_section" (func $host_get_parameter_section (param $index i32) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "invoke" (func $host_invoke (param $tag i32) (param $start i32) (param $length i32) (result i64)))

 (import "concordium" "state_lookup_entry" (func $state_lookup_entry (param $key_start i32) (param $key_length i32) (result i64)))
 (import "concordium" "state_iterate_prefix" (func $state_iterate_prefix (param $key_start i32) (param $key_length i32) (result i64)))
 (import "concordium" "state_iterator_next" (func $state_iterator_next (param $iterator i64) (result i64)))
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

  ;; Assert that an invocation resulted in success.
  (func $assert_invoke_success (param $rv i64)
      (call $assert_eq_64
            ;; First 24 bits may have some parameter-related data.
            ;; So we shift those away and check whether the result is 0,
            ;; which means that the invoke succeeded.
            (i64.shl (local.get $rv) (i64.const 24))
            (i64.const 0)))

 ;; Invoke the `$rcv` entrypoint on the contract itself. Returns the return value from host_invoke.
 (func $invoke_self_receive (param $rcv i32) (result i64)
    ;; Prepare the wasm memory with the parameter to be used in the invoke.
    (call $get_receive_self_address (i32.const 0)) ;; 0..16: self address.
    (i32.store16 (i32.const 16) (i32.const 0)) ;; 16..18: parameter size
    (i32.store16 (i32.const 18) (i32.const 1)) ;; 18..20: entrypoint size ("$rcv" = 7)
    ;; 20..21: [$rcv]
    (i32.store8 (i32.const 20) (local.get $rcv)) ;; Use $rcv as the entrypoint name
    (i64.store (i32.const 21) (i64.const 0)) ;; 21..29: amount (0)

    (call $host_invoke
        (i32.const 1)    ;; Calling a contract
        (i32.const 0)    ;; Start of parameter in wasm memory
        (i32.const 29)) ;; Length of parameter
   )

 ;; Contract

 ;; Initialize contract by creating the entry at [].
(func $init (export "init_test") (param i64) (result i32)
       ;; Create entry [].
       (call $state_entry_write
             (call $state_create_entry (i32.const 0) (i32.const 0))
             (i32.const 0)
             (i32.const 0)
             (i32.const 0))
       (drop)
       (call $state_entry_write
             (call $state_create_entry (i32.const 0) (i32.const 1))
             (i32.const 0)
             (i32.const 1)
             (i32.const 0))
       (drop)
       (call $state_entry_write
             (call $state_create_entry (i32.const 0) (i32.const 2))
             (i32.const 0)
             (i32.const 2)
             (i32.const 0))
       (drop)
       (call $state_entry_write
             (call $state_create_entry (i32.const 0) (i32.const 3))
             (i32.const 0)
             (i32.const 3)
             (i32.const 0))
       (drop)
       (call $state_entry_write
             (call $state_create_entry (i32.const 0) (i32.const 4))
             (i32.const 0)
             (i32.const 4)
             (i32.const 0))
       (drop)
       ;; Return success.
       (i32.const 0))

;; Receive method 'a'.
(func $receive_a (export "test.a") (param i64) (result i32)
    (local $entrypoint i32)
    ;; Get the parameter, which is 1 byte, indicating which receive function to call below.
    ;; And check that one byte was read.
    (call $assert_eq
        (call $host_get_parameter_section
            (i32.const 0) ;; parameter index
            (i32.const 0) ;; pointer in wasm memory
            (i32.const 1) ;; length
            (i32.const 0)) ;; offset
        (i32.const 1))
    ;; Save the parameter to $entrypoint.
    (local.set $entrypoint (i32.load8_u (i32.const 0)))

    ;; Set the state to 112.
    (call $set_state (i64.const 112))
    ;; Call the $entrypoint.
    ;; And assert that it returned with error code -1 (0b11111111111111111111111111111111).
    (call $assert_eq_64
          (call $invoke_self_receive (local.get $entrypoint))
          (i64.const 1103806595071)) ;; Corresponds to 0b10000000011111111111111111111111111111111.

    ;; Check that the state was rolled back.
    (call $assert_eq_64
          (call $get_state)
          (i64.const 112))
       (i32.const 0))

 ;; Queries the self balance, sets state to 113, and fails.
 (func $receive_b (export "test.b") (param i64) (result i32)
       ;; Get the self address and put it at memory position 0..16.
       (call $get_receive_self_address (i32.const 0))

       ;; Get the contract balance and assert that the invocation succeeded.
       (call $assert_invoke_success
            (call $host_invoke
                (i32.const 3)   ;; Tag for the contract balance query
                (i32.const 0)   ;; Offset in memory to start reading from.
                (i32.const 16))) ;; The length of the parameter.

       ;; Set state to 113.
       (call $set_state (i64.const 113))

       ;; Fail with error code -1.
       (i32.const -1))

 ;; Calls entrypoint 'd', sets state to 113, and fails.
 (func $receive_c (export "test.c") (param i64) (result i32)
       ;; Call the entrypoint b'd' == 100.
       (call $assert_invoke_success
             (call $invoke_self_receive (i32.const 100)))

       ;; ;; Set state to 113
       (call $set_state (i64.const 113))

       ;; Fail with error code -1.
       (i32.const -1))

;; Receive method 'e'.
;; This first writes to an entry at [].
;; Then call the method specified in the parameter (as a single character)
;; and ensure that the method did not modify any state.
(func $receive_e (export "test.e") (param i64) (result i32)
    (local $entry i64)
    (local $entrypoint i32)
    ;; Get the parameter, which is 1 byte, indicating which receive function to call below.
    ;; And check that one byte was read.
    (call $assert_eq
        (call $host_get_parameter_section
            (i32.const 0) ;; parameter index
            (i32.const 0) ;; pointer in wasm memory
            (i32.const 1) ;; length
            (i32.const 0)) ;; offset
        (i32.const 1))
    ;; Save the parameter to $entrypoint.
    (local.set $entrypoint (i32.load8_u (i32.const 0)))

    ;; Lookup the entry at [].
    (local.set $entry (call $state_lookup_entry (i32.const 500) (i32.const 0)))
    ;; And write 8 bytes to it, does not matter what exactly.
    (call $state_entry_write (local.get $entry) (i32.const 0) (i32.const 8) (i32.const 0))

    ;; Call the $entrypoint and make sure the state was not modified.
    (call $assert_eq_64
          (call $invoke_self_receive (local.get $entrypoint))
          ;; Corresponds to 0b0000000000000000000000001000000000000000000000000000000000000000
          ;; indicating the state has not changed, and there is a return value at index 1.
          (i64.const 1099511627776))
     ;; and check that the entry we read above is still alive and of same size.
    (call $assert_eq
       (call $state_entry_read (local.get $entry) (i32.const 0) (i32.const 8) (i32.const 0))
       (i32.const 8)
    )
    (drop)
    (i32.const 0)
)

;; Look up an entry at [0,0,0,0], do a self-call to d, and then check that
;; the entry can still be read, and returns the correct value.
(func $receive_f (export "test.f") (param i64) (result i32)
   (local $entry i64)
   ;; Get the id for the entry at [].
   (local.set $entry (call $state_lookup_entry (i32.const 0) (i32.const 4)))

   (call $assert_eq_64
          (call $invoke_self_receive (i32.const 100)) ;; 100 is ascii code for 'd'
          ;; Corresponds to 0b0000000000000000000000001000000000000000000000000000000000000000
          ;; indicating the state has not changed, and there is a return value at index 1.
          (i64.const 1099511627776)) 
     ;; and check that the entry we read above is still alive.
   (call $assert_eq
        (call $state_entry_read (local.get $entry) (i32.const 0) (i32.const 4) (i32.const 0))
        (i32.const 4)
   )

   ;; Return success.
   (i32.const 0))

;; Does nothing and returns success.
(func $receive_d (export "test.d") (param i64) (result i32)
       ;; Return success.
       (i32.const 0))

 (memory 1))
