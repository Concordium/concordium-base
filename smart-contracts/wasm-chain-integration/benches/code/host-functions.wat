(module

  ;; Simple init and receive functions used for benchmarking the host functions.
  ;;
  ;; A general precondition is that at least one page of linear memory is allocated.
  ;; Additional preconditions are listed above the relevant functions.

  ;; Data section
  ;; Let bytes 0-32 in be all zeros to be used as address in simple_transfer.
  (data (i32.const 32) "hostfn.send_target") ;; Used for hostfn.send


  ;; Logging events
  (import "concordium" "log_event" (func $log_event (param $start i32) (param $length i32) (result i32)))

  ;; Function parameter
  (import "concordium" "get_parameter_size" (func $get_parameter_size (result i32)))
  (import "concordium" "get_parameter_section" (func $get_parameter_section (param $location i32)
                                                 (param $length i32) (param $offset i32)(result i32)))

  ;; Smart contract instance state
  (import "concordium" "state_size" (func $state_size (result i32)))
  (import "concordium" "load_state" (func $load_state (param $location i32) (param $length i32)
                                      (param $offset i32) (result i32)))
  (import "concordium" "write_state" (func $write_state (param $location i32) (param $length i32)
                                       (param $offset i32) (result i32)))
  (import "concordium" "resize_state" (func $resize_state (param $new_size i32) (result i32)))

  ;; Chain data
  (import "concordium" "get_slot_time" (func $get_slot_time (result i64)))

  ;; Only in init function
  (import "concordium" "get_init_origin" (func $get_init_origin (param $start i32)))

  ;; Only in receive function
  (import "concordium" "get_receive_invoker" (func $get_receive_invoker (param $start i32)))
  (import "concordium" "get_receive_sender" (func $get_receive_sender (param $start i32)))
  (import "concordium" "get_receive_self_address" (func $get_receive_self_address (param $start i32)))
  (import "concordium" "get_receive_owner" (func $get_receive_owner (param $start i32)))
  (import "concordium" "get_receive_self_balance" (func $get_receive_self_balance (result i64)))

  ;; Action description
  (import "concordium" "accept" (func $accept (result i32)))
  (import "concordium" "simple_transfer" (func $simple_transfer (param $addr_bytes i32)
                                           (param $amount i64) (result i32)))

  (import "concordium" "send" (func $send (param $addr_index i64) (param $addr_subindex i64)
                                (param $receive_name i32) (param $receive_name_len i32)
                                (param $amount i64) (param $parameter i32) (param $parameter_len i32)
                                (result i32)))
  (import "concordium" "combine_and" (func $combine_and (param $first i32) (param $second i32)
                                        (result i32)))
  (import "concordium" "combine_or" (func $combine_or (param $first i32) (param $second i32)
                                         (result i32)))


  (func (export "hostfn.log_event") (param i64) (result i32)
    (loop $loop 
       (call $log_event (i32.const 0) (i32.const 10))
       (drop)
       (br $loop)
    )
    (return (call $accept))
  )

  ;; Precondition: Send parameter of size 10.
  (func (export "hostfn.get_parameter_size") (param i64) (result i32)
    (loop $loop 
        (call $get_parameter_size)
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition: Send parameter of size 10.
  (func (export "hostfn.get_parameter_section") (param i64) (result i32)
    (loop $loop
        (call $get_parameter_section (i32.const 0) (i32.const 0) (i32.const 0))
        (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.state_size") (param i64) (result i32)
    (loop $loop
        (call $state_size)
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition: Setup state with size 10.
  (func (export "hostfn.load_state") (param i64) (result i32)
    (loop $loop
      (call $load_state (i32.const 0) (i32.const 10) (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.write_state") (param i64) (result i32)
    (loop $loop
      (call $write_state (i32.const 0) (i32.const 10) (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  ;; try to do the most pessimistic sequence of resizes.
  ;; resize from 0 to max sizes back to 0, repeat
  (func (export "hostfn.resize_state") (param $arg i64) (result i32)
    (loop $loop
      (if (i64.eqz (local.get $arg))
        (block
          (local.set $arg (i64.const 1))
          (call $resize_state (i32.const 0))
          (br $loop)
        )
      )
      (local.set $arg (i64.const 0))
      (call $resize_state (i32.const 16383))
      (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.get_slot_time") (param i64) (result i32)
    (loop $loop
       (call $get_slot_time)
       (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "init_get_init_origin") (param i64) (result i32)
    (loop $loop
       (call $get_init_origin (i32.const 0))
       (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.get_receive_invoker") (param i64) (result i32)
    (loop $loop
      (call $get_receive_invoker (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.get_receive_sender") (param i64) (result i32)
    (loop $loop
      (call $get_receive_sender (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.get_receive_self_address") (param i64) (result i32)
    (loop $loop
      (call $get_receive_self_address (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.get_receive_owner") (param i64) (result i32)
    (loop $loop
      (call $get_receive_owner (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.get_receive_self_balance") (param i64) (result i32)
    (loop $loop
      (call $get_receive_self_balance (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.accept") (param i64) (result i32)
    (loop $loop
      (call $accept)
      (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition:
  ;; - Address specified in data section should be valid.
  ;; - Contract balance >= 1.
  (func (export "hostfn.simple_transfer") (param i64) (result i32)
    (loop $loop
      (call $simple_transfer
        (i32.const 0) ;; Address of 32 bytes. Specified in data section.
        (i64.const 1) ;; amount
        )
      (br $loop)
    )
    (i32.const 0)
  )

  ;; Preconditions:
  ;;  - Contract address should be <0,0>
  ;;  - Receive_name specified in data section should exist.
  (func (export "hostfn.send") (param i64) (result i32)
    (loop $loop
      (call $send
        (i64.const 0)  ;; addr_index
        (i64.const 0)  ;; addr_subindex
        (i32.const 32) ;; receive_name: "hostfn.send_target", specified in data section.
        (i32.const 18) ;; receive_name_len
        (i64.const 0)  ;; amount
        (i32.const 0)  ;; parameter
        (i32.const 0)  ;; parameter_len
        )
      (br $loop)
    )
    (i32.const 0)
  )

  ;; Not benched directly. Used by hostfn.send.
  (func (export "hostfn.send_target") (param i64) (result i32)
    (i32.const 0)
  )

  (func (export "hostfn.combine_and") (param i64) (result i32)
    (loop $loop
      (call $combine_and (call $accept) (call $accept))
      (br $loop)
    )
    (i32.const 0)
  )

  (func (export "hostfn.combine_or") (param i64) (result i32)
    (loop $loop
      (call $combine_or (call $accept) (call $accept))
      (br $loop)
    )
    (i32.const 0)
  )

  (memory 1)
)

;; Local Variables:
;; compile-command: "wat2wasm host-functions.wat"
;; End:
