(module

  ;; Simple init and receive functions used for benchmarking host functions for V1 contracts.
  ;;
  ;; A general precondition is that at least one page of linear memory is allocated.
  ;; Additional preconditions are listed above the relevant functions.

  ;; Function parameter
  (import "concordium" "get_parameter_size" (func $get_parameter_size (param $index i32) (result i32)))
  (import "concordium" "get_parameter_section" (func $get_parameter_section (param $index i32) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))

  ;; State functions
  (import "concordium" "state_create_entry" (func $state_create_entry (param $key_start i32) (param $key_length i32) (result i64)))
  (import "concordium" "state_entry_size" (func $state_entry_size (param $entry i64) (result i32)))
  (import "concordium" "state_entry_read" (func $state_entry_read (param $entry i64) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
  (import "concordium" "state_lookup_entry" (func $state_lookup_entry (param $key_start i32) (param $key_length i32) (result i64)))
  (import "concordium" "state_entry_write" (func $state_entry_write (param $entry i64) (param $read_location i32) (param $length i32) (param $offset i32) (result i32)))
  (import "concordium" "state_delete_entry" (func $state_delete_entry (param $key_start i32) (param $key_length i32) (result i32)))
  (import "concordium" "state_delete_prefix" (func $state_delete_prefix (param $key_start i32) (param $key_length i32) (result i32)))

  ;; Iterator functions
  (import "concordium" "state_iterate_prefix" (func $state_iterate_prefix (param $key_start i32) (param $key_length i32) (result i64)))
  (import "concordium" "state_iterator_next" (func $state_iterator_next (param $iter i64) (result i64)))
  (import "concordium" "state_iterator_delete" (func $state_iterator_delete (param $iter i64) (result i32)))
  (import "concordium" "state_iterator_key_size" (func $state_iterator_key_size (param $iter i64) (result i32)))
  (import "concordium" "state_iterator_key_read" (func $state_iterator_key_read
                                                   (param $iter i64)
                                                   (param $write_location i32)
                                                   (param $length i32)
                                                   (param $offset i32)
                                                   (result i32)))

  ;; Fallback related functions. Only available in receive functions.
  (import "concordium" "get_receive_entrypoint_size" (func $get_ep_size (result i32)))
  (import "concordium" "get_receive_entrypoint" (func $get_ep (param $start i32)))

  ;; Invoke another contract or a transfer.
  (import "concordium" "invoke" (func $invoke (param $tag i32) (param $start i32) (param $length i32) (result i64)))

  ;; return a value
  (import "concordium" "write_output" (func $write_output (param $start i32) (param $length i32) (param $offset i32) (result i32)))

  ;; cryptographic primitives
  (import "concordium" "verify_ed25519_signature" (func $verify_ed25519_signature (param $public_key i32) (param $signature i32) (param $message i32) (param $message_len i32) (result i32)))
  (import "concordium" "verify_ecdsa_secp256k1_signature" (func $verify_ecdsa_secp256k1_signature (param $public_key i32) (param $signature i32) (param $message i32) (result i32)))
  (import "concordium" "hash_sha2_256" (func $hash_sha2_256 (param $data i32) (param $data_len i32) (param $output i32)))
  (import "concordium" "hash_sha3_256" (func $hash_sha3_256 (param $data i32) (param $data_len i32) (param $output i32)))
  (import "concordium" "hash_keccak_256" (func $hash_keccak_256 (param $data i32) (param $data_len i32) (param $output i32)))

  ;; Precondition. Read the parameter index from the first 4 bytes of the memory, interpreting it in little endian.
  (func (export "hostfn.get_parameter_size") (param i64) (result i32)
    (local $idx i32)
    (local.set $idx (i32.load (i32.const 0)))
    (loop $loop
        (call $get_parameter_size (local.get $idx))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition. Read the parameter index from the first 4 bytes of the memory, interpreting it in little endian.
  ;; Read the size as the next 4 bytes.
  (func (export "hostfn.get_parameter_section") (param i64) (result i32)
    (local $idx i32)
    (local $len i32)
    (local.set $idx (i32.load (i32.const 0)))
    (local.set $len (i32.load (i32.const 4)))
    (loop $loop
        (call $get_parameter_section (local.get $idx) (i32.const 0) (local.get $len) (i32.const 0))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to look up.
  ;; The entry at the given key exists.
  (func (export "hostfn.state_create_entry") (param i64) (result i32)
    (local $entry i64)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (loop $loop
        (call $state_create_entry (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to look up.
  ;; The entry at the given key exists.
  (func (export "hostfn.state_lookup_entry") (param i64) (result i32)
    (local $entry i64)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (call $state_lookup_entry (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to look up.
  ;; The entry at the given key exists.
  (func (export "hostfn.state_entry_size") (param i64) (result i32)
    (local $entry i64)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (local.set $entry (call $state_lookup_entry (i32.const 0) (local.get $len)))
    (loop $loop
        (call $state_entry_size (local.get $entry))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to look up.
  ;; The entry at the given key exists.
  ;; The argument (param) is the length of data to read. It is assumed there is enough data to read.
  (func (export "hostfn.state_entry_read") (param $param i64) (result i32)
    (local $entry i64)
    (local $len i32)
    (local.set $len (i32.load (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (local.set $entry (call $state_lookup_entry (i32.const 0) (local.get $len)))
    (loop $loop
      (call $state_entry_read (local.get $entry) (i32.const 0) (i32.wrap_i64 (local.get $param)) (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to look up.
  ;; The entry at the given key exists.
  ;; The argument (param) is the length of data to write. The initial segment of memory will be read.
  ;; It is assumed there is enough data to read.
  (func (export "hostfn.state_entry_write") (param $param i64) (result i32)
    (local $entry i64)
    (local $len i32)
    (local.set $len (i32.load (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (local.set $entry (call $state_lookup_entry (i32.const 0) (local.get $len)))
    (loop $loop
      (call $state_entry_write (local.get $entry) (i32.const 0) (i32.wrap_i64 (local.get $param)) (i32.const 0))
      (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to look up.
  (func (export "hostfn.state_delete_entry") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (call $state_create_entry (i32.const 0) (local.get $len))
        (call $state_delete_entry (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to look up.
  (func (export "hostfn.state_delete_entry_nonexistent") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    ;; repeatedly delete the same entry
    (loop $loop
        (call $state_delete_entry (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to start iterating over.
  (func (export "hostfn.state_iterate_prefix") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (call $state_iterate_prefix (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to start iterating over.
  ;; A value exists at that location.
  (func (export "hostfn.state_iterator_delete") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (if (i32.ne (i32.const 1) (call $state_iterator_delete (call $state_iterate_prefix (i32.const 0) (local.get $len)))) (then unreachable))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to delete. For meaningful measurements
  ;; the prefix should exist.
  (func (export "hostfn.state_delete_prefix") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (call $state_create_entry (i32.const 0) (local.get $len))
        (call $state_delete_prefix (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to start iterating over.
  (func (export "hostfn.state_iterator_key_size") (param i64) (result i32)
    (local $len i32)
    (local $iter i64)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (local.set $iter (call $state_iterate_prefix (i32.const 0) (local.get $len)))
    (loop $loop
        (if (i32.ne (call $state_iterator_key_size (local.get $iter)) (local.get $len)) (then unreachable))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition, parameter is the key to start iterating over.
  (func (export "hostfn.state_iterator_key_read") (param i64) (result i32)
    (local $len i32)
    (local $key_len i32)
    (local $iter i64)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (local.set $iter (call $state_iterate_prefix (i32.const 0) (local.get $len)))
    (local.set $key_len (call $state_iterator_key_size (local.get $iter)))
    (loop $loop
        (if (i32.ne (local.get $key_len) (call $state_iterator_key_read (local.get $iter) (i32.const 0) (local.get $key_len) (i32.const 0))) (then unreachable))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; Precondition. Empty key is in the state.
  ;; It is assumed that the state is set up so that the first iterator step is meaningful.
  (func (export "hostfn.state_iterator_next") (param i64) (result i32)
    (local $len i32)
    (local $iter i64)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (loop $loop
        (local.set $iter (call $state_iterate_prefix (i32.const 0) (i32.const 0)))
        (loop $inner
            (br_if $inner (i64.ne (i64.const 18446744073709551615) (call $state_iterator_next (local.get $iter)))))
        (if (i32.ne (i32.const 0) (call $state_iterator_key_size (local.get $iter))) (then unreachable))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; The given parameter is what will be written.
  (func (export "hostfn.write_output") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (call $write_output (i32.const 0) (local.get $len) (i32.const 0))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; The given parameter is the parameter that will be passed to invoke.
  (func (export "hostfn.invoke_transfer") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (call $invoke (i32.const 0) (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  ;; The given parameter is the parameter that will be passed to invoke.
  (func (export "hostfn.invoke_contract") (param i64) (result i32)
    (local $len i32)
    (local.set $len (call $get_parameter_size (i32.const 0)))
    (call $get_parameter_section (i32.const 0) (i32.const 0) (local.get $len) (i32.const 0))
    (loop $loop
        (call $invoke (i32.const 1) (i32.const 0) (local.get $len))
        (br $loop)
    )
    (return (i32.const 0))
  )

  (func (export "hostfn.verify_ed25519_signature") (param i64) (result i32)
      (local $len i32)
      (call $get_parameter_section (i32.const 0) (i32.const 0) (i32.const 100) (i32.const 0))
      (local.set $len (i32.load (i32.const 96)))
      (loop $loop
        (call $verify_ed25519_signature (i32.const 0) (i32.const 32) (i32.const 100) (local.get $len))
        (br_if $loop) ;; only loop if we succeeded in verifying the signature
      )
      (return (i32.const 0))
  )

  (func (export "hostfn.verify_ecdsa_secp256k1_signature") (param i64) (result i32)
      (call $get_parameter_section (i32.const 0) (i32.const 0) (i32.const 129) (i32.const 0))
      (loop $loop
        (call $verify_ecdsa_secp256k1_signature (i32.const 0) (i32.const 33) (i32.const 97))
        (br_if $loop) ;; only loop if we succeeded in verifying the signature
      )
      (return (i32.const 0))
  )

  (func (export "hostfn.hash_sha2_256") (param i64) (result i32)
      (local $len i32)
      (call $get_parameter_section (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 0))
      (local.set $len (i32.load (i32.const 0)))
      (loop $loop
        (call $hash_sha2_256 (i32.const 0) (local.get $len) (i32.const 0))
        (br $loop)
      )
      (return (i32.const 0))
  )

  (func (export "hostfn.hash_sha3_256") (param i64) (result i32)
      (local $len i32)
      (call $get_parameter_section (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 0))
      (local.set $len (i32.load (i32.const 0)))
      (loop $loop
        (call $hash_sha3_256 (i32.const 0) (local.get $len) (i32.const 0))
        (br $loop)
      )
      (return (i32.const 0))
  )

  (func (export "hostfn.hash_keccak_256") (param i64) (result i32)
      (local $len i32)
      (call $get_parameter_section (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 0))
      (local.set $len (i32.load (i32.const 0)))
      (loop $loop
        (call $hash_keccak_256 (i32.const 0) (local.get $len) (i32.const 0))
        (br $loop)
      )
      (return (i32.const 0))
  )


  (memory 2)
)

;; Local Variables:
;; compile-command: "wat2wasm host-functions.wat"
;; End:
