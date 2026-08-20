(module

  ;; This module tests the energy cost of the state_entry_read host function.
  ;; The function looks up the entry with an empty key and reads the requested length.

  (import "concordium" "state_lookup_entry" (func $state_lookup_entry (param i32 i32) (result i64)))
  (import "concordium" "state_entry_read" (func $state_entry_read (param i64 i32 i32 i32) (result i32)))

  (memory 1)

  (func (export "test.state_entry_read") (param $requested_length i64) (result i32)
    (local $entry i64)
    (local.set $entry (call $state_lookup_entry (i32.const 0) (i32.const 0)))
    (call $state_entry_read
      (local.get $entry)
      (i32.const 0)
      (i32.wrap_i64 (local.get $requested_length))
      (i32.const 0)))
)

;; compile-command: "wat2wasm state-entry-read-energy.wat"
