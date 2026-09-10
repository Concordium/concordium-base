(module

  ;; This module tests the results and energy costs of state_entry_read and
  ;; state_entry_size for valid and invalid entry handles.

  (import "concordium" "state_lookup_entry" (func $state_lookup_entry (param i32 i32) (result i64)))
  (import "concordium" "state_delete_entry" (func $state_delete_entry (param i32 i32) (result i32)))
  (import "concordium" "state_delete_prefix" (func $state_delete_prefix (param i32 i32) (result i32)))
  (import "concordium" "state_entry_read" (func $state_entry_read (param i64 i32 i32 i32) (result i32)))
  (import "concordium" "state_entry_size" (func $state_entry_size (param i64) (result i32)))

  (memory 1)

  ;; Return a handle selected by mode:
  ;; 0 is valid, 1 is deleted directly, 2 has a stale generation, 3 is
  ;; absent, and 4 is invalidated by prefix deletion.
  (func $entry_for_mode (param $mode i32) (result i64)
    (local $entry i64)
    (local.set $entry (call $state_lookup_entry (i32.const 0) (i32.const 0)))
    (if (i32.eq (local.get $mode) (i32.const 1))
      (then
        (drop (call $state_delete_entry (i32.const 0) (i32.const 0)))))
    (if (i32.eq (local.get $mode) (i32.const 4))
      (then
        (drop (call $state_delete_prefix (i32.const 0) (i32.const 0)))))
    (if (i32.eq (local.get $mode) (i32.const 2))
      (then
        ;; The host starts in generation 1. Subtract one generation to use a
        ;; handle from generation 0.
        (local.set $entry
          (i64.sub (local.get $entry) (i64.const 4294967296)))))
    (if (i32.eq (local.get $mode) (i32.const 3))
      (then
        (local.set $entry (i64.const 42))))
    (local.get $entry))

  ;; The read parameter packs the requested length in the low 32 bits, the
  ;; offset in the next 28 bits, and the handle mode in the high 4 bits.
  (func (export "test.state_entry_read") (param $operation i64) (result i32)
    (call $state_entry_read
      (call $entry_for_mode
        (i32.wrap_i64 (i64.shr_u (local.get $operation) (i64.const 60))))
      (i32.const 0)
      (i32.wrap_i64 (local.get $operation))
      (i32.wrap_i64 (i64.shr_u (local.get $operation) (i64.const 32)))))

  (func (export "test.state_entry_size") (param $mode i64) (result i32)
    (call $state_entry_size
      (call $entry_for_mode (i32.wrap_i64 (local.get $mode)))))
)

;; compile-command: "wat2wasm state-entry-read-energy.wat"
