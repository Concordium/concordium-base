;; This module contains unit tests for the execution engine,
;; checking that the interpreter correctly executes the sign extension instructions.
(module
  ;; check that the arguments are equal, calling unreachable if they are not.
  (func $assert_eq_i64 (param $actual i64) (param $expected i64)
    (if (i64.eq (local.get $actual) (local.get $expected))
      (then nop)
      (else unreachable)))

  ;; check that the arguments are equal, calling unreachable if they are not.
  (func $assert_eq_i32 (param $actual i32) (param $expected i32)
    (if (i32.eq (local.get $actual) (local.get $expected))
      (then nop)
      (else unreachable)))

  (func (export "check_sign_extend_instructions")
    ;; https://github.com/WebAssembly/spec/blob/905f42d3e4d03a44614bee85d50cab988d55869d/test/core/i64.wast#L271
    (call $assert_eq_i64 (i64.extend8_s (i64.const 0)) (i64.const 0))
    (call $assert_eq_i64 (i64.extend8_s (i64.const 0x7f)) (i64.const 127))
    (call $assert_eq_i64 (i64.extend8_s (i64.const 0x80)) (i64.const -128))
    (call $assert_eq_i64 (i64.extend8_s (i64.const 0xff)) (i64.const -1))
    (call $assert_eq_i64 (i64.extend8_s (i64.const 0x01234567_89abcd_00)) (i64.const 0))
    (call $assert_eq_i64 (i64.extend8_s (i64.const 0xfedcba98_765432_80)) (i64.const -0x80))
    (call $assert_eq_i64 (i64.extend8_s (i64.const -1)) (i64.const -1))

    (call $assert_eq_i64 (i64.extend16_s (i64.const 0)) (i64.const 0))
    (call $assert_eq_i64 (i64.extend16_s (i64.const 0x7fff)) (i64.const 32767))
    (call $assert_eq_i64 (i64.extend16_s (i64.const 0x8000)) (i64.const -32768))
    (call $assert_eq_i64 (i64.extend16_s (i64.const 0xffff)) (i64.const -1))
    (call $assert_eq_i64 (i64.extend16_s (i64.const 0x12345678_9abc_0000)) (i64.const 0))
    (call $assert_eq_i64 (i64.extend16_s (i64.const 0xfedcba98_7654_8000)) (i64.const -0x8000))
    (call $assert_eq_i64 (i64.extend16_s (i64.const -1)) (i64.const -1))

    (call $assert_eq_i64 (i64.extend32_s (i64.const 0)) (i64.const 0))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0x7fff)) (i64.const 32767))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0x8000)) (i64.const 32768))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0xffff)) (i64.const 65535))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0x7fffffff)) (i64.const 0x7fffffff))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0x80000000)) (i64.const -0x80000000))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0xffffffff)) (i64.const -1))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0x01234567_00000000)) (i64.const 0))
    (call $assert_eq_i64 (i64.extend32_s (i64.const 0xfedcba98_80000000)) (i64.const -0x80000000))
    (call $assert_eq_i64 (i64.extend32_s (i64.const -1)) (i64.const -1))

    ;; https://github.com/WebAssembly/spec/blob/905f42d3e4d03a44614bee85d50cab988d55869d/test/core/i32.wast#L270
    (call $assert_eq_i32 (i32.extend8_s (i32.const 0)) (i32.const 0))
    (call $assert_eq_i32 (i32.extend8_s (i32.const 0x7f)) (i32.const 127))
    (call $assert_eq_i32 (i32.extend8_s (i32.const 0x80)) (i32.const -128))
    (call $assert_eq_i32 (i32.extend8_s (i32.const 0xff)) (i32.const -1))
    (call $assert_eq_i32 (i32.extend8_s (i32.const 0x012345_00)) (i32.const 0))
    (call $assert_eq_i32 (i32.extend8_s (i32.const 0xfedcba_80)) (i32.const -0x80))
    (call $assert_eq_i32 (i32.extend8_s (i32.const -1)) (i32.const -1))

    (call $assert_eq_i32 (i32.extend16_s (i32.const 0)) (i32.const 0))
    (call $assert_eq_i32 (i32.extend16_s (i32.const 0x7fff)) (i32.const 32767))
    (call $assert_eq_i32 (i32.extend16_s (i32.const 0x8000)) (i32.const -32768))
    (call $assert_eq_i32 (i32.extend16_s (i32.const 0xffff)) (i32.const -1))
    (call $assert_eq_i32 (i32.extend16_s (i32.const 0x0123_0000)) (i32.const 0))
    (call $assert_eq_i32 (i32.extend16_s (i32.const 0xfedc_8000)) (i32.const -0x8000))
    (call $assert_eq_i32 (i32.extend16_s (i32.const -1)) (i32.const -1))
  )
)
