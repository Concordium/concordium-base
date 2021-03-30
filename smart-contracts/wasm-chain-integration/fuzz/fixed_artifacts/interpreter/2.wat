(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func (param i64) (result i32)))
  (func (;0;) (type 0) (param i32)
    (local i32))
  (func (;1;) (type 1) (param i64) (result i32)
    i32.const 0
    call 0
    i32.const 0
    unreachable)
  (table (;0;) 763 funcref)
  (memory (;0;) 65396)
  (global (;0;) i32 (i32.const 1720752529))
  (export "CKCC" (memory 0))
  (export "init_A" (func 1))
  (elem (;0;) (i32.const 2) func 0)
  (data (;0;) (i32.const 639723110) "\ff\ff\ff"))

(;
AddressSanitizer:DEADLYSIGNAL
=================================================================
==233680==ERROR: AddressSanitizer: SEGV on unknown address 0x7f974f10ee67 (pc 0x7f9730480da8 bp 0x7ffff004fff0 sp 0x7ffff004f7a8 T0)
==233680==The signal is caused by a WRITE memory access.
    #0 0x7f9730480da8  /build/glibc-eX1tMB/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:328
    #1 0x5604be1e7ff7 in __asan_memcpy /rustc/llvm/src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3
    #2 0x5604be2b92f9 in wasm_transform::machine::_$LT$impl$u20$wasm_transform..artifact..Artifact$LT$I$C$R$GT$$GT$::run::h49675a4d496e1df6 (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x4992f9)
    #3 0x5604be318c9a in wasm_chain_integration::invoke_init::hf58bffc0f822a296 (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x4f8c9a)
    #4 0x5604be31cf5e in wasm_chain_integration::invoke_init_with_metering_from_source::he5b0301b9a30677e (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x4fcf5e)
    #5 0x5604be42ed19 in rust_fuzzer_test_input (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x60ed19)
    #6 0x5604beb0d0e0 in __rust_try (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xced0e0)
    #7 0x5604beb0cd3f in LLVMFuzzerTestOneInput (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xcecd3f)
    #8 0x5604beb210fc in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xd010fc)
    #9 0x5604beb108d9 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xcf08d9)
    #10 0x5604beb1a412 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xcfa412)
    #11 0x5604be16e2b6 in main (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x34e2b6)
    #12 0x7f97303e90b2 in __libc_start_main /build/glibc-eX1tMB/glibc-2.31/csu/../csu/libc-start.c:308:16
    #13 0x5604be16e45d in _start (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x34e45d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /build/glibc-eX1tMB/glibc-2.31/string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:328
==233680==ABORTING
────────────────────────────────────────────────────────────────────────────────

Error: Fuzz target exited with exit code: 1

Process finished with exit code 1

;)