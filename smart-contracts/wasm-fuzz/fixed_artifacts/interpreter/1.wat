(module
  (type (;0;) (func (param i32)))
  (type (;1;) (func (param i64) (result i32)))
  (func (;0;) (type 0) (param i32)
    (local i32)
    local.get 1
    i32.load offset=1633903980 align=1
    unreachable)
  (func (;1;) (type 1) (param i64) (result i32)
    i32.const 0
    call 0
    i32.const 0
    unreachable)
  (table (;0;) 388 funcref)
  (memory (;0;) 512)
  (global (;0;) i32 (i32.const 6815744))
  (export "init_ON" (func 1))
  (export "init_AA" (table 0))
  (elem (;0;) (i32.const 0) func 0)
  (data (;0;) (i32.const 27648) ""))

(;
AddressSanitizer:DEADLYSIGNAL
=================================================================
==223473==ERROR: AddressSanitizer: SEGV on unknown address 0x7f3c70c2ed6c (pc 0x55ff2f36d38f bp 0x7ffc249a3bc0 sp 0x7ffc249a0840 T0)
==223473==The signal is caused by a READ memory access.
    #0 0x55ff2f36d38f in wasm_transform::machine::_$LT$impl$u20$wasm_transform..artifact..Artifact$LT$I$C$R$GT$$GT$::run::h49675a4d496e1df6 (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x4a338f)
    #1 0x55ff2f3c736a in wasm_chain_integration::invoke_init::hf58bffc0f822a296 (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x4fd36a)
    #2 0x55ff2f3cb62e in wasm_chain_integration::invoke_init_with_metering_from_source::he5b0301b9a30677e (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x50162e)
    #3 0x55ff2f4dd4d9 in rust_fuzzer_test_input (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x6134d9)
    #4 0x55ff2fbbd920 in __rust_try (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xcf3920)
    #5 0x55ff2fbbd57f in LLVMFuzzerTestOneInput (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xcf357f)
    #6 0x55ff2fbd193c in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xd0793c)
    #7 0x55ff2fbc1119 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xcf7119)
    #8 0x55ff2fbcac52 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0xd00c52)
    #9 0x55ff2f21a2b6 in main (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x3502b6)
    #10 0x7f3c16afa0b2 in __libc_start_main /build/glibc-eX1tMB/glibc-2.31/csu/../csu/libc-start.c:308:16
    #11 0x55ff2f21a45d in _start (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x35045d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/home/mrapoport/concordium/smart-contracts/wasm-chain-integration/target/x86_64-unknown-linux-gnu/release/interpreter+0x4a338f) in wasm_transform::machine::_$LT$impl$u20$wasm_transform..artifact..Artifact$LT$I$C$R$GT$$GT$::run::h49675a4d496e1df6
==223473==ABORTING
────────────────────────────────────────────────────────────────────────────────

Error: Fuzz target exited with exit code: 1

Process finished with exit code 1
;)