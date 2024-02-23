;; This module defines a contract (named `contract`) for testing the interaction between
;; contract upgrade and querying the module reference of a contract.
;; In particular, `contract.upgrade` upgrades the contract and checks that querying the module
;; reference afterwards gives the expected (new) value.
;; This contract is the same as that defined in `upgrading-inspect-module0.wat`, except that
;; the `contract.init` will always fail.

(module
    ;; Imports
    (import "concordium" "get_parameter_section" (func $host_get_parameter_section (param $index i32) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
    (import "concordium" "get_parameter_size" (func $host_get_parameter_size (param $index i32) (result i32)))
    (import "concordium" "get_receive_self_address" (func $host_get_receive_self_address (param $start i32)))
    (import "concordium" "invoke" (func $host_invoke (param $tag i32) (param $start i32) (param $length i32) (result i64)))
    (import "concordium" "upgrade" (func $host_upgrade (param $start i32) (result i64)))

    ;; Read the return value into memory, takes the response from invoke and assumes the response is successful.
    (func $get_invoke_return_value (param $invoke_result i64) (param $write_offset i32) (param $length i32) (param $read_offset i32) (result i32)
       ;; Declare local variable for storing the index of the return value.
       (local $return_index i32)

       ;; Get the index of the response
       ;; The numeric value 8388607 is the mask 0b0111_1111_1111_1111_1111_1111
       (local.set $return_index (i32.and (i32.const 8388607)
                                         (i32.wrap_i64 (i64.shr_u (local.get $invoke_result) (i64.const 40)))))

       ;; Read the return value into memory.
       (return (call $host_get_parameter_section
                     (local.get $return_index) ;; Index of the return value.
                     (local.get $write_offset) ;; Write offset in memory.
                     (local.get $length) ;; Write length.
                     (local.get $read_offset))) ;; Offset to read from.
    )
    
    ;; Compare the byte arrays at two addresses, up to the given length.
    (func $mem_cmp (param $address_0 i32) (param $address_1 i32) (param $length i32) (result i32)
        (loop $cmp_loop
            local.get $length
            (if ;; $length is non-zero
                (then
                    local.get $address_0
                    i32.load8_u
                    local.get $address_1
                    i32.load8_u
                    i32.eq
                    (if ;; strings are equal so far
                        (then
                            ;; increment both addresses and decrease the length
                            local.get $address_0
                            i32.const 1
                            i32.add
                            local.set $address_0
                            local.get $address_1
                            i32.const 1
                            i32.add
                            local.set $address_1
                            local.get $length
                            i32.const 1
                            i32.sub
                            local.set $length
                            br $cmp_loop
                        )
                        (else
                            ;; Strings are not equal
                            (return (i32.const 0))
                        )
                    )
                )
                (else
                )
            )
        )
        ;; Strings are equal
        (return (i32.const 1))
    )

    ;; Contract: "contract"
    
    (func $init (export "init_contract") (param i64) (result i32)
        i32.const -1
    )

    ;; Check if the module reference of a contract matches the supplied value.
    ;; The parameter should be the contract address followed by the expected
    ;; module reference.
    ;; The return value is 0 if it matches, -1 if it does not and -2 if the contract
    ;; does not exist.
    (func $receive_check_module_reference 
            (export "contract.check_module_reference")
            (param $amount i64)
            (result i32)

        (local $invoke_return i64)

        ;; Read the parameter, which should be:
        ;; - contract address (8 bytes index, 8 bytes subindex)
        ;; - expected module reference (32 bytes)
        (call $host_get_parameter_section
            (i32.const 0) ;; Index 0 -- initial parameter
            (i32.const 0) ;; Write to start of memory
            (i32.const 48) ;; 48 bytes
            (i32.const 0) ;; at offset 0
            )
        (drop)

        (local.set $invoke_return 
            (call $host_invoke
                (i32.const 7) ;; Tag for "get module reference"
                (i32.const 0) ;; Memory location of contract address
                (i32.const 16) ;; Size of contract address
                )
        )
        
        ;; Return error code -2 if the contract does not exist
        (if (i64.eq (i64.const 0x03_0000_0000 (local.get $invoke_return)))
            (then
                (return (i32.const -2))
            )
        )

        (call $get_invoke_return_value
            (local.get $invoke_return)
            (i32.const 48) ;; Start writing at address 48
            (i32.const 32) ;; Length of module reference
            (i32.const 0) ;; Start at the beginning of the parameter section
            )
        (drop)
        (call $mem_cmp
            (i32.const 16) ;; Start of expected module reference
            (i32.const 48) ;; Start of observed module reference
            (i32.const 32) ;; Length of module reference
            )
        ;; Return 0 if a match and -1 if not.
        i32.const 1
        i32.sub
    )

    ;; Upgrade the contract. The parameter should be the module reference to upgrade to.
    ;; This checks if the module reference after the upgrade is the one it is supposed to be.
    ;; Return 0 if successful, -1 if the upgrade failed, -2 if the module reference cannot
    ;; be resolved after the upgrade, and -3 if the upgrade succeeded but the new module
    ;; reference is not correct.
    (func $receive_upgrade (export "contract.upgrade") (param $amount i64) (result i32)

        (local $invoke_return i64)

        ;; Get the 32-byte parameter that is the module reference to upgrade to
        (drop (call $host_get_parameter_section
                (i32.const 0)
                (i32.const 0)
                (i32.const 32)
                (i32.const 0)
            )
        )

        ;; Upgrade to the new module reference
        (if (i64.ne (i64.const 0) (call $host_upgrade (i32.const 0)))
            (then 
                (return (i32.const -1))
            )
        )

        ;; Get the contract's own address (at memory location 32)
        (call $host_get_receive_self_address (i32.const 32))

        (local.set $invoke_return 
            (call $host_invoke
                (i32.const 7) ;; Tag for "get module reference"
                (i32.const 32) ;; Memory location of contract address
                (i32.const 16) ;; Size of contract address
                )
        )
        
        ;; Return error code -2 if the contract does not exist
        (if (i64.eq (i64.const 0x03_0000_0000 (local.get $invoke_return)))
            (then
                (return (i32.const -2))
            )
        )

        (drop (call $get_invoke_return_value
            (local.get $invoke_return)
            (i32.const 32) ;; Start writing at address 32
            (i32.const 32) ;; Length of module reference
            (i32.const 0) ;; Start at the beginning of the parameter section
            )
        )
        (if
            (call $mem_cmp
                (i32.const 0) ;; Start of expected module reference
                (i32.const 32) ;; Start of observed module reference
                (i32.const 32) ;; Length of module reference
            )
            (then
                (return (i32.const 0))
            )
        )
        (return (i32.const -3))
    )

    (memory 1)
)