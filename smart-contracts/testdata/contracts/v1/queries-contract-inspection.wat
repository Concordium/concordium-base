(module
 ;; Imports
 (import "concordium" "get_parameter_section" (func $host_get_parameter_section (param $index i32) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "get_parameter_size" (func $host_get_parameter_size (param $index i32) (result i32)))
 (import "concordium" "invoke" (func $host_invoke (param $tag i32) (param $start i32) (param $length i32) (result i64)))

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
                     (local.get $read_offset)))) ;; Offset to read from.

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

 ;; Contract

 ;; Initialize contract.
 (func $init (export "init_contract") (param i64) (result i32)
       (return (i32.const 0))) ;; Successful init

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

 ;; Contract 2

 ;; Initialize contract.
 (func $init2 (export "init_contract2") (param i64) (result i32)
       (return (i32.const 0))) ;; Successful init

 ;; Check if the contract name of a contract matches the supplied value.
 ;; The parameter should be the contract address followed by the expected
 ;; contract name.
 ;; The return value is 0 if it matches, -1 if it does not and -2 if the contract
 ;; does not exist.
 (func $receive_check_name
        (export "contract2.check_name")
        (param $amount i64)
        (result i32)

    (local $param_len i32)
    (local $invoke_return i64)
    (local $return_len i32)
    (local $return_index i32)

    ;; Get the length of the parameter
    (local.set $param_len (call $host_get_parameter_size (i32.const 0)))
    ;; Read the parameter, which should be:
    ;; - contract address (8 bytes index, 8 bytes subindex)
    ;; - contract name (variable length)
    (call $host_get_parameter_section
        (i32.const 0) ;; Index 0 -- initial parameter
        (i32.const 0) ;; Write to start of memory
        (local.get $param_len) ;; full parameter
        (i32.const 0) ;; at offset 0
        )
    (drop)

    (local.set $invoke_return 
      (call $host_invoke
        (i32.const 8) ;; Tag for "get contract name"
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

    ;; Get the index of the response
    ;; The numeric value 8388607 is the mask 0b0111_1111_1111_1111_1111_1111
    (local.set $return_index (i32.and (i32.const 8388607)
                                        (i32.wrap_i64 (i64.shr_u (local.get $invoke_return) (i64.const 40)))))

    ;; Get the length of the response
    (local.set $return_len (call $host_get_parameter_size (local.get $return_index)))

    ;; If the length of the response is different from the provided name, then we return -1 already
    (if
        (i32.ne (local.get $return_len) (i32.sub (local.get $param_len) (i32.const 16)))
        (then
            (return (i32.const -1))
        )
    )

    ;; Otherwise, we get the value
    (call $get_invoke_return_value
        (local.get $invoke_return)
        (local.get $param_len) ;; Start writing after the input parameter
        (local.get $return_len) ;; Length of contract name
        (i32.const 0) ;; Start at the beginning of the parameter section
        )
    (drop)

    ;; And compare it to the expected value
    (call $mem_cmp
        (i32.const 16) ;; Start of expected name
        (local.get $param_len) ;; Start of observed name
        (local.get $return_len) ;; Length of module reference
        )
    ;; Return 0 if a match and -1 if not.
    i32.const 1
    i32.sub
 )

 (memory 1)
)