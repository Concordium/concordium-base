;; This module defines two smart contracts:
;;
;; - `contract` has the entrypoint `get_module_reference` which queries the module reference
;;   of a specified smart contract instance and logs it.
;; - `contract2` has the entrypoint `get_contract_name` which queries the contract name
;;   of a specified smart contract instance and logs it.

(module
 ;; Imports
 (import "concordium" "get_parameter_section" (func $host_get_parameter_section (param $index i32) (param $write_location i32) (param $length i32) (param $offset i32) (result i32)))
 (import "concordium" "get_parameter_size" (func $host_get_parameter_size (param $index i32) (result i32)))
 (import "concordium" "invoke" (func $host_invoke (param $tag i32) (param $start i32) (param $length i32) (result i64)))
 (import "concordium" "log_event" (func $host_log_event (param $start i32) (param $length i32) (result i32)))

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

 ;; Contract

 ;; Initialize contract.
 (func $init (export "init_contract") (param i64) (result i32)
       (return (i32.const 0))) ;; Successful init

 ;; Get the module reference of a specified instance.
 ;; The parameter should be the contract address.
 ;; If it can be resolved, the module reference is logged as an event and 0 is returned.
 ;; -1 is returned if no instance exists at the address specified.
 (func $receive_get_module_reference
        (export "contract.get_module_reference")
        (param $amount i64)
        (result i32)
    
    (local $invoke_return i64)

    ;; Read the parameter, which should be the contract address (16 bytes)
    (drop (call $host_get_parameter_section
        (i32.const 0) ;; Index 0 -- initial parameter
        (i32.const 0) ;; Write to start of memory
        (i32.const 16) ;; 16 bytes
        (i32.const 0) ;; at offset 0
        ))

    (local.set $invoke_return 
      (call $host_invoke
        (i32.const 7) ;; Tag for "get module reference"
        (i32.const 0) ;; Memory location of contract address
        (i32.const 16) ;; Size of contract address
        )
    )

    ;; Return error code -1 if the contract does not exist
    (if (i64.eq (i64.const 0x03_0000_0000 (local.get $invoke_return)))
        (then
            (return (i32.const -1))
        )
    )

    ;; Get the module reference
    (drop (call $get_invoke_return_value
        (local.get $invoke_return)
        (i32.const 16) ;; Start writing at address 16
        (i32.const 32) ;; Length of module reference
        (i32.const 0) ;; Start at the beginning of the parameter section
        ))
    
    ;; Log the module reference as an event.
    (drop (call $host_log_event
        (i32.const 16) ;; Start from address 16
        (i32.const 32) ;; Length of module reference
        ))

    (i32.const 0)
 )

 ;; Contract 2

 ;; Initialize contract.
 (func $init2 (export "init_contract2") (param i64) (result i32)
       (return (i32.const 0))) ;; Successful init

 ;; Get the contract name of a specified instance.
 ;; The parameter should be the contract address.
 ;; If it can be resolved, the contract name is logged as an event and 0 is returned.
 ;; -1 is returned if no instance exists at the address specified.
 (func $receive_get_contract_name
        (export "contract2.get_contract_name")
        (param $amount i64)
        (result i32)
    
    (local $invoke_return i64)
    (local $return_len i32)
    (local $return_index i32)

    ;; Read the parameter, which should be the contract address (16 bytes)
    (drop (call $host_get_parameter_section
        (i32.const 0) ;; Index 0 -- initial parameter
        (i32.const 0) ;; Write to start of memory
        (i32.const 16) ;; 16 bytes
        (i32.const 0) ;; at offset 0
        ))

    (local.set $invoke_return 
      (call $host_invoke
        (i32.const 8) ;; Tag for "get contract name"
        (i32.const 0) ;; Memory location of contract address
        (i32.const 16) ;; Size of contract address
        )
    )

    ;; Return error code -1 if the contract does not exist
    (if (i64.eq (i64.const 0x03_0000_0000 (local.get $invoke_return)))
        (then
            (return (i32.const -1))
        )
    )

    ;; Get the index of the response
    ;; The numeric value 8388607 is the mask 0b0111_1111_1111_1111_1111_1111
    (local.set $return_index (i32.and (i32.const 8388607)
                                        (i32.wrap_i64 (i64.shr_u (local.get $invoke_return) (i64.const 40)))))

    ;; Get the length of the response
    (local.set $return_len (call $host_get_parameter_size (local.get $return_index)))

    ;; Get the contract name
    (drop (call $get_invoke_return_value
        (local.get $invoke_return)
        (i32.const 16) ;; Start writing at address 16
        (local.get $return_len) ;; Length of contract name
        (i32.const 0) ;; Start at the beginning of the parameter section
        ))
    
    ;; Log the contract name as an event.
    (drop (call $host_log_event
        (i32.const 16) ;; Start from address 16
        (local.get $return_len) ;; Length of contract name
        ))

    (i32.const 0)
 )

 (memory 1)
)