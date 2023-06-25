;; The only purpose of this contract is to check
;; whether i32.extend16_s instruction is allowed in the module.
(module
 ;; Init contract
 (func $init_contract (export "init_contract") (param i64) (result i32)
       (i32.extend16_s (i32.const 3))
       (return (i32.const 0))) ;; Successful init
)
