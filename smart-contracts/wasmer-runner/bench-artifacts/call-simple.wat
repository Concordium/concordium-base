(module
    (type (;0;) (func (param i32) (result i32)))
    (import "test" "add_one" (func (;0;) $add_one (type 0)))
    (func (;2;) $just_call (type 0)
        (call $add_one (local.get 0))
    )
    (export "just_call" (func $just_call))
)