mod types;

pub use types::*;

/// Calculate the maximum stack height that can be use by this expression (i.e.,
/// number of values on the stack) excluding what is used by called functions
/// (but including their return values).
fn calc_max_stack_height(exp: &Expression) -> StackHeight {
    // TODO implement
    0
}
