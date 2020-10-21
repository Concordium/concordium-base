pub use crate::types::*;

// TODO This will probably be calculated during validation and be part of
// `Function`.
/// Calculate the maximum stack height that can be use by this expression (i.e.,
/// number of values on the stack) excluding what is used by called functions
/// (but including their return values).
pub fn calc_max_stack_height(exp: &Expression) -> StackHeight {
    // TODO implement
    todo!("{:?}", exp)
}
