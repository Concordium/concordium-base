use crate::unknown_message::*;
use curve_arithmetic::curve_arithmetic::*;

use pedersen_scheme::Commitment;

// Transforms a commitment into an unknown message
// should be done better
// there should be a trait for commitment scheme
pub fn message<C: Pairing>(commitment: &Commitment<C::G_1>) -> UnknownMessage<C> {
    let point = commitment.0;
    UnknownMessage(point)
}
