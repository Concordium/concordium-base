use crate::secret_sharing::*;
use curve_arithmetic::curve_arithmetic::*;
use elgamal::message::Message;

pub fn reveal_id_cred_pub<C: Curve>(shares: &[(ShareNumber, Message<C>)]) -> C {
    reveal_in_group(
        &shares
            .iter()
            .map(|(n, m)| (*n, m.value))
            .collect::<Vec<(ShareNumber, C)>>(),
    )
}
