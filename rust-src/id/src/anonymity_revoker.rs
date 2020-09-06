use crate::{secret_sharing::*, types::*};
use curve_arithmetic::*;
use elgamal::Message;

pub fn reveal_id_cred_pub<C: Curve>(shares: &[(ArIdentity, Message<C>)]) -> C {
    reveal_in_group(
        &shares
            .iter()
            .map(|(n, m)| (*n, m.value))
            .collect::<Vec<_>>(),
    )
}
