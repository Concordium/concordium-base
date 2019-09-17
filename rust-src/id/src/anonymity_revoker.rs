use curve_arithmetic::curve_arithmetic::*;
use elgamal::message::Message;
use secret_sharing::secret_sharing::*;

pub fn reveal_id_cred_pub<C: Curve>(shares: &Vec<(u64, Message<C>)>) -> C {
    reveal_in_group(&shares.into_iter().map(|(n, m)| (*n, m.0)).collect())
}
