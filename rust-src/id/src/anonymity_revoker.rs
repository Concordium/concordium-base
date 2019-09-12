use curve_arithmetic::curve_arithmetic::*;
use secret_sharing::secret_sharing::*;
use elgamal::message::Message;


pub fn reveal_id_cred_pub<C:Curve>(shares:&Vec<(u64, Message<C>)>) -> C{
    reveal_in_group(&shares.into_iter().map(|(n,m)| (*n, m.0)).collect())
}
