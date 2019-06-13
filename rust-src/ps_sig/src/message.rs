use curve_arithmetic::{bls12_381_instance::*, curve_arithmetic::*};

pub enum Message<C>
where
    C: Pairing, {
    KnownMessage(Vec<<C as Pairing>::ScalarField>),
    UnknownMessage(<C as Pairing>::G_1),
}

impl<C: Pairing> Message<C> {
    // turn value vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        match self {
            Message::KnownMessage(vs) => {
                let mut bytes: Vec<u8> = Vec::new();
                for v in vs.iter() {
                    bytes.extend_from_slice(&C::scalar_to_bytes(&v));
                }
                bytes.into_boxed_slice()
            }
            Message::UnknownMessage(g) => g.curve_to_bytes(),
        }
    }
}
