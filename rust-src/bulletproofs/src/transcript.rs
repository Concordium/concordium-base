use crypto_common::to_bytes;
use curve_arithmetic::Curve;
use merlin::Transcript;

pub trait TranscriptProtocol {
    fn domain_sep(&mut self);
    fn append_point<C: Curve>(&mut self, label: &'static [u8], point: &C);
    fn append_scalar<C: Curve>(&mut self, label: &'static [u8], scalar: &C::Scalar);
    fn challenge_scalar<C: Curve>(&mut self, label: &'static [u8]) -> C::Scalar;
}

impl TranscriptProtocol for Transcript {
    // FIXME: This needs to be updated once we unify the random oracles.
    fn domain_sep(&mut self) { self.append_message(b"dom-sep", b"TranscriptProtocol Example"); }

    fn append_point<C: Curve>(&mut self, label: &'static [u8], point: &C) {
        self.append_message(label, &to_bytes(point));
    }

    // FIXME: Avoid using to_bytes and the associated vector allocation.
    // Scalar bytes size is statically known.
    fn append_scalar<C: Curve>(&mut self, label: &'static [u8], scalar: &C::Scalar) {
        self.append_message(label, &to_bytes(scalar));
    }

    fn challenge_scalar<C: Curve>(&mut self, label: &'static [u8]) -> C::Scalar {
        let mut buf = [0; 32];
        self.challenge_bytes(label, &mut buf);
        C::scalar_from_bytes(&buf)
    }
}
