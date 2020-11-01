use curve_arithmetic::Pairing;

/// Curve used by the anonymity revoker.
pub type ArCurve = pairing::bls12_381::G1;
/// Pairing used by the identity provider.
pub type IpPairing = pairing::bls12_381::Bls12;
/// Field used by the identity provider and anonymity revoker.
/// This isthe base field of both the ArCurve and the IpPairing.
pub type BaseField = <pairing::bls12_381::Bls12 as Pairing>::ScalarField;
