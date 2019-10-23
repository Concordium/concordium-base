use curve_arithmetic::curve_arithmetic::*;
use ff::Field;
use rand::*;

use byteorder::{BigEndian, ReadBytesExt};
use serde_json::{json, Value};
use std::{convert::TryFrom, io::Cursor};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
/// A point at which the polynomial is evaluated to obtain the shares.
pub struct ShareNumber(pub u32);

impl ShareNumber {
    /// Curve scalars must be big enough to accommodate all 32 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_u64(u64::from(self.0)).unwrap() }

    pub fn to_bytes(self) -> Box<[u8]> { Box::from(self.0.to_be_bytes()) }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let r = cur.read_u32::<BigEndian>().ok()?;
        Some(ShareNumber(r))
    }

    pub fn to_json(self) -> Value { json!(self.0) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = u32::try_from(v.as_u64()?).ok()?;
        Some(ShareNumber(v))
    }
}

impl Into<u32> for ShareNumber {
    fn into(self) -> u32 { self.0 }
}

impl From<u32> for ShareNumber {
    fn from(n: u32) -> Self { ShareNumber(n) }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
/// Revealing threshold, i.e., degree of the polynomial + 1.
pub struct Threshold(pub u32);

impl Threshold {
    pub fn to_bytes(self) -> Box<[u8]> { Box::from(self.0.to_be_bytes()) }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let r = cur.read_u32::<BigEndian>().ok()?;
        Some(Threshold(r))
    }

    pub fn to_json(self) -> Value { json!(self.0) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = u32::try_from(v.as_u64()?).ok()?;
        Some(Threshold(v))
    }
}

impl Into<u32> for Threshold {
    fn into(self) -> u32 { self.0 }
}

impl From<u32> for Threshold {
    fn from(x: u32) -> Self { Threshold(x) }
}

pub struct SharingData<C: Curve> {
    /// The coefficients of the sharing polyomial, except the zeroth.
    pub coefficients: Vec<C::Scalar>,
    /// Shares, i.e., pairs (x, y) where x is the chosen point, and y is the
    /// evaluation of the polynomial at x. All share numbers must be distinct.
    pub shares: Vec<(ShareNumber, C::Scalar)>,
}

/// Revealing Threshold must be at least 1.
pub fn share<C: Curve, R: Rng>(
    // Secret to share
    secret: &C::Scalar,
    // The number of shares, i.e., points at which the sharing polynomial is evaluated.
    // The points are 1..number_of_shares.
    number_of_shares: ShareNumber,
    // Minimum number of shares needed to reveal the secret. Must be at least 1.
    revealing_threshold: Threshold,
    // Cryptographically secure random number generator.
    csprng: &mut R,
) -> SharingData<C> {
    assert!(revealing_threshold >= Threshold(1));

    let deg: u32 = revealing_threshold.into();
    let deg = deg - 1; // the degree of polynomial

    // the zeroth coefficient is the secret, we generate
    // other coefficients at random.
    // It is crucial that the random number generator is cryptographically secure.
    let mut coefficients: Vec<C::Scalar> = Vec::with_capacity(deg as usize);
    for _ in 0..deg {
        let r = C::generate_scalar(csprng);
        coefficients.push(r);
    }

    let number_of_shares: u32 = number_of_shares.into();
    let mut shares = Vec::with_capacity(number_of_shares as usize);
    for x in 1..=number_of_shares {
        let x = ShareNumber::from(x);
        let xs = x.to_scalar::<C>();
        let mut share: C::Scalar = C::Scalar::zero();

        // evaluate the polynomial at point 'xs'
        for coeff in coefficients.iter().rev() {
            share.mul_assign(&xs);
            share.add_assign(coeff);
        }
        // since the zeroth coefficient is not in the list of coefficients we do one
        // final step here
        share.mul_assign(&xs);
        share.add_assign(secret);

        shares.push((x, share))
    }

    SharingData {
        coefficients,
        shares,
    }
}

fn lagrange<C: Curve>(kxs: &[ShareNumber], i: ShareNumber) -> C::Scalar {
    kxs.iter().fold(C::Scalar::one(), |accum, j| {
        let mut fe_j = j.to_scalar::<C>();
        let mut j_minus_i = fe_j;
        j_minus_i.sub_assign(&i.to_scalar::<C>());
        match j_minus_i.inverse() {
            None => accum,
            Some(z) => {
                fe_j.mul_assign(&z);
                fe_j.mul_assign(&accum);
                fe_j
            }
        }
    })
}

/// Given a list of length n of pairs (x_i, j_i), with all x_i distinct,
/// interpolate a polynomial f of degree n and return f(0).
pub fn reveal<C: Curve>(shares: &[(ShareNumber, C::Scalar)]) -> C::Scalar {
    let kxs: Vec<ShareNumber> = shares.iter().map(|(fst, _)| *fst).collect();
    shares.iter().fold(C::Scalar::zero(), |accum, (i, v)| {
        let mut s = lagrange::<C>(&kxs, *i);
        s.mul_assign(&v);
        s.add_assign(&accum);
        s
    })
}

/// Same as above, but coefficients of the polynomial are group elements (and
/// the polynomial is valued in a group), as opposed to field elements.
pub fn reveal_in_group<C: Curve>(shares: &[(ShareNumber, C)]) -> C {
    let kxs: Vec<ShareNumber> = shares.iter().map(|(fst, _)| *fst).collect();
    shares.iter().fold(C::zero_point(), |accum, (i, v)| {
        let s = lagrange::<C>(&kxs, *i);
        let vs = v.mul_by_scalar(&s);
        vs.plus_point(&accum)
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::{Fr, G1};
    use rand::seq::sample_iter;

    #[test]
    pub fn test_secret_sharing() {
        let mut csprng = thread_rng();
        for i in 1u32..10 {
            let secret = <G1 as Curve>::generate_scalar(&mut csprng);
            let secret_point = <G1 as Curve>::one_point().mul_by_scalar(&secret);
            let threshold = csprng.gen_range(1, i + 1);
            let sharing_data = share::<G1, ThreadRng>(
                &secret,
                ShareNumber::from(i),
                Threshold::from(threshold),
                &mut csprng,
            );
            let sufficient_sample: Vec<(ShareNumber, <G1 as Curve>::Scalar)> =
                sample_iter(&mut csprng, sharing_data.shares.clone(), threshold as usize)
                    .expect("Threshold is <= number of shares.");
            let sufficient_sample_points = sufficient_sample
                .iter()
                .map(|(n, s)| (*n, G1::one_point().mul_by_scalar(&s)))
                .collect::<Vec<(ShareNumber, G1)>>();
            let revealed_data: Fr = reveal::<G1>(&sufficient_sample);
            assert_eq!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<G1>(&sufficient_sample_points);
            assert_eq!(revealed_data_point, secret_point);
            let insufficient_sample: Vec<(ShareNumber, <G1 as Curve>::Scalar)> =
                sample_iter(&mut csprng, sharing_data.shares, (threshold - 1) as usize)
                    .expect("Threshold - 1 is <= number of shares.");
            let insufficient_sample_points = insufficient_sample
                .iter()
                .map(|(n, s)| (*n, G1::one_point().mul_by_scalar(&s)))
                .collect::<Vec<(ShareNumber, G1)>>();
            let revealed_data: Fr = reveal::<G1>(&insufficient_sample);
            assert_ne!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<G1>(&insufficient_sample_points);
            assert_ne!(revealed_data_point, secret_point);
        }
    }
}
