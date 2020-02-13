use curve_arithmetic::curve_arithmetic::*;
use ff::Field;
use rand::*;

use crypto_common::*;
use pedersen_scheme::Value as PedersenValue;
use serde_json::{json, Value};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Serialize)]
/// A point at which the polynomial is evaluated to obtain the shares.
#[repr(transparent)]
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct ShareNumber(pub u32);

impl ShareNumber {
    /// Curve scalars must be big enough to accommodate all 32 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_u64(u64::from(self.0)) }

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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Serialize)]
/// Revealing threshold, i.e., degree of the polynomial + 1.
#[serde(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct Threshold(pub u32);

impl Threshold {
    /// Curve scalars must be big enough to accommodate all 32 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_u64(u64::from(self.0)) }

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
    pub coefficients: Vec<PedersenValue<C>>,
    /// Shares, i.e., pairs (x, y) where x is the chosen point, and y is the
    /// evaluation of the polynomial at x. All share numbers must be distinct.
    pub shares: Vec<(ShareNumber, PedersenValue<C>)>,
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
    let mut coefficients: Vec<PedersenValue<C>> = Vec::with_capacity(deg as usize);
    for _ in 0..deg {
        let r = PedersenValue::generate(csprng);
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

        shares.push((x, PedersenValue::new(share)))
    }

    SharingData {
        coefficients,
        shares,
    }
}

/// Compute the Lagrange basis polynomial evaluated at zero.
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
/// interpolate a polynomial f of max degree n-1 and return f(0).
pub fn reveal<C: Curve>(shares: &[(ShareNumber, PedersenValue<C>)]) -> C::Scalar {
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
    use rand::{rngs::ThreadRng, seq::SliceRandom};

    // Test Lagrange interpolation polynomials at x={0,1}
    #[test]
    pub fn test_lagrange() {
        // For any kxs, the 0'th Lagrange polynomial is 1 at x=0
        let mut kxs = Vec::new();
        kxs.push(ShareNumber::from(1));
        kxs.push(ShareNumber::from(2));
        kxs.push(ShareNumber::from(3));
        let p = ShareNumber::from(0);
        let r = lagrange::<G1>(&kxs, p);
        assert_eq!(r, G1::scalar_from_u64(1));

        // For kxs={1,2}, the 1'th Lagrange polynomial is 2 at x=1
        let mut kxs = Vec::new();
        kxs.push(ShareNumber::from(1));
        kxs.push(ShareNumber::from(2));
        let p = ShareNumber::from(1);
        let r = lagrange::<G1>(&kxs, p);
        assert_eq!(r, G1::scalar_from_u64(2));
    }

    // Check sharing polynomial and coefficient length are correct. Namely for a
    // (k,n)-RS-code, we have degree less than k and n points of evaluation (shares).
    #[test]
    pub fn test_share_output_length() {
        let mut csprng = thread_rng();
        let secret = <G1 as Curve>::generate_scalar(&mut csprng);
        let n = 12;
        let t = 4;

        let shared = share::<G1, ThreadRng>(
            &secret,
            ShareNumber::from(n),
            Threshold::from(t),
            &mut csprng,
        );

        assert!(shared.coefficients.len() < t as usize);
        assert_eq!(shared.shares.len(), n as usize);
    }

    /// Test sharing and reconstruction:
    ///   - For enough shares, we can reconstruct with success
    ///   - If one share has an error, we reconstruct something different from the secret
    ///   - If we try to reconstruct with too few points, we get an error
    #[test]
    pub fn test_secret_sharing() {
        let mut csprng = thread_rng();
        for i in 1u32..10 {
            // Generate secret point and secret-share it
            let generator = G1::one_point()
                .mul_by_scalar(&<G1 as Curve>::generate_non_zero_scalar(&mut csprng));
            let secret = <G1 as Curve>::generate_scalar(&mut csprng);
            let secret_point = generator.mul_by_scalar(&secret);
            let threshold = csprng.gen_range(1, i + 1);

            // Sample enough random points and reconstruct with success
            let sharing_data = share::<G1, ThreadRng>(
                &secret,
                ShareNumber::from(i),
                Threshold::from(threshold),
                &mut csprng,
            );
            let mut shares = sharing_data.shares;
            shares.shuffle(&mut csprng);
            let sufficient_sample = &shares[0..(threshold as usize)];
            let sufficient_sample_points = sufficient_sample
                .iter()
                .map(|(n, s)| (*n, generator.mul_by_scalar(&s)))
                .collect::<Vec<(ShareNumber, G1)>>();
            let revealed_data: Fr = reveal::<G1>(&sufficient_sample);
            assert_eq!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<G1>(&sufficient_sample_points);
            assert_eq!(revealed_data_point, secret_point);

            // Sample enough random points, add error to one, reconstruct with failure
            let sharing_data = share::<G1, ThreadRng>(
                &secret,
                ShareNumber::from(i),
                Threshold::from(threshold),
                &mut csprng,
            );
            let mut shares = sharing_data.shares;
            shares.shuffle(&mut csprng);
            shares.truncate(threshold as usize);
            let rand_elm = shares.choose_mut(&mut csprng).unwrap();
            *rand_elm = (rand_elm.0, curve_arithmetic::secret_value::Value::generate(&mut csprng));

            let revealed_data: Fr = reveal::<G1>(&shares);
            assert_ne!(revealed_data, secret);
            let sufficient_points_err = shares
                .iter()
                .map(|(n, s)| (*n, generator.mul_by_scalar(&s)))
                .collect::<Vec<(ShareNumber, G1)>>();
            let revealed_data_point: G1 = reveal_in_group::<G1>(&sufficient_points_err);
            assert_ne!(revealed_data_point, secret_point);

            // Sample less points than required and reconstruct with failure
            let sharing_data = share::<G1, ThreadRng>(
                &secret,
                ShareNumber::from(i),
                Threshold::from(threshold),
                &mut csprng,
            );
            let mut insufficient_shares = sharing_data.shares;
            insufficient_shares.shuffle(&mut csprng);
            let insufficient_sample = &insufficient_shares[0..((threshold - 1) as usize)];
            let insufficient_sample_points = insufficient_sample
                .iter()
                .map(|(n, s)| (*n, generator.mul_by_scalar(&s)))
                .collect::<Vec<(ShareNumber, G1)>>();
            let revealed_data: Fr = reveal::<G1>(&insufficient_sample);
            assert_ne!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<G1>(&insufficient_sample_points);
            assert_ne!(revealed_data_point, secret_point);
        }
    }
}
