//! Implementation of Shamir secret sharing.
use anyhow::bail;
use crypto_common::*;
use curve_arithmetic::*;
use ff::Field;
use pedersen_scheme::Value as PedersenValue;
use rand::*;
use serde_json::{json, Value};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Serial)]
/// Revealing threshold, i.e., degree of the polynomial + 1.
/// This value must always be at least 1.
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
pub struct Threshold(pub u8);

impl Deserial for Threshold {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x: u8 = source.get()?;
        if x >= 1 {
            Ok(Threshold(x))
        } else {
            bail!("Threshold must be at least 1.")
        }
    }
}

impl Threshold {
    /// Curve scalars must be big enough to accommodate all 8 bit unsigned
    /// integers.
    pub fn to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_u64(u64::from(self.0)) }

    pub fn to_json(self) -> Value { json!(self.0) }

    pub fn from_json(v: &Value) -> Option<Self> {
        let v = u8::try_from(v.as_u64()?).ok()?;
        if v >= 1 {
            Some(Threshold(v))
        } else {
            None
        }
    }
}

impl From<Threshold> for u8 {
    fn from(x: Threshold) -> Self { x.0 }
}

impl From<Threshold> for usize {
    fn from(x: Threshold) -> Self { x.0.into() }
}

impl TryFrom<u8> for Threshold {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(())
        } else {
            Ok(Threshold(value))
        }
    }
}

impl TryFrom<usize> for Threshold {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value == 0 || value >= 256 {
            Err(())
        } else {
            Ok(Threshold(value as u8))
        }
    }
}

impl std::fmt::Display for Threshold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.0.fmt(f) }
}

/// Data used to share a single value.
pub struct SharingData<C: Curve> {
    /// The coefficients of the sharing polyomial, except the zeroth.
    pub coefficients: Vec<PedersenValue<C>>,
    /// Shares, i.e., points y which are the evaluations of the polynomial at
    /// the specified points.
    pub shares:       Vec<PedersenValue<C>>,
}

/// Revealing Threshold must be at least 1.
/// We assume the points are anything that can be converted
/// to a u64. They should be distinct, and the polynomial will be evaluated
/// at points p in points. The preconditions are not checked.
pub fn share<C: Curve, P: Into<u64>, I: IntoIterator<Item = P> + ExactSizeIterator, R: Rng>(
    // Secret to share
    secret: &C::Scalar,
    // The points to base the evaluation on. We will evaluate the polynomial
    // on points p+1 for p in points. This is because we have to make sure to evaluate
    // the polynomial only on non-zero values. Note that there is no danger of overflow
    // if the field C::Scalar is > 64 bits, since the operations are performed there.
    points: I,
    // Minimum number of shares needed to reveal the secret. Must be at least 1.
    revealing_threshold: Threshold,
    // Cryptographically secure random number generator.
    csprng: &mut R,
) -> SharingData<C> {
    debug_assert!(revealing_threshold >= Threshold(1));

    let deg: u8 = revealing_threshold.into();
    let deg = deg - 1; // the degree of polynomial

    // the zeroth coefficient is the secret, we generate
    // other coefficients at random, except the highest coefficient
    // which should be non-zero.
    // It is crucial that the random number generator is cryptographically secure.
    let mut coefficients: Vec<PedersenValue<C>> = Vec::with_capacity(deg as usize);
    for _ in 1..deg {
        let r = PedersenValue::generate(csprng);
        coefficients.push(r);
    }
    // Add a non-zero coefficient if degree is at least 1 (otherwise we are
    // generating a constant polynomial).
    if deg > 0 {
        let r = PedersenValue::generate_non_zero(csprng);
        coefficients.push(r);
    }

    let number_of_shares = points.len();
    let mut shares = Vec::with_capacity(number_of_shares);
    for p in points {
        let x = C::scalar_from_u64(p.into());
        let mut share: C::Scalar = C::Scalar::zero();

        // evaluate the polynomial at point 'xs'
        for coeff in coefficients.iter().rev() {
            share.mul_assign(&x);
            share.add_assign(coeff);
        }
        // since the zeroth coefficient is not in the list of coefficients we do one
        // final step here
        share.mul_assign(&x);
        share.add_assign(secret);

        shares.push(PedersenValue::new(share))
    }

    SharingData {
        coefficients,
        shares,
    }
}

/// Compute the Lagrange basis polynomial evaluated at zero.
/// For the same reason as in 'share', we consider the points P offset by 1.
fn lagrange<P: Into<u64> + Copy, C: Curve>(kxs: &[P], i: P) -> C::Scalar {
    let point = C::scalar_from_u64(i.into());
    kxs.iter().fold(C::Scalar::one(), |accum, &j| {
        let mut fe_j = C::scalar_from_u64(j.into());
        let mut j_minus_i = fe_j;
        j_minus_i.sub_assign(&point);
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
/// This function does not check the precondition.
pub fn reveal<P: Into<u64> + Copy, C: Curve>(shares: &[(P, PedersenValue<C>)]) -> C::Scalar {
    let kxs = shares.iter().map(|(fst, _)| *fst).collect::<Vec<_>>();
    shares.iter().fold(C::Scalar::zero(), |accum, (i, v)| {
        let mut s = lagrange::<P, C>(&kxs, *i);
        s.mul_assign(v);
        s.add_assign(&accum);
        s
    })
}

/// Same as above, but coefficients of the polynomial are group elements (and
/// the polynomial is valued in a group), as opposed to field elements.
pub fn reveal_in_group<P: Into<u64> + Copy, C: Curve>(shares: &[(P, C)]) -> C {
    let kxs = shares.iter().map(|(fst, _)| *fst).collect::<Vec<_>>();
    shares.iter().fold(C::zero_point(), |accum, (i, v)| {
        let s = lagrange::<P, C>(&kxs, *i);
        let vs = v.mul_by_scalar(&s);
        vs.plus_point(&accum)
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::{Fr, G1};
    use rand::seq::SliceRandom;

    // Test Lagrange interpolation polynomials at x={0,1}
    #[test]
    pub fn test_lagrange() {
        // For any kxs, the 0'th Lagrange polynomial is 1 at x=0
        let mut kxs = Vec::<u32>::new();
        kxs.push(1);
        kxs.push(2);
        kxs.push(3);
        let p = 0;
        let r = lagrange::<u32, G1>(&kxs, p);
        assert_eq!(r, G1::scalar_from_u64(1));

        let kxs = vec![1, 2];
        let p = 1;
        let r = lagrange::<u32, G1>(&kxs, p);
        assert_eq!(r, G1::scalar_from_u64(2));
    }

    /// Check sharing polynomial and coefficient length are correct; we have n
    /// shares and the degree of the sharing polynomial is t (meaning there
    /// are t-1 coefficients in SharingData) since the constant term is the
    /// secret being shared.
    #[test]
    pub fn test_share_output_length() {
        let mut csprng = thread_rng();
        let secret = <G1 as Curve>::generate_scalar(&mut csprng);
        let n = std::cmp::max(1, std::cmp::min(200, csprng.gen::<u32>()));
        // x points to secret-share on.
        let mut xs = (0..n).collect::<Vec<_>>();
        xs.shuffle(&mut csprng);

        // select random threshold;
        let t = csprng.gen_range(1, xs.len() + 1);

        let shared = share::<G1, _, _, _>(&secret, xs.into_iter(), Threshold(t as u8), &mut csprng);

        assert_eq!(shared.coefficients.len() + 1, t as usize);
        assert_eq!(shared.shares.len(), n as usize);
    }

    /// Test sharing and reconstruction:
    ///   - For enough shares, we can reconstruct with success
    ///   - If one share has an error, we reconstruct something different from
    ///     the secret
    ///   - If we try to reconstruct with too few points, we get an error.
    #[test]
    pub fn test_secret_sharing() {
        let mut csprng = thread_rng();
        for i in 1u8..10 {
            // Generate secret point and secret-share it
            let generator = G1::one_point()
                .mul_by_scalar(&<G1 as Curve>::generate_non_zero_scalar(&mut csprng));
            let secret = <G1 as Curve>::generate_scalar(&mut csprng);
            let secret_point = generator.mul_by_scalar(&secret);
            let threshold = csprng.gen_range(1, i + 1);

            let mut xs = (1..=i).collect::<Vec<_>>();
            xs.shuffle(&mut csprng);

            // Sample enough random points and reconstruct with success
            let sharing_data = share::<G1, _, _, _>(
                &secret,
                xs.iter().copied(),
                Threshold::try_from(threshold).expect("Threshold is at least 1."),
                &mut csprng,
            );
            let mut shares = xs
                .iter()
                .copied()
                .zip(sharing_data.shares)
                .collect::<Vec<_>>();
            shares.shuffle(&mut csprng);
            let sufficient_sample = &shares[0..(threshold as usize)];
            let sufficient_sample_points = sufficient_sample
                .iter()
                .map(|(n, s)| (*n, generator.mul_by_scalar(s)))
                .collect::<Vec<(u8, G1)>>();
            let revealed_data: Fr = reveal::<_, G1>(sufficient_sample);
            assert_eq!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<_, G1>(&sufficient_sample_points);
            assert_eq!(revealed_data_point, secret_point);

            // Sample enough random points, add error to one, reconstruct with failure
            let sharing_data = share::<G1, _, _, _>(
                &secret,
                xs.iter().copied(),
                Threshold::try_from(threshold).expect("Threshold is at least 1."),
                &mut csprng,
            );
            let mut shares = xs
                .iter()
                .copied()
                .zip(sharing_data.shares)
                .collect::<Vec<_>>();
            shares.shuffle(&mut csprng);
            shares.truncate(threshold as usize);
            let rand_elm = shares.choose_mut(&mut csprng).unwrap();
            rand_elm.1 = curve_arithmetic::secret_value::Value::generate(&mut csprng);

            let revealed_data: Fr = reveal::<_, G1>(&shares);
            assert_ne!(revealed_data, secret);
            let sufficient_points_err = shares
                .iter()
                .map(|(n, s)| (*n, generator.mul_by_scalar(s)))
                .collect::<Vec<(u8, G1)>>();
            let revealed_data_point: G1 = reveal_in_group::<_, G1>(&sufficient_points_err);
            assert_ne!(revealed_data_point, secret_point);

            // Sample fewer points than required and reconstruct with failure
            let sharing_data = share::<G1, _, _, _>(
                &secret,
                xs.iter().copied(),
                Threshold::try_from(threshold).expect("Threshold is at least 1."),
                &mut csprng,
            );
            let mut insufficient_shares = xs
                .iter()
                .copied()
                .zip(sharing_data.shares)
                .collect::<Vec<_>>();
            insufficient_shares.shuffle(&mut csprng);
            let insufficient_sample = &insufficient_shares[0..((threshold - 1) as usize)];
            let insufficient_sample_points = insufficient_sample
                .iter()
                .map(|(n, s)| (*n, generator.mul_by_scalar(s)))
                .collect::<Vec<(u8, G1)>>();
            let revealed_data: Fr = reveal::<_, G1>(insufficient_sample);
            assert_ne!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<_, G1>(&insufficient_sample_points);
            assert_ne!(revealed_data_point, secret_point);
        }
    }
}
