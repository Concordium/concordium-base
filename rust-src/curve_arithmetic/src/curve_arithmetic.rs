use byteorder::ReadBytesExt;
use crypto_common::{Serial, Serialize};
use failure::{Fail, Fallible};
use ff::{Field, PrimeField};
use rand::*;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub enum CurveDecodingError {
    NotOnCurve,
}

impl Display for CurveDecodingError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result { write!(f, "Not a point on the curve.") }
}

impl Fail for CurveDecodingError {}

pub trait Curve:
    Serialize + Copy + Clone + Sized + Send + Sync + Debug + Display + PartialEq + Eq + 'static {
    type Scalar: PrimeField + Field + Serialize;
    type Base: Field;
    type Compressed;
    const SCALAR_LENGTH: usize;
    const GROUP_ELEMENT_LENGTH: usize;
    fn zero_point() -> Self;
    fn one_point() -> Self; // generator
    fn is_zero_point(&self) -> bool;
    #[must_use]
    fn inverse_point(&self) -> Self;
    #[must_use]
    fn double_point(&self) -> Self;
    #[must_use]
    fn plus_point(&self, other: &Self) -> Self;
    #[must_use]
    fn minus_point(&self, other: &Self) -> Self;
    #[must_use]
    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self;
    #[must_use]
    fn compress(&self) -> Self::Compressed;
    fn decompress(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
    fn bytes_to_curve_unchecked<R: ReadBytesExt>(b: &mut R) -> Fallible<Self>;
    fn generate<R: Rng>(rng: &mut R) -> Self;
    fn generate_scalar<R: Rng>(rng: &mut R) -> Self::Scalar;
    /// Generate a non-zero scalar. The default implementation does repeated
    /// sampling until a non-zero scalar is reached.
    fn generate_non_zero_scalar<R: Rng>(rng: &mut R) -> Self::Scalar {
        loop {
            let s = Self::generate_scalar(rng);
            if !s.is_zero() {
                return s;
            }
        }
    }
    /// Make a scalar from a 64-bit unsigned integer. This function assumes that
    /// the field is big enough to accommodate any 64-bit unsigned integer.
    fn scalar_from_u64(n: u64) -> Self::Scalar;
    /// Make a scalar by taking the first Scalar::CAPACITY bits and interpreting
    /// them as a little-endian integer.
    fn scalar_from_bytes<A: AsRef<[u8]>>(bs: A) -> Self::Scalar;
    /// Hash to a curve point from a seed. This is deterministic function.
    fn hash_to_group(m: &[u8]) -> Self;
}

#[allow(non_snake_case)]
pub fn multiscalar_multiplication_naive<C: Curve>(a: &[C::Scalar], G: &[C]) -> C {
    let n = a.len();
    if G.len() != n {
        panic!("a and G should have the same length");
    }
    let mut sum = C::zero_point();
    for i in 0..n {
        let aiGi = G[i].mul_by_scalar(&a[i]);
        sum = sum.plus_point(&aiGi);
    }
    sum
}

#[allow(non_snake_case)]
pub fn multiscalar_multiplication<C: Curve>(a: &[C::Scalar], G: &[C]) -> C { multiexp(G, a) }

pub trait Pairing: Sized + 'static + Clone {
    type ScalarField: PrimeField + Serialize;
    type G1: Curve<Base = Self::BaseField, Scalar = Self::ScalarField>;
    type G2: Curve<Base = Self::BaseField, Scalar = Self::ScalarField>;
    type G1Prepared;
    type G2Prepared;
    type BaseField: PrimeField;
    type TargetField: Field + Serial;

    fn miller_loop<'a, I>(i: I) -> Self::TargetField
    where
        I: IntoIterator<Item = &'a (&'a Self::G1Prepared, &'a Self::G2Prepared)>;

    /// Check whether the pairing equation holds given the left and right-hand
    /// sides.
    fn check_pairing_eq(g1x: &Self::G1, g2x: &Self::G2, g1y: &Self::G1, g2y: &Self::G2) -> bool {
        let pairs = [
            (&Self::g1_prepare(g1x), &Self::g2_prepare(g2x)),
            (
                &Self::g1_prepare(&g1y.inverse_point()),
                &Self::g2_prepare(g2y),
            ),
        ];
        let res = Self::miller_loop(pairs.iter());
        if let Some(mut y) = Self::final_exponentiation(&res) {
            y.sub_assign(&Self::TargetField::one());
            y.is_zero()
        } else {
            false
        }
    }

    /// Compute the product of the pairings, but more efficiently.
    fn pairing_product(
        g1x: &Self::G1,
        g2x: &Self::G2,
        g1y: &Self::G1,
        g2y: &Self::G2,
    ) -> Option<Self::TargetField> {
        let pairs = [
            (&Self::g1_prepare(g1x), &Self::g2_prepare(g2x)),
            (&Self::g1_prepare(g1y), &Self::g2_prepare(g2y)),
        ];
        let res = Self::miller_loop(pairs.iter());
        Self::final_exponentiation(&res)
    }

    fn final_exponentiation(_: &Self::TargetField) -> Option<Self::TargetField>;

    fn g1_prepare(_: &Self::G1) -> Self::G1Prepared;
    fn g2_prepare(_: &Self::G2) -> Self::G2Prepared;

    fn pair(p: &Self::G1, q: &Self::G2) -> Self::TargetField {
        let g1p = Self::g1_prepare(p);
        let g2p = Self::g2_prepare(q);
        let x = Self::miller_loop([(&g1p, &g2p)].iter());
        if x.is_zero() {
            panic!("Cannot perform final exponentiation on 0.")
        } else {
            Self::final_exponentiation(&x).unwrap()
        }
    }

    const SCALAR_LENGTH: usize;
    fn generate_scalar<R: Rng>(rng: &mut R) -> Self::ScalarField;
    /// Generate non-zero scalar by repeated sampling. Can be overriden by a
    /// more efficient implementation.
    fn generate_non_zero_scalar<R: Rng>(rng: &mut R) -> Self::ScalarField {
        loop {
            let s = Self::generate_scalar(rng);
            if !s.is_zero() {
                return s;
            }
        }
    }
}

/// Like 'multiexp_worker', but computes a reasonable window size automatically.
#[inline(always)]
pub fn multiexp<C: Curve>(gs: &[C], exps: &[C::Scalar]) -> C {
    // This number is based on the benchmark in benches/multiexp_bench.rs
    let window_size = 4;
    multiexp_worker(gs, exps, window_size)
}

/// This implements the WNAF method from
/// https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_13.pdf
/// Assumes:
/// - the lengths of inputs are the same
/// - window_size < 62
pub fn multiexp_worker<C: Curve>(gs: &[C], exps: &[C::Scalar], window_size: usize) -> C {
    // Compute the wnaf

    let k = exps.len();
    assert_eq!(gs.len(), k);
    assert!(window_size >= 1);
    assert!(window_size < 62);

    let table = multiexp_table(gs, window_size);

    multiexp_worker_given_table(exps, &table, window_size)
}

pub fn multiexp_worker_given_table<C: Curve>(
    exps: &[C::Scalar],
    table: &[Vec<C>],
    window_size: usize,
) -> C {
    // Compute the wnaf

    let k = exps.len();
    // assert_eq!(gs.len(), k);
    assert!(window_size >= 1);
    assert!(window_size < 62);

    // 2^{window_size + 1}
    let two_to_wp1: u64 = 2 << window_size;
    // a mask to extract the lowest window_size + 1 bits from a scalar.
    let mask: u64 = two_to_wp1 - 1;
    let mut wnaf = Vec::with_capacity(k);
    // 1 / 2 scalar
    let half = C::scalar_from_u64(2)
        .inverse()
        .expect("Field size must be at least 3.");

    for c in exps.iter() {
        let mut v = Vec::new();
        let mut c = *c;
        while !c.is_zero() {
            let limb = c.into_repr().as_ref()[0];
            // if the first bit is set
            if limb & 1 == 1 {
                let u = limb & mask;
                // check if window_size'th bit is set.
                if u & (1 << window_size) != 0 {
                    c.sub_assign(&C::scalar_from_u64(u));
                    c.add_assign(&C::scalar_from_u64(two_to_wp1));
                    v.push((u as i64) - (two_to_wp1 as i64));
                } else {
                    c.sub_assign(&C::scalar_from_u64(u));
                    v.push(u as i64);
                }
            } else {
                v.push(0);
            }
            c.mul_assign(&half);
        }
        wnaf.push(v);
    }

    // evaluate using the precomputed table
    let mut a = C::zero_point();
    for j in (0..=C::Scalar::NUM_BITS as usize).rev() {
        a = a.double_point();
        for i in 0..k {
            match wnaf[i].get(j) {
                Some(&ge) if ge > 0 => {
                    a = a.plus_point(&table[i][(ge / 2) as usize]);
                }
                Some(&ge) if ge < 0 => {
                    a = a.minus_point(&table[i][((-ge) / 2) as usize]);
                }
                _ => (),
            }
        }
    }
    a
}

pub fn multiexp_table<C: Curve>(gs: &[C], window_size: usize) -> Vec<Vec<C>> {
    let k = gs.len();
    let mut table = Vec::with_capacity(k);
    for g in gs.iter() {
        let sq = g.plus_point(&g);
        let mut tmp = *g;
        // All of the odd exponents, between 1 and 2^w.
        let num_exponents = 1 << (window_size - 1);
        let mut exps = Vec::with_capacity(num_exponents);
        exps.push(tmp);
        for _ in 1..num_exponents {
            tmp = tmp.plus_point(&sq);
            exps.push(tmp);
        }
        table.push(exps);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;

    #[test]
    pub fn test_multiscalar() {
        let mut csprng = thread_rng();
        for l in 1..100 {
            let mut gs = Vec::with_capacity(l);
            let mut es = Vec::with_capacity(l);
            for _ in 0..l {
                gs.push(G1::generate(&mut csprng));
                es.push(G1::generate_scalar(&mut csprng));
            }
            let mut goal = G1::zero_point();
            // Naive multiply + add method.
            for (g, e) in gs.iter().zip(es.iter()) {
                goal = goal.plus_point(&g.mul_by_scalar(e))
            }
            let g = multiexp(&gs, &es);
            assert!(
                goal.minus_point(&g).is_zero_point(),
                "Multiexponentiation produces a different answer than the naive method."
            )
        }
    }
}
