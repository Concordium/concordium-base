//! Basic definitions of the curve and pairing abstractions, and implementations
//! of these abstractions for the curves used on Concordium.
mod bls12_381_g1hash;
mod bls12_381_g2hash;
mod bls12_381_instance;

pub mod secret_value;
pub use secret_value::{Secret, Value};

use crate::common::{Serial, Serialize};
use byteorder::ReadBytesExt;
use ff::{Field, PrimeField};
use rand::*;
use std::{borrow::Borrow, fmt::Debug};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CurveDecodingError {
    #[error("Not a point on the curve.")]
    NotOnCurve,
}

/// A relatively large trait that covers what is needed to perform constructions
/// and proofs upon a base group. This can only be implemented by groups of
/// prime order size. More correctly this would be called a group, since it is
/// generally a subset of an elliptic curve, but the name is in use now.
pub trait Curve:
    Serialize + Copy + Clone + Sized + Send + Sync + Debug + PartialEq + Eq + 'static {
    /// The prime field of the group order size.
    type Scalar: PrimeField + Field + Serialize;
    /// Size in bytes of elements of the [Curve::Scalar] field.
    const SCALAR_LENGTH: usize;
    /// Size in bytes of group elements when serialized.
    const GROUP_ELEMENT_LENGTH: usize;
    /// Unit for the group operation.
    fn zero_point() -> Self;
    /// Chosen generator of the group.
    fn one_point() -> Self;
    fn is_zero_point(&self) -> bool;
    #[must_use]
    /// Return the group inverse of the given element.
    fn inverse_point(&self) -> Self;
    #[must_use]
    /// Given x compute x + x.
    fn double_point(&self) -> Self;
    #[must_use]
    /// The group operation.
    fn plus_point(&self, other: &Self) -> Self;
    #[must_use]
    /// Subtraction. This is generally more efficient than a combination of
    /// [Curve::inverse_point] and [Curve::plus_point].
    fn minus_point(&self, other: &Self) -> Self;
    #[must_use]
    /// Exponentiation by a scalar, i.e., compute n * x for a group element x
    /// and integer n.
    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self;
    /// Deserialize a value from a byte source, but do not check that it is in
    /// the group itself. This can be cheaper if the source of the value is
    /// trusted, but it must not be used on untrusted sources.
    fn bytes_to_curve_unchecked<R: ReadBytesExt>(b: &mut R) -> anyhow::Result<Self>;
    /// Generate a random group element, uniformly distributed.
    fn generate<R: Rng>(rng: &mut R) -> Self;
    /// Generate a random scalar value, uniformly distributed.
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

/// A pairing friendly curve is a collection of two groups and a pairing
/// function. The groups must be of prime order.
pub trait Pairing: Sized + 'static + Clone {
    type ScalarField: PrimeField + Serialize;
    /// The first group of the pairing.
    type G1: Curve<Scalar = Self::ScalarField>;
    /// The second group, must have the same order as [Pairing::G1]. Both G1 and
    /// G2 must be of prime order size.
    type G2: Curve<Scalar = Self::ScalarField>;
    /// An auxiliary type that is used as an input to the pairing function.
    type G1Prepared;
    /// An auxiliary type that is used as an input to the pairing function.
    type G2Prepared;
    /// Field of the size of G1 and G2.
    type BaseField: PrimeField;
    /// The target of the pairing function. The pairing function actually maps
    /// to a subgroup of the same order as G1 and G2, but this subgroup is
    /// not exposed here and is generally not useful. It is subgroup of the
    /// multiplicative subgroup of the field.
    type TargetField: Field + Serial;

    /// Compute the miller loop on the given sequence of prepared points.
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
pub fn multiexp<C: Curve, X: Borrow<C>>(gs: &[X], exps: &[C::Scalar]) -> C {
    // This number is based on the benchmark in benches/multiexp_bench.rs
    let window_size = 4;
    multiexp_worker(gs, exps, window_size)
}

/// This implements the WNAF method from
/// <https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_13.pdf>
///
/// Assumes:
/// - the lengths of inputs are the same
/// - window size at least 1
/// - window_size < 62
pub fn multiexp_worker<C: Curve, X: Borrow<C>>(
    gs: &[X],
    exps: &[C::Scalar],
    window_size: usize,
) -> C {
    // Compute the wnaf

    let k = exps.len();
    assert_eq!(gs.len(), k);
    assert!(window_size >= 1);
    assert!(window_size < 62);

    let table = multiexp_table(gs, window_size);

    multiexp_worker_given_table(exps, &table, window_size)
}

/// This function assumes the same properties about the inputs as
/// `multiexp_worker`, as well as the fact that the table corresponds to the
/// window-size and the given inputs.
///
/// See <https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_13.pdf> for what it means
/// for the table to be computed correctly.
pub fn multiexp_worker_given_table<C: Curve>(
    exps: &[C::Scalar],
    table: &[Vec<C>],
    window: usize,
) -> C {
    // Compute the wnaf
    let window_size = window + 1;
    let k = exps.len();
    // assert_eq!(gs.len(), k);
    assert!(window_size < 62);

    let mut wnaf = Vec::with_capacity(k);

    // The computation of the wnaf table here is a modification of the
    // implementation in <https://github.com/zkcrypto/group>
    // Compared to the high-level algorithm described in https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_13.pdf
    // this avoids any field arithmetic and operates directly on the bit
    // representation of the scalars, leading to a substantial performance
    // improvement.
    let width = 1u64 << window_size;
    let window_mask = width - 1;

    for c in exps.iter() {
        let mut pos = 0;
        let mut carry = 0;
        let repr = c.into_repr();
        let repr_limbs = repr.as_ref();
        let mut v = Vec::new();
        let num_bits = repr_limbs.len() * 64;
        while pos < num_bits {
            // Construct a buffer of bits of the scalar, starting at bit `pos`
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let cur_u64 = repr_limbs[u64_idx];
            let bit_buf = if bit_idx + window_size < 64 {
                // This window's bits are contained in a single u64
                cur_u64 >> bit_idx
            } else {
                let next_u64 = repr_limbs.get(u64_idx + 1).copied().unwrap_or(0);
                // Combine the current u64's bits with the bits from the next u64
                (cur_u64 >> bit_idx) | (next_u64 << (64 - bit_idx))
            };

            // Add the carry into the current window
            let window_val = carry + (bit_buf & window_mask);

            if window_val & 1 == 0 {
                // If the window value is even, preserve the carry and emit 0.
                // Why is the carry preserved?
                // If carry == 0 and window_val & 1 == 0, then the next carry should be 0
                // If carry == 1 and window_val & 1 == 0, then bit_buf & 1 == 1 so the next
                // carry should be 1
                v.push(0);
                pos += 1;
            } else {
                v.push(
                    if window_val < width / 2 {
                        carry = 0;
                        window_val as i64
                    } else {
                        carry = 1;
                        (window_val as i64).wrapping_sub(width as i64)
                    },
                );
                v.extend(std::iter::repeat(0).take(window_size - 1));
                pos += window_size;
            }
        }
        wnaf.push(v);
    }

    // evaluate using the precomputed table
    let mut a = C::zero_point();
    for j in (0..=C::Scalar::NUM_BITS as usize).rev() {
        a = a.double_point();
        for (wnaf_i, table_i) in wnaf.iter().zip(table.iter()) {
            match wnaf_i.get(j) {
                Some(&ge) if ge > 0 => {
                    a = a.plus_point(&table_i[(ge / 2) as usize]);
                }
                Some(&ge) if ge < 0 => {
                    a = a.minus_point(&table_i[((-ge) / 2) as usize]);
                }
                _ => (),
            }
        }
    }
    a
}

/// Compute the table of powers that can be used `multiexp_worker_given_table`.
pub fn multiexp_table<C: Curve, X: Borrow<C>>(gs: &[X], window_size: usize) -> Vec<Vec<C>> {
    let k = gs.len();
    let mut table = Vec::with_capacity(k);
    for g in gs.iter() {
        let sq = g.borrow().plus_point(g.borrow());
        let mut tmp = *g.borrow();
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
