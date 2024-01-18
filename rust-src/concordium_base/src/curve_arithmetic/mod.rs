//! Basic definitions of the curve and pairing abstractions, and implementations
//! of these abstractions for the curves used on Concordium.
pub mod arkworks_instances;
mod bls12_381_arkworks;
mod ed25519_instance;
mod field_adapters;

pub mod secret_value;
pub use secret_value::{Secret, Value};

use crate::common::{Serial, Serialize};
use rand::*;
use std::{borrow::Borrow, fmt, fmt::Debug};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CurveDecodingError {
    #[error("Not a point on the curve.")]
    NotOnCurve,
    #[error("{0} is not a field element.")]
    NotInField(String),
}

/// This trait represents an element of a field.
/// The trait essentially copies `ff::Field` from `v0.5`.
pub trait Field: Sized + Eq + Copy + Clone + Send + Sync + fmt::Debug {
    /// Returns an element chosen uniformly at random using a user-provided RNG.
    fn random<R: RngCore + ?std::marker::Sized>(rng: &mut R) -> Self;

    /// Returns the zero element of the field, the additive identity.
    fn zero() -> Self;

    /// Returns the one element of the field, the multiplicative identity.
    fn one() -> Self;

    /// Returns true iff this element is zero.
    fn is_zero(&self) -> bool;

    /// Squares this element.
    fn square(&mut self);

    /// Doubles this element.
    fn double(&mut self);

    /// Negates this element.
    fn negate(&mut self);

    /// Adds another element to this element.
    fn add_assign(&mut self, other: &Self);

    /// Subtracts another element from this element.
    fn sub_assign(&mut self, other: &Self);

    /// Multiplies another element by this element.
    fn mul_assign(&mut self, other: &Self);

    /// Computes the multiplicative inverse of this element, if nonzero.
    fn inverse(&self) -> Option<Self>;

    /// Exponentiates this element by a number represented with `u64` limbs,
    /// least significant digit first. This operation is variable time with
    /// respect to `self`, for all exponent.
    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        // Note: this implementations is
        // copied from the `ff` crate's trait method `ff::Field::pow_vartime()`.
        // https://docs.rs/ff/0.13.0/src/ff/lib.rs.html#178-191
        let mut res = Self::one();
        for e in exp.as_ref().iter().rev() {
            for i in (0..64).rev() {
                res.square();

                if ((*e >> i) & 1) == 1 {
                    res.mul_assign(self);
                }
            }
        }

        res
    }
}

/// This is an extension of the `Field` trait that adds some constants decribing
/// the element size and operations for converting to/from big integer
/// representation (an array of `u64` limbs.)
pub trait PrimeField: Field {
    /// How many bits are needed to represent an element of this field.
    const NUM_BITS: u32;

    /// How many bits of information can be reliably stored in the field
    /// element. It is expected that `num_limbs * 64 - CAPACITY < 64`, where
    /// `num_limbs` is the size of vector returned by
    /// [PrimeField::into_repr].
    const CAPACITY: u32;

    /// Get a big integer representation with least significant digit first.
    fn into_repr(self) -> Vec<u64>;

    /// Get a prime field element from its big integer representaion (least
    /// significant digit first).
    fn from_repr(_: &[u64]) -> Result<Self, CurveDecodingError>;
}

/// A relatively large trait that covers what is needed to perform constructions
/// and proofs upon a base group. This can only be implemented by groups of
/// prime order size. More correctly this would be called a group, since it is
/// generally a subset of an elliptic curve, but the name is in use now.
pub trait Curve:
    Serialize + Copy + Clone + Sized + Send + Sync + Debug + PartialEq + Eq + 'static {
    /// The prime field of the group order size.
    type Scalar: PrimeField + Serialize;
    type MultiExpType: MultiExp<CurvePoint = Self>;
    /// Size in bytes of elements of the [Curve::Scalar] field.
    const SCALAR_LENGTH: usize;
    /// Size in bytes of group elements when serialized.
    const GROUP_ELEMENT_LENGTH: usize;
    /// Create new instance of multiexp algorithm given some initial points.
    fn new_multiexp<X: Borrow<Self>>(gs: &[X]) -> Self::MultiExpType { Self::MultiExpType::new(gs) }
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
    /// Make a scalar by taking the first `Scalar::CAPACITY`` bits and
    /// interpreting them as a little-endian integer. If the input length is
    /// smaller than `num_limbs * 8` bytes then extra zeros are added in topmost
    /// bytes. If the input lenght is greater, bytes after the first
    /// `num_limbs * 8` are ignored. Where `num_limbs` is the size of vector
    /// returned by [PrimeField::into_repr].
    fn scalar_from_bytes<A: AsRef<[u8]>>(bs: A) -> Self::Scalar;
    /// Hash to a curve point from a seed. This is deterministic function.
    fn hash_to_group(m: &[u8]) -> Result<Self, CurveDecodingError>;
}

/// An abstraction over a multiexp algorithm.
pub trait MultiExp {
    type CurvePoint: Curve;

    /// Create new algorithm instance by providing initial points.
    /// Can be used to precompute a lookup table.
    // NOTE: this method does not take `window_size` as a parameter.
    // Some libraries do not expose `window_size`, so it is left to a
    // concrete implementation to take additional configuration parameters.
    fn new<X: Borrow<Self::CurvePoint>>(gs: &[X]) -> Self;

    /// Multiexp algorithm that uses points provided at the instantiation step
    /// and scalars provided as a parameter.
    fn multiexp<X: Borrow<<Self::CurvePoint as Curve>::Scalar>>(
        &self,
        exps: &[X],
    ) -> Self::CurvePoint;
}

pub struct GenericMultiExp<C> {
    table:       Vec<Vec<C>>,
    window_size: usize,
}

impl<C: Curve> GenericMultiExp<C> {
    // This number is based on the benchmark in benches/multiexp_bench.rs
    const DEFAULT_WINDOW_SIZE: usize = 4;

    /// Compute the table of powers that can be used `multiexp`.
    pub fn new<X: Borrow<C>>(gs: &[X], window_size: usize) -> Self {
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
        Self { table, window_size }
    }
}

impl<C: Curve> MultiExp for GenericMultiExp<C> {
    type CurvePoint = C;

    /// Construct new instance of a lookup table with the default window size.
    // fn new<X: Borrow<C>, I: IntoIterator<Item = X>>(gs: I) -> Self {
    fn new<X: Borrow<C>>(gs: &[X]) -> Self { Self::new(gs, Self::DEFAULT_WINDOW_SIZE) }

    /// This implements the WNAF method from
    /// <https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_13.pdf>
    ///
    /// Assumes:
    /// - the length of input is the same as the table length
    /// - window size at least 1
    /// - window size < 62
    fn multiexp<X: Borrow<<Self::CurvePoint as Curve>::Scalar>>(
        &self,
        exps: &[X],
    ) -> Self::CurvePoint {
        // Compute the wnaf
        let window_size_plus1 = self.window_size + 1;
        let k = exps.len();
        assert!(window_size_plus1 >= 2);
        assert!(window_size_plus1 < 63);

        let mut wnaf = Vec::with_capacity(k);

        // The computation of the wnaf table here is a modification of the
        // implementation in <https://github.com/zkcrypto/group>
        // Compared to the high-level algorithm described in https://link.springer.com/content/pdf/10.1007%2F3-540-45537-X_13.pdf
        // this avoids any field arithmetic and operates directly on the bit
        // representation of the scalars, leading to a substantial performance
        // improvement.
        let width = 1u64 << window_size_plus1;
        let window_mask = width - 1;

        for c in exps.iter() {
            let mut pos = 0;
            let mut carry = 0;
            let repr_limbs = c.borrow().into_repr();
            let mut v = Vec::new();
            let num_bits = repr_limbs.len() * 64;
            while pos < num_bits {
                // Construct a buffer of bits of the scalar, starting at bit `pos`
                let u64_idx = pos / 64;
                let bit_idx = pos % 64;
                let cur_u64 = repr_limbs[u64_idx];
                let bit_buf = if bit_idx + window_size_plus1 < 64 {
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
                    v.extend(std::iter::repeat(0).take(window_size_plus1 - 1));
                    pos += window_size_plus1;
                }
            }
            wnaf.push(v);
        }

        // evaluate using the precomputed table
        let mut a = C::zero_point();
        for j in (0..=C::Scalar::NUM_BITS as usize).rev() {
            a = a.double_point();
            for (wnaf_i, table_i) in wnaf.iter().zip(self.table.iter()) {
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

/// Calls a multiexp algorithm for a curve.
/// The function combines instantiation of an algorithm implementation and
/// computation.
#[inline(always)]
pub fn multiexp<C, X>(gs: &[X], exps: &[C::Scalar]) -> C
where
    C: Curve,
    X: Borrow<C>, {
    C::new_multiexp(gs).multiexp(exps)
}

#[cfg(test)]
mod tests {
    use super::{arkworks_instances::ArkGroup, *};
    use ark_bls12_381::G1Projective;

    type SomeCurve = ArkGroup<G1Projective>;

    #[test]
    pub fn test_multiscalar() {
        let mut csprng = thread_rng();
        for l in 1..100 {
            let mut gs = Vec::with_capacity(l);
            let mut es = Vec::with_capacity(l);
            for _ in 0..l {
                gs.push(SomeCurve::generate(&mut csprng));
                es.push(SomeCurve::generate_scalar(&mut csprng));
            }
            let mut goal = SomeCurve::zero_point();
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
