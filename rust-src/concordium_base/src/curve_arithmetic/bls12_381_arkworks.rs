use core::fmt;

use ark_bls12_381::*;
use ark_ec::{
    bls12::{G1Prepared, G2Prepared},
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::MillerLoopOutput,
    short_weierstrass::Projective,
    CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInt, PrimeField};
use byteorder::ReadBytesExt;
use num_bigint::BigUint;
use sha2::Sha256;

use crate::common::{Buffer, Deserial, ParseResult, Serial};

use anyhow::anyhow;

use super::{
    arkworks_instances::{ArkCurveConfig, ArkField, ArkGroup},
    Pairing,
};

impl ArkCurveConfig<G1Projective> for Projective<g1::Config> {
    type Hasher = MapToCurveBasedHasher<
        Projective<g1::Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<g1::Config>,
    >;

    const DOMAIN_STRING: &'static str = "BLS12381G1";
    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;
}

impl ArkCurveConfig<G2Projective> for Projective<g2::Config> {
    type Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>;

    const DOMAIN_STRING: &'static str = "BLS12381G2";
    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;
}

impl Deserial for Fr {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Fr> {
        let mut buf = [0u8; 32];
        source.read(&mut buf)?;
        // Construct the scalar from big endian bytes.
        let big_int: BigInt<4> = BigUint::from_bytes_be(&buf)
            .try_into()
            .map_err(|_| anyhow!("Cannot convert to bigint"))?;
        let res = Fr::from_bigint(big_int)
            .ok_or(anyhow!("Cannot convert from bigint to a field element"))?;
        Ok(res)
    }
}

impl Serial for Fr {
    fn serial<B: Buffer>(&self, out: &mut B) {
        // Note that it is crucial to use `into_bigint()` here.
        // The internal representation is accessible direclty, but it's NOT the same
        // (it's a Montgomery representation optimized for modular arithmetic)
        let frpr = self.into_bigint();
        for a in frpr.0.iter().rev() {
            a.serial(out);
        }
    }
}

/// This implementation is ad-hoc, using the fact that Fq12 is defined
/// via that specific tower of extensions (of degrees) 2 -> 3 -> 2,
/// and the specific representation of those fields.
/// We use big-endian representation all the way down to the field Fq.
impl Serial for Fq12 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        // coefficients in the extension F_6
        let c0_6 = self.c0;
        let c1_6 = self.c1;

        let coeffs = [
            // coefficients of c1_6 in the extension F_2
            c1_6.c2, c1_6.c1, c1_6.c0, // coefficients of c0_6 in the extension F_2
            c0_6.c2, c0_6.c1, c0_6.c0,
        ];
        for p in coeffs.iter() {
            let repr_c1: BigInt<6> = Fq::from(p.c1).into();
            let repr_c0: BigInt<6> = Fq::from(p.c0).into();
            for d in repr_c1.0.iter() {
                d.serial(out);
            }
            for d in repr_c0.0.iter() {
                d.serial(out);
            }
        }
    }
}

type Bls12 = ark_ec::bls12::Bls12<ark_bls12_381::Config>;

impl Pairing for Bls12 {
    type G1 = ArkGroup<<Bls12 as ark_ec::pairing::Pairing>::G1>;
    type G1Prepared = <Bls12 as ark_ec::pairing::Pairing>::G1Prepared;
    type G2 = ArkGroup<<Bls12 as ark_ec::pairing::Pairing>::G2>;
    type G2Prepared = <Bls12 as ark_ec::pairing::Pairing>::G2Prepared;
    type ScalarField = ArkField<Fr>;
    type TargetField = ArkField<<Bls12 as ark_ec::pairing::Pairing>::TargetField>;

    #[inline(always)]
    fn g1_prepare(g: &Self::G1) -> Self::G1Prepared {
        let res: G1Prepared<_> = g.into_ark().into_affine().into();
        res.into()
    }

    #[inline(always)]
    fn g2_prepare(g: &Self::G2) -> Self::G2Prepared {
        let res: G2Prepared<_> = g.into_ark().into_affine().into();
        res.into()
    }

    #[inline(always)]
    fn miller_loop<'a, I>(i: I) -> Self::TargetField
    where
        I: IntoIterator<Item = &'a (&'a Self::G1Prepared, &'a Self::G2Prepared)>, {
        let (xs, ys): (Vec<_>, Vec<_>) = i.into_iter().map(|x| *x).unzip();
        let res = <Bls12 as ark_ec::pairing::Pairing>::multi_miller_loop(
            xs.into_iter().map(|x| x.clone()),
            ys.into_iter().map(|x| x.clone()),
        )
        .0;
        res.into()
    }

    #[inline(always)]
    fn final_exponentiation(x: &Self::TargetField) -> Option<Self::TargetField> {
        let res = <Bls12 as ark_ec::pairing::Pairing>::final_exponentiation(MillerLoopOutput(x.0));
        res.map(|x| x.0.into())
    }

    #[inline(always)]
    fn generate_scalar<T: rand::Rng>(csprng: &mut T) -> Self::ScalarField {
        <Fr as ark_std::UniformRand>::rand(csprng).into()
    }
}

impl fmt::Display for ArkField<Fr> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for i in self.0.into_bigint().0.iter().rev() {
            write!(f, "{:016x}", *i)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::*,
        curve_arithmetic::{Curve, Field, PrimeField},
    };
    use num_bigint::BigUint;
    use rand::thread_rng;
    use std::io::Cursor;

    const SCALAR_BYTES_LE: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 255, 255, 255, 255, 255, 255, 0,
        0, 0, 0, 0, 0, 0, 0,
    ];

    // Check that scalar_from_bytes_helper works on small values.
    #[test]
    fn scalar_from_bytes_small() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let n = <ArkField<Fr>>::random(&mut rng);
            let mut bytes = to_bytes(&n);
            bytes.reverse();
            let m = <ArkGroup<G1Projective> as Curve>::scalar_from_bytes(&bytes);
            // make sure that n and m only differ in the topmost bit.
            let n = n.into_repr();
            let m = m.into_repr();
            let mask = !(1u64 << 63 | 1u64 << 62);
            assert_eq!(n[0], m[0], "First limb.");
            assert_eq!(n[1], m[1], "Second limb.");
            assert_eq!(n[2], m[2], "Third limb.");
            assert_eq!(n[3] & mask, m[3] & mask, "Fourth limb with top bit masked.");
        }
    }

    /// Test that `into_repr()` correclty converts a scalar constructed from a
    /// byte array to an array of limbs with least significant digits first.
    #[test]
    fn test_into() {
        let bigint: BigUint = BigUint::from_bytes_le(&SCALAR_BYTES_LE);
        let s: ArkField<Fr> = Fr::try_from(bigint)
            .expect("Expected a valid scalar")
            .into();
        assert_eq!(s.into_repr(), [1u64, 0u64, u64::MAX - 1, 0u64]);
    }

    /// Turn scalar elements into representations and back again, and compare.
    #[test]
    fn test_into_from_rep() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            let scalar = <ArkField<Fr>>::random(&mut csprng);
            let scalar_vec64 = scalar.into_repr();
            let scalar_res = <ArkField<Fr>>::from_repr(&scalar_vec64);
            assert!(scalar_res.is_ok());
            assert_eq!(scalar, scalar_res.unwrap());
        }
    }

    #[test]
    fn test_scalar_serialize_big_endian() {
        let bigint: BigUint = BigUint::from_bytes_le(&SCALAR_BYTES_LE);
        let b: BigInt<4> = bigint
            .try_into()
            .expect("Expeted valid biguint representing a fired element");
        let s: ArkField<Fr> = <Fr as ark_ff::PrimeField>::from_bigint(b)
            .expect("Expected a valid scalar")
            .into();
        let mut out = Vec::new();
        s.serial(&mut out);
        let scalar_bytes_be: Vec<u8> = SCALAR_BYTES_LE.into_iter().rev().collect();
        assert_eq!(scalar_bytes_be, out);
    }

    macro_rules! macro_test_scalar_byte_conversion {
        ($function_name:ident, $p:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _ in 0..1000 {
                    let scalar = <$p>::generate_scalar(&mut csprng);
                    let scalar_res = serialize_deserialize(&scalar);
                    assert!(scalar_res.is_ok());
                    assert_eq!(scalar, scalar_res.unwrap());
                }
            }
        };
    }

    macro_rules! macro_test_group_byte_conversion {
        ($function_name:ident, $p:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _ in 0..1000 {
                    let curve = <$p>::generate(&mut csprng);
                    let curve_res = serialize_deserialize(&curve);
                    assert!(curve_res.is_ok());
                    assert_eq!(curve, curve_res.unwrap());
                }
            }
        };
    }

    macro_rules! macro_test_group_byte_conversion_unchecked {
        ($function_name:ident, $p:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _ in 0..1000 {
                    let curve = <$p>::generate(&mut csprng);
                    let bytes = to_bytes(&curve);
                    let curve_res = <$p>::bytes_to_curve_unchecked(&mut Cursor::new(&bytes));
                    assert!(curve_res.is_ok());
                    assert_eq!(curve, curve_res.unwrap());
                }
            }
        };
    }

    type G1 = ArkGroup<G1Projective>;
    type G2 = ArkGroup<G2Projective>;

    macro_test_scalar_byte_conversion!(sc_bytes_conv_g1, G1);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_g2, G2);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_bls12, Bls12);

    macro_test_group_byte_conversion!(curve_bytes_conv_g1, G1);
    macro_test_group_byte_conversion!(curve_bytes_conv_g2, G2);

    macro_test_group_byte_conversion_unchecked!(u_curve_bytes_conv_g1, G1);
    macro_test_group_byte_conversion_unchecked!(u_curve_bytes_conv_g2, G2);
}
