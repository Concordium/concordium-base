use core::fmt;

use anyhow::anyhow;
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
        let frpr: BigInt<4> = self.0;
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

impl Deserial for Fq12 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        todo!()
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
