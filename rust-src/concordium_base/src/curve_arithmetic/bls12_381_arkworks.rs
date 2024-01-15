//! Trait implementations for the BLS12-381 curve from `arkworks`.
//! Include configuration for `G1` and `G2`, `Pairing`, and serialization for
//! the target group elements.
use core::fmt;

use ark_bls12_381::*;
use ark_ec::{
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

    const DOMAIN_STRING: &'static str = "CONCORDIUM-hashtoG1-with-BLS12381G1_XMD:SHA-256_SSWU_RO";
    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;
}

impl ArkCurveConfig<G2Projective> for Projective<g2::Config> {
    type Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>;

    const DOMAIN_STRING: &'static str = "CONCORDIUM-hashtoG2-with-BLS12381G2_XMD:SHA-256_SSWU_RO";
    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;
}

impl Deserial for Fr {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Fr> {
        let mut buf = [0u8; 32];
        source.read_exact(&mut buf)?;
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
        // The internal representation is accessible directly, but it's NOT the same.
        // The representation depends on the selected backend.
        // By default, it's a Montgomery representation optimized for modular
        // arithmetic.
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
            let repr_c1: BigInt<6> = p.c1.into_bigint();
            let repr_c0: BigInt<6> = p.c0.into_bigint();
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
    fn g1_prepare(g: &Self::G1) -> Self::G1Prepared { g.into_ark().into_affine().into() }

    #[inline(always)]
    fn g2_prepare(g: &Self::G2) -> Self::G2Prepared { g.into_ark().into_affine().into() }

    #[inline(always)]
    fn miller_loop<'a, I>(i: I) -> Self::TargetField
    where
        I: IntoIterator<Item = &'a (&'a Self::G1Prepared, &'a Self::G2Prepared)>, {
        let (xs, ys): (Vec<_>, Vec<_>) = i.into_iter().copied().unzip();
        let res = <Bls12 as ark_ec::pairing::Pairing>::multi_miller_loop(
            xs.into_iter().cloned(),
            ys.into_iter().cloned(),
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
    use std::str::FromStr;

    use super::*;
    use crate::{
        common::*,
        curve_arithmetic::{Curve, Field, PrimeField},
    };
    use ark_ec::hashing::HashToCurve;
    use ark_ff::field_hashers::HashToField;
    use num_bigint::BigUint;
    use num_traits::One;
    use rand::thread_rng;

    type Fq = ArkField<ark_bls12_381::Fq>;

    const SCALAR_BYTES_LE: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 255, 255, 255, 255, 255, 255, 0,
        0, 0, 0, 0, 0, 0, 0,
    ];

    /// Check that scalar_from_bytes_helper works on small values.
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

    /// Test that the scalar serialization produces big-endian bytes.
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

    /// A macro for testing that serializing a scalar and deserializing it back
    /// gives the same scalar.
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

    /// A macro for testing that serializing a point and deserializing it back
    /// gives the same point.
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

    type G1 = ArkGroup<G1Projective>;
    type G2 = ArkGroup<G2Projective>;

    fn from_coordinates_unchecked(x: Fq, y: Fq, z: Fq) -> G1 {
        G1Projective::new_unchecked(x.0, y.0, z.0).into()
    }

    fn from_coordinates_unchecked_g2(x: Fq2, y: Fq2, z: Fq2) -> G2 {
        G2Projective::new_unchecked(x, y, z).into()
    }

    macro_test_scalar_byte_conversion!(sc_bytes_conv_g1, G1);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_g2, G2);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_bls12, Bls12);

    macro_test_group_byte_conversion!(curve_bytes_conv_g1, G1);
    macro_test_group_byte_conversion!(curve_bytes_conv_g2, G2);

    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G1 {
        let hasher = <G1Projective as ArkCurveConfig<_>>::Hasher::new(dst)
            .expect("Expected valid domain separation string");
        let res = <G1Projective as ArkCurveConfig<_>>::Hasher::hash(&hasher, msg)
            .expect("Expected successful hashing to curve");
        ArkGroup(res.into())
    }

    fn hash_to_curve_g2(msg: &[u8], dst: &[u8]) -> G2 {
        let hasher = <G2Projective as ArkCurveConfig<_>>::Hasher::new(dst)
            .expect("Expected valid domain separation string");
        let res = <G2Projective as ArkCurveConfig<_>>::Hasher::hash(&hasher, msg)
            .expect("Expected successful hashing to curve");
        ArkGroup(res.into())
    }

    fn hash_to_field_fq2(msg: &[u8], dst: &[u8]) -> (Fq2, Fq2) {
        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fq2>>::new(dst);
        let fs: Vec<Fq2> = hasher.hash_to_field(msg, 2);
        (fs[0], fs[1])
    }

    // This tests the function hash_to_curve function according to
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.9.1 with
    // suite   = BLS12381G1_XMD:SHA-256_SSWU_RO_
    // dst     = QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_
    #[test]
    fn test_hash_to_curve() {
        let msg = "".as_bytes();
        let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        let p = hash_to_curve(msg, &dst[..]);
        assert_eq!(to_bytes(&p), vec![
            133, 41, 38, 173, 210, 32, 123, 118, 202, 79, 165, 122, 135, 52, 65, 108, 141, 201, 94,
            36, 80, 23, 114, 200, 20, 39, 135, 0, 238, 214, 209, 228, 232, 207, 98, 217, 192, 157,
            176, 250, 195, 73, 97, 43, 117, 158, 121, 161
        ]);
        // The point should have (in hex)
        // P.x     = 052926add2207b76ca4fa57a8734416c8dc95e24501772c8142787
        //           00eed6d1e4e8cf62d9c09db0fac349612b759e79a1
        // P.y     = 08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c6
        //           7e2e81a4cc68ee29813bb7994998f3eae0c9c6a265
        assert_eq!(p, from_coordinates_unchecked(
            Fq::from_str("794311575721400831362957049303781044852006323422624111893352859557450008308620925451441746926395141598720928151969").unwrap(),
            Fq::from_str("1343412193624222137939591894701031123123641958980729764240763391191550653712890272928110356903136085217047453540965").unwrap(), 
            Fq::one()));
        let msg = "abc".as_bytes();
        let p = hash_to_curve(msg, &dst[..]);
        assert_eq!(to_bytes(&p), vec![
            131, 86, 123, 197, 239, 156, 105, 12, 42, 178, 236, 223, 106, 150, 239, 28, 19, 156,
            192, 178, 242, 132, 220, 160, 169, 167, 148, 51, 136, 164, 154, 58, 238, 102, 75, 165,
            55, 154, 118, 85, 211, 198, 137, 0, 190, 47, 105, 3
        ]);
        // The point should have (in hex)
        // P.x     = 03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a794
        //           3388a49a3aee664ba5379a7655d3c68900be2f6903
        // P.y     = 0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67
        //           af215533311f0b8dfaaa154fa6b88176c229f2885d
        assert_eq!(p, from_coordinates_unchecked(
            Fq::from_str("513738460217615943921285247703448567647875874745567372796164155472383127756567780059136521508428662765965997467907").unwrap(),
            Fq::from_str("1786897908129645780825838873875416513994655004408749907941296449131605892957529391590865627492442562626458913769565").unwrap(), 
            Fq::one()));
        let msg = "abcdef0123456789".as_bytes();
        let p = hash_to_curve(msg, &dst[..]);
        assert_eq!(to_bytes(&p), vec![
            145, 224, 176, 121, 222, 162, 154, 104, 240, 56, 62, 233, 79, 237, 27, 148, 9, 149, 39,
            36, 7, 227, 187, 145, 107, 191, 38, 140, 38, 61, 221, 87, 166, 162, 114, 0, 167, 132,
            203, 194, 72, 232, 79, 53, 124, 232, 45, 152
        ]);
        // The point should have (in hex)
        // P.x     = 11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf26
        //           8c263ddd57a6a27200a784cbc248e84f357ce82d98
        // P.y     = 03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa
        //           1f517c0889501dc7413753f9599b099ebcbbd2d709
        assert_eq!(p, from_coordinates_unchecked(
            Fq::from_str("2751628761372137084683207295437105268166375184027748372156952770986741873369176463286511518644061904904607431667096").unwrap(),
            Fq::from_str("563036982304416203921640398061260377444881693369806087719971277317609936727208012968659302318886963927918562170633").unwrap(), 
            Fq::one()));
        let msg = "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_bytes();
        let p = hash_to_curve(msg, &dst[..]);
        assert_eq!(to_bytes(&p), vec![
            181, 246, 142, 170, 105, 59, 149, 204, 184, 82, 21, 220, 101, 250, 129, 3, 141, 105,
            98, 159, 112, 174, 238, 13, 15, 103, 124, 242, 34, 133, 231, 191, 88, 215, 203, 134,
            238, 254, 143, 46, 155, 195, 248, 203, 132, 250, 196, 136
        ]);
        // The point should have (in hex)
        // P.x     = 15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677c
        //           f22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488
        // P.y     = 1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443
        //           076715f91bb90a48ba1e370edce6ae1062f5e6dd38
        assert_eq!(p, from_coordinates_unchecked(
            Fq::from_str("3380432694887674439773082418192083720584748080704959172978586229921475315220434165460350679208315690319508336723080").unwrap(),
            Fq::from_str("3698526739072864408749571082270628561764415577445404115596990919801523793138348254443092179877354467167123794222392").unwrap(), 
            Fq::one()));
        let msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes();
        let p = hash_to_curve(msg, &dst[..]);
        assert_eq!(to_bytes(&p), vec![
            136, 42, 171, 174, 139, 125, 237, 176, 231, 138, 235, 97, 154, 211, 191, 217, 39, 122,
            47, 119, 186, 127, 173, 32, 239, 106, 171, 220, 108, 49, 209, 155, 165, 166, 209, 34,
            131, 85, 50, 148, 193, 130, 92, 75, 60, 162, 220, 254
        ]);
        // The point should have (in hex)
        // P.x     = 082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aab
        //           dc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe
        // P.y     = 05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779a
        //           d1e942856a20c438e8d99bc8abfbf74729ce1f7ac8
        assert_eq!(p, from_coordinates_unchecked(
            Fq::from_str("1256967425542823069694513550918025689490036478501181600525944653952846100887848729514132077573887342346961531624702").unwrap(),
            Fq::from_str("880372082403694543476959909256504267215588055450016885103797700856746532134585942561958795215862304181527267736264").unwrap(), 
            Fq::one()));
    }

    #[test]
    fn test_hash_to_field_fq2() {
        // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

        {
            //    msg     =
            //    u[0]    = 03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9
            //              cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8
            //        + I * 05a2acec64114845711a54199ea339abd125ba38253b70a92c876d
            //              f10598bd1986b739cad67961eb94f7076511b3b39a
            //    u[1]    = 02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846b
            //              c825de191b5b7641148c0dbc237726a334473eee94
            //        + I * 145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b
            //              2f6eb0c4b94c9115b436e6fa4607e95a98de30a435
            let msg = b"";
            let (u0, u1) = hash_to_field_fq2(msg, dst);
            assert_eq!(
                u0,
                Fq2{
                c0: Fq::from_str("593868448310005448561172252387029516360409945786457439875974315031640021389835649561235021338510064922970633805048").unwrap().0,
                c1: Fq::from_str("867375309489067512797459860887365951877054038763818448057326190302701649888849997836339069389536967202878289851290").unwrap().0}
            );
            assert_eq!(
                u1,
                Fq2{
                c0: Fq::from_str("457889704519948843474026022562641969443315715595459159112874498082953431971323809145630315884223143822925947137684").unwrap().0,
                c1: Fq::from_str("3132697209754082586339430915081913810572071485832539443682634025529375380328136128542015469873094481703191673087029").unwrap().0}
            );
        }

        {
            //    msg     = abc
            // u[0]    = 15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44
            //         a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771
            //   + I * 01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670f
            //         d8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd
            // u[1]    = 187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f
            //         8c372a693f60a033b461d81b025864a0ad051a06e4
            //   + I * 08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a
            //         051ea586f3538a6ebb1e80881a082fa2b24df9f566
            let msg = b"abc";
            let (u0, u1) = hash_to_field_fq2(msg, dst);
            assert_eq!(
                u0,
                Fq2{
                c0: Fq::from_str("3381151350286428005095780827831774583653641216459357823974407145557165174365389989442078766443621078367363453769585").unwrap().0,
                c1: Fq::from_str("274174695370444263853418070745339731640467919355184108253716879519695397069963034977795744692362177212201505728989").unwrap().0}
            );
            assert_eq!(
                u1,
                Fq2{
                c0: Fq::from_str("3761918608077574755256083960277010506684793456226386707192711779006489497410866269311252402421709839991039401264868").unwrap().0,
                c1: Fq::from_str("1342131492846344403298252211066711749849099599627623100864413228392326132610002371925674088601653350525231531947366").unwrap().0}
            );
        }
    }

    #[test]
    fn test_hash_to_curve_g2() {
        // Test vectors are from https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-J.10.1
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        {
            //    msg     =
            //    P.x     =
            // 0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a
            //        + I *
            // 05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d
            //    P.y     =
            // 0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92
            //        + I *
            // 12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6
            let msg = b"";
            let p_should_be = from_coordinates_unchecked_g2(
                Fq2{
                    c0: Fq::from_str("193548053368451749411421515628510806626565736652086807419354395577367693778571452628423727082668900187036482254730").unwrap().0,
                    c1: Fq::from_str("891930009643099423308102777951250899694559203647724988361022851024990473423938537113948850338098230396747396259901").unwrap().0
                },
                Fq2{
                    c0: Fq::from_str("771717272055834152378281705972671257005357145478800908373659404991537354153455452961747174765859335819766715637138").unwrap().0,
                    c1: Fq::from_str("2810310118582126634041133454180705304393079139103252956502404531123692847658283858246402311867775854528543237781718").unwrap().0
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            // msg     = abc
            // P.x     = 02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6
            //     + I * 139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8
            // P.y     = 1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48
            //     + I * 00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16
            let msg = b"abc";
            let p_should_be = from_coordinates_unchecked_g2(
                Fq2{
                    c0: Fq::from_str("424958340463073975547762735517193206833255107941790909009827635556634414746056077714431786321247871628515967727334").unwrap().0,
                    c1: Fq::from_str("3018679803970127877262826393814472528557413504329194740495363852840690589001358162447917674089074634504498585239512").unwrap().0
                },
                Fq2{
                    c0: Fq::from_str("3621308185128395459888995526527127556614768604472132176060423302734876099689739385100475320409412954617897892887112").unwrap().0,
                    c1: Fq::from_str("102447784096837908713257069727879782642075240724579670654226801345708452018676587771714457671432122751958633012502").unwrap().0
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            // msg     = abcdef0123456789
            // P.x     = 121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0
            //     + I * 190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c
            // P.y     = 05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8
            //     + I * 0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be
            let msg = b"abcdef0123456789";
            let p_should_be = from_coordinates_unchecked_g2(
                Fq2{
                    c0: Fq::from_str("2785790728239146617702443308248535381016035748520698399690132325213972292102741627498014391457605127656937478044880").unwrap().0,
                    c1: Fq::from_str("3855709393631831880910167818276435187147963371126198799654803099743427431977934703201153169947378798970358200024876").unwrap().0
                },
                Fq2{
                    c0: Fq::from_str("821938378705205565995357931232097952117504537366318395539093959918654729488074273868834599496909844419980823111624").unwrap().0,
                    c1: Fq::from_str("1802420335575779950982935580421454302087567926385222707947527353462942499437987207287862072369052390195154530059198").unwrap().0
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            // msg     = q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
            // P.x     = 19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da
            //     + I * 0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91
            // P.y     = 14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192
            //     + I * 09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662
            let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
            let p_should_be = from_coordinates_unchecked_g2(
                Fq2{
                    c0: Fq::from_str("3949041098513688455491231180749724794697192943196730030853285011755806989731870696216017360514887069032515603535834").unwrap().0,
                    c1: Fq::from_str("1416893694506131976809002935212216317132941942570763849323065381335907430566747765697423320407614734575486820936593").unwrap().0
                },
                Fq2{
                    c0: Fq::from_str("3227453710863835032992962605851449401391399355135442728893790186263669279022343042444878900124369614767241382891922").unwrap().0,
                    c1: Fq::from_str("1498738834073759871886466122933996764471889514532827927202777922460876335493588931070034160657995151627624577390178").unwrap().0
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
        {
            //   msg     =
            // a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            //   P.x     =
            // 01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534
            //       + I *
            // 11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569
            //   P.y     =
            // 0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e
            //       + I *
            // 03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52
            let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let p_should_be = from_coordinates_unchecked_g2(
                Fq2{
                    c0: Fq::from_str("254155017921606149907129844368549510385368618440139550318910532874259603395336903946742408725761795820224536519988").unwrap().0,
                    c1: Fq::from_str("2768431459296730426779166218544149791601585986233130583011501727704972362141149700714785450629498506208393873593705").unwrap().0
                },
                Fq2{
                    c0: Fq::from_str("1755339344744337457318565116062025669984750617937721245220711425551575490663761638802010265668157125441634554205566").unwrap().0,
                    c1: Fq::from_str("560643043433789571968941329642646582974304556331567393300563909451776257854214387388500126524984624222885267024722").unwrap().0
                },
                Fq2::one()
            );
            let p = hash_to_curve_g2(msg, dst);
            assert_eq!(p, p_should_be);
        }
    }
}
