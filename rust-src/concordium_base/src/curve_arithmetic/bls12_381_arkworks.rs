use ark_bls12_381::*;
use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInt};
use sha2::Sha256;

use crate::common::{Serial, Buffer};

use super::arkworks_instances::ArkCurveConfig;

impl ArkCurveConfig<G1Projective> for G1Projective {
    type Hasher =
        MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

    const DOMAIN_STRING: &'static str = "";
    const GROUP_ELEMENT_LENGTH: usize = 64;
    const SCALAR_LENGTH: usize = 32;
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