use super::arkworks_instances::CurveElementLength;
use ark_curve25519::*;

impl CurveElementLength for EdwardsProjective {
    const GROUP_ELEMENT_LENGTH: usize = 64;
    const SCALAR_LENGTH: usize = 32;
}
