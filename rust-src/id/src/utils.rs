use curve_arithmetic::Curve;
use ff::Field;
use pedersen_scheme::Commitment;

/// Given a list of commitments g^{a_i}h^{r_i}
/// and a point x (the share number), compute
/// g^p(x)h^r(x) where
/// p(x) = a_0 + a_1 x + ... + a_n x^n
/// r(x) = r_0 + r_1 x + ... + r_n x^n
pub fn commitment_to_share<C: Curve>(
    share_number: &C::Scalar,
    coeff_commitments: &[Commitment<C>],
) -> Commitment<C> {
    // TODO: This would benefit from multiexponentiation.
    let mut cmm_share_point: C = C::zero_point();
    // Horner's scheme in the exponent
    for cmm in coeff_commitments.iter().rev() {
        // FIXME: This would benefit from multiexponentiation.
        cmm_share_point = cmm_share_point.mul_by_scalar(&share_number);
        cmm_share_point = cmm_share_point.plus_point(cmm);
    }
    Commitment(cmm_share_point)
}

/// Interpret the array as coefficients of a polynomial starting at 0,
/// and evaluate the polynomial at the given point.
pub fn evaluate_poly<F: Field, R: AsRef<F>>(coeffs: &[R], point: &F) -> F {
    let mut eval: F = F::zero();
    // Horner's scheme at point point
    for rand in coeffs.iter().rev() {
        eval.mul_assign(&point);
        eval.add_assign(rand.as_ref());
    }
    eval
}
