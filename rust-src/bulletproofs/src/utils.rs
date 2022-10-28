//! Shared functions used by the proofs in this crate
use crate::inner_product_proof::{
    inner_product, prove_inner_product_with_scalars, InnerProductProof,
};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use ff::Field;
use rand::Rng;
use random_oracle::RandomOracle;

/// Struct containing generators G and H needed for range proofs
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, SerdeBase16Serialize)]
pub struct Generators<C: Curve> {
    #[size_length = 4]
    pub G_H: Vec<(C, C)>,
}

impl<C: Curve> Generators<C> {
    /// **Warning** do not use in production!
    /// This generates a list of generators of a given size for
    /// testing purposes. For production, generators must be created such that
    /// discrete logarithms between different generators are not known, which is
    /// not guaranteed by this function.
    #[cfg(test)]
    pub(crate) fn generate(n: usize, csprng: &mut impl Rng) -> Self {
        let mut gh = Vec::with_capacity(n);
        for _ in 0..n {
            let x = C::generate(csprng);
            let y = C::generate(csprng);
            gh.push((x, y));
        }
        Self { G_H: gh }
    }

    /// Returns the prefix of length nm of a given generator.
    /// This function panics if nm > length of the generator.
    pub fn take(&self, nm: usize) -> Self {
        Self {
            G_H: self.G_H[0..nm].to_vec(),
        }
    }
}

/// This function takes one argument n and returns the
/// vector (z^j, z^{j+1}, ..., z^{j+n-1}) in F^n for any field F
/// The arguments are
/// - z - the field element z
/// - first_power - the first power j
/// - n - the integer n.
pub fn z_vec<F: Field>(z: F, first_power: u64, n: usize) -> Vec<F> {
    let mut z_n = Vec::with_capacity(n);
    let exp: [u64; 1] = [first_power];
    let mut z_i = z.pow(exp);
    for _ in 0..n {
        z_n.push(z_i);
        z_i.mul_assign(&z);
    }
    z_n
}

/// Pads a non-empty field vector to a power of two length by repeating the last
/// element For empty vectors the function is the identity.
pub(crate) fn pad_vector_to_power_of_two<F: Field>(vec: &mut Vec<F>) {
    let n = vec.len();
    if n == 0 {
        return;
    }
    let k = n.next_power_of_two();
    if let Some(last) = vec.last().cloned() {
        let d = k - n;
        for _ in 0..d {
            vec.push(last)
        }
    }
}

/// Degree-`1` polynomials l(X), r(X) describes by their coefficients
pub(crate) struct LeftRightPolynomials<'a, F: Field> {
    /// `l_0` - first coefficient of `l(X)`, a vector of field elements
    pub l_0: &'a [F],
    /// `l_1` - second coefficient of `l(X)`, a vector of field elements
    pub l_1: &'a [F],
    /// `r_0` - first coefficient of `r(X)`, a vector of field elements
    pub r_0: &'a [F],
    /// `r_1` - second coefficient of `r(X)`, a vector of field elements
    pub r_1: &'a [F],
}

/// Degree-`2` polynomial t(X) described by its coefficients
struct TPolynomial<F: Field>(F, F, F);

/// This function calculates the inner product `t(X)` of degree-1 vector
/// polynomials `l(X)` and `r(X)` The arguments are
/// - `lr` - the coeffcients of `l(X)` and `r(X)`
/// The output is the coefficients of t(X) where
/// `t(X) = t_0+X*t_1+X^2*t_2 = <l(X), r(X)>
/// Precondition:
/// all vectors in `lr` should have the same length. This function may panic if
/// this is not the case
fn compute_tx_polynomial<F: Field>(lr: &LeftRightPolynomials<F>) -> TPolynomial<F> {
    let (l_0, l_1, r_0, r_1) = (lr.l_0, lr.l_1, lr.r_0, lr.r_1);
    // t_0 <- <l_0,r_0>
    let t_0 = inner_product(l_0, r_0);
    // t_2 <- <l_1,r_1>
    let t_2 = inner_product(l_1, r_1);
    // t_1 <- <l_0+l_1,r_0+r_1> - t_0 - t_1
    let mut t_1 = F::zero();
    // add <l_0+l_1,r_0+r_1>
    for i in 0..l_0.len() {
        let mut l_side = l_0[i];
        l_side.add_assign(&l_1[i]);
        let mut r_side = r_0[i];
        r_side.add_assign(&r_1[i]);
        let mut prod = l_side;
        prod.mul_assign(&r_side);
        t_1.add_assign(&prod);
    }
    // subtract t_0 and t_1
    t_1.sub_assign(&t_0);
    t_1.sub_assign(&t_2);

    TPolynomial(t_0, t_1, t_2)
}

/// This function evaluates polynomials `l(X)`, `r(X)`, `t(X)` at `x`.
/// - `x` - evaluation point, a field element
/// - `l_0` - first coefficient of `l(X)`, a vector of field elements
/// - `l_1` - second coefficient of `l(X)`, a vector of field elements
/// - `r_0` - first coefficient of `r(X)`, a vector of field elements
/// - `r_1` - second coefficient of `r(X)`, a vector of field elements
/// - `t_0, t_1, t_2` coefficients of `t(X)`, each a field element
///
/// The output is `l(x), r(x), t(x)`
///
/// Precondition:
/// the input vectors `l_0,l_1,r_0,r_1` should have the same length. This
/// function may panic if this is not the case
#[allow(clippy::too_many_arguments)]
fn evaluate_lx_rx_tx<F: Field>(
    x: F,
    lr: &LeftRightPolynomials<F>,
    t_poly: &TPolynomial<F>,
) -> (Vec<F>, Vec<F>, F) {
    let mut x_sq = x;
    x_sq.mul_assign(&x);
    // c = a+b*x
    let eval_x = |(a, b): (&F, &F)| {
        let mut c: F = *b;
        c.mul_assign(&x);
        c.add_assign(a);
        c
    };
    // Compute l(x) and r(x)
    let lx = lr.l_0.iter().zip(lr.l_1.iter()).map(eval_x).collect();
    let rx = lr.r_0.iter().zip(lr.r_1.iter()).map(eval_x).collect();
    // Compute t(x)
    // tx <- t_0 + t_1*x + t_2*x^2
    let mut tx = t_poly.0;
    let mut tx_1 = t_poly.1;
    tx_1.mul_assign(&x);
    tx.add_assign(&tx_1);
    let mut tx_2 = t_poly.2;
    tx_2.mul_assign(&x_sq);
    tx.add_assign(&tx_2);

    (lx, rx, tx)
}

/// Generators used by `prove_blinded_inner_product`
#[allow(non_snake_case)]
pub(crate) struct VecComGens<'a, C: Curve> {
    pub B:       C,
    pub B_tilde: C,
    pub G:       &'a [C],
    pub H:       &'a [C],
}

#[allow(non_snake_case)]
pub(crate) struct BlindedInnerProof<C: Curve> {
    /// Commitment to the t_1 coefficient of polynomial `t(x)`
    pub T_1:      C,
    /// Commitment to the t_2 coefficient of polynomial `t(x)`
    pub T_2:      C,
    /// Evaluation of t(x) at the challenge point `x`
    pub tx:       C::Scalar,
    /// Blinding factor for the commitment to `tx`
    pub tx_tilde: C::Scalar,
    /// Blinding factor for the commitment to the inner-product arguments
    pub e_tilde:  C::Scalar,
    /// Inner product proof
    pub ip_proof: InnerProductProof<C>,
}

/// This function takes care of computing the blinded inner product as required
/// by range or set-(non)-membership proofs. The arguments are:
/// - `transcript` - the random oracle for Fiat Shamir
/// - `csprng` - cryptographic safe randomness generator
/// - `t_0_tilde` - the randomness for the commitment to `t_0`
/// - `a_tilde` - the randomness of commitment `A`
/// - `s_tilde` - the randomness of commitment `S`
/// - `lr` - the l(X) and r(X) polynomials defined by their coefficients `gens`
///   - the generators used for (vector) commitments, among them `H`.
/// - `H_prime_scalars` - the scalars used to compute `H'` from `H`
/// This function assumes that `lr`, `gens`, and `H_prime_scalars` parts have
/// consistent length, it may panic otherwise
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_blinded_inner_product<C: Curve, R: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    t_0_tilde: C::Scalar,
    a_tilde: C::Scalar,
    s_tilde: C::Scalar,
    lr: LeftRightPolynomials<C::Scalar>,
    gens: VecComGens<C>,
    H_prime_scalars: &[C::Scalar],
) -> Option<BlindedInnerProof<C>> {
    // Part 3: Computation of polynomial t(x) = <l(x),r(x)>
    let t_poly = compute_tx_polynomial(&lr);

    // Commit to t_1 and t_2
    let t_1_tilde = C::generate_scalar(csprng);
    let t_2_tilde = C::generate_scalar(csprng);
    let T_1 = gens
        .B
        .mul_by_scalar(&t_poly.1)
        .plus_point(&gens.B_tilde.mul_by_scalar(&t_1_tilde));
    let T_2 = gens
        .B
        .mul_by_scalar(&t_poly.2)
        .plus_point(&gens.B_tilde.mul_by_scalar(&t_2_tilde));
    // append T1, T2 commitments to transcript
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);

    // Part 4: Evaluate l(.), r(.), and t(.) at challenge point x
    // get challenge x from transcript
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
    // Compute l(x), r(x), and t(x)
    let (lx, rx, tx) = evaluate_lx_rx_tx(x, &lr, &t_poly);
    // Compute the blinding t_x_tilde
    // t_x_tilde <- t_0_tilde + t_1_tilde*x + t_2_tilde*x^2
    let mut tx_tilde = t_0_tilde;
    let mut tx_s1 = t_1_tilde;
    tx_s1.mul_assign(&x);
    tx_tilde.add_assign(&tx_s1);
    let mut tx_s2 = t_2_tilde;
    tx_s2.mul_assign(&x);
    tx_s2.mul_assign(&x);
    tx_tilde.add_assign(&tx_s2);
    // Compute blinding e_tilde
    // e_tilde <- a_tilde + s_tilde * x
    let mut e_tilde = s_tilde;
    e_tilde.mul_assign(&x);
    e_tilde.add_assign(&a_tilde);
    // append tx, tx_tilde, e_tilde to transcript
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);

    // Part 5: Inner product proof for tx = <lx,rx>
    // get challenge w from transcript
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");
    // get generator q
    let Q = gens.B.mul_by_scalar(&w);
    // compute inner product proof
    let proof =
        prove_inner_product_with_scalars(transcript, gens.G, gens.H, H_prime_scalars, &Q, &lx, &rx);
    proof.map(|ip_proof| BlindedInnerProof {
        T_1,
        T_2,
        tx,
        tx_tilde,
        e_tilde,
        ip_proof,
    })
}

#[cfg(test)]
mod tests {

    use super::{pad_vector_to_power_of_two, z_vec};
    use ff::Field;
    use rand::thread_rng;

    type SomeField = pairing::bls12_381::Fq;

    #[test]
    fn test_vector_padding() {
        let n = 10;
        let mut vec = Vec::with_capacity(n);
        for _ in 0..n {
            vec.push(SomeField::one())
        }
        vec.push(SomeField::zero());
        pad_vector_to_power_of_two(&mut vec);
        assert_eq!(vec.len(), 16, "Vector should have power of two length.");
        for i in 0..vec.len() {
            if i < n {
                assert_eq!(
                    *vec.get(i).unwrap(),
                    SomeField::one(),
                    "Vector element {} should be one",
                    i
                )
            } else {
                assert_eq!(
                    *vec.get(i).unwrap(),
                    SomeField::zero(),
                    "Vector element {} should be zero",
                    i
                )
            }
        }
    }

    #[test]
    fn test_vector_padding_with_empty() {
        let mut vec: Vec<SomeField> = Vec::with_capacity(42);
        pad_vector_to_power_of_two(&mut vec);
        assert_eq!(vec.len(), 0, "Vector should still have length 0.");
    }

    #[test]
    fn test_vector_padding_with_power_of_two() {
        let n = 16;
        let mut vec = Vec::with_capacity(n);
        for _ in 0..n {
            vec.push(SomeField::one())
        }
        pad_vector_to_power_of_two(&mut vec);
        assert_eq!(vec.len(), n, "Vector should still have length n.");
    }

    #[test]
    fn test_z_vec() {
        let rng = &mut thread_rng();
        let mut z = SomeField::random(rng);
        let n = 10;
        let vec = z_vec(z, 2, n);
        assert_eq!(vec.len(), n, "Vector length should be {}", n);
        z.square();
        assert_eq!(*vec.get(0).unwrap(), z, "First element should be z^2")
    }
}
