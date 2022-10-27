//! Shared functions used by the proofs in this crate
use crate::inner_product_proof::inner_product;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use ff::Field;
#[cfg(test)]
use rand::Rng;
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

/// This function calculates the inner product `t(X)` of degree-1 vector
/// polynomials `l(X)` and `r(X)` The arguments are
/// - `l_0` - first coefficient of `l(X)`, a vector of field elements
/// - `l_1` - second coefficient of `l(X)`, a vector of field elements
/// - `r_0` - first coefficient of `r(X)`, a vector of field elements
/// - `r_1` - second coefficient of `r(X)`, a vector of field elements
///
/// The output is `(t_0,t_1,t_2)` where
/// `t(X) = t_0+X*t_1+X^2*t_2 = <l(X), r(X)>
///
/// Precondition:
/// all input vectors should have the same length. This function may panic if
/// this is not the case
pub(crate) fn compute_tx_polynomial<F: Field>(
    l_0: &[F],
    l_1: &[F],
    r_0: &[F],
    r_1: &[F],
) -> (F, F, F) {
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

    (t_0, t_1, t_2)
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
/// the input vectors `l_0,l_1,r_0,r_1` should have the same length. This function may panic if
/// this is not the case
pub(crate) fn evaluate_lx_rx_tx<F: Field>(
    x: F,
    l_0: &[F],
    l_1: &[F],
    r_0: &[F],
    r_1: &[F],
    t_0: F,
    t_1: F,
    t_2: F,
) -> (Vec<F>, Vec<F>, F) {
    let n = l_0.len();
    let mut x_sq = x;
    x_sq.mul_assign(&x);
    // Compute l(x) and r(x)
    let mut lx = Vec::with_capacity(n);
    let mut rx = Vec::with_capacity(n);
    for i in 0..n {
        // l[i] <- l_0[i] + x* l_1[i]
        let mut lx_i = l_1[i];
        lx_i.mul_assign(&x);
        lx_i.add_assign(&l_0[i]);
        lx.push(lx_i);
        // r[i] = r_0[i] + x* r_1[i]
        let mut rx_i = r_1[i];
        rx_i.mul_assign(&x);
        rx_i.add_assign(&r_0[i]);
        rx.push(rx_i);
    }
    // Compute t(x)
    // tx <- t_0 + t_1*x + t_2*x^2
    let mut tx = t_0;
    let mut tx_1 = t_1;
    tx_1.mul_assign(&x);
    tx.add_assign(&tx_1);
    let mut tx_2 = t_2;
    tx_2.mul_assign(&x_sq);
    tx.add_assign(&tx_2);
    
    (lx,rx,tx)
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
