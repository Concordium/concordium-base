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
    /// This **unsafely** generates a list of generators of a given size for
    /// testing purposes. For production, generator must be created with
    /// care.
    #[cfg(test)]
    pub fn generate(n: usize, csprng: &mut impl Rng) -> Self {
        let mut gh = Vec::with_capacity(n);
        for _ in 0..n {
            let x = C::generate(csprng);
            let y = C::generate(csprng);
            gh.push((x, y));
        }
        Self { G_H: gh }
    }

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
pub fn z_vec<F: Field>(z: F, first_power: usize, n: usize) -> Vec<F> {
    let mut z_n = Vec::with_capacity(n);
    // let mut z_i = F::one();
    // FIXME: This should would be better to do with `pow`.
    // for _ in 0..first_power {
    //    z_i.mul_assign(&z);
    //}
    let exp: [u64; 1] = [first_power as u64];
    let mut z_i = z.pow(exp);
    for _ in 0..n {
        z_n.push(z_i);
        z_i.mul_assign(&z);
    }
    z_n
}

/// Converts the u64 set vector into a vector over the field
pub fn get_set_vector<C: Curve>(the_set: &[u64]) -> Vec<C::Scalar> {
    let n = the_set.len();
    let mut s_vec = Vec::with_capacity(n);
    for elem_i in the_set {
        let s_i = C::scalar_from_u64(*elem_i);
        s_vec.push(s_i);
    }
    s_vec
}

/// Pads a field vector two a power of two length by repeating the last element
pub fn pad_vector_to_power_of_two<F: Field>(vec: &mut Vec<F>) {
    let n = vec.len();
    let k = n.next_power_of_two();
    if let Some(last) = vec.last().cloned() {
        let d = k - n;
        for _ in 0..d {
            vec.push(last)
        }
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use rand::thread_rng;

    use super::{pad_vector_to_power_of_two, z_vec};

    // type SomeCurve = pairing::bls12_381::G1;
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
