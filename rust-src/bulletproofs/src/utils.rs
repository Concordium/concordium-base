use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use ff::{Field, PrimeField};

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

/// Converts the u64 set vector into a vector over the field
pub fn get_set_vector<F: PrimeField>(the_set: &[u64]) -> Option<Vec<F>> {
    let n = the_set.len();
    let mut s_vec = Vec::with_capacity(n);
    for i in 0..n {
        let s_i = F::from_repr(F::Repr::from(the_set[i]));
        if s_i.is_err() {
            return None;
        }
        s_vec.push(s_i.unwrap());
    }
    Some(s_vec)
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

    use super::pad_vector_to_power_of_two;
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
        assert_eq!(
            *vec.last().unwrap(),
            SomeField::zero(),
            "Vector should be padded with last element."
        )
    }
}
