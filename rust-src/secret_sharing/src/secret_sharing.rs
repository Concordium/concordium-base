use curve_arithmetic::curve_arithmetic::*;
use pairing::Field;
use rand::*;

pub struct SharingData<C: Curve> {
    coefficients: Vec<(u64, C::Scalar)>,
    shares:       Vec<(u64, C::Scalar)>,
}

pub fn share<C: Curve, R: Rng>(
    secret: &C::Scalar,
    number_of_shares: u64,
    revealing_threshold: u64,
    csprng: &mut R,
) -> SharingData<C> {
    let deg = revealing_threshold - 1; // the degree of polynomial
                                       // if (number_of_shares as u64).overflowing_pow(deg as u32).1 {println!("{},{}",
                                       // number_of_shares, revealing_threshold);}
                                       // println!("xxx---{}", (number_of_shares as u64).overflowing_pow(deg).1);
                                       // assert!(!((number_of_shares as u64).overflowing_pow(deg as u32).1));
    let coefficients: Vec<(u64, C::Scalar)> = (1..deg + 1)
        .into_iter()
        .map(|x| (x, C::generate_scalar(csprng)))
        .collect();
    let shares = (1..number_of_shares + 1)
        .into_iter()
        .map(|x| {
            let share: C::Scalar = coefficients.iter().fold(*secret, |accum, (exp, coeff)| {
                let mut term = C::scalar_from_u64(x).unwrap().pow([*exp]);
                term.mul_assign(&coeff);
                term.add_assign(&accum);
                term
            });
            (x, share)
        })
        .collect();
    SharingData {
        coefficients,
        shares,
    }
}

fn lagrange<C: Curve>(kxs: &Vec<u64>, i: u64) -> C::Scalar {
    kxs.iter().fold(C::Scalar::one(), |accum, j| {
        let mut fe_j = C::scalar_from_u64(*j).unwrap();
        let mut j_minus_i = fe_j.clone();
        j_minus_i.sub_assign(&C::scalar_from_u64(i).unwrap());
        match j_minus_i.inverse() {
            None => accum,
            Some(z) => {
                fe_j.mul_assign(&z);
                fe_j.mul_assign(&accum);
                fe_j 
            }
        }
    })
}
pub fn reveal<C: Curve>(shares: Vec<&(u64, C::Scalar)>) -> C::Scalar {
    let kxs: Vec<u64> = shares.iter().map(|(fst, _)| *fst).collect();
    shares.iter().fold(C::Scalar::zero(), |accum, (i, v)| {
        let mut s = lagrange::<C>(&kxs, *i);
        s.mul_assign(&v);
        s.add_assign(&accum);
        s
    })
}

mod test {
    use super::*;
    use pairing::bls12_381::{Fr, G1};

    #[test]
    pub fn test_secret_sharing() {
        let mut csprng = thread_rng();
        for i in 1..100 {
            let secret = <G1 as Curve>::generate_scalar(&mut csprng);
            let threshold = csprng.gen_range(1, i + 1);
            let sharing_data = share::<G1, ThreadRng>(&secret, i, threshold, &mut csprng);
            let sufficient_sample = sample(&mut csprng, &sharing_data.shares, threshold as usize);
            let revealed_data: Fr = reveal::<G1>(sufficient_sample);
            assert_eq!(revealed_data, secret);
            let insufficient_sample = sample(&mut csprng, &sharing_data.shares, (threshold-1) as usize);
            let revealed_data: Fr = reveal::<G1>(insufficient_sample);
            assert_ne!(revealed_data, secret);

        }
    }
}
