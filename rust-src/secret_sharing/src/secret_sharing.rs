use curve_arithmetic::curve_arithmetic::*;
use pairing::Field;
use rand::*;

pub struct SharingData<C: Curve> {
    pub coefficients: Vec<(u64, C::Scalar)>,
    pub shares:       Vec<(u64, C::Scalar)>,
}

pub fn share<C: Curve, R: Rng>(
    secret: &C::Scalar,
    number_of_shares: u64,
    revealing_threshold: u64,
    csprng: &mut R,
) -> SharingData<C> {
    let deg = revealing_threshold - 1; // the degree of polynomial
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
pub fn reveal<C: Curve>(shares: &Vec<(u64, C::Scalar)>) -> C::Scalar {
    let kxs: Vec<u64> = shares.iter().map(|(fst, _)| *fst).collect();
    shares.iter().fold(C::Scalar::zero(), |accum, (i, v)| {
        let mut s = lagrange::<C>(&kxs, *i);
        s.mul_assign(&v);
        s.add_assign(&accum);
        s
    })
}

pub fn reveal_in_group<C: Curve>(shares: &Vec<(u64, C)>) -> C {
    let kxs: Vec<u64> = shares.iter().map(|(fst, _)| *fst).collect();
    shares.iter().fold(C::zero_point(), |accum, (i, v)| {
        let s = lagrange::<C>(&kxs, *i);
        let vs = v.mul_by_scalar(&s);
        vs.plus_point(&accum)
    })
}

mod test {
    use super::*;
    use pairing::bls12_381::{Fr, G1};

    #[test]
    pub fn test_secret_sharing() {
        let mut csprng = thread_rng();
        for i in 1..10 {
            let secret = <G1 as Curve>::generate_scalar(&mut csprng);
            let secret_point = <G1 as Curve>::one_point().mul_by_scalar(&secret);
            let threshold = csprng.gen_range(1, i + 1);
            let sharing_data = share::<G1, ThreadRng>(&secret, i, threshold, &mut csprng);
            let sufficient_sample: Vec<(u64, <G1 as Curve>::Scalar)> =
                sample(&mut csprng, &sharing_data.shares, threshold as usize)
                    .into_iter()
                    .map(|&(n, s)| (n, s))
                    .collect();
            let sufficient_sample_points = sufficient_sample
                .iter()
                .map(|(n, s)| (*n, G1::one_point().mul_by_scalar(&s)))
                .collect();
            let revealed_data: Fr = reveal::<G1>(&sufficient_sample);
            assert_eq!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<G1>(&sufficient_sample_points);
            assert_eq!(revealed_data_point, secret_point);
            let insufficient_sample: Vec<(u64, <G1 as Curve>::Scalar)> =
                sample(&mut csprng, &sharing_data.shares, (threshold - 1) as usize)
                    .into_iter()
                    .map(|&(n, s)| (n, s))
                    .collect();
            let insufficient_sample_points = insufficient_sample
                .iter()
                .map(|(n, s)| (*n, G1::one_point().mul_by_scalar(&s)))
                .collect();
            let revealed_data: Fr = reveal::<G1>(&insufficient_sample);
            assert_ne!(revealed_data, secret);
            let revealed_data_point: G1 = reveal_in_group::<G1>(&insufficient_sample_points);
            assert_ne!(revealed_data_point, secret_point);
        }
    }
}
