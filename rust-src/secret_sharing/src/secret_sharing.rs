use curve_arithmetic::curve_arithmetic::*;
use pairing::Field;
use rand::*;

pub struct SharingData<C: Curve> {
    coefficients: Vec<(u32, C::Scalar)>,
    shares:       Vec<(u32, C::Scalar)>,
}

pub fn share<C: Curve, R: Rng>(
    secret: &C::Scalar,
    number_of_shares: u32,
    revealing_threshold: u32,
    csprng: &mut R,
) -> SharingData<C> {
    let deg = revealing_threshold - 1; // the degree of polynomial
    assert!(!(number_of_shares as u64).overflowing_pow(deg).1);
    let coefficients: Vec<(u32, C::Scalar)> = (1..deg + 1)
        .into_iter()
        .map(|x| (x, C::generate_scalar(csprng)))
        .collect();
    let shares = (1..number_of_shares + 1)
        .into_iter()
        .map(|x| {
            let share: C::Scalar = coefficients.iter().fold(*secret, |accum, (exp, coeff)| {
                let mut term = C::scalar_from_u64((x as u64).pow(*exp)).unwrap();
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

fn lagrange<C:Curve>(kxs: &Vec<u32>, i: u32) -> C::Scalar{
    kxs.iter().fold(C::Scalar::one(), |accum, j|  match C::scalar_from_u64((j-i) as u64).unwrap().inverse(){
        None => accum,
        Some(z) => {let mut res = C::scalar_from_u64(*j as u64).unwrap(); res.mul_assign(&z); res.add_assign(&accum); res} 
    }
    )
}
pub fn reveal<C: Curve>(shares: Vec<(u32, C::Scalar)>) -> C::Scalar { 
    let kxs :Vec<u32> = shares.iter().map(|(fst, _)| *fst).collect();
    shares.iter().fold(C::Scalar::zero(), |accum, (i,v)| {let mut s = lagrange::<C>(&kxs, *i); s.mul_assign(&v); s.add_assign(&accum); s})

}
