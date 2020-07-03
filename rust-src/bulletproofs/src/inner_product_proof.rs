use curve_arithmetic::Curve;
use curve_arithmetic::multiscalar_multiplication;
use curve_arithmetic::multiscalar_multiplication_naive;
use curve_arithmetic::multiexp_worker;
use curve_arithmetic::multiexp_worker_given_table;
use curve_arithmetic::multiexp_table;
use ff::{Field, PrimeField};
use merlin::Transcript;
use crate::transcript::TranscriptProtocol;
use group::{CurveAffine, CurveProjective, EncodedPoint};
use pairing::{
    bls12_381::{
        Bls12, Fq, Fr, FrRepr, G1Affine, G1Compressed, G1Prepared, G2Affine, G2Compressed,
        G2Prepared, G1, G2,
    },
    Engine, PairingCurveAffine,
};

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct InnerProductProof<C:Curve> {
    pub L: Vec<C>,
    pub R: Vec<C>,
    pub a: C::Scalar,
    pub b: C::Scalar,
}

#[allow(non_snake_case)]
pub fn prove_inner_product<C: Curve> (
    transcript: &mut Transcript,
    mut G_vec: Vec<C>,
    mut H_vec: Vec<C>,
    Q: &C,
    mut a_vec: Vec<C::Scalar>,
    mut b_vec: Vec<C::Scalar>
) -> InnerProductProof<C>{
    let mut n = G_vec.len();
    assert!(n.is_power_of_two());
    let k = n.next_power_of_two().trailing_zeros() as usize; //This line is also used in Bulletproofs's implementation

    let mut L = Vec::with_capacity(k);
    let mut R = Vec::with_capacity(k);


    for j in 0..k {
        n = G_vec.len();
        let a_lo = &a_vec[..n/2];
        let a_hi = &a_vec[n/2..];
        let G_lo = &G_vec[..n/2];
        let G_hi = &G_vec[n/2..];
        let b_lo = &b_vec[..n/2];
        let b_hi = &b_vec[n/2..];
        let H_lo = &H_vec[..n/2];
        let H_hi = &H_vec[n/2..];
        let a_lo_G_hi = multiscalar_multiplication(a_lo, G_hi);
        let a_hi_G_lo = multiscalar_multiplication(a_hi, G_lo);
        let b_hi_H_lo = multiscalar_multiplication(b_hi, H_lo);
        let b_lo_H_hi = multiscalar_multiplication(b_lo, H_hi);
        let a_lo_b_hi_Q = Q.mul_by_scalar(&inner_product(a_lo, b_hi));
        let a_hi_b_lo_Q = Q.mul_by_scalar(&inner_product(a_hi, b_lo));

        let Lj = a_lo_G_hi.plus_point(&b_hi_H_lo).plus_point(&a_lo_b_hi_Q);
        let Rj = a_hi_G_lo.plus_point(&b_lo_H_hi).plus_point(&a_hi_b_lo_Q);

        //Maybe faster:
        // let mut Lj_scalars = Vec::with_capacity(n+1);
        // Lj_scalars.extend_from_slice(a_lo);
        // Lj_scalars.extend_from_slice(b_hi);
        // Lj_scalars.push(inner_product(a_lo, b_hi));
        // let mut Lj_points = Vec::with_capacity(n+1);
        // Lj_points.extend_from_slice(G_hi);
        // Lj_points.extend_from_slice(H_lo);
        // Lj_points.push(*Q);
        // let Lj = multiscalar_multiplication(&Lj_scalars, &Lj_points);
        // let mut Rj_scalars = Vec::with_capacity(n+1);
        // Rj_scalars.extend_from_slice(a_hi);
        // Rj_scalars.extend_from_slice(b_lo);
        // Rj_scalars.push(inner_product(a_hi, b_lo));
        // let mut Rj_points = Vec::with_capacity(n+1);
        // Rj_points.extend_from_slice(G_lo);
        // Rj_points.extend_from_slice(H_hi);
        // Rj_points.push(*Q);
        // let Rj = multiscalar_multiplication(&Rj_scalars, &Rj_points);
        //end maybe faster

        transcript.append_point(b"Lj", &Lj);
        transcript.append_point(b"Rj", &Rj);
        L.push(Lj);
        R.push(Rj);
        let u_j : C::Scalar = transcript.challenge_scalar::<C>(b"uj");
        // println!("Prover's u_{:?} = {:?}", j, u_j);
        let u_j_inv = u_j.inverse().unwrap(); // avoid this


       
        let mut a = Vec::with_capacity(a_lo.len());
        let mut b = Vec::with_capacity(a_lo.len());
        let mut G = Vec::with_capacity(a_lo.len());
        let mut H = Vec::with_capacity(a_lo.len());
        let G_scalars = vec![u_j_inv, u_j]; // For faster way
        let H_scalars = vec![u_j, u_j_inv]; // For faster way
        for i in 0..a_lo.len() {
            // Calculating new a vector: 
            let mut a_lo_u_j = a_lo[i];
            a_lo_u_j.mul_assign(&u_j);

            let mut u_j_inv_a_hi = a_hi[i];
            u_j_inv_a_hi.mul_assign(&u_j_inv);

            let mut sum = a_lo_u_j;
            sum.add_assign(&u_j_inv_a_hi);
            a.push(sum);

            // Calculating new b vector: 
            let mut b_lo_u_j_inv = b_lo[i];
            b_lo_u_j_inv.mul_assign(&u_j_inv);

            let mut u_j_b_hi = b_hi[i];
            u_j_b_hi.mul_assign(&u_j);

            let mut sum = b_lo_u_j_inv;
            sum.add_assign(&u_j_b_hi);
            b.push(sum);

            // Calculating new G vector: 
            // let G_lo_u_j_inv = G_lo[i].mul_by_scalar(&u_j_inv);
            // let u_j_G_hi = G_hi[i].mul_by_scalar(&u_j);
            // let sum = G_lo_u_j_inv.plus_point(&u_j_G_hi);

            //Maybe faster
            let G_points = vec![G_lo[i], G_hi[i]];
            let sum = multiscalar_multiplication(&G_scalars, &G_points);
            //end maybe faster
            G.push(sum);

            // Calculating new H vector: 
            // let H_lo_u_j = H_lo[i].mul_by_scalar(&u_j);
            // let u_j_inv_H_hi = H_hi[i].mul_by_scalar(&u_j_inv);
            // let sum = H_lo_u_j.plus_point(&u_j_inv_H_hi);
            //Maybe faster
            let H_points = vec![H_lo[i], H_hi[i]];
            let sum = multiscalar_multiplication(&H_scalars, &H_points);
            //end maybe faster
            H.push(sum);
        }
        a_vec = a;
        b_vec = b;
        G_vec = G;
        H_vec = H;        
    }

    let a = a_vec[0];
    let b = b_vec[0];

    InnerProductProof{L, R, a, b}
}

#[allow(non_snake_case)]
pub fn prove_inner_product_with_scalars<C: Curve> (
    transcript: &mut Transcript,
    mut G_vec: Vec<C>,
    mut H_vec: Vec<C>,
    H_prime_scalars: &[C::Scalar],
    Q: &C,
    mut a_vec: Vec<C::Scalar>,
    mut b_vec: Vec<C::Scalar>
) -> InnerProductProof<C>{
    let mut n = G_vec.len();
    assert!(n.is_power_of_two());
    let k = n.next_power_of_two().trailing_zeros() as usize; //This line is also used in Bulletproofs's implementation

    let mut L = Vec::with_capacity(k);
    let mut R = Vec::with_capacity(k);

    for j in 0..k {
        n = G_vec.len();
        let a_lo = &a_vec[..n/2];
        let a_hi = &a_vec[n/2..];
        let G_lo = &G_vec[..n/2];
        let G_hi = &G_vec[n/2..];
        let b_lo = &b_vec[..n/2];
        let b_hi = &b_vec[n/2..];
        let H_lo = &H_vec[..n/2];
        let H_hi = &H_vec[n/2..];
        let a_lo_G_hi = multiscalar_multiplication(a_lo, G_hi);
        let a_hi_G_lo = multiscalar_multiplication(a_hi, G_lo);
        let b_hi_H_lo : C;
        let b_lo_H_hi : C;
        if j == 0 {
            let scalars_hi = &H_prime_scalars[n/2..];
            let scalars_lo = &H_prime_scalars[..n/2];
            let b_hi : Vec<C::Scalar> = b_hi.iter().zip(scalars_lo.iter()).map(|(&x, y)| {let mut xy = x; xy.mul_assign(y); xy}).collect(); 
            let b_lo : Vec<C::Scalar> = b_lo.iter().zip(scalars_hi.iter()).map(|(&x, y)| {let mut xy = x; xy.mul_assign(y); xy}).collect(); 
            b_hi_H_lo = multiscalar_multiplication(&b_hi, H_lo);
            b_lo_H_hi = multiscalar_multiplication(&b_lo, H_hi);
        }
        else {
            b_hi_H_lo = multiscalar_multiplication(b_hi, H_lo);
            b_lo_H_hi = multiscalar_multiplication(b_lo, H_hi);
        }
        let a_lo_b_hi_Q = Q.mul_by_scalar(&inner_product(a_lo, b_hi));
        let a_hi_b_lo_Q = Q.mul_by_scalar(&inner_product(a_hi, b_lo));

        let Lj = a_lo_G_hi.plus_point(&b_hi_H_lo).plus_point(&a_lo_b_hi_Q);
        let Rj = a_hi_G_lo.plus_point(&b_lo_H_hi).plus_point(&a_hi_b_lo_Q);

        transcript.append_point(b"Lj", &Lj);
        transcript.append_point(b"Rj", &Rj);
        L.push(Lj);
        R.push(Rj);
        let u_j : C::Scalar = transcript.challenge_scalar::<C>(b"uj");
        // println!("Prover's u_{:?} = {:?}", j, u_j);
        let u_j_inv = u_j.inverse().unwrap(); // TODO avoid unwrap


       
        let mut a = Vec::with_capacity(a_lo.len());
        let mut b = Vec::with_capacity(a_lo.len());
        let mut G = Vec::with_capacity(a_lo.len());
        let mut H = Vec::with_capacity(a_lo.len());
        let G_scalars = vec![u_j_inv, u_j]; // For faster way
        let mut H_scalars = vec![u_j, u_j_inv];
        
        for i in 0..a_lo.len() {
            // Calculating new a vector: 
            let mut a_lo_u_j = a_lo[i];
            a_lo_u_j.mul_assign(&u_j);

            let mut u_j_inv_a_hi = a_hi[i];
            u_j_inv_a_hi.mul_assign(&u_j_inv);

            let mut sum = a_lo_u_j;
            sum.add_assign(&u_j_inv_a_hi);
            a.push(sum);

            // Calculating new b vector: 
            let mut b_lo_u_j_inv = b_lo[i];
            b_lo_u_j_inv.mul_assign(&u_j_inv);

            let mut u_j_b_hi = b_hi[i];
            u_j_b_hi.mul_assign(&u_j);

            let mut sum = b_lo_u_j_inv;
            sum.add_assign(&u_j_b_hi);
            b.push(sum);

            // Calculating new G vector: 
            // let G_lo_u_j_inv = G_lo[i].mul_by_scalar(&u_j_inv);
            // let u_j_G_hi = G_hi[i].mul_by_scalar(&u_j);
            // let sum = G_lo_u_j_inv.plus_point(&u_j_G_hi);

            //Maybe faster
            let G_points = vec![G_lo[i], G_hi[i]];
            let sum = multiscalar_multiplication(&G_scalars, &G_points);
            //end maybe faster
            G.push(sum);

            // Calculating new H vector: 
            // let H_lo_u_j = H_lo[i].mul_by_scalar(&u_j);
            // let u_j_inv_H_hi = H_hi[i].mul_by_scalar(&u_j_inv);
            // let sum = H_lo_u_j.plus_point(&u_j_inv_H_hi);
            //Maybe faster
            let H_points = vec![H_lo[i], H_hi[i]];
            if j == 0 {
                let mut u_j = u_j;
                let mut u_j_inv = u_j_inv;
                u_j.mul_assign(&H_prime_scalars[i]);
                u_j_inv.mul_assign(&H_prime_scalars[i+a_lo.len()]);
                H_scalars = vec![u_j, u_j_inv];
            }
            let sum = multiscalar_multiplication(&H_scalars, &H_points);
            //end maybe faster
            H.push(sum);
        }
        a_vec = a;
        b_vec = b;
        G_vec = G;
        H_vec = H;        
    }

    let a = a_vec[0];
    let b = b_vec[0];

    InnerProductProof{L, R, a, b}
}


#[allow(non_snake_case)]
pub fn verify_scalars<C: Curve>(transcript: &mut Transcript, n: usize,
    proof: &InnerProductProof<C>) -> (Vec<C::Scalar>, Vec<C::Scalar>, Vec<C::Scalar>){
    // let n = G_vec.len();
    let L = &proof.L;
    let R = &proof.R;
    let a = proof.a;
    let b = proof.b;
    let mut ab = a;
    ab.mul_assign(&b); 
    
    let mut u = Vec::with_capacity(L.len());
    let mut u_inv = Vec::with_capacity(L.len());
    let mut u_sq = Vec::with_capacity(L.len());
    let mut u_inv_sq = Vec::with_capacity(L.len());
    for j in 0..L.len() {
        transcript.append_point(b"Lj", &L[j]);
        transcript.append_point(b"Rj", &R[j]);
        let u_j : C::Scalar = transcript.challenge_scalar::<C>(b"uj");
        // println!("Verifier's u_{:?} = {:?}", j, u_j);
        
        u.push(u_j);
        let u_j_inv = u_j.inverse().unwrap(); // be careful here
        u_inv.push(u_j_inv); 
        let mut u_j_sq = u_j;
        u_j_sq.mul_assign(&u_j);
        u_sq.push(u_j_sq);
        
        let mut u_j_inv_sq = u_j_inv;
        u_j_inv_sq.mul_assign(&u_j_inv);
        u_inv_sq.push(u_j_inv_sq);
    }
    
    let mut s = Vec::with_capacity(n);
    let mut s_0 = u_inv[0];
    for i in 1..u_inv.len() { // This could be done in the above loop
        s_0.mul_assign(&u_inv[i]);
    }

    s.push(s_0);

    for i in 1..n {
        //The following two lines are taken from Bulletproofs's implementation. 
        let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
        let k = 1 << lg_i;
        let mut s_i = s[i-k];
        s_i.mul_assign(&u_sq[L.len()-1-lg_i]);
        s.push(s_i);
    }
    (u_sq, u_inv_sq, s)
}

#[allow(non_snake_case)]
pub fn verify_inner_product<C:Curve>(
    transcript: &mut Transcript,
    G_vec: Vec<C>,
    H_vec: Vec<C>,
    P_prime: C,
    Q: C,
    proof: &InnerProductProof<C>
) -> bool {
    let n = G_vec.len();
    let L = &proof.L;
    let R = &proof.R;
    let a = proof.a;
    let b = proof.b;
    let mut ab = a;
    ab.mul_assign(&b); 
    
    let (u_sq, u_inv_sq, s) = verify_scalars(transcript, n, &proof);

    let mut s_inv = s.clone();
    s_inv.reverse();

    let G = multiscalar_multiplication(&s, &G_vec);
    let H = multiscalar_multiplication(&s_inv, &H_vec);
    // println!("Verifiers's G = <s, G_vec> \n= {:?}", G);

    let mut sum = L[0].mul_by_scalar(&u_sq[0]).plus_point(&(R[0].mul_by_scalar(&u_inv_sq[0])));
    for j in 1..L.len() {
        sum = sum.plus_point(&(L[j].mul_by_scalar(&u_sq[j]).plus_point(&(R[j].mul_by_scalar(&u_inv_sq[j])))));
    }

    let RHS = G.mul_by_scalar(&a).plus_point(&H.mul_by_scalar(&b)).plus_point(&Q.mul_by_scalar(&ab)).minus_point(&sum);
    P_prime.minus_point(&RHS).is_zero_point()
}

#[allow(non_snake_case)]
fn f<C:Curve>(g : C) -> C {
    g.double_point()
}

#[allow(non_snake_case)]
pub fn inner_product<F : Field>(a: &[F], b: &[F]) -> F{
    let n = a.len();
    if b.len() != n {
        panic!("a and b should have the same length");
    }
    let mut sum = F::zero();
    for i in 0..n {
        let mut aibi =a[i];
        aibi.mul_assign(&b[i]);
        sum.add_assign(&aibi);
    }
    sum
}


// #[allow(non_snake_case)]
// pub fn multiscalar_multiplication<C: Curve>(a: &[C::Scalar], G: &[C]) -> C{
//     let n = a.len();
//     if G.len() != n {
//         panic!("a and G should have the same length");
//     }
//     let mut sum = C::zero_point();
//     for i in 0..n {
//         let aiGi =G[i].mul_by_scalar(&a[i]);
//         sum = sum.plus_point(&aiGi);
//     }
//     sum
// }




#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::FqRepr;
    use rand::{thread_rng};
    use std::time::{Duration, Instant};
    use std::thread;
    type SomeCurve = G1;
    type SomeField = Fr;

    #[test]
    fn testinner(){
        let one = SomeField::one();
        let mut two = SomeField::one();
        two.add_assign(&one);
        let mut three = SomeField::one();
        three.add_assign(&two);
        println!("{:?}", one);
        println!("{:?}", two);
        println!("{:?}", three);

        let v = vec![one, two, three];
        let u = vec![three, one, two];
        let ip = inner_product(&v, &u);
        println!("{:?}", ip);
        // assert!(true);
    }

    #[test]
    fn test_msm_basic(){
        let rng = &mut thread_rng();
        let mut Gis = Vec::new();
        let g1 = SomeCurve::generate(rng);
        let g2 = G1::generate(rng);
        Gis.push(g1);
        Gis.push(g2);
        let mut ais = Vec::new();
        let a1 = SomeCurve::generate_scalar(rng);
        let a2 = SomeCurve::generate_scalar(rng);
        ais.push(a1);
        ais.push(a2);

        println!("Naively with two points and two scalars");
        let now = Instant::now();
        let a1g1 = g1.mul_by_scalar(&a1);
        let a2g2 = g2.mul_by_scalar(&a2);
        let mut sum = a1g1;
        sum = sum.plus_point(&a2g2);
        println!("Done in {} µs", now.elapsed().as_micros());
        println!("sum1: {}", sum);

        println!("Using fast msm with two points and two scalars");
        let now = Instant::now();
        let sum2 = multiscalar_multiplication(&ais[..], &Gis[..]);
        println!("Done in {} µs", now.elapsed().as_micros());
        println!("sum2: {}", sum2);
        assert_eq!(sum, sum2);
    }

    #[test]
    fn test_msm_list(){
        let rng = &mut thread_rng();
        let n = 10000;
        let mut Gis = Vec::with_capacity(n);
        let mut ais = Vec::with_capacity(n);
        for _ in 0..n {
            let g = SomeCurve::generate(rng);
            Gis.push(g);
            let a = SomeCurve::generate_scalar(rng);
            ais.push(a);
        }

        let w = 8;
        let table = multiexp_table(&Gis, w);
        let sum = multiexp_worker_given_table(&ais, &table, w);
        let mut list : Vec<SomeCurve> = Vec::with_capacity(n);

        println!("Naively creating list");
        let now = Instant::now();
        for i in 0..n{
            list.push(Gis[i].mul_by_scalar(&ais[i]));
        }
        println!("Done in {} ms", now.elapsed().as_millis());

        let mut list2 : Vec<SomeCurve> = Vec::with_capacity(n);
        println!("Using fast msm to create list");
        let now = Instant::now();
        for i in 0..n{
            let table_vec = table[i].clone();
            let elem = multiexp_worker_given_table(&[ais[i]], &[table_vec], w);
            // let elem = multiscalar_multiplication(&[ais[i]], &[Gis[i]]);
            list2.push(elem);
        }
        println!("Done in {} ms", now.elapsed().as_millis());
        println!("Equal? {}", list == list2);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_msm_bench(){
        let rng = &mut thread_rng();
        let n = 100000;
        let mut Gis = Vec::with_capacity(n);
        let mut ais = Vec::with_capacity(n);
        for _ in 0..n {
            let g = SomeCurve::generate(rng);
            Gis.push(g);
            let a = SomeCurve::generate_scalar(rng);
            ais.push(a);
        }
        
        println!("Doing msm in two go's");
        let now = Instant::now();
        let sum1 = multiscalar_multiplication(&ais[..n/2], &Gis[..n/2]);
        let sum2 = multiscalar_multiplication(&ais[n/2..], &Gis[n/2..]);
        let sum = sum1.plus_point(&sum2);
        
        println!("Done in {} ms", now.elapsed().as_millis());
        println!("sum: {}", sum);
        let sleeping_time = Duration::from_millis(3000);
        // let now = time::Instant::now();

        thread::sleep(sleeping_time);

        println!("Doing msm in one go");
        let now = Instant::now();
        let sum = multiscalar_multiplication(&ais[..], &Gis[..]);

        println!("Done in {} ms", now.elapsed().as_millis());
        println!("sum: {}", sum);
    }


    #[test]
    fn test_msm_with_one_vector(){
        let rng = &mut thread_rng();
        let mut Gis = Vec::new();
        // let mut ais = Vec::new();
        let n = 100000;
        let one = SomeField::one();
        let ais = vec![one; n];
        for _ in 0..n {
            let g = SomeCurve::generate(rng);
            Gis.push(g);
            // let a = SomeCurve::generate_scalar(rng);
            // ais.push(a);
        }

        println!("Doing msm naively");
        let now = Instant::now();
        let sum = multiscalar_multiplication_naive(&ais[..], &Gis[..]);

        println!("Done in {} ms", now.elapsed().as_millis());
        println!("sum: {}", sum);

        println!("Doing msm using wnaf stuff");
        let now = Instant::now();
        let sum = multiexp_worker(&Gis[..], &ais[..], 1);//(&ais[..], &Gis[..]);

        println!("Done in {} ms", now.elapsed().as_millis());
        println!("sum: {}", sum);

        
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_inner_product_proof(){
        //Testing with n = 4
        let rng = &mut thread_rng();
        let n = 32*16;
        let mut G_vec = vec![];
        let mut H_vec = vec![];
        let mut a_vec = vec![];
        let mut b_vec = vec![];
        for _ in 0..n {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            let a = SomeCurve::generate_scalar(rng);
            let b = SomeCurve::generate_scalar(rng);

            G_vec.push(g);
            H_vec.push(h);
            a_vec.push(a);
            b_vec.push(b);
        }

        let Q =  SomeCurve::generate(rng);
        let P_prime = multiscalar_multiplication(&a_vec, &G_vec).plus_point(&multiscalar_multiplication(&b_vec, &H_vec)).plus_point(&Q.mul_by_scalar(&inner_product(&a_vec, &b_vec)));
        // let P_prime = SomeCurve::zero_point();
        let mut transcript = Transcript::new(&[]);
        
        println!("Producing inner product proof with vector len = {}", n);
        let now = Instant::now();
        let proof = prove_inner_product(&mut transcript, G_vec.clone(), H_vec.clone(), &Q, a_vec, b_vec);
        println!("Done in {} ms", now.elapsed().as_millis());
        // let P_prime = P_prime_;

        let mut transcript = Transcript::new(&[]);
        println!("{}", verify_inner_product(&mut transcript, G_vec.clone(), H_vec.clone(), P_prime, Q, &proof));
        // assert!(verify_inner_product(&mut transcript, G_vec, H_vec, P_prime, Q, proof));

    }

    #[test]
    #[allow(non_snake_case)]
    fn compare_inner_product_proof(){
        //Testing with n = 4
        let rng = &mut thread_rng();
        let n = 32*16;
        let mut G_vec = vec![];
        let mut H_vec = vec![];
        let mut a_vec = vec![];
        let mut b_vec = vec![];
        let y = SomeCurve::generate_scalar(rng);
        for i in 0..n {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            let a = SomeCurve::generate_scalar(rng);
            let b = SomeCurve::generate_scalar(rng);

            G_vec.push(g);
            H_vec.push(h);
            a_vec.push(a);
            b_vec.push(b);
        }

        let Q =  SomeCurve::generate(rng);
        let H = H_vec.clone();
        let mut H_prime : Vec<SomeCurve> = Vec::with_capacity(n);
        let y_inv = y.inverse().unwrap();
        let mut y_inv_i = SomeField::one();
        let mut H_prime_scalars : Vec<SomeField> = Vec::with_capacity(n);
        for i in 0..n {
            H_prime.push(H[i].mul_by_scalar(&y_inv_i)); // 245 ms vs 126 ms or 625 ms vs 510
            H_prime_scalars.push(y_inv_i);
            y_inv_i.mul_assign(&y_inv);
        }
        let P_prime = multiscalar_multiplication(&a_vec, &G_vec).plus_point(&multiscalar_multiplication(&b_vec, &H_prime)).plus_point(&Q.mul_by_scalar(&inner_product(&a_vec, &b_vec)));
        // let P_prime = SomeCurve::zero_point();
        let mut transcript = Transcript::new(&[]);
        
        println!("Producing inner product proof");
        let now = Instant::now();
        // let proof = prove_inner_product(&mut transcript, G_vec.clone(), H_prime.clone(), &Q, a_vec, b_vec);
        let proof = prove_inner_product_with_scalars(&mut transcript, G_vec.clone(), H_vec.clone(), &H_prime_scalars, &Q, a_vec, b_vec);
        println!("Done in {} ms", now.elapsed().as_millis());
        // let P_prime = P_prime_;

        let mut transcript = Transcript::new(&[]);
        println!("{}", verify_inner_product(&mut transcript, G_vec, H_prime, P_prime, Q, &proof));
        // assert!(verify_inner_product(&mut transcript, G_vec, H_vec, P_prime, Q, proof));

    }
}