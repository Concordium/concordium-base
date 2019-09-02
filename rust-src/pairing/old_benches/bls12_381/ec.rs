mod g1 {
    use rand::{Rand, Rng, SeedableRng, XorShiftRng};

    use pairing::{bls12_381::*, CurveAffine, CurveProjective};

    #[bench]
    fn bench_g1_mul_assign(b: &mut ::test::Bencher) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let v: Vec<(G1, Fr)> = (0..SAMPLES)
            .map(|_| (G1::rand(&mut rng), Fr::rand(&mut rng)))
            .collect();

        let mut count = 0;
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.mul_assign(v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        });
    }

    #[bench]
    fn bench_g1_add_assign(b: &mut ::test::Bencher) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let v: Vec<(G1, G1)> = (0..SAMPLES)
            .map(|_| (G1::rand(&mut rng), G1::rand(&mut rng)))
            .collect();

        let mut count = 0;
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        });
    }

    #[bench]
    fn bench_g1_add_assign_mixed(b: &mut ::test::Bencher) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let v: Vec<(G1, G1Affine)> = (0..SAMPLES)
            .map(|_| (G1::rand(&mut rng), G1::rand(&mut rng).into()))
            .collect();

        let mut count = 0;
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_assign_mixed(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        });
    }

    macro_rules! bench_hashing {
        ($benchname:ident, $curveimpl:path, $curvetype:path) => {
            #[bench]
            fn $benchname(b: &mut ::test::Bencher) {
                const SAMPLES: usize = 1000;

                let mut rng =
                    XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

                let v: Vec<[u8; 32]> = (0..SAMPLES).map(|_| rng.gen::<[u8; 32]>()).collect();

                let mut count = 0;
                b.iter(|| {
                    let _ = <$curveimpl as $curvetype>::hash_to_group_element(&v[count]);
                    count = (count + 1) % SAMPLES;
                });
            }
        };
    }

    bench_hashing!(bench_g1_hash_to_group_projective, G1, CurveProjective);
    bench_hashing!(bench_g1_hash_to_group_affine, G1Affine, CurveAffine);
}

mod g2 {
    use rand::{Rand, SeedableRng, XorShiftRng};

    use pairing::{bls12_381::*, CurveProjective};

    #[bench]
    fn bench_g2_mul_assign(b: &mut ::test::Bencher) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let v: Vec<(G2, Fr)> = (0..SAMPLES)
            .map(|_| (G2::rand(&mut rng), Fr::rand(&mut rng)))
            .collect();

        let mut count = 0;
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.mul_assign(v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        });
    }

    #[bench]
    fn bench_g2_add_assign(b: &mut ::test::Bencher) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let v: Vec<(G2, G2)> = (0..SAMPLES)
            .map(|_| (G2::rand(&mut rng), G2::rand(&mut rng)))
            .collect();

        let mut count = 0;
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_assign(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        });
    }

    #[bench]
    fn bench_g2_add_assign_mixed(b: &mut ::test::Bencher) {
        const SAMPLES: usize = 1000;

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let v: Vec<(G2, G2Affine)> = (0..SAMPLES)
            .map(|_| (G2::rand(&mut rng), G2::rand(&mut rng).into()))
            .collect();

        let mut count = 0;
        b.iter(|| {
            let mut tmp = v[count].0;
            tmp.add_assign_mixed(&v[count].1);
            count = (count + 1) % SAMPLES;
            tmp
        });
    }
}
