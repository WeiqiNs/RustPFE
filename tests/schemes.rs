mod common;

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use common::{Bcfg, Bjk, InnerProductScheme, Kim, Kks, Lin, Opt, QuadraticScheme, Sgp, Tao};
use pfe::group::ShapeError;

fn decrypts_inner_products_exactly_within_the_range<S: InnerProductScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let msk = S::setup(4, rng);
    let (decrypt, decrypt_many) = (S::decryptor(&msk, -100, 100), S::batch_decryptor(&msk, -100, 100));
    let sk = S::keygen(&msk, &[1, -2, 3, 4], rng).unwrap();
    let cases: [(&[i64], Option<i64>); 7] = [
        (&[5, 6, 7, 8], Some(46)),
        (&[-4, 5, -6, 0], Some(-32)),
        (&[2, 1, 0, 0], Some(0)),
        (&[0, 0, 0, 25], Some(100)),
        (&[0, 0, 0, -25], Some(-100)),
        (&[1, 0, 0, 25], None),
        (&[-1, 0, 0, -25], None),
    ];
    let cts: Vec<_> = cases.iter().map(|(x, _)| S::encrypt(&msk, x, rng).unwrap()).collect();
    for ((x, want), ct) in cases.iter().zip(&cts) {
        assert_eq!(decrypt(&sk, ct), *want, "{}: x = {x:?}", S::NAME);
    }
    let wants: Vec<_> = cases.iter().map(|&(_, want)| want).collect();
    assert_eq!(decrypt_many(&sk, &cts), wants, "{}: decrypt_many", S::NAME);
}

fn decrypts_one_ciphertext_under_many_keys<S: InnerProductScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let msk = S::setup(4, rng);
    let decrypt = S::decryptor(&msk, -100, 100);
    let ct = S::encrypt(&msk, &[5, 6, 7, 8], rng).unwrap();
    let cases: [(&[i64], i64); 3] = [(&[1, -2, 3, 4], 46), (&[0, 0, 0, 1], 8), (&[1, 1, 1, 1], 26)];
    for (y, want) in cases {
        assert_eq!(
            decrypt(&S::keygen(&msk, y, rng).unwrap(), &ct),
            Some(want),
            "{}: y = {y:?}",
            S::NAME
        );
    }
}

fn handles_inner_product_vectors_of_length_one<S: InnerProductScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let msk = S::setup(1, rng);
    let decrypt = S::decryptor(&msk, -100, 100);
    let value = decrypt(
        &S::keygen(&msk, &[-3], rng).unwrap(),
        &S::encrypt(&msk, &[7], rng).unwrap(),
    );
    assert_eq!(value, Some(-21), "{}", S::NAME);
}

fn rejects_inner_product_vectors_of_the_wrong_length<S: InnerProductScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let msk = S::setup(4, rng);
    for v in [&[1, 2, 3][..], &[1, 2, 3, 4, 5]] {
        let wrong = Some(ShapeError {
            expected: 4,
            actual: v.len(),
        });
        assert_eq!(S::keygen(&msk, v, rng).err(), wrong, "{}: keygen({v:?})", S::NAME);
        assert_eq!(S::encrypt(&msk, v, rng).err(), wrong, "{}: encrypt({v:?})", S::NAME);
    }
}

fn quadratic_function() -> Vec<Vec<i64>> {
    vec![vec![1, 0, 2], vec![0, -1, 0], vec![3, 1, 1]]
}

fn decrypts_quadratic_forms_exactly_within_the_range<S: QuadraticScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let (pk, msk) = S::setup(3, rng);
    let (decrypt, decrypt_many) = (S::decryptor(-100, 100), S::batch_decryptor(-100, 100));
    let sk = S::keygen(&msk, &quadratic_function(), rng).unwrap();
    let cases: [(&[i64], &[i64], Option<i64>); 7] = [
        (&[1, -2, 3], &[4, 5, -6], Some(35)),
        (&[-1, 1, 0], &[2, 0, 1], Some(-4)),
        (&[0, 0, 0], &[4, 5, -6], Some(0)),
        (&[1, 0, 0], &[100, 0, 0], Some(100)),
        (&[0, 1, 0], &[0, 100, 0], Some(-100)),
        (&[1, 0, 0], &[101, 0, 0], None),
        (&[0, 1, 0], &[0, 101, 0], None),
    ];
    let cts: Vec<_> = cases
        .iter()
        .map(|(x, y, _)| S::encrypt(&pk, x, y, rng).unwrap())
        .collect();
    for ((x, y, want), ct) in cases.iter().zip(&cts) {
        assert_eq!(decrypt(&sk, ct), *want, "{}: x = {x:?}, y = {y:?}", S::NAME);
    }
    let wants: Vec<_> = cases.iter().map(|&(_, _, want)| want).collect();
    assert_eq!(decrypt_many(&sk, &cts), wants, "{}: decrypt_many", S::NAME);
}

fn decrypts_one_quadratic_ciphertext_under_many_keys<S: QuadraticScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let (pk, msk) = S::setup(3, rng);
    let decrypt = S::decryptor(-100, 100);
    let ct = S::encrypt(&pk, &[1, -2, 3], &[4, 5, -6], rng).unwrap();
    let identity = vec![vec![1, 0, 0], vec![0, 1, 0], vec![0, 0, 1]];
    let corner = vec![vec![0, 0, 0], vec![0, 0, 0], vec![0, 0, 1]];
    for (f, want) in [(quadratic_function(), 35), (identity, -24), (corner, -18)] {
        assert_eq!(
            decrypt(&S::keygen(&msk, &f, rng).unwrap(), &ct),
            Some(want),
            "{}: f = {f:?}",
            S::NAME
        );
    }
}

fn handles_quadratic_vectors_of_length_one<S: QuadraticScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let (pk, msk) = S::setup(1, rng);
    let decrypt = S::decryptor(-100, 100);
    let ct = S::encrypt(&pk, &[7], &[2], rng).unwrap();
    assert_eq!(
        decrypt(&S::keygen(&msk, &[vec![-3]], rng).unwrap(), &ct),
        Some(-42),
        "{}",
        S::NAME
    );
}

fn rejects_quadratic_inputs_of_the_wrong_shape<S: QuadraticScheme<E>, E: Pairing>() {
    let rng = &mut ark_std::test_rng();
    let (pk, msk) = S::setup(3, rng);
    let short_rows = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
    let few_rows = vec![vec![1, 2, 3], vec![4, 5, 6]];
    assert_eq!(
        S::keygen(&msk, &short_rows, rng).err(),
        Some(ShapeError { expected: 3, actual: 2 }),
        "{}",
        S::NAME
    );
    assert_eq!(
        S::keygen(&msk, &few_rows, rng).err(),
        Some(ShapeError { expected: 3, actual: 2 }),
        "{}",
        S::NAME
    );
    let short_x = S::encrypt(&pk, &[1, 2], &[1, 2, 3], rng).err();
    let long_y = S::encrypt(&pk, &[1, 2, 3], &[1, 2, 3, 4], rng).err();
    assert_eq!(short_x, Some(ShapeError { expected: 3, actual: 2 }), "{}", S::NAME);
    assert_eq!(long_y, Some(ShapeError { expected: 3, actual: 4 }), "{}", S::NAME);
}

macro_rules! inner_product_tests {
    ($($module:ident => $scheme:ty, $curve:ty;)*) => {$(
        mod $module {
            use super::*;

            #[test]
            fn decrypts_inner_products_exactly_within_the_range() {
                super::decrypts_inner_products_exactly_within_the_range::<$scheme, $curve>();
            }

            #[test]
            fn decrypts_one_ciphertext_under_many_keys() {
                super::decrypts_one_ciphertext_under_many_keys::<$scheme, $curve>();
            }

            #[test]
            fn handles_vectors_of_length_one() {
                super::handles_inner_product_vectors_of_length_one::<$scheme, $curve>();
            }

            #[test]
            fn rejects_vectors_of_the_wrong_length() {
                super::rejects_inner_product_vectors_of_the_wrong_length::<$scheme, $curve>();
            }
        }
    )*};
}

macro_rules! quadratic_tests {
    ($($module:ident => $scheme:ty, $curve:ty;)*) => {$(
        mod $module {
            use super::*;

            #[test]
            fn decrypts_quadratic_forms_exactly_within_the_range() {
                super::decrypts_quadratic_forms_exactly_within_the_range::<$scheme, $curve>();
            }

            #[test]
            fn decrypts_one_ciphertext_under_many_keys() {
                super::decrypts_one_quadratic_ciphertext_under_many_keys::<$scheme, $curve>();
            }

            #[test]
            fn handles_vectors_of_length_one() {
                super::handles_quadratic_vectors_of_length_one::<$scheme, $curve>();
            }

            #[test]
            fn rejects_inputs_of_the_wrong_shape() {
                super::rejects_quadratic_inputs_of_the_wrong_shape::<$scheme, $curve>();
            }
        }
    )*};
}

inner_product_tests! {
    bjk_bls12_381 => Bjk, Bls12_381;
    bjk_bn254 => Bjk, Bn254;
    tao_bls12_381 => Tao, Bls12_381;
    tao_bn254 => Tao, Bn254;
    kim_bls12_381 => Kim, Bls12_381;
    kim_bn254 => Kim, Bn254;
    lin_bls12_381 => Lin, Bls12_381;
    lin_bn254 => Lin, Bn254;
    kks_bls12_381 => Kks, Bls12_381;
    kks_bn254 => Kks, Bn254;
    opt_bls12_381 => Opt, Bls12_381;
    opt_bn254 => Opt, Bn254;
}

quadratic_tests! {
    bcfg_bls12_381 => Bcfg, Bls12_381;
    bcfg_bn254 => Bcfg, Bn254;
    sgp_bls12_381 => Sgp, Bls12_381;
    sgp_bn254 => Sgp, Bn254;
}
