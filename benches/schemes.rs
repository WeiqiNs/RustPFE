#[path = "../tests/common/mod.rs"]
mod common;

use std::time::Duration;

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use common::{Bcfg, Bjk, InnerProductScheme, Kim, Kks, Lin, Opt, QuadraticScheme, Sgp, Tao};
use criterion::{Criterion, criterion_group, criterion_main};
use pfe::rand::Rng;

const BOUND: i64 = 10_000;
const LENGTHS: [usize; 2] = [10, 100];
const BATCH: usize = 10;

fn entries(n: usize, largest: i64, rng: &mut impl Rng) -> Vec<i64> {
    (0..n).map(|_| rng.gen_range(0..=largest)).collect()
}

fn inner_product_sample(n: usize, rng: &mut impl Rng) -> (Vec<i64>, Vec<i64>, i64) {
    let largest = (BOUND as f64 / n as f64).sqrt() as i64;
    let (x, y) = (entries(n, largest, rng), entries(n, largest, rng));
    let value = x.iter().zip(&y).map(|(a, b)| a * b).sum();
    (x, y, value)
}

fn quadratic_sample(n: usize, rng: &mut impl Rng) -> (Vec<i64>, Vec<i64>, Vec<Vec<i64>>, i64) {
    let largest = (BOUND as f64 / (n * n) as f64).cbrt() as i64;
    let (x, y) = (entries(n, largest, rng), entries(n, largest, rng));
    let f: Vec<Vec<i64>> = (0..n).map(|_| entries(n, largest, rng)).collect();
    let value = (0..n)
        .flat_map(|i| (0..n).map(move |j| (i, j)))
        .map(|(i, j)| x[i] * f[i][j] * y[j])
        .sum();
    (x, y, f, value)
}

fn inner_product<S: InnerProductScheme<E>, E: Pairing>(c: &mut Criterion, curve: &str) {
    for n in LENGTHS {
        let rng = &mut ark_std::test_rng();
        let (x, y, want) = inner_product_sample(n, rng);
        let msk = S::setup(n, rng);
        let sk = S::keygen(&msk, &y, rng).unwrap();
        let cts: Vec<_> = (0..BATCH).map(|_| S::encrypt(&msk, &x, rng).unwrap()).collect();
        let (decrypt, decrypt_many) = (S::decryptor(&msk, 0, BOUND), S::batch_decryptor(&msk, 0, BOUND));
        assert_eq!(decrypt(&sk, &cts[0]), Some(want), "{} decrypted wrongly", S::NAME);
        assert_eq!(
            decrypt_many(&sk, &cts),
            vec![Some(want); BATCH],
            "{} decrypted wrongly",
            S::NAME
        );
        let mut group = c.benchmark_group(format!("{curve}/inner-product/n={n}/{}", S::NAME));
        group.bench_function("Setup", |b| b.iter(|| S::setup(n, rng)));
        group.bench_function("KeyGen", |b| b.iter(|| S::keygen(&msk, &y, rng)));
        group.bench_function("Enc", |b| b.iter(|| S::encrypt(&msk, &x, rng)));
        group.bench_function("Dec", |b| b.iter(|| decrypt(&sk, &cts[0])));
        group.bench_function("DecMany", |b| b.iter(|| decrypt_many(&sk, &cts)));
        group.finish();
    }
}

fn quadratic<S: QuadraticScheme<E>, E: Pairing>(c: &mut Criterion, curve: &str) {
    for n in LENGTHS {
        let rng = &mut ark_std::test_rng();
        let (x, y, f, want) = quadratic_sample(n, rng);
        let (pk, msk) = S::setup(n, rng);
        let sk = S::keygen(&msk, &f, rng).unwrap();
        let cts: Vec<_> = (0..BATCH).map(|_| S::encrypt(&pk, &x, &y, rng).unwrap()).collect();
        let (decrypt, decrypt_many) = (S::decryptor(0, BOUND), S::batch_decryptor(0, BOUND));
        assert_eq!(decrypt(&sk, &cts[0]), Some(want), "{} decrypted wrongly", S::NAME);
        assert_eq!(
            decrypt_many(&sk, &cts),
            vec![Some(want); BATCH],
            "{} decrypted wrongly",
            S::NAME
        );
        let mut group = c.benchmark_group(format!("{curve}/quadratic/n={n}/{}", S::NAME));
        group.bench_function("Setup", |b| b.iter(|| S::setup(n, rng)));
        group.bench_function("KeyGen", |b| b.iter(|| S::keygen(&msk, &f, rng)));
        group.bench_function("Enc", |b| b.iter(|| S::encrypt(&pk, &x, &y, rng)));
        group.bench_function("Dec", |b| b.iter(|| decrypt(&sk, &cts[0])));
        group.bench_function("DecMany", |b| b.iter(|| decrypt_many(&sk, &cts)));
        group.finish();
    }
}

fn every_scheme<E: Pairing>(c: &mut Criterion, curve: &str) {
    inner_product::<Bjk, E>(c, curve);
    inner_product::<Tao, E>(c, curve);
    inner_product::<Kim, E>(c, curve);
    inner_product::<Lin, E>(c, curve);
    inner_product::<Kks, E>(c, curve);
    inner_product::<Opt, E>(c, curve);
    quadratic::<Bcfg, E>(c, curve);
    quadratic::<Sgp, E>(c, curve);
}

fn every_curve(c: &mut Criterion) {
    every_scheme::<Bls12_381>(c, "bls12_381");
    every_scheme::<Bn254>(c, "bn254");
}

criterion_group! {
    name = schemes;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = every_curve
}
criterion_main!(schemes);
