use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use pfe::group::{g1_mul_vec, g2_mul_vec, random_vector};
use rayon::prelude::*;

#[test]
fn first_table_builds_finish_while_the_pool_is_busy_with_another_table() {
    let rng = &mut ark_std::test_rng();
    let scalars: Vec<<Bls12_381 as Pairing>::ScalarField> = random_vector(8, rng);
    let others: Vec<<Bn254 as Pairing>::ScalarField> = random_vector(8, rng);
    let (done, finished) = mpsc::channel();
    thread::spawn({
        let done = done.clone();
        move || {
            let points = g2_mul_vec::<Bls12_381>(&scalars);
            done.send(points.len()).unwrap();
        }
    });
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(1));
        let lengths: usize = (0..64)
            .into_par_iter()
            .map(|_| g1_mul_vec::<Bn254>(&others).len())
            .sum();
        done.send(lengths).unwrap();
    });
    let timeout = Duration::from_secs(60);
    let first = finished
        .recv_timeout(timeout)
        .expect("a table build hung while the pool was busy");
    let second = finished
        .recv_timeout(timeout)
        .expect("a table build hung while the pool was busy");
    assert_eq!(first + second, 8 + 64 * 8);
}
