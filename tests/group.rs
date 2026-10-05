use ark_bls12_381::{Bls12_381, Fr};
use ark_std::{One, Zero};
use pfe::group::{
    DlogTable, Gt, Matrix, PairingProduct, ShapeError, VectorOps, g1_mul_vec, g2_mul_vec, gt_generator, int_matrix,
    masked_g1, masked_g2, msm_g1, pair,
};

fn matrix(rows: &[[i64; 2]; 2]) -> Matrix<Fr> {
    int_matrix(rows, 2).unwrap()
}

#[test]
fn invert_swaps_zero_pivots_and_tracks_the_determinant() {
    let m = matrix(&[[0, 2], [3, 0]]);
    let (inverse, det) = m.invert().unwrap();
    assert_eq!(det, Fr::from(-6));
    let v = [Fr::from(5), Fr::from(7)];
    assert_eq!(inverse.mul_vec(&m.mul_vec(&v)), v);
}

#[test]
fn invert_rejects_singular_matrices() {
    assert!(matrix(&[[1, 2], [2, 4]]).invert().is_none());
}

#[test]
fn shape_errors_describe_the_mismatch() {
    assert_eq!(
        ShapeError { expected: 3, actual: 2 }.to_string(),
        "input has 2 entries where 3 are needed"
    );
}

#[test]
fn dlog_table_finds_exactly_its_range() {
    let base = gt_generator::<Bls12_381>();
    let table = DlogTable::new(base, -5, 10);
    for (exponent, found) in [(-5, true), (0, true), (7, true), (10, true), (11, false), (-6, false)] {
        assert_eq!(
            table.find(base * Fr::from(exponent)),
            found.then_some(exponent),
            "base^{exponent}"
        );
    }
}

#[test]
fn dlog_table_over_the_identity_finds_only_the_identity() {
    let table = DlogTable::<Bls12_381>::new(Gt::zero(), 3, 9);
    assert_eq!(table.find(Gt::zero()), Some(3));
    assert_eq!(table.find(gt_generator()), None);
}

#[test]
fn pairing_product_matches_the_pairing_it_expands() {
    let points = g1_mul_vec::<Bls12_381>(&[Fr::from(2), Fr::from(3)]);
    let others = g2_mul_vec::<Bls12_381>(&[Fr::from(5), Fr::from(7)]);
    let mut e = PairingProduct::default();
    e.mul(&points, &others);
    e.div(&points[..1], &others[..1]);
    assert_eq!(e.value(), gt_generator::<Bls12_381>() * Fr::from(21));
}

#[test]
#[should_panic(expected = "lo <= hi")]
fn dlog_table_rejects_an_empty_range() {
    DlogTable::new(gt_generator::<Bls12_381>(), 1, 0);
}

#[test]
#[should_panic(expected = "lengths differ")]
fn plus_rejects_mismatched_lengths() {
    let _ = [Fr::one()].plus(&[Fr::one(), Fr::one()]);
}

#[test]
#[should_panic(expected = "lengths differ")]
fn inner_rejects_mismatched_lengths() {
    let _ = [Fr::one()].inner(&[Fr::one(), Fr::one()]);
}

#[test]
#[should_panic(expected = "one entry per column")]
fn mul_vec_rejects_mismatched_lengths() {
    let _ = matrix(&[[1, 0], [0, 1]]).mul_vec(&[Fr::one()]);
}

#[test]
#[should_panic(expected = "one entry per row")]
fn mul_mat_rejects_mismatched_lengths() {
    let _ = [Fr::one()].mul_mat(&matrix(&[[1, 0], [0, 1]]));
}

#[test]
#[should_panic(expected = "differ")]
fn msm_g1_rejects_mismatched_lengths() {
    let points = g1_mul_vec::<Bls12_381>(&[Fr::one()]);
    let _ = msm_g1::<Bls12_381>(&points, &[Fr::one(), Fr::zero()]);
}

#[test]
#[should_panic(expected = "differ")]
fn masked_g1_rejects_mismatched_lengths() {
    let _ = masked_g1::<Bls12_381>(
        &g1_mul_vec::<Bls12_381>(&[Fr::one()]),
        Fr::one(),
        &[Fr::one(), Fr::one()],
    );
}

#[test]
#[should_panic(expected = "differ")]
fn masked_g2_rejects_mismatched_lengths() {
    let _ = masked_g2::<Bls12_381>(
        &g2_mul_vec::<Bls12_381>(&[Fr::one()]),
        Fr::one(),
        &[Fr::one(), Fr::one()],
    );
}

#[test]
#[should_panic(expected = "differ")]
fn pair_rejects_mismatched_lengths() {
    let _ = pair::<Bls12_381>(
        &g1_mul_vec::<Bls12_381>(&[Fr::one()]),
        &g2_mul_vec::<Bls12_381>(&[Fr::one(), Fr::one()]),
    );
}
