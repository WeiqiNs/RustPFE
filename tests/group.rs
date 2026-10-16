use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_std::{One, UniformRand, Zero};
use pfe::group::{
    DecodeError, Decoder, DlogTable, Encoder, Gt, Matrix, PairingProduct, Scalar, ShapeError, VectorOps, decode,
    g1_mul, g1_mul_vec, g2_mul, g2_mul_vec, gt_generator, int_matrix, masked_g1, pair, random_vector,
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
fn invert_and_products_hold_for_matrices_split_into_tasks() {
    let rng = &mut ark_std::test_rng();
    let m = Matrix::<Fr>::random(40, 40, rng);
    let (inverse, _) = m.invert().unwrap();
    let v: Vec<Fr> = random_vector(40, rng);
    assert_eq!(inverse.mul_vec(&m.mul_vec(&v)), v);
    assert_eq!(v.mul_mat(&m), m.transpose().mul_vec(&v));
}

#[test]
fn invert_rejects_singular_matrices() {
    assert!(matrix(&[[1, 2], [2, 4]]).invert().is_none());
}

fn assert_generator_multiples<E: Pairing>() {
    let z = Scalar::<E>::rand(&mut ark_std::test_rng());
    assert_eq!(g1_mul::<E>(z), (E::G1::generator() * z).into_affine());
    assert_eq!(g2_mul::<E>(z), (E::G2::generator() * z).into_affine());
}

#[test]
fn cached_generator_tables_are_per_curve() {
    assert_generator_multiples::<Bls12_381>();
    assert_generator_multiples::<Bn254>();
    assert_generator_multiples::<Bls12_381>();
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
#[should_panic(expected = "one point per row")]
fn mul_bilinear_rejects_mismatched_lengths() {
    let points = g1_mul_vec::<Bls12_381>(&[Fr::one()]);
    let others = g2_mul_vec::<Bls12_381>(&[Fr::one(), Fr::one()]);
    PairingProduct::<Bls12_381>::default().mul_bilinear(&points, &matrix(&[[1, 0], [0, 1]]), &others);
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
fn pair_rejects_mismatched_lengths() {
    let _ = pair::<Bls12_381>(
        &g1_mul_vec::<Bls12_381>(&[Fr::one()]),
        &g2_mul_vec::<Bls12_381>(&[Fr::one(), Fr::one()]),
    );
}

fn header(n: u32) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

fn off_subgroup_g1() -> G1Affine {
    let p = G1Affine::get_point_from_x_unchecked(Fq::zero(), true).unwrap();
    assert!(p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve());
    p
}

fn off_subgroup_g2() -> G2Affine {
    (1u64..)
        .filter_map(|k| G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(k), Fq::zero()), true))
        .find(|p| p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve())
        .unwrap()
}

#[test]
fn encoding_round_trips_every_element_kind() {
    let rng = &mut ark_std::test_rng();
    let scalar = Fr::from(-1);
    let v: Vec<Fr> = random_vector(3, rng);
    let m = Matrix::<Fr>::random(2, 3, rng);
    let g1 = G1Affine::default();
    let g1s = g1_mul_vec::<Bls12_381>(&random_vector(5, rng));
    let g2 = g2_mul::<Bls12_381>(Fr::from(9));
    let g2s = g2_mul_vec::<Bls12_381>(&random_vector(5, rng));
    let data = Encoder::new(3)
        .one(&scalar)
        .many(&v)
        .matrix(&m)
        .one(&g1)
        .many(&g1s)
        .one(&g2)
        .many(&g2s)
        .bytes();
    assert_eq!(data.len(), 4 + 32 + 3 * 32 + 6 * 32 + 48 + 5 * 48 + 96 + 5 * 96);
    let restored = decode::<Bls12_381, _>(&data, |d, n| {
        Ok((
            n,
            d.scalar()?,
            d.vector(n)?,
            d.matrix(2, n)?,
            d.g1()?,
            d.g1s(5)?,
            d.g2()?,
            d.g2s(5)?,
        ))
    })
    .unwrap();
    assert_eq!(restored, (3, scalar, v, m, g1, g1s, g2, g2s));
}

#[test]
fn decode_accepts_well_formed_input_and_rejects_malformed_input() {
    type Read = fn(&mut Decoder<'_, Bls12_381>, usize) -> Result<(), DecodeError>;
    let scalar: Read = |d, _| d.scalar().map(|_| ());
    let g1: Read = |d, _| d.g1().map(|_| ());
    let square: Read = |d, n| d.matrix(n, n).map(|_| ());
    let two_by_two: Read = |d, _| d.matrix(2, 2).map(|_| ());
    let three_g2: Read = |d, _| d.g2s(3).map(|_| ());
    let valid_g2 = g2_mul::<Bls12_381>(Fr::from(5));
    let cases = [
        ("one scalar", Encoder::new(1).one(&Fr::from(7)).bytes(), scalar, Ok(())),
        ("empty", Vec::new(), scalar, Err(DecodeError::Truncated)),
        (
            "zero dimension",
            header(0),
            scalar,
            Err(DecodeError::Shape(ShapeError { expected: 1, actual: 0 })),
        ),
        (
            "dimension beyond the input",
            [header(1 << 30), vec![0; 64]].concat(),
            square,
            Err(DecodeError::Truncated),
        ),
        (
            "matrix beyond the input",
            Encoder::new(1).one(&Fr::from(7)).bytes(),
            two_by_two,
            Err(DecodeError::Truncated),
        ),
        (
            "scalar at or above the order",
            [header(1), vec![0xff; 32]].concat(),
            scalar,
            Err(DecodeError::InvalidScalar),
        ),
        (
            "point with invalid flags",
            [header(1), vec![0xff; 48]].concat(),
            g1,
            Err(DecodeError::InvalidPoint),
        ),
        (
            "x with no point on the curve",
            {
                let mut x_is_one = Encoder::new(1).one(&G1Affine::from(G1Projective::generator())).bytes();
                for byte in &mut x_is_one[5..] {
                    *byte = 0;
                }
                x_is_one[4] &= 0xe0;
                *x_is_one.last_mut().unwrap() = 1;
                x_is_one
            },
            g1,
            Err(DecodeError::InvalidPoint),
        ),
        (
            "G1 point outside the subgroup",
            Encoder::new(1).one(&off_subgroup_g1()).bytes(),
            g1,
            Err(DecodeError::InvalidPoint),
        ),
        (
            "G2 point outside the subgroup",
            Encoder::new(1).many(&[valid_g2, valid_g2, off_subgroup_g2()]).bytes(),
            three_g2,
            Err(DecodeError::InvalidPoint),
        ),
        (
            "trailing byte",
            [Encoder::new(1).one(&Fr::from(7)).bytes(), vec![0]].concat(),
            scalar,
            Err(DecodeError::TrailingBytes),
        ),
    ];
    for (name, input, read, want) in cases {
        assert_eq!(decode(&input, read), want, "{name}");
    }
}

#[test]
fn decode_errors_describe_themselves() {
    let cases = [
        (
            DecodeError::Shape(ShapeError { expected: 1, actual: 0 }),
            "group: input has 0 entries where 1 are needed",
        ),
        (DecodeError::Truncated, "group: encoding is truncated"),
        (DecodeError::TrailingBytes, "group: encoding has trailing bytes"),
        (DecodeError::InvalidScalar, "group: encoding holds an invalid scalar"),
        (DecodeError::InvalidPoint, "group: encoding holds an invalid point"),
    ];
    for (error, want) in cases {
        assert_eq!(error.to_string(), want);
    }
}
