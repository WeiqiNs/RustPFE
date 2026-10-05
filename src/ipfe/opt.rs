use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

use crate::group::{
    DlogTable, G1, G2, G2Prepared, Gt, Matrix, PairingProduct, Scalar, ShapeError, VectorOps, concat, g1_mul_vec,
    g2_mul_vec, gt_generator, int_vector, prepare, random_vector,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    pub n: usize,
    pub a: Matrix<Scalar<E>>,
    pub b: Matrix<Scalar<E>>,
    pub bi: Matrix<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    pub r: Vec<G2<E>>,
    pub vec: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub r: Vec<G1<E>>,
    pub vec: Vec<G1<E>>,
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> MasterKey<E> {
    let (b, inverse, _) = Matrix::random_invertible(4, rng);
    MasterKey {
        n,
        a: Matrix::random(2, n, rng),
        b,
        bi: inverse.transpose(),
    }
}

pub fn base<E: Pairing>() -> Gt<E> {
    gt_generator::<E>()
}

pub fn keygen<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    function: &[i64],
    rng: &mut R,
) -> Result<Key<E>, ShapeError> {
    let f = int_vector::<Scalar<E>>(function, msk.n)?;
    let s: Vec<Scalar<E>> = random_vector(2, rng);
    let masked = s.mul_mat(&msk.a).plus(&f);
    Ok(Key {
        r: g2_mul_vec::<E>(&msk.b.mul_vec(&concat(&[&s, &msk.a.mul_vec(&masked)]))),
        vec: g2_mul_vec::<E>(&masked),
    })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    message: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let m = int_vector::<Scalar<E>>(message, msk.n)?;
    let s: Vec<Scalar<E>> = random_vector(2, rng);
    Ok(Ciphertext {
        r: g1_mul_vec::<E>(&msk.bi.mul_vec(&concat(&[&msk.a.mul_vec(&m), &s]))),
        vec: g1_mul_vec::<E>(&s.mul_mat(&msk.a).plus(&m)),
    })
}

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, ct: &Ciphertext<E>) -> Option<i64> {
    decrypt_with(table, &sk.r, &sk.vec, ct)
}

pub fn decrypt_many<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, cts: &[Ciphertext<E>]) -> Vec<Option<i64>> {
    let (r, vec) = (prepare::<E>(&sk.r), prepare::<E>(&sk.vec));
    cts.iter().map(|ct| decrypt_with(table, &r, &vec, ct)).collect()
}

fn decrypt_with<E: Pairing, Q: Clone + Into<G2Prepared<E>>>(
    table: &DlogTable<E>,
    r: &[Q],
    vec: &[Q],
    ct: &Ciphertext<E>,
) -> Option<i64> {
    let mut e = PairingProduct::default();
    e.mul(&ct.vec, vec);
    e.div(&ct.r, r);
    table.find(e.value())
}
