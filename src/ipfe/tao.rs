use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use ark_std::{UniformRand, Zero};

use crate::group::{
    DlogTable, G1, G2, G2Prepared, Gt, Matrix, Scalar, ShapeError, VectorOps, concat, g1_mul_vec, g2_mul_vec,
    gt_generator, int_vector, pair, prepare, zeros,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    pub n: usize,
    pub b: Matrix<Scalar<E>>,
    pub bi: Matrix<Scalar<E>>,
    pub base: Gt<E>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    pub vec: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub vec: Vec<G1<E>>,
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> MasterKey<E> {
    let r = Scalar::<E>::rand(rng);
    let (b, inverse, _) = Matrix::random_invertible(2 * n + 5, rng);
    MasterKey {
        n,
        b,
        bi: inverse.scale(r).transpose(),
        base: gt_generator::<E>() * r,
    }
}

pub fn keygen<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    function: &[i64],
    rng: &mut R,
) -> Result<Key<E>, ShapeError> {
    let f = int_vector::<Scalar<E>>(function, msk.n)?;
    let tail = [Scalar::<E>::rand(rng), Scalar::<E>::rand(rng), Scalar::<E>::zero()];
    let encoded = concat(&[&f, &zeros(msk.n + 2), &tail]);
    Ok(Key {
        vec: g2_mul_vec::<E>(&encoded.mul_mat(&msk.b)),
    })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    message: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let m = int_vector::<Scalar<E>>(message, msk.n)?;
    let zero = Scalar::<E>::zero();
    let tail = [Scalar::<E>::rand(rng), Scalar::<E>::rand(rng), zero, zero, zero];
    let encoded = concat(&[&m, &zeros(msk.n), &tail]);
    Ok(Ciphertext {
        vec: g1_mul_vec::<E>(&encoded.mul_mat(&msk.bi)),
    })
}

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, ct: &Ciphertext<E>) -> Option<i64> {
    decrypt_with(table, &sk.vec, ct)
}

pub fn decrypt_many<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, cts: &[Ciphertext<E>]) -> Vec<Option<i64>> {
    let vec = prepare::<E>(&sk.vec);
    cts.iter().map(|ct| decrypt_with(table, &vec, ct)).collect()
}

fn decrypt_with<E: Pairing>(
    table: &DlogTable<E>,
    vec: &[impl Clone + Into<G2Prepared<E>>],
    ct: &Ciphertext<E>,
) -> Option<i64> {
    table.find(pair::<E>(&ct.vec, vec))
}
