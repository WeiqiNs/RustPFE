use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    G1, G2, Matrix, Scalar, ShapeError, VectorOps, dlog, g1_mul, g1_mul_vec, g2_mul, g2_mul_vec, int_vector, pair,
    pair_one,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    pub n: usize,
    pub det: Scalar<E>,
    pub b: Matrix<Scalar<E>>,
    pub bi: Matrix<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    pub r: G2<E>,
    pub vec: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub r: G1<E>,
    pub vec: Vec<G1<E>>,
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> MasterKey<E> {
    let (b, inverse, det) = Matrix::random_invertible(n, rng);
    MasterKey {
        n,
        det,
        b,
        bi: inverse.scale(det).transpose(),
    }
}

pub fn keygen<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    function: &[i64],
    rng: &mut R,
) -> Result<Key<E>, ShapeError> {
    let f = int_vector::<Scalar<E>>(function, msk.n)?;
    let alpha = Scalar::<E>::rand(rng);
    Ok(Key {
        r: g2_mul::<E>(alpha * msk.det),
        vec: g2_mul_vec::<E>(&f.scale(alpha).mul_mat(&msk.b)),
    })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    message: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let m = int_vector::<Scalar<E>>(message, msk.n)?;
    let beta = Scalar::<E>::rand(rng);
    Ok(Ciphertext {
        r: g1_mul::<E>(beta),
        vec: g1_mul_vec::<E>(&m.scale(beta).mul_mat(&msk.bi)),
    })
}

pub fn decrypt<E: Pairing>(sk: &Key<E>, ct: &Ciphertext<E>, lo: i64, hi: i64) -> Option<i64> {
    dlog::<E>(pair_one::<E>(ct.r, sk.r), pair::<E>(&ct.vec, &sk.vec), lo, hi)
}
