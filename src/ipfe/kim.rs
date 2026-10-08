use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    self, G1, G2, G2Prepared, Matrix, Scalar, ShapeError, VectorOps, dlog, g1_mul, g1_mul_vec, g2_mul, g2_mul_vec,
    int_vector, pair, pair_one,
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

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    pub r: G2Prepared<E>,
    pub vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: Clone + Into<G2Prepared<E>>;
    fn sides(&self) -> (&Self::Point, &[Self::Point]);
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

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        r: sk.r.into(),
        vec: group::prepare::<E>(&sk.vec),
    }
}

pub fn decrypt<E: Pairing>(sk: &impl DecryptionKey<E>, ct: &Ciphertext<E>, lo: i64, hi: i64) -> Option<i64> {
    let (r, vec) = sk.sides();
    dlog::<E>(pair_one::<E>(ct.r, r.clone()), pair::<E>(&ct.vec, vec), lo, hi)
}

impl<E: Pairing> DecryptionKey<E> for Key<E> {
    type Point = G2<E>;
    fn sides(&self) -> (&G2<E>, &[G2<E>]) {
        (&self.r, &self.vec)
    }
}

impl<E: Pairing> DecryptionKey<E> for PreparedKey<E> {
    type Point = G2Prepared<E>;
    fn sides(&self) -> (&G2Prepared<E>, &[G2Prepared<E>]) {
        (&self.r, &self.vec)
    }
}
