use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

use crate::group::{
    self, DlogTable, G1, G2, G2Prepared, Gt, Matrix, PairingProduct, Scalar, ShapeError, VectorOps, concat, g1_mul_vec,
    g2_mul_vec, gt_generator, int_vector, random_vector,
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

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    pub r: Vec<G2Prepared<E>>,
    pub vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: Clone + Into<G2Prepared<E>>;
    fn sides(&self) -> (&[Self::Point], &[Self::Point]);
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

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        r: group::prepare::<E>(&sk.r),
        vec: group::prepare::<E>(&sk.vec),
    }
}

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &impl DecryptionKey<E>, ct: &Ciphertext<E>) -> Option<i64> {
    let (r, vec) = sk.sides();
    let mut e = PairingProduct::default();
    e.mul(&ct.vec, vec);
    e.div(&ct.r, r);
    table.find(e.value())
}

impl<E: Pairing> DecryptionKey<E> for Key<E> {
    type Point = G2<E>;
    fn sides(&self) -> (&[G2<E>], &[G2<E>]) {
        (&self.r, &self.vec)
    }
}

impl<E: Pairing> DecryptionKey<E> for PreparedKey<E> {
    type Point = G2Prepared<E>;
    fn sides(&self) -> (&[G2Prepared<E>], &[G2Prepared<E>]) {
        (&self.r, &self.vec)
    }
}
