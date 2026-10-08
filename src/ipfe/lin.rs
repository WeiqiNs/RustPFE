use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    self, DlogTable, G1, G2, G2Prepared, Gt, Scalar, ShapeError, VectorOps, concat, g1_mul_vec, g2_mul_vec,
    gt_generator, int_vector, pair, random_vector, zeros,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    pub n: usize,
    pub s1: Vec<Scalar<E>>,
    pub s2: Vec<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    pub vec: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub vec: Vec<G1<E>>,
}

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    pub vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: Clone + Into<G2Prepared<E>>;
    fn side(&self) -> &[Self::Point];
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> MasterKey<E> {
    MasterKey {
        n,
        s1: random_vector(2 * n, rng),
        s2: random_vector(2 * n + 1, rng),
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
    let padded = concat(&[&int_vector::<Scalar<E>>(function, msk.n)?, &zeros(msk.n)]);
    let key = concat(&[&[padded.inner(&msk.s1)], &padded]);
    let r = Scalar::<E>::rand(rng);
    Ok(Key {
        vec: g2_mul_vec::<E>(&concat(&[&[-r], &msk.s2.scale(r).plus(&key)])),
    })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    message: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let padded = concat(&[&int_vector::<Scalar<E>>(message, msk.n)?, &zeros(msk.n)]);
    let r = Scalar::<E>::rand(rng);
    let ct = concat(&[&[-r], &msk.s1.scale(r).plus(&padded)]);
    Ok(Ciphertext {
        vec: g1_mul_vec::<E>(&concat(&[&[msk.s2.inner(&ct)], &ct])),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        vec: group::prepare::<E>(&sk.vec),
    }
}

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &impl DecryptionKey<E>, ct: &Ciphertext<E>) -> Option<i64> {
    table.find(pair::<E>(&ct.vec, sk.side()))
}

impl<E: Pairing> DecryptionKey<E> for Key<E> {
    type Point = G2<E>;
    fn side(&self) -> &[G2<E>] {
        &self.vec
    }
}

impl<E: Pairing> DecryptionKey<E> for PreparedKey<E> {
    type Point = G2Prepared<E>;
    fn side(&self) -> &[G2Prepared<E>] {
        &self.vec
    }
}
