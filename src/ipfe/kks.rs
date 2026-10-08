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
    pub eta: Scalar<E>,
    pub eta_bar: Scalar<E>,
    pub s: Vec<Scalar<E>>,
    pub t: Vec<Scalar<E>>,
    pub u: Vec<Scalar<E>>,
    pub v: Vec<Scalar<E>>,
    pub h: Vec<Scalar<E>>,
    pub h_hat: Vec<Scalar<E>>,
    pub h_bar: Vec<Scalar<E>>,
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
    let (eta, eta_bar) = (Scalar::<E>::rand(rng), Scalar::<E>::rand(rng));
    let (s, t): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n, rng), random_vector(n, rng));
    let (u, v): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n + 2, rng), random_vector(n + 2, rng));
    let h = s.plus(&t.scale(eta));
    let h_hat = random_vector::<Scalar<E>, _>(n, rng).plus(&random_vector::<Scalar<E>, _>(n, rng).scale(eta));
    let h_bar = u.plus(&v.scale(eta_bar));
    MasterKey {
        n,
        eta,
        eta_bar,
        s,
        t,
        u,
        v,
        h,
        h_hat,
        h_bar,
    }
}

pub fn base<E: Pairing>() -> Gt<E> {
    gt_generator::<E>()
}

fn ciphertext_half<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    h: &[Scalar<E>],
    m: &[Scalar<E>],
    rng: &mut R,
) -> Vec<Scalar<E>> {
    let r = Scalar::<E>::rand(rng);
    let ct1 = concat(&[&[r, msk.eta * r], &m.plus(&h.scale(r))]);
    concat(&[&[-msk.u.inner(&ct1), -msk.v.inner(&ct1)], &ct1])
}

fn key_half<E: Pairing, R: Rng + ?Sized>(msk: &MasterKey<E>, key: &[Scalar<E>], rng: &mut R) -> Vec<Scalar<E>> {
    let r = Scalar::<E>::rand(rng);
    concat(&[&[r, msk.eta_bar * r], &key.plus(&msk.h_bar.scale(r))])
}

pub fn keygen<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    function: &[i64],
    rng: &mut R,
) -> Result<Key<E>, ShapeError> {
    let f = int_vector::<Scalar<E>>(function, msk.n)?;
    let key = concat(&[&[-msk.s.inner(&f), -msk.t.inner(&f)], &f]);
    let encoded = concat(&[&key_half(msk, &key, rng), &key_half(msk, &zeros(key.len()), rng)]);
    Ok(Key {
        vec: g2_mul_vec::<E>(&encoded),
    })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    message: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let m = int_vector::<Scalar<E>>(message, msk.n)?;
    let encoded = concat(&[
        &ciphertext_half(msk, &msk.h, &m, rng),
        &ciphertext_half(msk, &msk.h_hat, &m, rng),
    ]);
    Ok(Ciphertext {
        vec: g1_mul_vec::<E>(&encoded),
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
