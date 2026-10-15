use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    self, DecodeError, DlogTable, Encoder, Encoding, G1, G2, G2Prepared, G2Side, Gt, Scalar, ShapeError, VectorOps,
    check_dimension, concat, g1_mul_vec, g2_mul_vec, gt_generator, int_vector, pair, random_vector, zeros,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    n: usize,
    eta: Scalar<E>,
    eta_bar: Scalar<E>,
    s: Vec<Scalar<E>>,
    t: Vec<Scalar<E>>,
    u: Vec<Scalar<E>>,
    v: Vec<Scalar<E>>,
    h: Vec<Scalar<E>>,
    h_hat: Vec<Scalar<E>>,
    h_bar: Vec<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    n: usize,
    vec: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    n: usize,
    vec: Vec<G1<E>>,
}

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: G2Side<E>;
    fn side(&self) -> &[Self::Point];
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Result<MasterKey<E>, ShapeError> {
    check_dimension(n)?;
    let (eta, eta_bar) = (Scalar::<E>::rand(rng), Scalar::<E>::rand(rng));
    let (s, t): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n, rng), random_vector(n, rng));
    let (u, v): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n + 2, rng), random_vector(n + 2, rng));
    let h = s.plus(&t.scale(eta));
    let h_hat = random_vector::<Scalar<E>, _>(n, rng).plus(&random_vector::<Scalar<E>, _>(n, rng).scale(eta));
    let h_bar = u.plus(&v.scale(eta_bar));
    Ok(MasterKey {
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
    })
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
        n: msk.n,
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
        n: msk.n,
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

impl<E: Pairing> Encoding for MasterKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n)
            .one(&self.eta)
            .one(&self.eta_bar)
            .many(&self.s)
            .many(&self.t)
            .many(&self.u)
            .many(&self.v)
            .many(&self.h)
            .many(&self.h_hat)
            .many(&self.h_bar)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                eta: dec.scalar()?,
                eta_bar: dec.scalar()?,
                s: dec.vector(n)?,
                t: dec.vector(n)?,
                u: dec.vector(n + 2)?,
                v: dec.vector(n + 2)?,
                h: dec.vector(n)?,
                h_hat: dec.vector(n)?,
                h_bar: dec.vector(n + 2)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Key<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.vec).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                vec: dec.g2s(2 * n + 8)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Ciphertext<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.vec).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                vec: dec.g1s(2 * n + 8)?,
            })
        })
    }
}
