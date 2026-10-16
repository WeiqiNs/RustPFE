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
    s1: Vec<Scalar<E>>,
    s2: Vec<Scalar<E>>,
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
    n: usize,
    vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: G2Side<E>;
    fn side(&self) -> &[Self::Point];
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Result<MasterKey<E>, ShapeError> {
    check_dimension(n)?;
    Ok(MasterKey {
        n,
        s1: random_vector(2 * n, rng),
        s2: random_vector(2 * n + 1, rng),
    })
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
        n: msk.n,
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
        n: msk.n,
        vec: g1_mul_vec::<E>(&concat(&[&[msk.s2.inner(&ct)], &ct])),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        n: sk.n,
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

group::dimension!(MasterKey, Key, PreparedKey, Ciphertext);

impl<E: Pairing> Encoding for MasterKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.s1).many(&self.s2).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                s1: dec.vector(2 * n)?,
                s2: dec.vector(2 * n + 1)?,
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
                vec: dec.g2s(2 * n + 2)?,
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
                vec: dec.g1s(2 * n + 2)?,
            })
        })
    }
}
