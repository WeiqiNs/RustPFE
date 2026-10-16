use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use ark_std::{UniformRand, Zero};

use crate::group::{
    self, DecodeError, DlogTable, Encoder, Encoding, G1, G2, G2Prepared, G2Side, Gt, Matrix, Scalar, ShapeError,
    VectorOps, check_dimension, concat, g1_mul_vec, g2_mul_vec, gt_generator, int_vector, pair, zeros,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    n: usize,
    b: Matrix<Scalar<E>>,
    bi: Matrix<Scalar<E>>,
    r: Scalar<E>,
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
    let r = Scalar::<E>::rand(rng);
    let (b, inverse, _) = Matrix::random_invertible(2 * n + 5, rng);
    Ok(MasterKey {
        n,
        b,
        bi: inverse.scale(r).transpose(),
        r,
    })
}

impl<E: Pairing> MasterKey<E> {
    pub fn base(&self) -> Gt<E> {
        gt_generator::<E>() * self.r
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
        n: msk.n,
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
        n: msk.n,
        vec: g1_mul_vec::<E>(&encoded.mul_mat(&msk.bi)),
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
        Encoder::new(self.n)
            .matrix(&self.b)
            .matrix(&self.bi)
            .one(&self.r)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            let width = 2 * n + 5;
            Ok(Self {
                n,
                b: dec.matrix(width, width)?,
                bi: dec.matrix(width, width)?,
                r: dec.scalar()?,
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
                vec: dec.g2s(2 * n + 5)?,
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
                vec: dec.g1s(2 * n + 5)?,
            })
        })
    }
}
