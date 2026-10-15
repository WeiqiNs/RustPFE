use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use ark_std::{UniformRand, Zero};

use crate::group::{
    self, DecodeError, Encoder, Encoding, G1, G2, G2Prepared, G2Side, Matrix, Scalar, ShapeError, VectorOps,
    check_dimension, concat, dlog, g1_mul_vec, g2_mul_vec, int_vector, pair,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    n: usize,
    b: Matrix<Scalar<E>>,
    bi: Matrix<Scalar<E>>,
    d: Matrix<Scalar<E>>,
    di: Matrix<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    n: usize,
    r: Vec<G2<E>>,
    vec: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    n: usize,
    r: Vec<G1<E>>,
    vec: Vec<G1<E>>,
}

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    r: Vec<G2Prepared<E>>,
    vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: G2Side<E>;
    fn sides(&self) -> (&[Self::Point], &[Self::Point]);
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Result<MasterKey<E>, ShapeError> {
    check_dimension(n)?;
    let (b, b_inverse, _) = Matrix::random_invertible(2 * n + 4, rng);
    let (d, d_inverse, _) = Matrix::random_invertible(2, rng);
    Ok(MasterKey {
        n,
        b,
        bi: b_inverse.transpose(),
        d,
        di: d_inverse.transpose(),
    })
}

pub fn keygen<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    function: &[i64],
    rng: &mut R,
) -> Result<Key<E>, ShapeError> {
    let f = int_vector::<Scalar<E>>(function, msk.n)?;
    let (beta, beta_t) = (Scalar::<E>::rand(rng), Scalar::<E>::rand(rng));
    let zero = Scalar::<E>::zero();
    let encoded = concat(&[&f.scale(beta), &f.scale(beta_t), &[zero, beta, zero, beta_t]]);
    Ok(Key {
        n: msk.n,
        r: g2_mul_vec::<E>(&[beta, beta_t].mul_mat(&msk.d)),
        vec: g2_mul_vec::<E>(&encoded.mul_mat(&msk.b)),
    })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    message: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let m = int_vector::<Scalar<E>>(message, msk.n)?;
    let (alpha, alpha_t) = (Scalar::<E>::rand(rng), Scalar::<E>::rand(rng));
    let zero = Scalar::<E>::zero();
    let encoded = concat(&[&m.scale(alpha), &m.scale(alpha_t), &[alpha, zero, alpha_t, zero]]);
    Ok(Ciphertext {
        n: msk.n,
        r: g1_mul_vec::<E>(&[alpha, alpha_t].mul_mat(&msk.di)),
        vec: g1_mul_vec::<E>(&encoded.mul_mat(&msk.bi)),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        r: group::prepare::<E>(&sk.r),
        vec: group::prepare::<E>(&sk.vec),
    }
}

pub fn decrypt<E: Pairing>(sk: &impl DecryptionKey<E>, ct: &Ciphertext<E>, lo: i64, hi: i64) -> Option<i64> {
    let (r, vec) = sk.sides();
    dlog::<E>(pair::<E>(&ct.r, r), pair::<E>(&ct.vec, vec), lo, hi)
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

impl<E: Pairing> Encoding for MasterKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n)
            .matrix(&self.b)
            .matrix(&self.bi)
            .matrix(&self.d)
            .matrix(&self.di)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            let width = 2 * n + 4;
            Ok(Self {
                n,
                b: dec.matrix(width, width)?,
                bi: dec.matrix(width, width)?,
                d: dec.matrix(2, 2)?,
                di: dec.matrix(2, 2)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Key<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.r).many(&self.vec).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                r: dec.g2s(2)?,
                vec: dec.g2s(2 * n + 4)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Ciphertext<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.r).many(&self.vec).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                r: dec.g1s(2)?,
                vec: dec.g1s(2 * n + 4)?,
            })
        })
    }
}
