use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    self, DecodeError, Dimension, Encoder, Encoding, G1, G2, G2Prepared, G2Side, Matrix, Scalar, ShapeError, VectorOps,
    check_dimension, dlog, g1_mul, g1_mul_vec, g2_mul, g2_mul_vec, int_vector, pair, pair_one,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    n: usize,
    det: Scalar<E>,
    b: Matrix<Scalar<E>>,
    bi: Matrix<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    n: usize,
    r: G2<E>,
    vec: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    n: usize,
    r: G1<E>,
    vec: Vec<G1<E>>,
}

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    n: usize,
    r: G2Prepared<E>,
    vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: G2Side<E>;
    fn sides(&self) -> (&Self::Point, &[Self::Point]);
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Result<MasterKey<E>, ShapeError> {
    check_dimension(n)?;
    let (b, inverse, det) = Matrix::random_invertible(n, rng);
    Ok(MasterKey {
        n,
        det,
        b,
        bi: inverse.scale(det).transpose(),
    })
}

pub fn keygen<E: Pairing, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    function: &[i64],
    rng: &mut R,
) -> Result<Key<E>, ShapeError> {
    let f = int_vector::<Scalar<E>>(function, msk.n)?;
    let alpha = Scalar::<E>::rand(rng);
    Ok(Key {
        n: msk.n,
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
        n: msk.n,
        r: g1_mul::<E>(beta),
        vec: g1_mul_vec::<E>(&m.scale(beta).mul_mat(&msk.bi)),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        n: sk.n,
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

impl<E: Pairing> Dimension for MasterKey<E> {
    fn n(&self) -> usize {
        self.n
    }
}

impl<E: Pairing> Dimension for Key<E> {
    fn n(&self) -> usize {
        self.n
    }
}

impl<E: Pairing> Dimension for PreparedKey<E> {
    fn n(&self) -> usize {
        self.n
    }
}

impl<E: Pairing> Dimension for Ciphertext<E> {
    fn n(&self) -> usize {
        self.n
    }
}

impl<E: Pairing> Encoding for MasterKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n)
            .one(&self.det)
            .matrix(&self.b)
            .matrix(&self.bi)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                det: dec.scalar()?,
                b: dec.matrix(n, n)?,
                bi: dec.matrix(n, n)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Key<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).one(&self.r).many(&self.vec).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                r: dec.g2()?,
                vec: dec.g2s(n)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Ciphertext<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).one(&self.r).many(&self.vec).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                r: dec.g1()?,
                vec: dec.g1s(n)?,
            })
        })
    }
}
