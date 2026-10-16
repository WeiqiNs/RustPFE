use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

use crate::group::{
    self, DecodeError, DlogTable, Encoder, Encoding, G1, G2, G2Prepared, G2Side, Gt, Matrix, PairingProduct, Scalar,
    ShapeError, VectorOps, check_dimension, concat, g1_mul_vec, g2_mul_vec, gt_generator, int_vector, random_vector,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    n: usize,
    a: Matrix<Scalar<E>>,
    b: Matrix<Scalar<E>>,
    bi: Matrix<Scalar<E>>,
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
    n: usize,
    r: Vec<G2Prepared<E>>,
    vec: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: G2Side<E>;
    fn sides(&self) -> (&[Self::Point], &[Self::Point]);
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Result<MasterKey<E>, ShapeError> {
    check_dimension(n)?;
    let (b, inverse, _) = Matrix::random_invertible(4, rng);
    Ok(MasterKey {
        n,
        a: Matrix::random(2, n, rng),
        b,
        bi: inverse.transpose(),
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
    let f = int_vector::<Scalar<E>>(function, msk.n)?;
    let s: Vec<Scalar<E>> = random_vector(2, rng);
    let masked = s.mul_mat(&msk.a).plus(&f);
    Ok(Key {
        n: msk.n,
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
        n: msk.n,
        r: g1_mul_vec::<E>(&msk.bi.mul_vec(&concat(&[&msk.a.mul_vec(&m), &s]))),
        vec: g1_mul_vec::<E>(&s.mul_mat(&msk.a).plus(&m)),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        n: sk.n,
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

group::dimension!(MasterKey, Key, PreparedKey, Ciphertext);

impl<E: Pairing> Encoding for MasterKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n)
            .matrix(&self.a)
            .matrix(&self.b)
            .matrix(&self.bi)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                a: dec.matrix(2, n)?,
                b: dec.matrix(4, 4)?,
                bi: dec.matrix(4, 4)?,
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
                r: dec.g2s(4)?,
                vec: dec.g2s(n)?,
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
                r: dec.g1s(4)?,
                vec: dec.g1s(n)?,
            })
        })
    }
}
