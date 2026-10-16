use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    self, DecodeError, DlogTable, Encoder, Encoding, G1, G2, G2Prepared, G2Side, Gt, Matrix, PairingProduct, Scalar,
    ShapeError, VectorOps, check_dimension, g1_mul, g1_mul_vec, g2_mul, g2_mul_vec, gt_generator, int_matrix,
    int_vector, masked_g1, masked_g2, random_vector,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    n: usize,
    s: Vec<Scalar<E>>,
    t: Vec<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    n: usize,
    s: Vec<G1<E>>,
    t: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    n: usize,
    f: Matrix<Scalar<E>>,
    secret: G2<E>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    n: usize,
    gamma: G1<E>,
    a0: Vec<G1<E>>,
    a1: Vec<G1<E>>,
    b0: Vec<G2<E>>,
    b1: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    n: usize,
    f: Matrix<Scalar<E>>,
    secret: G2Prepared<E>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: G2Side<E>;
    fn split(&self) -> (&Matrix<Scalar<E>>, &Self::Point);
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Result<(PublicKey<E>, MasterKey<E>), ShapeError> {
    check_dimension(n)?;
    let (s, t): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n, rng), random_vector(n, rng));
    Ok((
        PublicKey {
            n,
            s: g1_mul_vec::<E>(&s),
            t: g2_mul_vec::<E>(&t),
        },
        MasterKey { n, s, t },
    ))
}

pub fn base<E: Pairing>() -> Gt<E> {
    gt_generator::<E>()
}

pub fn keygen<E: Pairing, Row: AsRef<[i64]>>(msk: &MasterKey<E>, function: &[Row]) -> Result<Key<E>, ShapeError> {
    let f = int_matrix::<Scalar<E>, Row>(function, msk.n)?;
    let secret = g2_mul::<E>(msk.s.inner(&f.mul_vec(&msk.t)));
    Ok(Key { n: msk.n, f, secret })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    pk: &PublicKey<E>,
    left: &[i64],
    right: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let x = int_vector::<Scalar<E>>(left, pk.n)?;
    let y = int_vector::<Scalar<E>>(right, pk.n)?;
    let gamma = Scalar::<E>::rand(rng);
    let (w, inverse, _) = Matrix::random_invertible(2, rng);
    let wi = inverse.transpose();
    Ok(Ciphertext {
        n: pk.n,
        gamma: g1_mul::<E>(gamma),
        a0: masked_g1::<E>(&pk.s, gamma * wi.at(0, 1), &x.scale(wi.at(0, 0))),
        a1: masked_g1::<E>(&pk.s, gamma * wi.at(1, 1), &x.scale(wi.at(1, 0))),
        b0: masked_g2::<E>(&pk.t, -w.at(0, 1), &y.scale(w.at(0, 0))),
        b1: masked_g2::<E>(&pk.t, -w.at(1, 1), &y.scale(w.at(1, 0))),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        n: sk.n,
        f: sk.f.clone(),
        secret: sk.secret.into(),
    }
}

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &impl DecryptionKey<E>, ct: &Ciphertext<E>) -> Option<i64> {
    let (f, secret) = sk.split();
    let mut e = PairingProduct::default();
    e.mul(&[ct.gamma], std::slice::from_ref(secret));
    e.mul_bilinear(&ct.a0, f, &ct.b0);
    e.mul_bilinear(&ct.a1, f, &ct.b1);
    table.find(e.value())
}

impl<E: Pairing> DecryptionKey<E> for Key<E> {
    type Point = G2<E>;
    fn split(&self) -> (&Matrix<Scalar<E>>, &G2<E>) {
        (&self.f, &self.secret)
    }
}

impl<E: Pairing> DecryptionKey<E> for PreparedKey<E> {
    type Point = G2Prepared<E>;
    fn split(&self) -> (&Matrix<Scalar<E>>, &G2Prepared<E>) {
        (&self.f, &self.secret)
    }
}

group::dimension!(MasterKey, PublicKey, Key, PreparedKey, Ciphertext);

impl<E: Pairing> Encoding for MasterKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.s).many(&self.t).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                s: dec.vector(n)?,
                t: dec.vector(n)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for PublicKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.s).many(&self.t).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                s: dec.g1s(n)?,
                t: dec.g2s(n)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Key<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).matrix(&self.f).one(&self.secret).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                f: dec.matrix(n, n)?,
                secret: dec.g2()?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Ciphertext<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n)
            .one(&self.gamma)
            .many(&self.a0)
            .many(&self.a1)
            .many(&self.b0)
            .many(&self.b1)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                gamma: dec.g1()?,
                a0: dec.g1s(n)?,
                a1: dec.g1s(n)?,
                b0: dec.g2s(n)?,
                b1: dec.g2s(n)?,
            })
        })
    }
}
