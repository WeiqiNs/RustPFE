use ark_ec::CurveGroup;
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
    w: Scalar<E>,
    a: Vec<Scalar<E>>,
    b: Vec<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    n: usize,
    a: Vec<G1<E>>,
    b: Vec<G2<E>>,
    w: G2<E>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    n: usize,
    f: Matrix<Scalar<E>>,
    s1: G1<E>,
    s2: G1<E>,
    af: Vec<G1<E>>,
    fb: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    n: usize,
    c: Vec<G1<E>>,
    c_hat: Vec<G1<E>>,
    d: Vec<G2<E>>,
    d_hat: Vec<G2<E>>,
    e: G2<E>,
    e_hat: G2<E>,
}

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    n: usize,
    key: Key<E>,
    fb: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: G2Side<E>;
    fn split(&self) -> (&Key<E>, &[Self::Point]);
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Result<(PublicKey<E>, MasterKey<E>), ShapeError> {
    check_dimension(n)?;
    let w = Scalar::<E>::rand(rng);
    let (a, b): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n, rng), random_vector(n, rng));
    let pk = PublicKey {
        n,
        a: g1_mul_vec::<E>(&a),
        b: g2_mul_vec::<E>(&b),
        w: g2_mul::<E>(w),
    };
    Ok((pk, MasterKey { n, w, a, b }))
}

pub fn base<E: Pairing>() -> Gt<E> {
    gt_generator::<E>()
}

pub fn keygen<E: Pairing, Row: AsRef<[i64]>, R: Rng + ?Sized>(
    msk: &MasterKey<E>,
    function: &[Row],
    rng: &mut R,
) -> Result<Key<E>, ShapeError> {
    let f = int_matrix::<Scalar<E>, Row>(function, msk.n)?;
    let gamma = Scalar::<E>::rand(rng);
    let fb = f.mul_vec(&msk.b);
    Ok(Key {
        n: msk.n,
        s1: g1_mul::<E>(msk.a.inner(&fb) + gamma * msk.w),
        s2: g1_mul::<E>(gamma),
        af: g1_mul_vec::<E>(&msk.a.mul_mat(&f)),
        fb: g2_mul_vec::<E>(&fb),
        f,
    })
}

pub fn encrypt<E: Pairing, R: Rng + ?Sized>(
    pk: &PublicKey<E>,
    left: &[i64],
    right: &[i64],
    rng: &mut R,
) -> Result<Ciphertext<E>, ShapeError> {
    let x = int_vector::<Scalar<E>>(left, pk.n)?;
    let y = int_vector::<Scalar<E>>(right, pk.n)?;
    let [r, s, t, z] = [(); 4].map(|_| Scalar::<E>::rand(rng));
    let blind = r * s - z - t;
    Ok(Ciphertext {
        n: pk.n,
        c: masked_g1::<E>(&pk.a, r, &x),
        c_hat: masked_g1::<E>(&pk.a, t, &x.scale(s)),
        d: masked_g2::<E>(&pk.b, s, &y),
        d_hat: masked_g2::<E>(&pk.b, z, &y.scale(r)),
        e: g2_mul::<E>(blind),
        e_hat: (pk.w * blind).into_affine(),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
        n: sk.n,
        key: sk.clone(),
        fb: group::prepare::<E>(&sk.fb),
    }
}

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &impl DecryptionKey<E>, ct: &Ciphertext<E>) -> Option<i64> {
    let (key, fb) = sk.split();
    let mut e = PairingProduct::default();
    e.mul_bilinear(&ct.c, &key.f, &ct.d);
    e.div(&key.af, &ct.d_hat);
    e.div(&ct.c_hat, fb);
    e.div(&[key.s1], &[ct.e]);
    e.mul(&[key.s2], &[ct.e_hat]);
    table.find(e.value())
}

impl<E: Pairing> DecryptionKey<E> for Key<E> {
    type Point = G2<E>;
    fn split(&self) -> (&Key<E>, &[G2<E>]) {
        (self, &self.fb)
    }
}

impl<E: Pairing> DecryptionKey<E> for PreparedKey<E> {
    type Point = G2Prepared<E>;
    fn split(&self) -> (&Key<E>, &[G2Prepared<E>]) {
        (&self.key, &self.fb)
    }
}

group::dimension!(MasterKey, PublicKey, Key, PreparedKey, Ciphertext);

impl<E: Pairing> Encoding for MasterKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).one(&self.w).many(&self.a).many(&self.b).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                w: dec.scalar()?,
                a: dec.vector(n)?,
                b: dec.vector(n)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for PublicKey<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n).many(&self.a).many(&self.b).one(&self.w).bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                a: dec.g1s(n)?,
                b: dec.g2s(n)?,
                w: dec.g2()?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Key<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n)
            .matrix(&self.f)
            .one(&self.s1)
            .one(&self.s2)
            .many(&self.af)
            .many(&self.fb)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                f: dec.matrix(n, n)?,
                s1: dec.g1()?,
                s2: dec.g1()?,
                af: dec.g1s(n)?,
                fb: dec.g2s(n)?,
            })
        })
    }
}

impl<E: Pairing> Encoding for Ciphertext<E> {
    fn encode(&self) -> Vec<u8> {
        Encoder::new(self.n)
            .many(&self.c)
            .many(&self.c_hat)
            .many(&self.d)
            .many(&self.d_hat)
            .one(&self.e)
            .one(&self.e_hat)
            .bytes()
    }

    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        group::decode::<E, _>(data, |dec, n| {
            Ok(Self {
                n,
                c: dec.g1s(n)?,
                c_hat: dec.g1s(n)?,
                d: dec.g2s(n)?,
                d_hat: dec.g2s(n)?,
                e: dec.g2()?,
                e_hat: dec.g2()?,
            })
        })
    }
}
