use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    self, DlogTable, G1, G2, G2Prepared, Gt, Matrix, PairingProduct, Scalar, ShapeError, VectorOps, g1_mul, g1_mul_vec,
    g2_mul, g2_mul_vec, gt_generator, int_matrix, int_vector, masked_g1, masked_g2, random_vector, scale_g2,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    pub n: usize,
    pub w: Scalar<E>,
    pub a: Vec<Scalar<E>>,
    pub b: Vec<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub n: usize,
    pub a: Vec<G1<E>>,
    pub b: Vec<G2<E>>,
    pub w: G2<E>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    pub f: Matrix<Scalar<E>>,
    pub s1: G1<E>,
    pub s2: G1<E>,
    pub af: Vec<G1<E>>,
    pub fb: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub c: Vec<G1<E>>,
    pub c_hat: Vec<G1<E>>,
    pub d: Vec<G2<E>>,
    pub d_hat: Vec<G2<E>>,
    pub e: G2<E>,
    pub e_hat: G2<E>,
}

#[derive(Clone, Debug)]
pub struct PreparedKey<E: Pairing> {
    pub key: Key<E>,
    pub fb: Vec<G2Prepared<E>>,
}

pub trait DecryptionKey<E: Pairing> {
    type Point: Clone + Into<G2Prepared<E>>;
    fn split(&self) -> (&Key<E>, &[Self::Point]);
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> (PublicKey<E>, MasterKey<E>) {
    let w = Scalar::<E>::rand(rng);
    let (a, b): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n, rng), random_vector(n, rng));
    let pk = PublicKey {
        n,
        a: g1_mul_vec::<E>(&a),
        b: g2_mul_vec::<E>(&b),
        w: g2_mul::<E>(w),
    };
    (pk, MasterKey { n, w, a, b })
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
        c: masked_g1::<E>(&pk.a, r, &x),
        c_hat: masked_g1::<E>(&pk.a, t, &x.scale(s)),
        d: masked_g2::<E>(&pk.b, s, &y),
        d_hat: masked_g2::<E>(&pk.b, z, &y.scale(r)),
        e: g2_mul::<E>(blind),
        e_hat: scale_g2::<E>(pk.w, blind),
    })
}

pub fn prepare<E: Pairing>(sk: &Key<E>) -> PreparedKey<E> {
    PreparedKey {
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
