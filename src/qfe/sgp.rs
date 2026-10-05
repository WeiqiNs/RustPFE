use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    DlogTable, G1, G2, G2Prepared, Gt, Matrix, PairingProduct, Scalar, ShapeError, VectorOps, g1_mul, g1_mul_vec,
    g2_mul, g2_mul_vec, gt_generator, int_matrix, int_vector, masked_g1, masked_g2, random_vector,
};

#[derive(Clone, Debug)]
pub struct MasterKey<E: Pairing> {
    pub n: usize,
    pub s: Vec<Scalar<E>>,
    pub t: Vec<Scalar<E>>,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub n: usize,
    pub s: Vec<G1<E>>,
    pub t: Vec<G2<E>>,
}

#[derive(Clone, Debug)]
pub struct Key<E: Pairing> {
    pub f: Matrix<Scalar<E>>,
    pub secret: G2<E>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    pub gamma: G1<E>,
    pub a0: Vec<G1<E>>,
    pub a1: Vec<G1<E>>,
    pub b0: Vec<G2<E>>,
    pub b1: Vec<G2<E>>,
}

pub fn setup<E: Pairing, R: Rng + ?Sized>(n: usize, rng: &mut R) -> (PublicKey<E>, MasterKey<E>) {
    let (s, t): (Vec<Scalar<E>>, Vec<Scalar<E>>) = (random_vector(n, rng), random_vector(n, rng));
    (
        PublicKey {
            n,
            s: g1_mul_vec::<E>(&s),
            t: g2_mul_vec::<E>(&t),
        },
        MasterKey { n, s, t },
    )
}

pub fn base<E: Pairing>() -> Gt<E> {
    gt_generator::<E>()
}

pub fn keygen<E: Pairing, Row: AsRef<[i64]>>(msk: &MasterKey<E>, function: &[Row]) -> Result<Key<E>, ShapeError> {
    let f = int_matrix::<Scalar<E>, Row>(function, msk.n)?;
    let secret = g2_mul::<E>(msk.s.inner(&f.mul_vec(&msk.t)));
    Ok(Key { f, secret })
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
        gamma: g1_mul::<E>(gamma),
        a0: masked_g1::<E>(&pk.s, gamma * wi.at(0, 1), &x.scale(wi.at(0, 0))),
        a1: masked_g1::<E>(&pk.s, gamma * wi.at(1, 1), &x.scale(wi.at(1, 0))),
        b0: masked_g2::<E>(&pk.t, -w.at(0, 1), &y.scale(w.at(0, 0))),
        b1: masked_g2::<E>(&pk.t, -w.at(1, 1), &y.scale(w.at(1, 0))),
    })
}

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, ct: &Ciphertext<E>) -> Option<i64> {
    decrypt_with(table, sk, &sk.secret, ct)
}

pub fn decrypt_many<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, cts: &[Ciphertext<E>]) -> Vec<Option<i64>> {
    let secret: G2Prepared<E> = sk.secret.into();
    cts.iter().map(|ct| decrypt_with(table, sk, &secret, ct)).collect()
}

fn decrypt_with<E: Pairing, Q: Clone + Into<G2Prepared<E>>>(
    table: &DlogTable<E>,
    sk: &Key<E>,
    secret: &Q,
    ct: &Ciphertext<E>,
) -> Option<i64> {
    let mut e = PairingProduct::default();
    e.mul(&[ct.gamma], std::slice::from_ref(secret));
    e.mul_bilinear(&ct.a0, &sk.f, &ct.b0);
    e.mul_bilinear(&ct.a1, &sk.f, &ct.b1);
    table.find(e.value())
}
