use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use ark_std::rand::Rng;

use crate::group::{
    DlogTable, G1, G2, G2Prepared, Gt, Matrix, PairingProduct, Scalar, ShapeError, VectorOps, g1_mul, g1_mul_vec,
    g2_mul, g2_mul_vec, gt_generator, int_matrix, int_vector, masked_g1, masked_g2, prepare, random_vector, scale_g2,
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

pub fn decrypt<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, ct: &Ciphertext<E>) -> Option<i64> {
    decrypt_with(table, sk, &sk.fb, ct)
}

pub fn decrypt_many<E: Pairing>(table: &DlogTable<E>, sk: &Key<E>, cts: &[Ciphertext<E>]) -> Vec<Option<i64>> {
    let fb = prepare::<E>(&sk.fb);
    cts.iter().map(|ct| decrypt_with(table, sk, &fb, ct)).collect()
}

fn decrypt_with<E: Pairing>(
    table: &DlogTable<E>,
    sk: &Key<E>,
    fb: &[impl Clone + Into<G2Prepared<E>>],
    ct: &Ciphertext<E>,
) -> Option<i64> {
    let mut e = PairingProduct::default();
    e.mul_bilinear(&ct.c, &sk.f, &ct.d);
    e.div(&sk.af, &ct.d_hat);
    e.div(&ct.c_hat, fb);
    e.div(&[sk.s1], &[ct.e]);
    e.mul(&[sk.s2], &[ct.e_hat]);
    table.find(e.value())
}
