mod dlog;
mod encoding;
mod linalg;

pub use dlog::{DlogTable, dlog};
pub use encoding::{DecodeError, Decoder, Encoder, Encoding, decode};
pub use linalg::{
    MAX_DIMENSION, Matrix, ShapeError, VectorOps, check_dimension, concat, int_matrix, int_vector, random_vector, zeros,
};

use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::scalar_mul::BatchMulPreprocessing;
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_std::cfg_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub type Scalar<E> = <E as Pairing>::ScalarField;
pub type G1<E> = <E as Pairing>::G1Affine;
pub type G2<E> = <E as Pairing>::G2Affine;
pub type Gt<E> = PairingOutput<E>;
pub type G2Prepared<E> = <E as Pairing>::G2Prepared;

pub trait G2Side<E: Pairing>: Clone + Into<G2Prepared<E>> + Sync {}

impl<E: Pairing, T: Clone + Into<G2Prepared<E>> + Sync> G2Side<E> for T {}

pub trait Dimension {
    fn n(&self) -> usize;
}

fn must_match(a: usize, b: usize) {
    assert_eq!(a, b, "group: lengths {a} and {b} differ");
}

const SCALARS_FOR_WINDOW_8: usize = 1 << 12;

static GENERATOR_TABLES: Mutex<BTreeMap<TypeId, &'static (dyn Any + Send + Sync)>> = Mutex::new(BTreeMap::new());

fn generator_tables() -> MutexGuard<'static, BTreeMap<TypeId, &'static (dyn Any + Send + Sync)>> {
    GENERATOR_TABLES
        .lock()
        .expect("group: no thread panics while holding the generator tables")
}

fn generator_table<G: CurveGroup>() -> &'static BatchMulPreprocessing<G> {
    let key = TypeId::of::<G>();
    let existing = generator_tables().get(&key).copied();
    let table = match existing {
        Some(table) => table,
        None => {
            let built = Box::new(BatchMulPreprocessing::new(G::generator(), SCALARS_FOR_WINDOW_8));
            *generator_tables().entry(key).or_insert_with(|| Box::leak(built))
        }
    };
    table
        .downcast_ref()
        .expect("group: generator tables are keyed by their group's TypeId")
}

pub fn g1_mul<E: Pairing>(z: Scalar<E>) -> G1<E> {
    g1_mul_vec::<E>(&[z])[0]
}

pub fn g2_mul<E: Pairing>(z: Scalar<E>) -> G2<E> {
    g2_mul_vec::<E>(&[z])[0]
}

pub fn g1_mul_vec<E: Pairing>(v: &[Scalar<E>]) -> Vec<G1<E>> {
    generator_table::<E::G1>().batch_mul(v)
}

pub fn g2_mul_vec<E: Pairing>(v: &[Scalar<E>]) -> Vec<G2<E>> {
    generator_table::<E::G2>().batch_mul(v)
}

pub fn scale_g2<E: Pairing>(p: G2<E>, k: Scalar<E>) -> G2<E> {
    (p * k).into_affine()
}

pub fn msm_g1<E: Pairing>(points: &[G1<E>], scalars: &[Scalar<E>]) -> G1<E> {
    must_match(points.len(), scalars.len());
    E::G1::msm_unchecked(points, scalars).into_affine()
}

fn masked<G: CurveGroup>(base: &[G::Affine], r: G::ScalarField, m: &[G::ScalarField]) -> Vec<G::Affine> {
    must_match(base.len(), m.len());
    let encoded = generator_table::<G>().batch_mul(m);
    let sums: Vec<G> = cfg_iter!(base).zip(&encoded).map(|(p, e)| *p * r + e).collect();
    G::normalize_batch(&sums)
}

pub fn masked_g1<E: Pairing>(base: &[G1<E>], r: Scalar<E>, m: &[Scalar<E>]) -> Vec<G1<E>> {
    masked::<E::G1>(base, r, m)
}

pub fn masked_g2<E: Pairing>(base: &[G2<E>], r: Scalar<E>, m: &[Scalar<E>]) -> Vec<G2<E>> {
    masked::<E::G2>(base, r, m)
}

pub fn prepare<E: Pairing>(qs: &[impl G2Side<E>]) -> Vec<G2Prepared<E>> {
    cfg_iter!(qs).map(|q| q.clone().into()).collect()
}

pub fn pair<E: Pairing>(ps: &[G1<E>], qs: &[impl G2Side<E>]) -> Gt<E> {
    must_match(ps.len(), qs.len());
    E::multi_pairing(ps.iter().copied(), prepare::<E>(qs))
}

pub fn pair_one<E: Pairing>(p: G1<E>, q: impl Into<G2Prepared<E>>) -> Gt<E> {
    E::pairing(p, q)
}

pub fn gt_generator<E: Pairing>() -> Gt<E> {
    E::pairing(E::G1::generator(), E::G2::generator())
}

pub struct PairingProduct<E: Pairing> {
    ps: Vec<G1<E>>,
    qs: Vec<G2Prepared<E>>,
}

impl<E: Pairing> Default for PairingProduct<E> {
    fn default() -> Self {
        Self {
            ps: Vec::new(),
            qs: Vec::new(),
        }
    }
}

impl<E: Pairing> PairingProduct<E> {
    pub fn mul(&mut self, ps: &[G1<E>], qs: &[impl G2Side<E>]) {
        must_match(ps.len(), qs.len());
        self.ps.extend_from_slice(ps);
        self.qs.extend(prepare::<E>(qs));
    }

    pub fn div(&mut self, ps: &[G1<E>], qs: &[impl G2Side<E>]) {
        let negated: Vec<G1<E>> = ps.iter().map(|p| -*p).collect();
        self.mul(&negated, qs);
    }

    pub fn mul_bilinear(&mut self, p: &[G1<E>], f: &Matrix<Scalar<E>>, q: &[G2<E>]) {
        self.mul(&combine::<E>(p, f), q);
    }

    pub fn value(self) -> Gt<E> {
        E::multi_pairing(self.ps, self.qs)
    }
}

fn combine<E: Pairing>(p: &[G1<E>], f: &Matrix<Scalar<E>>) -> Vec<G1<E>> {
    (0..f.cols()).map(|j| msm_g1::<E>(p, &f.column(j))).collect()
}
