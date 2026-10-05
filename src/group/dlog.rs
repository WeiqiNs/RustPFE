use std::collections::HashMap;

use ark_ec::pairing::Pairing;
use ark_std::Zero;

use super::{Gt, Scalar};

pub struct DlogTable<E: Pairing> {
    lo: i64,
    span: u64,
    steps: u64,
    shift: Gt<E>,
    giant: Gt<E>,
    baby: HashMap<Gt<E>, u64>,
}

fn baby_step_count(span: u64) -> u64 {
    span.isqrt() + 1
}

impl<E: Pairing> DlogTable<E> {
    pub fn new(base: Gt<E>, lo: i64, hi: i64) -> Self {
        assert!(lo <= hi, "dlog: a table needs lo <= hi");
        let span = hi.abs_diff(lo);
        let steps = baby_step_count(span);
        let mut baby = HashMap::with_capacity(steps as usize);
        let mut power = Gt::<E>::zero();
        for j in 0..steps {
            baby.entry(power).or_insert(j);
            power += base;
        }
        Self {
            lo,
            span,
            steps,
            shift: base * -Scalar::<E>::from(lo),
            giant: base * -Scalar::<E>::from(steps),
            baby,
        }
    }

    pub fn find(&self, target: Gt<E>) -> Option<i64> {
        let mut gamma = target + self.shift;
        for i in 0..=self.span / self.steps {
            if let Some(&j) = self.baby.get(&gamma) {
                let k = i * self.steps + j;
                if k <= self.span {
                    return Some(self.lo.wrapping_add_unsigned(k));
                }
            }
            gamma += self.giant;
        }
        None
    }
}

pub fn dlog<E: Pairing>(base: Gt<E>, target: Gt<E>, lo: i64, hi: i64) -> Option<i64> {
    DlogTable::new(base, lo, hi).find(target)
}
