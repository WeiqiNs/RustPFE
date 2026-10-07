use std::fmt;

use ark_ff::Field;
use ark_std::rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapeError {
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for ShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "input has {} entries where {} are needed",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for ShapeError {}

pub fn zeros<F: Field>(n: usize) -> Vec<F> {
    vec![F::zero(); n]
}

pub fn random_vector<F: Field, R: Rng + ?Sized>(n: usize, rng: &mut R) -> Vec<F> {
    (0..n).map(|_| F::rand(rng)).collect()
}

pub fn int_vector<F: Field + From<i64>>(xs: &[i64], n: usize) -> Result<Vec<F>, ShapeError> {
    if xs.len() != n {
        return Err(ShapeError {
            expected: n,
            actual: xs.len(),
        });
    }
    Ok(xs.iter().map(|&x| F::from(x)).collect())
}

pub fn int_matrix<F: Field + From<i64>, Row: AsRef<[i64]>>(rows: &[Row], n: usize) -> Result<Matrix<F>, ShapeError> {
    if rows.len() != n {
        return Err(ShapeError {
            expected: n,
            actual: rows.len(),
        });
    }
    let mut data = Vec::with_capacity(n * n);
    for row in rows {
        data.extend(int_vector::<F>(row.as_ref(), n)?);
    }
    Ok(Matrix { rows: n, cols: n, data })
}

pub fn concat<F: Field>(parts: &[&[F]]) -> Vec<F> {
    parts.concat()
}

pub trait VectorOps<F> {
    fn plus(&self, other: &[F]) -> Vec<F>;
    fn scale(&self, k: F) -> Vec<F>;
    fn inner(&self, other: &[F]) -> F;
    fn mul_mat(&self, m: &Matrix<F>) -> Vec<F>;
}

impl<F: Field> VectorOps<F> for [F] {
    fn plus(&self, other: &[F]) -> Vec<F> {
        assert_eq!(self.len(), other.len(), "linalg: lengths differ");
        self.iter().zip(other).map(|(a, b)| *a + b).collect()
    }

    fn scale(&self, k: F) -> Vec<F> {
        self.iter().map(|a| *a * k).collect()
    }

    fn inner(&self, other: &[F]) -> F {
        assert_eq!(self.len(), other.len(), "linalg: lengths differ");
        self.iter().zip(other).map(|(a, b)| *a * b).sum()
    }

    fn mul_mat(&self, m: &Matrix<F>) -> Vec<F> {
        assert_eq!(
            self.len(),
            m.rows,
            "linalg: a vector-matrix product needs one entry per row"
        );
        let mut r = zeros(m.cols);
        for (i, vi) in self.iter().enumerate() {
            for (j, rj) in r.iter_mut().enumerate() {
                *rj += *vi * m.at(i, j);
            }
        }
        r
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrix<F> {
    rows: usize,
    cols: usize,
    data: Vec<F>,
}

impl<F: Field> Matrix<F> {
    pub fn random<R: Rng + ?Sized>(rows: usize, cols: usize, rng: &mut R) -> Self {
        Self {
            rows,
            cols,
            data: random_vector(rows * cols, rng),
        }
    }

    pub fn random_invertible<R: Rng + ?Sized>(n: usize, rng: &mut R) -> (Self, Self, F) {
        std::iter::repeat_with(|| Self::random(n, n, rng))
            .find_map(|m| m.invert().map(|(inverse, det)| (m, inverse, det)))
            .expect("an endless supply of random matrices contains an invertible one")
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn at(&self, i: usize, j: usize) -> F {
        self.data[i * self.cols + j]
    }

    pub fn column(&self, j: usize) -> Vec<F> {
        (0..self.rows).map(|i| self.at(i, j)).collect()
    }

    pub fn transpose(&self) -> Self {
        let data = (0..self.cols)
            .flat_map(|j| (0..self.rows).map(move |i| self.at(i, j)))
            .collect();
        Self {
            rows: self.cols,
            cols: self.rows,
            data,
        }
    }

    pub fn scale(&self, k: F) -> Self {
        Self {
            rows: self.rows,
            cols: self.cols,
            data: self.data.scale(k),
        }
    }

    pub fn mul_vec(&self, v: &[F]) -> Vec<F> {
        assert_eq!(
            self.cols,
            v.len(),
            "linalg: a matrix-vector product needs one entry per column"
        );
        self.data.chunks(self.cols).map(|row| row.inner(v)).collect()
    }

    pub fn invert(&self) -> Option<(Self, F)> {
        let n = self.rows;
        let width = 2 * n;
        let mut work = zeros(n * width);
        for (i, (row, source)) in work.chunks_mut(width).zip(self.data.chunks(n)).enumerate() {
            row[..n].copy_from_slice(source);
            row[n + i] = F::one();
        }
        let mut pivot_row = zeros(width);
        let mut det = F::one();
        for col in 0..n {
            let pivot = (col..n).find(|&i| !work[i * width + col].is_zero())?;
            if pivot != col {
                let (above, below) = work.split_at_mut(pivot * width);
                above[col * width..(col + 1) * width].swap_with_slice(&mut below[..width]);
                det = -det;
            }
            det *= work[col * width + col];
            let scale = work[col * width + col].inverse()?;
            for (p, x) in pivot_row[col..]
                .iter_mut()
                .zip(&work[col * width + col..(col + 1) * width])
            {
                *p = *x * scale;
            }
            for (i, row) in work.chunks_mut(width).enumerate() {
                if i == col {
                    row[col..].copy_from_slice(&pivot_row[col..]);
                    continue;
                }
                let factor = row[col];
                for (x, p) in row[col..].iter_mut().zip(&pivot_row[col..]) {
                    *x -= factor * p;
                }
            }
        }
        let data = work.chunks(width).flat_map(|row| row[n..].iter().copied()).collect();
        Some((Self { rows: n, cols: n, data }, det))
    }
}
