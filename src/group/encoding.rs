use std::fmt;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

use super::{G1, G2, Matrix, Scalar, ShapeError, check_dimension};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Shape(ShapeError),
    Truncated,
    TrailingBytes,
    InvalidScalar,
    InvalidPoint,
}

pub trait Encoding: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(data: &[u8]) -> Result<Self, DecodeError>;
}

pub struct Encoder {
    data: Vec<u8>,
}

pub struct Decoder<'a, E: Pairing> {
    data: &'a [u8],
    _curve: PhantomData<E>,
}

const DIMENSION_BYTES: usize = 4;

trait Element: CanonicalSerialize + CanonicalDeserialize + Default {}

impl<T: CanonicalSerialize + CanonicalDeserialize + Default> Element for T {}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(shape) => write!(f, "group: {shape}"),
            Self::Truncated => f.write_str("group: encoding is truncated"),
            Self::TrailingBytes => f.write_str("group: encoding has trailing bytes"),
            Self::InvalidScalar => f.write_str("group: encoding holds an invalid scalar"),
            Self::InvalidPoint => f.write_str("group: encoding holds an invalid point"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<ShapeError> for DecodeError {
    fn from(shape: ShapeError) -> Self {
        Self::Shape(shape)
    }
}

fn size<T: Element>() -> usize {
    T::default().compressed_size()
}

impl Encoder {
    pub fn new(n: usize) -> Self {
        let n = u32::try_from(n).expect("group: a dimension fits in 32 bits");
        Self {
            data: n.to_be_bytes().to_vec(),
        }
    }

    pub fn one<T: CanonicalSerialize>(mut self, v: &T) -> Self {
        v.serialize_compressed(&mut self.data)
            .expect("group: writing to a Vec cannot fail");
        self
    }

    pub fn many<T: CanonicalSerialize>(self, vs: &[T]) -> Self {
        vs.iter().fold(self, Self::one)
    }

    pub fn matrix<F: CanonicalSerialize>(self, m: &Matrix<F>) -> Self {
        self.many(m.data())
    }

    pub fn bytes(self) -> Vec<u8> {
        self.data
    }
}

pub fn decode<E: Pairing, T>(
    data: &[u8],
    read: impl FnOnce(&mut Decoder<'_, E>, usize) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut dec = Decoder {
        data,
        _curve: PhantomData,
    };
    let header = dec.take(1, DIMENSION_BYTES)?;
    let n = u32::from_be_bytes(header.try_into().expect("group: the header is four bytes")) as usize;
    check_dimension(n)?;
    if n > dec.data.len() / size::<Scalar<E>>() {
        return Err(DecodeError::Truncated);
    }
    let value = read(&mut dec, n)?;
    if !dec.data.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

fn single<T>(mut values: Vec<T>) -> T {
    values.pop().expect("group: a count-one read yields one element")
}

impl<'a, E: Pairing> Decoder<'a, E> {
    fn take(&mut self, count: usize, size: usize) -> Result<&'a [u8], DecodeError> {
        if count > self.data.len() / size {
            return Err(DecodeError::Truncated);
        }
        let (taken, rest) = self.data.split_at(count * size);
        self.data = rest;
        Ok(taken)
    }

    fn elements<T: Element>(&mut self, count: usize, invalid: DecodeError) -> Result<Vec<T>, DecodeError> {
        let values = self
            .take(count, size::<T>())?
            .chunks(size::<T>())
            .map(|chunk| T::deserialize_with_mode(chunk, Compress::Yes, Validate::No))
            .collect::<Result<Vec<T>, _>>()
            .map_err(|_| invalid)?;
        T::batch_check(values.iter()).map_err(|_| invalid)?;
        Ok(values)
    }

    pub fn scalar(&mut self) -> Result<Scalar<E>, DecodeError> {
        self.vector(1).map(single)
    }

    pub fn vector(&mut self, count: usize) -> Result<Vec<Scalar<E>>, DecodeError> {
        self.elements(count, DecodeError::InvalidScalar)
    }

    pub fn matrix(&mut self, rows: usize, cols: usize) -> Result<Matrix<Scalar<E>>, DecodeError> {
        let count = rows.checked_mul(cols).ok_or(DecodeError::Truncated)?;
        let data = self.elements(count, DecodeError::InvalidScalar)?;
        Ok(Matrix::from_data(rows, cols, data))
    }

    pub fn g1(&mut self) -> Result<G1<E>, DecodeError> {
        self.g1s(1).map(single)
    }

    pub fn g1s(&mut self, count: usize) -> Result<Vec<G1<E>>, DecodeError> {
        self.elements(count, DecodeError::InvalidPoint)
    }

    pub fn g2(&mut self) -> Result<G2<E>, DecodeError> {
        self.g2s(1).map(single)
    }

    pub fn g2s(&mut self, count: usize) -> Result<Vec<G2<E>>, DecodeError> {
        self.elements(count, DecodeError::InvalidPoint)
    }
}
