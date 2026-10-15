use pfe::group::ShapeError;
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

create_exception!(pfe, DecodeError, PyValueError);

pub fn shape(err: ShapeError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

pub fn decode(err: pfe::group::DecodeError) -> PyErr {
    DecodeError::new_err(err.to_string())
}

pub fn check_match(key: usize, ciphertext: usize) -> PyResult<()> {
    if key == ciphertext {
        return Ok(());
    }
    Err(shape(ShapeError {
        expected: key,
        actual: ciphertext,
    }))
}
