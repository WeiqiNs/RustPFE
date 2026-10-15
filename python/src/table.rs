use ark_bls12_381::Bls12_381;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(frozen, module = "pfe")]
pub struct Gt(pub pfe::group::Gt<Bls12_381>);

#[pyclass(frozen, module = "pfe")]
pub struct DlogTable(pub pfe::group::DlogTable<Bls12_381>);

#[pymethods]
impl DlogTable {
    #[new]
    fn new(py: Python<'_>, base: &Gt, lo: i64, hi: i64) -> PyResult<Self> {
        check_bounds(lo, hi)?;
        let base = base.0;
        Ok(Self(py.detach(|| pfe::group::DlogTable::new(base, lo, hi))))
    }
}

pub const MAX_SPAN: u64 = 1 << 40;

pub fn check_bounds(lo: i64, hi: i64) -> PyResult<()> {
    if lo > hi {
        return Err(PyValueError::new_err("dlog: a table needs lo <= hi"));
    }
    if hi.abs_diff(lo) > MAX_SPAN {
        return Err(PyValueError::new_err(format!(
            "dlog: a range may span at most {MAX_SPAN}"
        )));
    }
    Ok(())
}
