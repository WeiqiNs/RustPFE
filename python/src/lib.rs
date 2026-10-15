#[macro_use]
mod scheme;

mod errors;
mod ipfe;
mod qfe;
mod table;

use pyo3::prelude::*;

#[pymodule(name = "pfe")]
fn root(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<table::Gt>()?;
    m.add_class::<table::DlogTable>()?;
    m.add("DecodeError", m.py().get_type::<errors::DecodeError>())?;
    let ipfe = scheme::add_submodule(m, "pfe.ipfe")?;
    ipfe::register(&ipfe)?;
    let qfe = scheme::add_submodule(m, "pfe.qfe")?;
    qfe::register(&qfe)
}
