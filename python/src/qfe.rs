use pyo3::prelude::*;

qfe_module!(bcfg, "pfe.qfe.bcfg", keygen(rng));
qfe_module!(sgp, "pfe.qfe.sgp", keygen);

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    bcfg::register(parent)?;
    sgp::register(parent)
}
