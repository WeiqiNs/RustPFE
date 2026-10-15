use pyo3::prelude::*;

ipfe_module!(bjk, "pfe.ipfe.bjk", range);
ipfe_module!(tao, "pfe.ipfe.tao", table(msk));
ipfe_module!(kim, "pfe.ipfe.kim", range);
ipfe_module!(lin, "pfe.ipfe.lin", table);
ipfe_module!(kks, "pfe.ipfe.kks", table);
ipfe_module!(opt, "pfe.ipfe.opt", table);

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    bjk::register(parent)?;
    tao::register(parent)?;
    kim::register(parent)?;
    lin::register(parent)?;
    kks::register(parent)?;
    opt::register(parent)
}
