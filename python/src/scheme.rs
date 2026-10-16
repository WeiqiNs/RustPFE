use pyo3::prelude::*;

pub fn add_submodule<'py>(parent: &Bound<'py, PyModule>, qualified: &str) -> PyResult<Bound<'py, PyModule>> {
    let py = parent.py();
    let module = PyModule::new(py, qualified)?;
    parent.add_submodule(&module)?;
    py.import("sys")?.getattr("modules")?.set_item(qualified, &module)?;
    Ok(module)
}

macro_rules! encoded_class {
    ($name:ident, $inner:ty, $path:literal $({ $($extra:tt)* })?) => {
        #[pyclass(frozen, module = $path)]
        pub struct $name(pub $inner);

        #[pymethods]
        impl $name {
            #[new]
            fn new(py: Python<'_>, data: &[u8]) -> PyResult<Self> {
                Self::from_bytes(py, data)
            }

            #[staticmethod]
            fn from_bytes(py: Python<'_>, data: &[u8]) -> PyResult<Self> {
                py.detach(|| <$inner as Encoding>::decode(data))
                    .map(Self)
                    .map_err(errors::decode)
            }

            fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, &self.0.encode())
            }

            fn __reduce__<'py>(slf: &Bound<'py, Self>) -> (Bound<'py, PyType>, (Bound<'py, PyBytes>,)) {
                (slf.get_type(), (slf.get().__bytes__(slf.py()),))
            }

            #[getter]
            fn n(&self) -> usize {
                self.0.n()
            }

            $($($extra)*)?
        }
    };
}

macro_rules! with_key {
    ($sk:expr, |$key:ident| $body:expr) => {
        match &$sk {
            Decryptor::Key(k) => {
                let $key = &k.get().0;
                $body
            }
            Decryptor::Prepared(k) => {
                let $key = &k.get().0;
                $body
            }
        }
    };
}

macro_rules! table_decrypt {
    () => {
        #[pyfunction]
        fn decrypt(
            py: Python<'_>,
            table: &crate::table::DlogTable,
            sk: Decryptor,
            ct: &Ciphertext,
        ) -> PyResult<Option<i64>> {
            errors::check_match(sk.n(), ct.0.n())?;
            Ok(py.detach(|| with_key!(sk, |key| scheme::decrypt(&table.0, key, &ct.0))))
        }
    };
}

macro_rules! module_base {
    () => {
        #[pyfunction]
        fn base() -> crate::table::Gt {
            crate::table::Gt(scheme::base::<Bls12_381>())
        }
    };
}

macro_rules! scheme_module {
    (
        $kind:ident :: $name:ident, $path:literal,
        MasterKey { $($msk_extra:tt)* }, { $($items:tt)* },
        classes [$($class:ident),*], functions [$($function:ident),*]
    ) => {
        pub mod $name {
            use ark_bls12_381::Bls12_381;
            use pfe::group::{Dimension, Encoding};
            use pfe::rand::rngs::OsRng;
            use pfe::$kind::$name as scheme;
            use pyo3::prelude::*;
            use pyo3::types::{PyBytes, PyType};

            use crate::errors;

            encoded_class!(MasterKey, scheme::MasterKey<Bls12_381>, $path { $($msk_extra)* });
            encoded_class!(Key, scheme::Key<Bls12_381>, $path);
            encoded_class!(Ciphertext, scheme::Ciphertext<Bls12_381>, $path);
            $(encoded_class!($class, scheme::$class<Bls12_381>, $path);)*

            #[pyclass(frozen, module = $path)]
            pub struct PreparedKey(pub scheme::PreparedKey<Bls12_381>);

            #[pymethods]
            impl PreparedKey {
                #[getter]
                fn n(&self) -> usize {
                    self.0.n()
                }
            }

            #[derive(FromPyObject)]
            pub enum Decryptor {
                Key(Py<Key>),
                Prepared(Py<PreparedKey>),
            }

            impl Decryptor {
                fn n(&self) -> usize {
                    with_key!(self, |key| key.n())
                }
            }

            #[pyfunction]
            fn prepare(py: Python<'_>, sk: &Key) -> PreparedKey {
                PreparedKey(py.detach(|| scheme::prepare(&sk.0)))
            }

            $($items)*

            pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
                let m = crate::scheme::add_submodule(parent, $path)?;
                m.add_class::<MasterKey>()?;
                m.add_class::<Key>()?;
                m.add_class::<Ciphertext>()?;
                m.add_class::<PreparedKey>()?;
                $(m.add_class::<$class>()?;)*
                m.add_function(wrap_pyfunction!(setup, &m)?)?;
                m.add_function(wrap_pyfunction!(keygen, &m)?)?;
                m.add_function(wrap_pyfunction!(encrypt, &m)?)?;
                m.add_function(wrap_pyfunction!(prepare, &m)?)?;
                m.add_function(wrap_pyfunction!(decrypt, &m)?)?;
                $(m.add_function(wrap_pyfunction!($function, &m)?)?;)*
                Ok(())
            }
        }
    };
}

macro_rules! ipfe_module {
    ($name:ident, $path:literal, range) => {
        ipfe_module!(@module $name, $path, MasterKey {}, {
            #[pyfunction]
            fn decrypt(py: Python<'_>, sk: Decryptor, ct: &Ciphertext, lo: i64, hi: i64) -> PyResult<Option<i64>> {
                crate::table::check_bounds(lo, hi)?;
                errors::check_match(sk.n(), ct.0.n())?;
                Ok(py.detach(|| with_key!(sk, |key| scheme::decrypt(key, &ct.0, lo, hi))))
            }
        }, functions []);
    };
    ($name:ident, $path:literal, table) => {
        ipfe_module!(@module $name, $path, MasterKey {}, {
            module_base!();
            table_decrypt!();
        }, functions [base]);
    };
    ($name:ident, $path:literal, table(msk)) => {
        ipfe_module!(@module $name, $path, MasterKey {
            fn base(&self) -> crate::table::Gt {
                crate::table::Gt(self.0.base())
            }
        }, {
            table_decrypt!();
        }, functions []);
    };
    (
        @module $name:ident, $path:literal,
        MasterKey { $($msk_extra:tt)* }, { $($items:tt)* }, functions [$($function:ident),*]
    ) => {
        scheme_module!(ipfe::$name, $path, MasterKey { $($msk_extra)* }, {
            #[pyfunction]
            fn setup(py: Python<'_>, n: usize) -> PyResult<MasterKey> {
                py.detach(|| scheme::setup::<Bls12_381, _>(n, &mut OsRng))
                    .map(MasterKey)
                    .map_err(errors::shape)
            }

            #[pyfunction]
            fn keygen(py: Python<'_>, msk: &MasterKey, function: Vec<i64>) -> PyResult<Key> {
                py.detach(|| scheme::keygen(&msk.0, &function, &mut OsRng))
                    .map(Key)
                    .map_err(errors::shape)
            }

            #[pyfunction]
            fn encrypt(py: Python<'_>, msk: &MasterKey, message: Vec<i64>) -> PyResult<Ciphertext> {
                py.detach(|| scheme::encrypt(&msk.0, &message, &mut OsRng))
                    .map(Ciphertext)
                    .map_err(errors::shape)
            }

            $($items)*
        }, classes [], functions [$($function),*]);
    };
}

macro_rules! qfe_module {
    ($name:ident, $path:literal, keygen) => {
        qfe_module!(@module $name, $path, []);
    };
    ($name:ident, $path:literal, keygen(rng)) => {
        qfe_module!(@module $name, $path, [&mut OsRng]);
    };
    (@module $name:ident, $path:literal, [$($rng:expr)?]) => {
        scheme_module!(qfe::$name, $path, MasterKey {}, {
            module_base!();
            table_decrypt!();

            #[pyfunction]
            fn setup(py: Python<'_>, n: usize) -> PyResult<(PublicKey, MasterKey)> {
                py.detach(|| scheme::setup::<Bls12_381, _>(n, &mut OsRng))
                    .map(|(pk, msk)| (PublicKey(pk), MasterKey(msk)))
                    .map_err(errors::shape)
            }

            #[pyfunction]
            fn keygen(py: Python<'_>, msk: &MasterKey, function: Vec<Vec<i64>>) -> PyResult<Key> {
                py.detach(|| scheme::keygen(&msk.0, &function $(, $rng)?))
                    .map(Key)
                    .map_err(errors::shape)
            }

            #[pyfunction]
            fn encrypt(py: Python<'_>, pk: &PublicKey, left: Vec<i64>, right: Vec<i64>) -> PyResult<Ciphertext> {
                py.detach(|| scheme::encrypt(&pk.0, &left, &right, &mut OsRng))
                    .map(Ciphertext)
                    .map_err(errors::shape)
            }
        }, classes [PublicKey], functions [base]);
    };
}
