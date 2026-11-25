//! Python wheel (PyO3, abi3 for CPython 3.10+): `import byoai_chain`.
//!   byoai_chain.call(request_json: str) -> str      # the shared JSON API
//!   byoai_chain.canon(dialect: str, text: str) -> str
//!   byoai_chain.__version__
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
fn call(request_json: &str) -> String {
    crate::api::call_json(request_json)
}

#[pyfunction]
fn canon(dialect: &str, text: &str) -> PyResult<String> {
    crate::api::canon_text(dialect, text).map_err(|e| PyValueError::new_err(e.0))
}

#[pymodule]
fn byoai_chain(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(call, m)?)?;
    m.add_function(wrap_pyfunction!(canon, m)?)?;
    m.add("__version__", crate::VERSION)?;
    Ok(())
}
