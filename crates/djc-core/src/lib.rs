pub mod py_html_transformer;
pub mod py_safe_eval;
pub mod py_template_parser;

#[cfg(not(any(PyPy, GraalPy)))]
use std::sync::atomic::{AtomicI64, Ordering};

#[cfg(not(any(PyPy, GraalPy)))]
use pyo3::exceptions::PyImportError;
use pyo3::prelude::*;

use djc_template_parser::{
    Comment, EndTag, ForLoopTag, GenericTag, ParserConfig, Tag, TagAttr, TagConfig, TagMeta,
    TagSectionSpec, TagSpec, TagValue, TagValueFilter, TagWithBodySpec, TemplateVersion, Token,
    ValueChild, ValueKind,
};

use crate::py_html_transformer::set_html_attributes;
use crate::py_safe_eval::safe_eval;
use crate::py_template_parser::{compile_tag_attrs, compile_value, parse_tag};

/// The interpreter that imported this module first, or -1 before any import.
#[cfg(not(any(PyPy, GraalPy)))]
static FIRST_INTERPRETER: AtomicI64 = AtomicI64::new(-1);

/// Refuses the import in any interpreter other than the first one that made it.
///
/// `#[pyclass]` types and their statics are created once per process, so a second
/// interpreter in the process would share Python objects with the first, and
/// nothing has checked that this is safe. PyO3 runs this check only for modules
/// built with single-phase init. Multi-phase init, which it now uses, skips it, so
/// a host that starts several interpreters, such as mod_wsgi with more than one
/// application group, must get this error rather than undefined behaviour.
#[cfg(not(any(PyPy, GraalPy)))]
fn check_interpreter(py: Python<'_>) -> PyResult<()> {
    // SAFETY: the GIL is held while a module is imported, and that is all
    // these two calls need.
    let current =
        unsafe { pyo3::ffi::PyInterpreterState_GetID(pyo3::ffi::PyInterpreterState_Get()) };
    if current < 0 {
        return Err(PyErr::fetch(py));
    }
    // An import repeated in the same interpreter, such as after a `sys.modules`
    // reset, must keep working, so only a different id is refused.
    match FIRST_INTERPRETER.compare_exchange(-1, current, Ordering::SeqCst, Ordering::SeqCst) {
        Err(first) if first != current => Err(PyImportError::new_err(
            "djc_core can only be imported in one interpreter per process",
        )),
        _ => Ok(()),
    }
}

/// Singular Python API that brings togther all the other Rust crates.
/// Each crate is exposed as a submodule.
// Importing this module turns the GIL on in free-threaded Python, and Python
// prints a `RuntimeWarning`. `PYTHON_GIL=0` or `-X gil=0` keeps it off. We ask
// for the GIL because a `ParserConfig` shared between threads raises
// "Already borrowed" without it when `set_tag()` runs while `parse_tag()`
// copies the config, and the Ruff crates have not been checked without it.
// Stating this here also stops a PyO3 upgrade from changing the default
// silently.
#[pymodule(gil_used = true)]
fn djc_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // PyPy has no subinterpreters, and does not provide the calls this needs.
    #[cfg(not(any(PyPy, GraalPy)))]
    check_interpreter(m.py())?;

    // HTML transformer
    let html_transformer = PyModule::new(m.py(), "html_transformer")?;
    m.add_submodule(&html_transformer)?;
    html_transformer.add_function(wrap_pyfunction!(set_html_attributes, &html_transformer)?)?;

    // Safe eval
    let safe_eval_module = PyModule::new(m.py(), "safe_eval")?;
    m.add_submodule(&safe_eval_module)?;
    safe_eval_module.add_function(wrap_pyfunction!(safe_eval, &safe_eval_module)?)?;

    // Template parser
    let template_parser = PyModule::new(m.py(), "template_parser")?;
    m.add_submodule(&template_parser)?;
    // Template parser - functions
    template_parser.add_function(wrap_pyfunction!(compile_tag_attrs, &template_parser)?)?;
    template_parser.add_function(wrap_pyfunction!(compile_value, &template_parser)?)?;
    template_parser.add_function(wrap_pyfunction!(parse_tag, &template_parser)?)?;
    // Template parser - AST API
    template_parser.add_class::<Comment>()?;
    template_parser.add_class::<EndTag>()?;
    template_parser.add_class::<ForLoopTag>()?;
    template_parser.add_class::<GenericTag>()?;
    template_parser.add_class::<Tag>()?;
    template_parser.add_class::<TagAttr>()?;
    template_parser.add_class::<TagMeta>()?;
    template_parser.add_class::<TagValue>()?;
    template_parser.add_class::<TagValueFilter>()?;
    template_parser.add_class::<TemplateVersion>()?;
    template_parser.add_class::<Token>()?;
    template_parser.add_class::<ValueChild>()?;
    template_parser.add_class::<ValueKind>()?;
    // Template parser - Config API
    template_parser.add_class::<ParserConfig>()?;
    template_parser.add_class::<TagConfig>()?;
    template_parser.add_class::<TagSectionSpec>()?;
    template_parser.add_class::<TagSpec>()?;
    template_parser.add_class::<TagWithBodySpec>()?;

    Ok(())
}
