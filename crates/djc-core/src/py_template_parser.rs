/// Python interface for the djc_template_parser crate.
use pyo3::exceptions::{PySyntaxError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;

use djc_template_parser::{
    CompileError, ParseError, ParserConfig, Tag, TagAttr, TagValue,
    compile_tag_attrs as compile_tag_attrs_rust, compile_value as compile_value_rust,
    parse_tag as parse_tag_rust,
};

/// Convert a ParseError to the appropriate Python exception
fn _parse_error_to_py(e: ParseError) -> PyErr {
    match e {
        ParseError::Syntax(_) => PySyntaxError::new_err(e.to_string()),
        ParseError::Value(_) => PyValueError::new_err(e.to_string()),
    }
}

/// Convert a CompileError to the appropriate Python exception
fn _compile_error_to_py(e: CompileError) -> PyErr {
    match e {
        CompileError::Syntax(_) => PySyntaxError::new_err(e.to_string()),
        CompileError::Generic(_) => PyValueError::new_err(e.to_string()),
    }
}

/// Parse a template tag string into a Tag AST
///
/// **Arguments:**
/// * `input` - The tag string to parse
/// * `config` - Optional parser config containing information about tags (flags, sections, etc.)
///                       If None, a default config is used (no flags, no sections)
#[pyfunction]
#[pyo3(signature = (input, config=None))]
pub fn parse_tag(input: &str, config: Option<ParserConfig>) -> PyResult<Tag> {
    let config_ref = config.as_ref();
    parse_tag_rust(input, config_ref).map_err(_parse_error_to_py)
}

/// Compile a list of parsed tag attributes into a Python code defining a function.
///
/// **Arguments:**
/// * `attributes` - A list of TagAttr objects to compile
#[pyfunction]
#[pyo3(signature = (attributes))]
pub fn compile_tag_attrs(py: Python, attributes: &Bound<PyList>) -> PyResult<String> {
    let attrs: Vec<TagAttr> = attributes.extract()?;
    let result = py.detach(|| compile_tag_attrs_rust(&attrs));
    result.map_err(_compile_error_to_py)
}

/// Compile a parsed tag value into a Python code defining a function.
///
/// **Arguments:**
/// * `value` - The tag value to compile
#[pyfunction]
#[pyo3(signature = (value))]
pub fn compile_value(py: Python, value: &Bound<PyAny>) -> PyResult<String> {
    let value: TagValue = value.extract()?;
    let result = py.detach(|| compile_value_rust(&value));
    result.map_err(_compile_error_to_py)
}
