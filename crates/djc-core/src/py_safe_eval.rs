/// Python interface for the djc_safe_eval crate.
use pyo3::exceptions::PySyntaxError;
use pyo3::prelude::*;

use djc_safe_eval::safe_eval as safe_eval_rust;

/// Transform a Python expression string to make it safe for evaluation.
///
/// This function takes a Python expression string and transforms it into safe code
/// by wrapping potentially unsafe operations (like variable access, function calls,
/// attribute access, etc.) with sandboxed function calls.
///
/// Args:
///     source (str): The Python expression string to transform.
///
/// Returns:
///     str: The transformed Python expression as a string.
///
/// Raises:
///     SyntaxError: If the input is not valid Python syntax or contains forbidden constructs.
///
/// Example:
///     >>> safe_eval("my_var + 1")
///     'variable("my_var") + 1'
///
///     >>> safe_eval("lambda x: x + my_var")
///     'lambda x: x + variable("my_var")'
#[pyfunction]
#[pyo3(signature = (source))]
pub fn safe_eval(source: &str) -> PyResult<String> {
    let result = safe_eval_rust(source).map_err(|e| PySyntaxError::new_err(e.to_string()))?;
    Ok(result)
}
