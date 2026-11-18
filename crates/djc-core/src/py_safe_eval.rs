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
///     SyntaxError: If the input is not valid Python syntax, contains forbidden constructs,
///         or nests too deeply (more than about 97 chained operators, or more than 20
///         nested calls and brackets in the code it writes, such as 21 nested lists).
///
/// Example:
///     >>> safe_eval("my_var + 1")
///     "_sx_variable(_sx_context, _sx_source, (0, 6), 'my_var') + 1"
///
///     >>> safe_eval("lambda x: x + my_var")
///     "lambda x: x + _sx_variable(_sx_context, _sx_source, (14, 20), 'my_var')"
#[pyfunction]
#[pyo3(signature = (source))]
pub fn safe_eval(source: &str) -> PyResult<String> {
    let result = safe_eval_rust(source).map_err(|e| PySyntaxError::new_err(e.to_string()))?;
    Ok(result)
}
