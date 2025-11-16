pub mod codegen;
pub mod comments;
pub mod transformer;
mod utils {
    pub mod python_ast;
}

// Re-export public API
pub use codegen::generate_python_code;
pub use transformer::{Comment, Token, TransformResult, transform_expression_string};

pub fn safe_eval(source: &str) -> Result<String, String> {
    let result = transform_expression_string(source)?;
    let generated_code = codegen::generate_python_code(&result.expression);
    Ok(generated_code)
}
