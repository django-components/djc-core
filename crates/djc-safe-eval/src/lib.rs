pub mod codegen;
pub mod comments;
pub mod nesting;
mod parse;
mod stack;
pub mod transformer;
mod utils {
    pub mod literal_source;
    pub mod python_ast;
}

// Re-export public API
pub use codegen::generate_python_code;
pub use parse::parse_expression;
pub use transformer::{
    Comment, Token, TransformResult, parse_expression_with_adjusted_error_ranges,
    transform_expression_string,
};

pub fn safe_eval(source: &str) -> Result<String, String> {
    // The transformed tree is dropped here, which calls itself once per
    // level, so this whole call needs the same stack guarantee as the passes
    // it calls.
    stack::with_enough_stack(|| {
        let result = transform_expression_string(source)?;
        Ok(result.code)
    })
}
