use ruff_python_ast as ast;
use ruff_python_codegen as codegen;
use ruff_source_file::LineEnding;

/// Generate Python code from a transformed AST expression
pub fn generate_python_code(expr: &ast::Expr) -> String {
    let indentation = codegen::Indentation::default();
    let generator = codegen::Generator::new(&indentation, LineEnding::default());
    generator.expr(expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transformer::transform_expression_string;

    fn _test_transformation(input: &str, expected: &str) {
        let result = transform_expression_string(input);
        assert!(result.is_ok());
        let transform_result = result.unwrap();
        let generated = generate_python_code(&transform_result.expression);
        assert_eq!(generated, expected);
    }

    fn _test_forbidden_syntax(input: &str) {
        let result = transform_expression_string(input);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("Parse error") || error.contains("Unexpected token"));
    }

    #[test]
    fn test_generate_simple_literal() {
        _test_transformation("42", "42");
    }

    #[test]
    fn test_generate_binary_operation() {
        _test_transformation("1 + 2", "1 + 2");
    }

    #[test]
    fn test_generate_unary_operation() {
        _test_transformation("-42", "-42");
    }

    #[test]
    fn test_generate_comparison() {
        _test_transformation("1 == 2", "1 == 2");
    }

    #[test]
    fn test_generate_list() {
        _test_transformation("[1, 2, 3]", "[1, 2, 3]");
    }

    #[test]
    fn test_generate_dict() {
        _test_transformation("{'a': 1, 'b': 2}", "{'a': 1, 'b': 2}");
    }
}
