//! Parse an expression once it has passed the nesting check.

use ruff_python_ast::ModExpression;
use ruff_python_parser::{ParseError, Parsed};

use crate::nesting::check_nesting;
use crate::stack::with_enough_stack;

/// Parse an expression, rejecting one nested too deeply (see
/// `nesting::MAX_NESTING`) before anything builds or walks its tree.
pub fn parse_expression(source: &str) -> Result<Parsed<ModExpression>, ParseError> {
    // Bound the tree's depth from the tokens first: the passes after this one,
    // and dropping the tree, call themselves once per level.
    check_nesting(source)?;
    with_enough_stack(|| ruff_python_parser::parse_expression(source))
}
