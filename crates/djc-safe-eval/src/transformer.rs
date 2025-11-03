//! # Safe Python eval transformer
//!
//! This module provides a logic that takes Python code, and transforms potentially
//! unsafe Python expressions (e.g. function calls) into safe code that can be evaluated.
//!
//! ## Overview
//!
//! The transformer:
//!
//! 1. Parses Python expressions using `ruff_python_parser`
//! 2. Validates them against a whitelist of allowed AST nodes
//! 3. Transforms specific nodes to enable sandboxing
//! 4. Unparses them back to Python code using `ruff_python_codegen`
//!
//! ## Transformations
//!
//! The following transformations are applied to make expressions safe for evaluation:
//!
//! 1. **Variable access** - `my_var` → `variable(context, source, token, "my_var")` where `token` is `(start_index, end_index)`
//! 2. **Function calls** - `foo(1, 2, a=3, *args, **kwargs)` → `call(context, source, token, foo, 1, 2, a=x, *args, **kwargs)`
//! 3. **Attribute access** - `obj.attr` → `attribute(context, source, token, obj, "attr")`
//! 4. **Subscript access** - `obj[key]` → `subscript(context, source, token, obj, key)`
//! 5. **Walrus operator** - `(x := value)` → `assign(context, source, token, "x", value)` where `token` contains the entire expression range
//!
//! Because of the changes above, we also need to transform:
//!
//! 6. **Slice notation** - `obj[1:10:2]` → `subscript(context, source, token, obj, slice(context, source, token, 1, 10, 2))` - Because slice syntax is valid only inside square brackets.
//! 7. **F-strings** - `f"Hello {price!r:.2f}"` → `format(context, source, token, "Hello {}", (variable(context, source, token, "price"), "r", ".2f"))` - To avoid issues with quote escaping and enable error reporting
//! 8. **T-strings** - `t"Hello {name!r:>10}"` → `template(context, source, token, "Hello ", interpolation(context, source, token, variable(context, source, token, "name"), "expr", "r", ">10"))` - To avoid issues with quote escaping
//!
//! ## Variable Scoping
//!
//! Variables are tracked to handle different scoping rules:
//!
//! ### Comprehensions
//! Variables introduced in comprehensions are local to the comprehension and NOT transformed:
//! - `[x for x in items]` → `[x for x in variable(context, source, token, "items")]`
//! - The variable `x` is NOT transformed because it's local to the comprehension
//!
//! However, walrus operator assignments in comprehensions DO leak out (matching Python behavior):
//! - `[y for x in items if (y := x + 1)]` - the variable `y` is accessible after the comprehension
//!
//! ### Lambda Functions
//! Lambda parameters are local to the lambda and NOT transformed:
//! - `lambda x: x + 1` - the parameter `x` is NOT transformed
//!
//! Unlike comprehensions, walrus assignments in lambdas do NOT leak out (matching Python behavior):
//! - `(lambda: (x := 3))()` - the variable `x` is NOT accessible after the lambda executes
//!
//! ## Allowed Python features
//!
//! - **Literals**: strings, numbers, bytes, booleans, None, Ellipsis
//! - **String formatting**: f-strings `f"Hello {name}"`, t-strings, `%` formatting
//! - **Data structures**: lists, tuples, sets, dicts
//! - **Operators**: unary (`+`, `-`, `not`, `~`), binary (`+`, `-`, `*`, `/`, `%`, `**`, `//`), comparison, boolean
//! - **Comprehensions**: list, set, dict, generator (but NOT async comprehensions)
//! - **Conditionals**: ternary operator (`x if y else z`)
//! - **Variables**: identifiers
//! - **Function calls**: all calls
//! - **Spread operators**: `*args`, `**kwargs`
//! - **Attribute access**: `obj.attr`
//! - **Subscript access**: `obj[key]`, including slices `obj[start:end:step]`
//! - **Lambda expressions**: `lambda x: x + 1``
//!
//! ## Disallowed Python Features
//!
//! The following are explicitly forbidden for security:
//! - **Statements**: assignments, del, import, class/function definitions, etc.
//! - **Async/await**: async comprehensions, await expressions
//! - **Generators**: yield, yield from
//!
//! ## Variable Tracking
//!
//! The transformer tracks two types of variables with their positions:
//!
//! ### Used Variables
//! Variables that are accessed from the outside context (not local to comprehensions/lambdas).
//! These are variables that need to be provided in the evaluation context.
//! Example: In `lambda c: a + 1 + d`, the variables `a` and `d` are used from context (not `c`, which is a lambda parameter).
//!
//! ### Assigned Variables
//! Variables assigned via the walrus operator (`:=`) that become available outside their scope.
//! These are only tracked if they propagate up (e.g., from comprehensions, but not from lambdas).
//! Example: In `[y for x in items if (y := x + 1)]`, the variable `y` is assigned and available after the comprehension.
//!
//! Both types are returned as `Token` instances with position information (byte offsets and line/column numbers).
//!
//! ## Error Handling
//!
//! The transformer returns `Result<TransformResult, String>` where errors include:
//! - Parse errors from invalid Python syntax
//! - Validation errors when forbidden AST nodes are encountered
//!

// Python AST types
// As based on Python docs 3.14 (15/10/2025)
// https://docs.python.org/3/library/ast.html#root-nodes
//
// Associated with them are the corresponding Rust types in ruff_python_ast::*
//
// -------------------
// LEGEND:
// - ✅ ALLOWED
// - ❌ DISALLOWED
// - ⚠️ CAREFUL / NEEDS INTERCEPTION
// - 🔵 IMPLEMENTED
// -------------------
//
// Root nodes:
// - ❌ Module         - ModModule
// - ✅ Expression     - ModExpression
// - ❌ Interactive    - X (No Rust type?)
// - ❌ FunctionType   - X (No Rust type?)
//
// Literals:
// - 🔵✅ Constant (str)   - ExprStringLiteral
// - 🔵✅ Constant (bytes) - ExprBytesLiteral
// - 🔵✅ Constant (int)   - ExprNumberLiteral  (int, float, complex?)
// - 🔵✅ Constant (bool)  - ExprBooleanLiteral
// - 🔵✅ Constant (None)  - ExprNoneLiteral
// - 🔵✅ Constant (...)   - ExprEllipsisLiteral
// - 🔵✅ JoinedStr        - FString (f"{a} {b}")
// - 🔵✅                  - ExprFString
// - 🔵✅ TemplateStr      - TString (t"{a} {b}")
// - 🔵✅                  - ExprTString
// - 🔵✅ Interpolation    - InterpolatedElement
// - 🔵✅                  - InterpolatedStringLiteralElement
// - 🔵✅                  - InterpolatedStringFormatSpec
// - 🔵✅ List             - ExprList
// - 🔵✅ Tuple            - ExprTuple
// - 🔵✅ Set              - ExprSet
// - 🔵✅ Dict             - ExprDict
//
// Variables:
// - 🔵⚠️ Name           - ExprName           (variable name) - Wrap in `variable(context, source, token, "name")`
// - 🔵✅ Load           - ExprContext::Load  (x)
// - 🔵❌ Store          - ExprContext::Store (x = 1)
// - 🔵❌ Del            - ExprContext::Del   (del x)
// - 🔵✅ Starred        - ExprStarred        (star spread, e.g. `fn(*args, **kwargs)`)
//
// Expressions:
// - 🔵✅ UnaryOp        - ExprUnaryOp (not, invert, + (pos sign), - (neg sign))
// - 🔵✅ BinOp          - ExprBinOp (add, sub, mul, div, mod, pow, lshift, rshift, bitand, bitxor, bitor)
// - 🔵✅ BoolOp         - ExprBoolOp (and, or)
// - 🔵✅ Compare        - ExprCompare (<, <=, >, >=, ==, !=, in, not in, is, is not)
// - 🔵⚠️ Call           - ExprCall (function call) - Intercept to prevent calling private / dunder methods
// - 🔵✅ Keyword        - Keyword (keyword argument when calling a function)
// - 🔵✅ IfExp          - ExprIf (ternary operator, e.g. `x if y else z`)
// - 🔵⚠️ Attribute      - ExprAttribute (attribute access, e.g. `x.y`) - Intercept to prevent accessing private / dunder attributes
// - 🔵⚠️ NamedExpr      - ExprNamed (walrus operator, e.g. `x := y`; assigns to context) - Intercepted to set the value to the context
// - 🔵⚠️ Subscript      - ExprSubscript (subscript access, e.g. `x[y]`) - Intercept to prevent accessing private / dunder attributes
// - 🔵⚠️ Slice          - ExprSlice (e.g. numeric part in `x[1:2]`, same as `slice(1, 2)`) - Transformed to slice(1, 2) calls
// - 🔵⚠️ GeneratorExp   - ExprGenerator (e.g. `(x for x in range(10))`) - Disallow async
// - 🔵⚠️ ListComp       - ExprListComp (e.g. `[x for x in range(10)]`) - Disallow async
// - 🔵⚠️ SetComp        - ExprSetComp (e.g. `{x for x in range(10)}`) - Disallow async
// - 🔵⚠️ DictComp       - ExprDictComp (e.g. `{x: x for x in range(10)}`) - Disallow async
// - 🔵⚠️ comprehension  - Comprehension (single `for` in comprehension) - Disallow async
//
// Statements:
// - 🔵❌ Assign         - StmtAssign
// - 🔵❌ AnnAssign      - StmtAnnAssign
// - 🔵❌ AugAssign      - StmtAugAssign
// - 🔵❌ Raise          - StmtRaise
// - 🔵❌ Assert         - StmtAssert
// - 🔵❌ Delete         - StmtDelete
// - 🔵❌ Pass           - StmtPass
// - 🔵❌ TypeAlias      - StmtTypeAlias
// - ❌                  - StmtExpr (expr wrapper in Ruff Python AST. We should never see this)
//
// Statements (imports):
// - 🔵❌ Import         - StmtImport
// - 🔵❌ ImportFrom     - StmtImportFrom
// - 🔵❌ Alias          - Alias
//
// Statements (control flow):
// - 🔵❌ If             - StmtIf
// - 🔵❌                - ElifElseClause
// - 🔵❌ For            - StmtFor
// - 🔵❌ While          - StmtWhile
// - 🔵❌ Break          - StmtBreak
// - 🔵❌ Continue       - StmtContinue
// - 🔵❌ Try            - StmtTry
// - 🔵❌ TryStar        - StmtTry (with is_star flag)
// - 🔵❌ ExceptHandler  - ExceptHandlerExceptHandler
// - 🔵❌ With           - StmtWith
// - 🔵❌ withitem       - WithItem
//
// Statements (pattern matching):
// - 🔵❌ Match          - StmtMatch
// - 🔵❌ match_case     - MatchCase
// - 🔵❌ MatchValue     - PatternMatchValue
// - 🔵❌ MatchSingleton - PatternMatchSingleton
// - 🔵❌ MatchSequence  - PatternMatchSequence
// - 🔵❌ MatchStar      - PatternMatchStar
// - 🔵❌ MatchMapping   - PatternMatchMapping
// - 🔵❌ MatchClass     - PatternMatchClass
// - 🔵❌                - PatternArguments (arg position in class match)
// - 🔵❌                - PatternKeyword (kwarg position in class match)
// - 🔵❌ MatchAs        - PatternMatchAs
// - 🔵❌ MatchOr        - PatternMatchOr
//
// Type annotations:
// - ❌ TypeIgnore     - X (No Rust type?)
//
// Type parameters (Python 3.12+):
// - 🔵❌ TypeVar        - TypeParamTypeVar (e.g. `type T = int` or `[T]` in generic function)
// - 🔵❌ ParamSpec      - TypeParamParamSpec (e.g. `[**P]` in generic function)
// - 🔵❌ TypeVarTuple   - TypeParamTypeVarTuple (e.g. `[*Ts]` in generic function)
// - 🔵❌                - TypeParams (the `[T]` syntax in `def func[T](x: T) -> T:`)
//
// Function and class definitions:
// - 🔵❌ FunctionDef    - StmtFunctionDef
// - 🔵✅ Lambda         - ExprLambda
// - 🔵✅                - Arguments
// - 🔵✅                - Parameters
// - 🔵✅                - Parameter
// - 🔵✅                - ParameterWithDefault
// - 🔵❌ Return         - StmtReturn
// - 🔵❌ Yield          - ExprYield
// - 🔵❌ YieldFrom      - ExprYieldFrom
// - 🔵❌ Global         - StmtGlobal
// - 🔵❌ NonLocal       - StmtNonlocal
// - 🔵❌ ClassDef       - StmtClassDef
//
// Async and await:
// - 🔵❌ AsyncFunctionDef - X (No Rust type?)
// - 🔵❌ Await          - ExprAwait
// - 🔵❌ AsyncFor       - X (No Rust type?)
// - 🔵❌ AsyncWith      - X (No Rust type?)
// - 🔵❌ AsyncComprehension - X (No Rust type?)
//
// Other:
// - 🔵✅              - Identifier (name of a variable, function, class, etc.)
// - 🔵❌              - Decorator
// - 🔵⚠️              - Comments - Ignored/removed from the expression
// - ❌                - StmtIpyEscapeCommand
// - ❌                - ExprIpyEscapeCommand

use crate::utils::python_ast::{
    attribute, call, get_expr_range, interceptor_call, none_literal, string_literal,
};
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast, Expr, Stmt};
use ruff_python_parser::parse_expression;
use ruff_source_file::LineIndex;
use std::cell::RefCell;
use std::collections::HashSet;

/// Metadata of a matched token with its position information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// String content of the token
    pub content: String,
    /// Start index in the original input string
    pub start_index: usize,
    /// End index in the original input string
    pub end_index: usize,
    /// Line and column number (1-indexed)
    pub line_col: (usize, usize),
}

/// Result of transforming an expression string
#[derive(Debug, Clone)]
pub struct TransformResult {
    /// The transformed expression
    pub expression: Expr,
    /// Tokens for variables that are used from the outside context
    pub used_vars: Vec<Token>,
    /// Tokens for variables that are assigned via walrus operator (:=)
    pub assigned_vars: Vec<Token>,
}

/// The main entry point for transforming an expression string.
/// Returns the transformed expression along with tokens for variables used and assigned.
pub fn transform_expression_string(source: &str) -> Result<TransformResult, String> {
    let transformer = SandboxTransformer::new();
    let ast = parse_expression(source).map_err(|e| format!("Parse error: {}", e))?;

    // Create a LineIndex to convert byte offsets to line/column positions
    let line_index = LineIndex::from_source_text(source);

    // The top-level AST for an expression is an `ast::Mod::Expression`.
    // We want to transform the single expression inside it.
    // ast.syntax() returns a &ModExpression for parse_expression
    let module = ast.syntax();
    // It should have a single expression inside it
    let mut expr = *module.body.clone();
    transformer.visit_expr(&mut expr);

    // Check if any validation errors occurred during transformation
    if let Some(error) = transformer.get_error() {
        return Err(error);
    }

    // Get the used variables and convert to Vec of Tokens
    // Also convert byte offsets to line/column positions
    let mut used_vars: Vec<Token> = transformer
        .get_used_variables()
        .into_iter()
        .map(|(name, start, end)| {
            // Convert byte offset to line/column (only for start position)
            let start_pos =
                line_index.line_column(ruff_text_size::TextSize::from(start as u32), source);

            // Extract the variable name from the source text for token content
            let content = if start < end && end <= source.len() {
                source[start..end].to_string()
            } else {
                name.clone()
            };

            Token {
                content,
                start_index: start,
                end_index: end,
                line_col: (
                    start_pos.line.to_zero_indexed() + 1,   // Convert to 1-indexed
                    start_pos.column.to_zero_indexed() + 1, // Convert to 1-indexed
                ),
            }
        })
        .collect();
    // Sort by start_index for consistent output
    used_vars.sort_by(|a, b| a.start_index.cmp(&b.start_index));

    // Get the assigned variables (from walrus operator) and convert to Vec of Tokens
    let mut assigned_vars: Vec<Token> = transformer
        .get_assignments()
        .into_iter()
        .map(|(name, start, end)| {
            // Convert byte offset to line/column (only for start position)
            let start_pos =
                line_index.line_column(ruff_text_size::TextSize::from(start as u32), source);

            // Extract the variable name from the source text for token content
            let content = if start < end && end <= source.len() {
                source[start..end].to_string()
            } else {
                name.clone()
            };

            Token {
                content,
                start_index: start,
                end_index: end,
                line_col: (
                    start_pos.line.to_zero_indexed() + 1,   // Convert to 1-indexed
                    start_pos.column.to_zero_indexed() + 1, // Convert to 1-indexed
                ),
            }
        })
        .collect();
    // Sort by start_index for consistent output
    assigned_vars.sort_by(|a, b| a.start_index.cmp(&b.start_index));

    Ok(TransformResult {
        expression: expr,
        used_vars,
        assigned_vars,
    })
}

/// Our custom AST transformer that validates and transforms Python expressions
/// to make them safe for evaluation in a sandboxed environment.
pub struct SandboxTransformer {
    // Track locally introduced variables (from comprehensions, lambdas, etc.)
    // that should NOT be transformed to `variable("name", context)` calls
    // Using RefCell so we can modify it during traversal (e.g., when we encounter
    // walrus assignments in lambdas)
    local_variables: RefCell<HashSet<String>>,
    // Track validation errors instead of panicking
    // NOTE: Inside transformer methods (visit_xxx) we have only read access to SandboxTransformer
    // hence why we use RefCell to borrow the value from the outside.
    validation_error: RefCell<Option<String>>,
    // Track variables assigned via walrus operator (:=) in this scope.
    // These need to be propagated up to parent scopes so they remain accessible.
    // This is so that we replicate how Python behaves, where e.g. a walrus op
    // inside a comprehension remains available even outside the comprehension.
    // ```py
    // items = [1, 2, 3]
    // [y for x in items if (y := x + 1)]
    // print(y)  # 4
    // ```
    // We use a Vec to store all occurrences with their positions.
    // Each tuple is (variable_name, start_index, end_index).
    assignments: RefCell<Vec<(String, usize, usize)>>,
    // Track variables that are needed from the outside context (not local).
    // These are variables that need to be accessed via variable(context, source, token, "name").
    // When we transform `var_name` to `variable(context, source, token, "var_name")`, we record
    // that `var_name` is needed. This helps determine what variables the expression
    // requires from the context in which it's evaluated.
    // We use a Vec to store all occurrences with their positions.
    // Each tuple is (variable_name, start_index, end_index).
    used_variables: RefCell<Vec<(String, usize, usize)>>,
    // Whether we're currently inside a lambda expression.
    // In lambdas, walrus assignments should NOT be transformed to assign() calls
    // and should NOT leak to the outer context. Instead, they should be kept as
    // regular Python walrus operators and added to local_variables.
    is_in_lambda: bool,
}

impl SandboxTransformer {
    pub fn new() -> Self {
        Self {
            local_variables: RefCell::new(HashSet::new()),
            validation_error: RefCell::new(None),
            assignments: RefCell::new(Vec::new()),
            used_variables: RefCell::new(Vec::new()),
            is_in_lambda: false,
        }
    }

    /// Create a new SandboxTransformer with additional local variables (union)
    /// We have to create a new copy because inside visit_xxx methods we have only read access.
    ///
    /// The child transformer:
    /// - Inherits parent's local_variables + additional_locals
    /// - Starts with empty assignments (to track only new assignments made in child scope)
    /// Note: Assignments are NOT added to local_variables because we still want to transform
    /// references to assigned variables (they are set via assign() in the context, not in Python scope)
    fn with_locals(&self, additional_locals: HashSet<String>, propagate_assignments: bool) -> Self {
        let mut new_locals = self.local_variables.borrow().clone();
        new_locals.extend(additional_locals);

        Self {
            local_variables: RefCell::new(new_locals),
            validation_error: RefCell::new(self.validation_error.borrow().clone()),
            assignments: RefCell::new(Vec::new()),
            used_variables: RefCell::new(Vec::new()),
            // If parent is already in a lambda, child is also in a lambda (for nested lambdas)
            // Otherwise, set based on propagate_assignments (false means we're in a lambda)
            is_in_lambda: self.is_in_lambda || !propagate_assignments,
        }
    }

    /// Set a validation error
    fn set_error(&self, error: String) {
        *self.validation_error.borrow_mut() = Some(error);
    }

    /// Get the validation error
    fn get_error(&self) -> Option<String> {
        self.validation_error.borrow().clone()
    }

    /// Check if there are any errors
    fn has_error(&self) -> bool {
        self.validation_error.borrow().is_some()
    }

    /// Record a new variable assignment from walrus operator.
    /// These will remain available within he current function scope.
    /// Thus, if we are in a comprehension, the assignment will remain available even after leaving the scope.
    /// ```py
    /// items = [1, 2, 3]
    /// [y for x in items if (y := x + 1)]
    /// print(y)  # 4
    /// ```
    /// Records all occurrences of each variable name.
    fn add_assignment(&self, var_name: String, start_index: usize, end_index: usize) {
        self.assignments
            .borrow_mut()
            .push((var_name, start_index, end_index));
    }

    /// Get all assignments made in this function scope with their positions
    fn get_assignments(&self) -> Vec<(String, usize, usize)> {
        self.assignments.borrow().clone()
    }

    /// Record a variable that is needed from the outside context.
    /// This is called when we transform a variable access to variable(context, source, token, "name").
    /// Records all occurrences of each variable name.
    fn add_used_variable(&self, var_name: String, start_index: usize, end_index: usize) {
        self.used_variables
            .borrow_mut()
            .push((var_name, start_index, end_index));
    }

    /// Get all variables that are needed from the outside context with their positions
    fn get_used_variables(&self) -> Vec<(String, usize, usize)> {
        self.used_variables.borrow().clone()
    }

    /// Propagate assignments and errors from a child transformer back to this one
    fn propagate_from_child(&self, child: &SandboxTransformer, propagate_assignments: bool) {
        // Propagate assignments up (so walrus variables remain accessible after leaving the scope)
        // Only propagate if requested (comprehensions propagate, but lambdas don't)
        if propagate_assignments {
            self.assignments
                .borrow_mut()
                .extend(child.get_assignments());
        }

        // Always propagate used_variables up (variables needed from context)
        self.used_variables
            .borrow_mut()
            .extend(child.get_used_variables());

        // Always propagate errors up
        if child.has_error() {
            self.set_error(child.get_error().unwrap());
        }
    }

    /// Check if a variable name is local
    fn is_local_variable(&self, name: &str) -> bool {
        // NOTE: Previously this contained also walrus assignments `(x := 2)`.
        // because the variable should be available after assignment, e.g. `(x := 2) and x > 1`.
        // HOWEVER, we actually replace the walrus operator with call to `assign(...)`,
        // and thus the variable is not assigned in THIS scope.
        // So we still need to replace later references with `variable("name", context)` calls.
        self.local_variables.borrow().contains(name)
    }

    /// Visit an expression with additional local variables
    fn visit_expr_with_locals(
        &self,
        expr: &mut Expr,
        new_local_vars: HashSet<String>,
        propagate_assignments: bool,
    ) {
        let child_transformer = self.with_locals(new_local_vars, propagate_assignments);
        child_transformer.visit_expr(expr);
        self.propagate_from_child(&child_transformer, propagate_assignments);
    }

    /// Visit a comprehension with additional local variables from the generator targets
    /// Returns the walrus-assigned variables that were added to local_variables (for lambdas)
    fn visit_comprehension_with_locals(
        &self,
        comprehension: &mut ast::Comprehension,
        new_local_vars: HashSet<String>,
    ) -> HashSet<String> {
        let child_transformer = self.with_locals(new_local_vars.clone(), true);
        child_transformer.visit_comprehension(comprehension);
        // Comprehensions propagate walrus assignments (they leak out in Python)
        self.propagate_from_child(&child_transformer, true);

        // Return walrus-assigned variables that were added to local_variables
        // These are variables that are in the child's local_variables but not in the original new_local_vars
        let child_local_vars = child_transformer.local_variables.borrow().clone();
        let walrus_assigned: HashSet<String> = child_local_vars
            .difference(&new_local_vars)
            .cloned()
            .collect();
        walrus_assigned
    }

    /// Extract variable names from a target expression (for comprehensions)
    fn extract_target_variables(target: &Expr) -> HashSet<String> {
        let mut vars = HashSet::new();
        match target {
            // E.g. `x` in `[x+1 for x in range(10)]`
            Expr::Name(name) => {
                vars.insert(name.id.as_str().to_string());
            }
            // E.g. `(x, y)` in `[x+1 for x, y in range(10)]`
            Expr::Tuple(tuple) => {
                for elt in &tuple.elts {
                    vars.extend(Self::extract_target_variables(elt));
                }
            }
            _ => {
                panic!(
                    "Validation Error: Unsupported target type in comprehension: {:?}",
                    target
                );
            }
        }
        vars
    }

    /// Helper function to handle comprehension logic common to ListComp, SetComp, DictComp, and Generator
    /// This function:
    /// 1. Checks for async generators
    /// 2. Extracts local variables from generator targets
    /// 3. Visits generators and collects walrus-assigned variables
    /// 4. Adds walrus-assigned variables to local_vars and lambda's local_variables if needed
    /// 5. Calls the provided closure to transform the element(s)
    fn handle_comprehension<F>(&self, generators: &mut [ast::Comprehension], transform_elements: F)
    where
        F: FnOnce(&Self, HashSet<String>),
    {
        // Check if any generator is async
        for generator in generators.iter() {
            if generator.is_async {
                self.set_error(
                    "Validation Error: Async comprehensions are not allowed for security reasons"
                        .to_string(),
                );
                return;
            }
        }

        // Extract all locally introduced variables from all generators
        let mut local_vars = HashSet::new();
        for generator in generators.iter() {
            local_vars.extend(Self::extract_target_variables(&generator.target));
        }

        // IMPORTANT: Visit generators FIRST (including if conditions where walrus might occur)
        // This way, any walrus assignments in the if conditions will be tracked and propagated
        // before we visit the element
        // Collect walrus-assigned variables from all generators
        // These need to be added to local_vars before visiting the element
        let mut walrus_assigned_vars = HashSet::new();
        for generator in generators.iter_mut() {
            let walrus_vars = self.visit_comprehension_with_locals(generator, local_vars.clone());
            walrus_assigned_vars.extend(walrus_vars);
        }

        // Add walrus-assigned variables to local_vars so they're available in the element
        local_vars.extend(walrus_assigned_vars.clone());

        // If we're in a lambda, also add walrus-assigned variables to the lambda's local_variables
        // so they're available in the rest of the lambda body (e.g., after the comprehension)
        if self.is_in_lambda {
            for var in &walrus_assigned_vars {
                self.local_variables.borrow_mut().insert(var.clone());
            }
        }

        // Transform the element(s) with local variables
        // This includes the variables introduced by generators (like 'x' in [x+1 for x in items])
        // and walrus-assigned variables (like 'y' in [y for x in items if (y := x * 2)])
        // Comprehensions propagate walrus assignments
        transform_elements(self, local_vars);
    }
}

impl Transformer for SandboxTransformer {
    /// Override the default visit_expr to implement our validation and transformation logic
    fn visit_expr(&self, expr: &mut Expr) {
        match expr {
            // ✅ ALLOWED - Literals
            Expr::StringLiteral(_)
            | Expr::BytesLiteral(_)
            | Expr::NumberLiteral(_)
            | Expr::BooleanLiteral(_)
            | Expr::NoneLiteral(_)
            | Expr::EllipsisLiteral(_) => {
                // These are safe, no transformation needed
            }

            // ✅ ALLOWED - Data structures
            Expr::List(list) => {
                // Transform all elements
                for element in list.elts.iter_mut() {
                    self.visit_expr(element);
                }
            }
            Expr::Tuple(tuple) => {
                // Transform all elements
                for element in tuple.elts.iter_mut() {
                    self.visit_expr(element);
                }
            }
            Expr::Dict(dict) => {
                // Transform all keys and values
                for item in dict.items.iter_mut() {
                    if let Some(key) = &mut item.key {
                        self.visit_expr(key);
                    }
                    self.visit_expr(&mut item.value);
                }
            }
            Expr::Set(set) => {
                // Transform all elements
                for element in set.elts.iter_mut() {
                    self.visit_expr(element);
                }
            }

            // ✅ ALLOWED - Basic expressions
            Expr::UnaryOp(unary_op) => {
                // Transform the operand
                self.visit_expr(&mut unary_op.operand);
            }
            Expr::BinOp(bin_op) => {
                // Transform the left and right operands
                self.visit_expr(&mut bin_op.left);
                self.visit_expr(&mut bin_op.right);
            }
            Expr::BoolOp(bool_op) => {
                // Transform all values in the boolean operation
                for value in bool_op.values.iter_mut() {
                    self.visit_expr(value);
                }
            }
            Expr::Compare(compare) => {
                // Transform the left side and all comparators
                self.visit_expr(&mut compare.left);
                for comparator in compare.comparators.iter_mut() {
                    self.visit_expr(comparator);
                }
            }
            // ✅ Ternary if expression: `x if condition else y`
            Expr::If(if_expr) => {
                // Transform all three parts: test (condition), body (true branch), orelse (false branch)
                self.visit_expr(&mut if_expr.test);
                self.visit_expr(&mut if_expr.body);
                self.visit_expr(&mut if_expr.orelse);
            }

            // ✅ ALLOWED - Comprehensions (but check for async)
            Expr::ListComp(list_comp) => {
                self.handle_comprehension(&mut list_comp.generators, |transformer, local_vars| {
                    // Transform element with local variables
                    // Comprehensions propagate walrus assignments
                    transformer.visit_expr_with_locals(&mut list_comp.elt, local_vars, true)
                });
            }
            Expr::SetComp(set_comp) => {
                self.handle_comprehension(&mut set_comp.generators, |transformer, local_vars| {
                    // Transform element with local variables
                    // Comprehensions propagate walrus assignments
                    transformer.visit_expr_with_locals(&mut set_comp.elt, local_vars, true);
                });
            }
            Expr::DictComp(dict_comp) => {
                self.handle_comprehension(&mut dict_comp.generators, |transformer, local_vars| {
                    // Transform key and value with local variables
                    // Comprehensions propagate walrus assignments
                    transformer.visit_expr_with_locals(
                        &mut dict_comp.key,
                        local_vars.clone(),
                        true,
                    );
                    transformer.visit_expr_with_locals(&mut dict_comp.value, local_vars, true);
                });
            }
            Expr::Generator(generator) => {
                self.handle_comprehension(&mut generator.generators, |transformer, local_vars| {
                    // Transform element with local variables
                    // Comprehensions propagate walrus assignments
                    transformer.visit_expr_with_locals(&mut generator.elt, local_vars, true);
                });
            }

            // ⚠️ Variable names transform from `my_var` to `variable(context, source, token, "my_var")`
            Expr::Name(name) => {
                // Check if this is a locally introduced variable (from comprehensions, lambdas, etc.)
                // or if it was assigned via walrus operator
                let var_name = name.id.as_str();
                if self.is_local_variable(var_name) {
                    // This is a local variable, don't transform it to variable(context, source, token, "name")
                    // Just allow it as-is
                } else {
                    // Transform `var_name` to `variable(context, source, token, "var_name")`.
                    // That way, when evaluating the modified expression, we can plug in
                    // the definition of `variable()` and safely handle the variable access.
                    // The token tuple contains (start_index, end_index) for error reporting.
                    // We need to replace the current Expr::Name with Expr::Call
                    let var_name = name.id.as_str().to_string();
                    let range = name.range;

                    // Record that this variable is needed from the outside context
                    // Convert TextSize to usize for start and end indices
                    let start_index = range.start().to_usize();
                    let end_index = range.end().to_usize();
                    self.add_used_variable(var_name.clone(), start_index, end_index);

                    // Create a StringLiteral for the variable name
                    let var_name_literal = string_literal(&var_name, range);

                    // `variable(context, source, (start_index, end_index), "var_name")`
                    let call_expr =
                        interceptor_call("variable", vec![var_name_literal], vec![], range);

                    // Replace the current expression with the call
                    *expr = call_expr;
                }
            }

            // ⚠️ Function call transform from `foo(a, b=2, **c)` to `call(foo, a, b=2, **c)`
            Expr::Call(call_expr) => {
                // Transform to call(fn, *args, **kwargs)
                // First, recursively transform the function expression and arguments
                self.visit_expr(&mut call_expr.func);
                self.visit_arguments(&mut call_expr.arguments);

                // Now wrap the entire call in `call(fn, *args, **kwargs)`
                // This keeps the original function signature intact

                // Prepend the function as the first positional argument to call()
                let mut args = vec![*call_expr.func.clone()];
                args.extend(call_expr.arguments.args.to_vec());

                // `call(context, source, (start_index, end_index), fn, *args, **kwargs)`
                let wrapper_call = interceptor_call(
                    "call",
                    args,
                    call_expr.arguments.keywords.to_vec(),
                    call_expr.range,
                );

                // Replace the current expression with the wrapper call
                *expr = wrapper_call;
            }
            Expr::Starred(starred) => {
                // Allow starred expressions (e.g., *args in function calls)
                // Transform the value inside the starred expression
                self.visit_expr(&mut starred.value);
            }

            // ⚠️ Attribute access transform from `obj.attr` to `attribute(obj, "attr")`
            Expr::Attribute(attr) => {
                // Transform to attribute(obj, "attr_name")
                // First, recursively transform the object expression
                self.visit_expr(&mut attr.value);

                // Now wrap the attribute access in attribute(obj, "attr_name")
                let range = attr.range;
                let attr_name = attr.attr.as_str().to_string();

                // Create a StringLiteral for the attribute name
                let attr_name_literal = string_literal(&attr_name, range);

                // `attribute(context, source, (start_index, end_index), obj, "attr_name")`
                let wrapper_call = interceptor_call(
                    "attribute",
                    vec![*attr.value.clone(), attr_name_literal],
                    vec![],
                    range,
                );

                // Replace the current expression with the wrapper call
                *expr = wrapper_call;
            }

            // ⚠️ Subscript subscript transform from `obj[key]` to `subscript(obj, key)`
            Expr::Subscript(subscript) => {
                // Transform to subscript(obj, key)
                // First, recursively transform both the object and the key expressions
                self.visit_expr(&mut subscript.value);
                self.visit_expr(&mut subscript.slice);

                // Now wrap the subscript access in subscript(obj, key)
                let range = subscript.range;

                // `subscript(context, source, (start_index, end_index), obj, key)`
                let wrapper_call = interceptor_call(
                    "subscript",
                    vec![*subscript.value.clone(), *subscript.slice.clone()],
                    vec![],
                    range,
                );

                // Replace the current expression with the wrapper call
                *expr = wrapper_call;
            }

            // ⚠️ Slice transform from `obj[1:10:2]` to `slice(1, 10, 2)`
            Expr::Slice(slice) => {
                // Transform slice expressions (e.g., obj[1:10:2]) into slice(1, 10, 2) calls
                // This is necessary because we're wrapping subscripts in subscript() calls,
                // and Python doesn't allow : syntax outside of []

                // First, recursively transform the lower, upper, and step expressions if they exist
                if let Some(lower) = &mut slice.lower {
                    self.visit_expr(lower);
                }
                if let Some(upper) = &mut slice.upper {
                    self.visit_expr(upper);
                }
                if let Some(step) = &mut slice.step {
                    self.visit_expr(step);
                }

                // Now convert the slice into a slice() call
                let range = slice.range;
                let slice_args = vec![
                    // lower
                    slice
                        .lower
                        .as_ref()
                        .map(|e| *e.clone())
                        .unwrap_or_else(|| none_literal(range)),
                    // upper
                    slice
                        .upper
                        .as_ref()
                        .map(|e| *e.clone())
                        .unwrap_or_else(|| none_literal(range)),
                    // step
                    slice
                        .step
                        .as_ref()
                        .map(|e| *e.clone())
                        .unwrap_or_else(|| none_literal(range)),
                ];

                // `slice(context, source, (start_index, end_index), lower, upper, step)`
                let slice_call = interceptor_call("slice", slice_args, vec![], range);

                // Replace the current expression with the slice() call
                *expr = slice_call;
            }

            // ⚠️ Walrus operator transform from `x := y` to `assign(context, source, token, "x", y)`
            // BUT: Inside lambdas, we keep it as a Python walrus operator and add the variable to local_variables
            Expr::Named(named) => {
                // First, recursively transform the value expression
                self.visit_expr(&mut named.value);

                // Get the variable name from the target
                let var_name = match &*named.target {
                    Expr::Name(name) => name.id.as_str().to_string(),
                    _ => {
                        self.set_error(
                            "Validation Error: Named expression target must be a simple variable name"
                                .to_string(),
                        );
                        return;
                    }
                };

                let range = named.range;

                if self.is_in_lambda {
                    // Inside a lambda: keep the walrus operator as-is (don't transform to assign())
                    // and add the variable to local_variables so subsequent references don't get transformed
                    // to variable() calls. This way the variable stays local to the lambda and doesn't
                    // leak to the outer context.
                    self.local_variables.borrow_mut().insert(var_name.clone());
                    // Keep the walrus operator as-is - don't transform it to assign()
                    // The expression remains: (var_name := value)
                } else {
                    // Not in a lambda: transform to assign() call and record assignment
                    // Extract position from the target (variable name), not the entire named expression
                    let target_range = match &*named.target {
                        Expr::Name(name) => name.range,
                        _ => range, // Fallback to entire expression if target is not a simple name
                    };
                    let start_index = target_range.start().to_usize();
                    let end_index = target_range.end().to_usize();
                    self.add_assignment(var_name.clone(), start_index, end_index);

                    // Create a StringLiteral for the variable name
                    let var_name_literal = string_literal(&var_name, range);

                    // `assign(context, source, (start_index, end_index), "var_name", value)`
                    let wrapper_call = interceptor_call(
                        "assign",
                        vec![var_name_literal, *named.value.clone()],
                        vec![],
                        range,
                    );

                    // Replace the current expression with the wrapper call
                    *expr = wrapper_call;
                }
            }

            // ⚠️ F-string transform from `f"Hello {price!r:.2f}"` to `format(context, source, token, "Hello {}", (variable(context, source, token, "price"), "r", ".2f"))`
            Expr::FString(f_string) => {
                // Transform f-strings to .format() calls to avoid quote escaping issues
                // f"Hello {name}" becomes "Hello {}".format(name)

                let range = f_string.range;
                let mut format_args: Vec<Expr> = Vec::new();
                let mut template_parts: Vec<String> = Vec::new();

                // Process all parts of the f-string
                for part in &mut f_string.value {
                    if let ast::FStringPart::FString(f_str) = part {
                        // Process each element in the f-string
                        for element in f_str.elements.iter_mut() {
                            match element {
                                ast::InterpolatedStringElement::Literal(lit) => {
                                    // Add literal text to template
                                    template_parts.push(lit.value.to_string());
                                }
                                ast::InterpolatedStringElement::Interpolation(interpolation) => {
                                    // Transform the expression
                                    self.visit_expr(&mut interpolation.expression);

                                    // Get range from the expression before cloning
                                    let expr_range =
                                        get_expr_range(&interpolation.expression, range);
                                    let value_expr = *interpolation.expression.clone();

                                    // Build conversion flag string ("r", "s", "a", or None)
                                    let conversion_flag = match interpolation.conversion {
                                        ast::ConversionFlag::None => none_literal(expr_range),
                                        ast::ConversionFlag::Str => string_literal("s", expr_range),
                                        ast::ConversionFlag::Ascii => {
                                            string_literal("a", expr_range)
                                        }
                                        ast::ConversionFlag::Repr => {
                                            string_literal("r", expr_range)
                                        }
                                    };

                                    // Build format spec. Either:
                                    // - static string (`:.2f`, `:>10`, etc.)
                                    // - dynamic expression (`{width}.{precision}f`)
                                    // We don't call built-in `format()` here; we pass the format spec as metadata
                                    // and let our `format()` interceptor handle it.
                                    let format_spec_expr =
                                        if let Some(format_spec) = &mut interpolation.format_spec {
                                            // Build the format spec - can be static or dynamic
                                            let mut spec_template_parts = Vec::new();
                                            let mut spec_format_args = Vec::new();

                                            for spec_element in format_spec.elements.iter_mut() {
                                                match spec_element {
                                                    ast::InterpolatedStringElement::Literal(lit) => {
                                                        spec_template_parts.push(lit.value.to_string());
                                                    }
                                                    ast::InterpolatedStringElement::Interpolation(
                                                        spec_interp,
                                                    ) => {
                                                        // Format specs with expressions!
                                                        // e.g., f"{value:{width}.{precision}f}"
                                                        // Transform the expression in the format spec
                                                        self.visit_expr(&mut spec_interp.expression);

                                                        // Add {} placeholder
                                                        spec_template_parts.push("{}".to_string());

                                                        // Add the transformed expression to spec args
                                                        spec_format_args
                                                            .push(*spec_interp.expression.clone());
                                                    }
                                                }
                                            }

                                            let spec_template_str = spec_template_parts.join("");

                                            // Build the format spec expression
                                            if spec_format_args.is_empty() {
                                                // Static format spec - just use a string literal
                                                string_literal(&spec_template_str, expr_range)
                                            } else {
                                                // Dynamic format spec - we need to pass both template and args
                                                // We'll pass this as a tuple: (template, *args)
                                                let spec_template_literal =
                                                    string_literal(&spec_template_str, expr_range);
                                                // Create a tuple: (template, arg1, arg2, ...)
                                                Expr::Tuple(ast::ExprTuple {
                                                    node_index: Default::default(),
                                                    range: expr_range,
                                                    ctx: ast::ExprContext::Load,
                                                    parenthesized: false,
                                                    elts: {
                                                        let mut tuple_elts =
                                                            vec![spec_template_literal];
                                                        tuple_elts.extend(spec_format_args);
                                                        tuple_elts.into()
                                                    },
                                                })
                                            }
                                        } else {
                                            // No format spec - use empty string
                                            string_literal("", expr_range)
                                        };

                                    // Add simple placeholder to template
                                    template_parts.push("{}".to_string());

                                    // Pass each interpolation as a tuple: (value, conversion_flag, format_spec)
                                    // This allows our format() interceptor to apply conversion and format_spec
                                    // instead of calling built-in functions that won't be caught by error handling
                                    let interpolation_tuple = Expr::Tuple(ast::ExprTuple {
                                        node_index: Default::default(),
                                        range: expr_range,
                                        ctx: ast::ExprContext::Load,
                                        parenthesized: false,
                                        elts: vec![value_expr, conversion_flag, format_spec_expr]
                                            .into(),
                                    });

                                    // Add the tuple to format args
                                    format_args.push(interpolation_tuple);
                                }
                            }
                        }
                    }
                }

                // Build the template string
                let template_str = template_parts.join("");

                // Create a string literal for the template
                let template_literal = string_literal(&template_str, range);

                // `format(context, source, token, "template {}", *args)`
                // We use an intercepted format() function instead of the built-in .format() method
                // so that errors inside f-strings get nice error reporting with underlining
                let mut format_args_with_template = vec![template_literal];
                format_args_with_template.extend(format_args);

                let format_call =
                    interceptor_call("format", format_args_with_template, vec![], range);

                // Replace the f-string with the intercepted format() call
                *expr = format_call;
            }

            // ⚠️ T-string transform from `t"Hello {name!r:>10}"` to `template(context, source, token, "Hello ", interpolation(context, source, token, variable(context, source, token, "name"), "expr", "r", ">10"))`
            Expr::TString(t_string) => {
                // Transform t-strings to Template() constructor calls
                // t"Hello {name}" becomes Template("Hello ", Interpolation(name, "name", None, ""), "")
                // See: https://docs.python.org/3.14/library/string.templatelib.html#template-strings

                let range = t_string.range;
                let mut template_args: Vec<Expr> = Vec::new();

                // Process all parts of the t-string (TString doesn't have wrapper, just TString directly)
                for t_str in &mut t_string.value {
                    // Process each element in the t-string
                    for element in t_str.elements.iter_mut() {
                        match element {
                            ast::InterpolatedStringElement::Literal(lit) => {
                                // Add literal string to Template args
                                let string_lit_literal = string_literal(&lit.value, lit.range);
                                template_args.push(string_lit_literal);
                            }
                            ast::InterpolatedStringElement::Interpolation(interpolation) => {
                                // Transform the expression
                                self.visit_expr(&mut interpolation.expression);

                                // Use the interpolation expression's range for token info
                                let expr_range = get_expr_range(&interpolation.expression, range);

                                // Get the expression text (we'll use a placeholder for now)
                                // In a real implementation, we'd preserve the original expression text from source
                                // Python docs recommend to use an empty string in manually-created
                                // Interpolations.
                                // See https://docs.python.org/3.14/library/string.templatelib.html#string.templatelib.Interpolation.expression
                                let expr_text = "".to_string(); // TODO: preserve original expression text

                                // Build conversion argument
                                let conversion_expr = match interpolation.conversion {
                                    ast::ConversionFlag::None => none_literal(interpolation.range),
                                    ast::ConversionFlag::Str => {
                                        string_literal("s", interpolation.range)
                                    }
                                    ast::ConversionFlag::Ascii => {
                                        string_literal("a", interpolation.range)
                                    }
                                    ast::ConversionFlag::Repr => {
                                        string_literal("r", interpolation.range)
                                    }
                                };

                                // Build format spec - can be static string or dynamic expression
                                let format_spec_expr = if let Some(format_spec) =
                                    &mut interpolation.format_spec
                                {
                                    let mut spec_template_parts = Vec::new();
                                    let mut spec_format_args = Vec::new();

                                    for spec_element in format_spec.elements.iter_mut() {
                                        match spec_element {
                                            ast::InterpolatedStringElement::Literal(lit) => {
                                                spec_template_parts.push(lit.value.to_string());
                                            }
                                            ast::InterpolatedStringElement::Interpolation(
                                                spec_interp,
                                            ) => {
                                                // Dynamic format spec with expressions!
                                                self.visit_expr(&mut spec_interp.expression);
                                                spec_template_parts.push("{}".to_string());
                                                spec_format_args
                                                    .push(*spec_interp.expression.clone());
                                            }
                                        }
                                    }

                                    let spec_template_str = spec_template_parts.join("");

                                    // Build the format spec expression
                                    // Use interpolation.range for consistency with conversion expressions
                                    if spec_format_args.is_empty() {
                                        // Static format spec - just use a string literal
                                        string_literal(&spec_template_str, interpolation.range)
                                    } else {
                                        // Dynamic format spec - use "{}".format(args...)
                                        let spec_template_literal =
                                            string_literal(&spec_template_str, interpolation.range);
                                        // `"{}".format(args...)`
                                        call(
                                            attribute(
                                                spec_template_literal,
                                                "format",
                                                interpolation.range,
                                            ),
                                            spec_format_args,
                                            vec![],
                                            interpolation.range,
                                        )
                                    }
                                } else {
                                    // No format spec - use empty string
                                    string_literal("", interpolation.range)
                                };

                                // `interpolation(context, source, token, value, expression, conversion, format_spec)`
                                // Use interpolation.range for error reporting to point to the exact {expression!r:format} location
                                let interpolation_call = interceptor_call(
                                    "interpolation",
                                    vec![
                                        *interpolation.expression.clone(),
                                        string_literal(&expr_text, expr_range),
                                        conversion_expr,
                                        format_spec_expr,
                                    ],
                                    vec![],
                                    interpolation.range,
                                );

                                template_args.push(interpolation_call);
                            }
                        }
                    }
                }

                // `template(context, source, token, ...)`
                let template_call = interceptor_call("template", template_args, vec![], range);

                // Replace the t-string with the template() call
                *expr = template_call;
            }

            // ⚠️ In lambdas we don't transform the args/kwrags introduced by the function
            Expr::Lambda(lambda) => {
                // First, transform default parameter values in the OUTER scope
                // (before lambda parameters become local variables)
                // This is because default values are evaluated when the lambda is defined,
                // not when it's called, so they should use the outer scope's variables
                if let Some(parameters) = &mut lambda.parameters {
                    // Transform defaults for positional-only args
                    for param in &mut parameters.posonlyargs {
                        if let Some(default) = &mut param.default {
                            self.visit_expr(default);
                        }
                    }
                    // Transform defaults for regular positional/keyword args
                    for param in &mut parameters.args {
                        if let Some(default) = &mut param.default {
                            self.visit_expr(default);
                        }
                    }
                    // Transform defaults for keyword-only args
                    for param in &mut parameters.kwonlyargs {
                        if let Some(default) = &mut param.default {
                            self.visit_expr(default);
                        }
                    }
                }

                // Now extract lambda parameter names into local variables
                let mut local_vars = HashSet::new();
                if let Some(parameters) = &lambda.parameters {
                    for param in &parameters.posonlyargs {
                        local_vars.insert(param.name().to_string());
                    }
                    for param in &parameters.args {
                        local_vars.insert(param.name().to_string());
                    }
                    for param in &parameters.kwonlyargs {
                        local_vars.insert(param.name().to_string());
                    }
                    if let Some(vararg) = &parameters.vararg {
                        local_vars.insert(vararg.name().to_string());
                    }
                    if let Some(kwarg) = &parameters.kwarg {
                        local_vars.insert(kwarg.name().to_string());
                    }
                }

                // Transform the lambda body with the parameter names as local variables
                // This ensures lambda parameters are not transformed to variable("param", context) calls
                // Lambdas do NOT propagate walrus assignments (they don't leak out in Python)
                self.visit_expr_with_locals(&mut lambda.body, local_vars, false);
            }

            _ => {
                panic!("Validation Error: Unsupported expression: {:?}", expr);
            }
        }
    }

    /// Override to forbid all statements
    fn visit_stmt(&self, _stmt: &mut Stmt) {
        self.set_error(
            "Validation Error: Statements are not allowed in expression context".to_string(),
        );
        return;
    }

    /// Override visit_comprehension to handle local variables properly
    fn visit_comprehension(&self, comprehension: &mut ast::Comprehension) {
        // Comprehension breakdown:
        // [x + 1 for x, y in range(n, 1) if (z := x + y) if True]
        //  ^^^^^                                                    <-- elt (owned by ExprListComp)
        //            ^^^^                                           <-- target (owned by Comprehension)
        //                    ^^^^^^^^^^^                            <-- iter (owned by Comprehension)
        //                                ^^^^^^^^^^^^^^^^^^^^^^     <-- ifs (owned by Comprehension)
        //
        // NOTE: The 'elt' is NOT part of Comprehension - it's owned by ExprListComp/ExprSetComp/etc.
        //       The visit_comprehension method only handles: target, iter, ifs
        //
        // Comprehensions are evaluated in the order:
        // 1. iter
        // 2. ifs
        // 3. elt
        //
        // We don't visit the target as it's a newly introduced variable that doesn't need transformation
        // Instead, we only visit the iter and ifs. elt is visited by respective comps like ListComp.

        // Visit the iterable expression FIRST
        // This is important because the iter might contain walrus assignments that need to be
        // available in the if conditions
        // E.g., for x in [(a := i) for i in items] if (b := a + 1)
        //       The 'a' from the inner comprehension should be available in the if condition
        self.visit_expr(&mut comprehension.iter);

        // Now visit all if conditions - these should have access to:
        // - Local variables introduced by this comprehension's target
        // - Walrus assignments made in the iter expression
        for if_expr in comprehension.ifs.iter_mut() {
            self.visit_expr(if_expr);
        }
    }
}
