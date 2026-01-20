//! # Abstract Syntax Tree (AST) for Django Template Tags
//!
//! This module defines the core data structures that represent parsed Django template tags
//! as an Abstract Syntax Tree (AST). These structures are used throughout the template
//! parsing and compilation pipeline.
//!
//! ## Overview
//!
//! The AST represents Django template tags in a structured format that captures:
//! - Tag names and attributes
//! - Values with their types (strings, numbers, variables, template_strings, etc.)
//! - Filter chains and filter arguments
//! - Position information (line/column, start/end indices)
//!
//! ## Core types
//!
//! - **`Tag`**: Represents a complete template tag with name, attributes, and metadata - `{% my_tag ... %}` or `<my_tag ... />`
//! - **`TagAttr`**: Represents a single attribute (key-value pair or flag) - `key=value` or `flag`
//! - **`TagValue`**: Represents a value with type information and optional filters - `'some_val'|upper`
//! - **`Token`**: Represents a token with position information
//! - **`TagValueFilter`**: Represents a filter applied to a value
//! - **`ValueKind`**: Enum of supported value types (list, dict, int, float, variable, template_string, translation, string)
//!
//! All AST types are exposed to Python via PyO3 bindings.
//!
//! ## Example
//!
//! ```rust
//! use crate::djc_template_parser::ast::*;
//!
//! // A Django tag: {% my_tag key=val %}
//! let tag = Tag::Generic(GenericTag {
//!     meta: TagMeta {
//!         token: Token {
//!             content: "{% my_tag key=val %}".to_string(),
//!             start_index: 0,
//!             end_index: 20,
//!             line_col: (1, 1),
//!         },
//!         name: Token {
//!             content: "my_tag".to_string(),
//!             start_index: 3,
//!             end_index: 9,
//!             line_col: (1, 4),
//!         },
//!         used_variables: vec![Token {
//!             content: "val".to_string(),
//!             start_index: 14,
//!             end_index: 17,
//!             line_col: (1, 15),
//!         }],
//!         assigned_variables: vec![],
//!     },
//!     attrs: vec![TagAttr {
//!         token: Token {
//!             content: "key=val".to_string(),
//!             start_index: 10,
//!             end_index: 17,
//!             line_col: (1, 11),
//!         },
//!         key: Some(Token {
//!             content: "key".to_string(),
//!             start_index: 10,
//!             end_index: 13,
//!             line_col: (1, 11),
//!         }),
//!         value: TagValue {
//!             token: Token {
//!                 content: "val".to_string(),
//!                 start_index: 14,
//!                 end_index: 17,
//!                 line_col: (1, 15),
//!             },
//!             value: Token {
//!                 content: "val".to_string(),
//!                 start_index: 14,
//!                 end_index: 17,
//!                 line_col: (1, 15),
//!             },
//!             children: vec![],
//!             spread: None,
//!             filters: vec![],
//!             kind: ValueKind::Variable,
//!             used_variables: vec![Token {
//!                 content: "val".to_string(),
//!                 start_index: 14,
//!                 end_index: 17,
//!                 line_col: (1, 15),
//!             }],
//!             assigned_variables: vec![],
//!         },
//!         is_flag: false,
//!     }],
//!     is_self_closing: false,
//! });
//! ```

use pyo3::prelude::*;

use crate::grammar::Rule;

// #########################################################
// VALUES
// #########################################################

/// Child value that can be either a TagValue or a Template
///
/// Used in `TagValue.children` to support nested templates in template strings
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub enum ValueChild {
    Value(TagValue),
}

impl ValueChild {
    pub fn as_value(&self) -> Option<&TagValue> {
        // Extract the value from ValueChild
        match self {
            ValueChild::Value(v) => Some(v),
        }
    }
}

#[pymethods]
impl ValueChild {
    #[new]
    fn new(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        // Try to extract as TagValue first
        if let Ok(value) = obj.extract::<TagValue>() {
            return Ok(ValueChild::Value(value));
        }

        // If neither works, return an error
        Err(pyo3::exceptions::PyTypeError::new_err(
            "ValueChild must be created with either a TagValue or Template",
        ))
    }

    fn __eq__(&self, other: &ValueChild) -> bool {
        match (self, other) {
            (ValueChild::Value(a), ValueChild::Value(b)) => a == b,
            _ => false,
        }
    }

    fn __repr__(&self) -> String {
        match self {
            ValueChild::Value(v) => format!("ValueChild::Value({:?})", v),
        }
    }
}

/// Top-level tag attribute, e.g. `key=my_var` or without key like `my_var|filter`
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct TagAttr {
    /// Token containing the entire attribute span (key + value with filters)
    #[pyo3(get)]
    pub token: Token,
    /// Key token if this is a key-value pair (e.g., "key" in key=value)
    #[pyo3(get)]
    pub key: Option<Token>,
    #[pyo3(get)]
    pub value: TagValue,
    #[pyo3(get)]
    pub is_flag: bool,
}

#[pymethods]
impl TagAttr {
    // These methods with `[new]` will become constructors (`__new__()`)
    // See https://pyo3.rs/main/class.html#constructor
    #[new]
    #[pyo3(signature = (token, key, value, is_flag))]
    fn new(token: Token, key: Option<Token>, value: TagValue, is_flag: bool) -> Self {
        Self {
            token,
            key,
            value,
            is_flag,
        }
    }

    // Allow to compare objects with `==`
    fn __eq__(&self, other: &TagAttr) -> bool {
        self.token == other.token
            && self.key == other.key
            && self.value == other.value
            && self.is_flag == other.is_flag
    }

    fn __repr__(&self) -> String {
        format!(
            "TagAttr(token={:?}, key={:?}, value={:?}, is_flag={})",
            self.token, self.key, self.value, self.is_flag
        )
    }
}

#[pyclass(eq, eq_int)]
#[derive(Debug, PartialEq, Clone)]
pub enum ValueKind {
    List,
    Dict,
    Int,
    Float,
    Variable,
    TemplateString, // A string that contains a Django template tags, e.g. `"{{ my_var }}"`
    Translation,
    String,
    PythonExpr, // A Python expression wrapped in parentheses, e.g. `("hello".upper())`
}

#[pymethods]
impl ValueKind {
    #[new]
    fn new(kind: &str) -> PyResult<Self> {
        match kind {
            "list" => Ok(ValueKind::List),
            "dict" => Ok(ValueKind::Dict),
            "int" => Ok(ValueKind::Int),
            "float" => Ok(ValueKind::Float),
            "variable" => Ok(ValueKind::Variable),
            "template_string" => Ok(ValueKind::TemplateString),
            "translation" => Ok(ValueKind::Translation),
            "string" => Ok(ValueKind::String),
            "python_expr" => Ok(ValueKind::PythonExpr),
            _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid ValueKind: {}",
                kind
            ))),
        }
    }

    fn __str__(&self) -> String {
        match self {
            ValueKind::List => "list".to_string(),
            ValueKind::Dict => "dict".to_string(),
            ValueKind::Int => "int".to_string(),
            ValueKind::Float => "float".to_string(),
            ValueKind::Variable => "variable".to_string(),
            ValueKind::TemplateString => "template_string".to_string(),
            ValueKind::Translation => "translation".to_string(),
            ValueKind::String => "string".to_string(),
            ValueKind::PythonExpr => "python_expr".to_string(),
        }
    }
}

/// Metadata of a matched token with its position information
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct Token {
    /// String content of the token
    #[pyo3(get)]
    pub content: String,
    /// Start index in the original input string
    #[pyo3(get)]
    pub start_index: usize,
    /// End index in the original input string
    #[pyo3(get)]
    pub end_index: usize,
    /// Line and column number
    #[pyo3(get)]
    pub line_col: (usize, usize),
}

#[pymethods]
impl Token {
    #[new]
    fn new(
        content: String,
        start_index: usize,
        end_index: usize,
        line_col: (usize, usize),
    ) -> Self {
        Self {
            content,
            start_index,
            end_index,
            line_col,
        }
    }

    fn __eq__(&self, other: &Token) -> bool {
        self.content == other.content
            && self.start_index == other.start_index
            && self.end_index == other.end_index
            && self.line_col == other.line_col
    }

    fn __repr__(&self) -> String {
        format!(
            "Token(content='{}', start_index={}, end_index={}, line_col={:?})",
            self.content, self.start_index, self.end_index, self.line_col
        )
    }
}

// Rust-only methods
impl Token {
    /// Create a Token from a pest Pair without applying any offsets
    ///
    /// This extracts the raw position information and content from the pair.
    pub fn from_pair(pair: &pest::iterators::Pair<'_, Rule>) -> Self {
        let span = pair.as_span();
        let (line, col) = pair.line_col();
        let content = pair.as_str().to_string();

        Self {
            content,
            start_index: span.start(),
            end_index: span.end(),
            line_col: (line, col),
        }
    }

    /// Apply column offsets to this token, adjusting content and positions
    ///
    /// # Arguments
    /// * `col_start_offset` - Offset to apply to start position (positive = skip chars at start, negative = extend before)
    /// * `col_end_offset` - Offset to apply to end position (positive = extend after, negative = skip chars at end)
    ///
    /// When offsets are non-zero, the content will be sliced to match the adjusted boundaries.
    ///
    /// # Examples
    /// For a comment `{# text #}`:
    /// - `col_start_offset: 2` skips `{#` at the start
    /// - `col_end_offset: -2` skips `#}` at the end
    pub fn crop_cols(mut self, col_start_offset: isize, col_end_offset: isize) -> Self {
        // Adjust indices
        self.start_index = (self.start_index as isize + col_start_offset) as usize;
        self.end_index = (self.end_index as isize + col_end_offset) as usize;

        // Adjust column (only on first line)
        let (line, col) = self.line_col;
        if line == 1 {
            self.line_col = (line, (col as isize + col_start_offset) as usize);
        }

        // Slice the content to match the adjusted boundaries
        if col_start_offset != 0 || col_end_offset != 0 {
            let content_start = col_start_offset.max(0) as usize;
            let content_end = (self.content.len() as isize + col_end_offset) as usize;
            if content_start < content_end && content_end <= self.content.len() {
                self.content = self.content[content_start..content_end].to_string();
            } else {
                self.content = String::new();
            }
        }

        self
    }

    /// Offset a token by adjusting its indices, line, and column positions.
    /// This is used when a token's positions need to be adjusted relative to a different source context.
    ///
    /// - `index_offset`: Amount to add to start_index and end_index
    /// - `line_offset`: Amount to add to the line number (lines are 1-indexed, so this is added directly)
    /// - `col_offset`: Amount to add to the column (only applied to the first line, columns are 1-indexed)
    pub fn offset(mut self, index_offset: usize, line_offset: usize, col_offset: usize) -> Self {
        // Adjust indices
        self.start_index += index_offset;
        self.end_index += index_offset;

        // Adjust line and column
        let (line, col) = self.line_col;
        let adjusted_line = line + line_offset;

        // Column offset only applies to the first line
        let adjusted_col = if line == 1 { col + col_offset } else { col };

        self.line_col = (adjusted_line, adjusted_col);
        self
    }
}

/// Metadata about how some piece of text will be interpreted in Python.
///
/// E.g. `my_var.item_count` is a variable, while `[1, 2, 3]` is a list of int literals, etc.
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct TagValue {
    /// Token containing the entire value span including filters and spread
    #[pyo3(get)]
    pub token: Token,
    /// Token for just the value itself (excluding filters and spread)
    #[pyo3(get)]
    pub value: Token,
    /// Children of this TagValue - e.g. list items like `[1, 2, 3]` or dict key-value entries like `{"key": "value"}`
    /// For TemplateString, contains the parsed Template structure
    pub children: Vec<ValueChild>,

    #[pyo3(get)]
    pub kind: ValueKind,
    #[pyo3(get)]
    pub spread: Option<String>,
    #[pyo3(get)]
    pub filters: Vec<TagValueFilter>,
    /// Context variables that this TagValue needs
    #[pyo3(get)]
    pub used_variables: Vec<Token>,
    /// Context variables that this TagValue introduces
    #[pyo3(get)]
    pub assigned_variables: Vec<Token>,
}

#[pymethods]
impl TagValue {
    #[new]
    #[pyo3(signature = (token, value, kind, spread, filters, used_variables, assigned_variables, children))]
    fn new(
        token: Token,
        value: Token,
        kind: ValueKind,
        spread: Option<String>,
        filters: Vec<TagValueFilter>,
        used_variables: Vec<Token>,
        assigned_variables: Vec<Token>,
        children: Vec<ValueChild>,
    ) -> Self {
        Self {
            token,
            value,
            children,
            kind,
            spread,
            filters,
            used_variables,
            assigned_variables,
        }
    }

    fn __eq__(&self, other: &TagValue) -> bool {
        self.token == other.token
            && self.value == other.value
            && self.children == other.children
            && self.kind == other.kind
            && self.spread == other.spread
            && self.filters == other.filters
            && self.used_variables == other.used_variables
            && self.assigned_variables == other.assigned_variables
    }

    fn __repr__(&self) -> String {
        format!(
            "TagValue(token={:?}, value={:?}, children={:?}, kind={:?}, spread={:?}, filters={:?}, used_variables={:?}, assigned_variables={:?})",
            self.token, self.value, self.children, self.kind, self.spread, self.filters, self.used_variables, self.assigned_variables
        )
    }
}

/// Filter applied to a value.
///
/// E.g. `my_var|upper` is a filter `upper` applied to the variable `my_var`.
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct TagValueFilter {
    /// Token containing the entire filter span including `|`, `:`, and argument
    #[pyo3(get)]
    pub token: Token,
    /// Token for just the filter name
    #[pyo3(get)]
    pub name: Token,
    /// Argument of the filter, e.g. `my_var`
    #[pyo3(get)]
    pub arg: Option<TagValue>,
}

#[pymethods]
impl TagValueFilter {
    #[new]
    #[pyo3(signature = (token, name, arg))]
    fn new(token: Token, name: Token, arg: Option<TagValue>) -> Self {
        Self { token, name, arg }
    }

    fn __eq__(&self, other: &TagValueFilter) -> bool {
        self.token == other.token && self.name == other.name && self.arg == other.arg
    }

    fn __repr__(&self) -> String {
        format!(
            "TagValueFilter(token={:?}, name={:?}, arg={:?})",
            self.token, self.name, self.arg
        )
    }
}

// #########################################################
// COMMENTS
// #########################################################

/// Represents a Django template comment `{# ... #}` or `{% comment %}...{% endcomment %}`
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct Comment {
    /// Token containing the entire comment span including `{# #}` delimiters
    #[pyo3(get)]
    pub token: Token,
    /// Token for the comment text (without the delimiters)
    #[pyo3(get)]
    pub value: Token,
}

#[pymethods]
impl Comment {
    #[new]
    fn new(token: Token, value: Token) -> Self {
        Self { token, value }
    }

    fn __eq__(&self, other: &Comment) -> bool {
        self.token == other.token && self.value == other.value
    }

    fn __repr__(&self) -> String {
        format!("Comment(token={:?}, value={:?})", self.token, self.value)
    }
}

// #########################################################
// TAGS
// #########################################################

/// Common tag metadata shared by all tag types.
///
/// This contains the core information that every tag has: its token, name,
/// and variable usage information.
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct TagMeta {
    /// Token containing the entire tag span including delimiters (e.g., `{% %}` or `< />`)
    #[pyo3(get)]
    pub token: Token,
    /// Token for the tag name, e.g., 'slot' in `{% slot ... %}`
    #[pyo3(get)]
    pub name: Token,
    /// Context variables that this Tag needs (used variables from all attributes)
    #[pyo3(get)]
    pub used_variables: Vec<Token>,
    /// Context variables that this Tag introduces (assigned variables from all attributes)
    #[pyo3(get)]
    pub assigned_variables: Vec<Token>,
}

#[pymethods]
impl TagMeta {
    #[new]
    fn new(
        token: Token,
        name: Token,
        used_variables: Vec<Token>,
        assigned_variables: Vec<Token>,
    ) -> Self {
        Self {
            token,
            name,
            used_variables,
            assigned_variables,
        }
    }

    fn __eq__(&self, other: &TagMeta) -> bool {
        self.token == other.token
            && self.name == other.name
            && self.used_variables == other.used_variables
            && self.assigned_variables == other.assigned_variables
    }

    fn __repr__(&self) -> String {
        format!(
            "TagMeta(token={:?}, name={:?}, used_variables={:?}, assigned_variables={:?})",
            self.token, self.name, self.used_variables, self.assigned_variables
        )
    }
}

/// Represents a template tag, including its name, attributes, and other metadata.
///
/// Examples:
/// - `{% slot key=val key2=val2 %}`
/// - `{% endslot %}`
/// - `<slot key=val key2=val2 />`
/// - `<slot />`
///
/// Note that this captures only the content between the opening and closing tags.
/// So start and end tags are separate entities. E.g.
///
/// ```django
/// {% component "button" %}
///   Click me!
/// {% endcomponent %}
/// ```
///
/// Is two `GenericTag` nodes:
/// - `{% component "button" %}`
/// - `{% endcomponent %}`
///
/// NOTE: This does NOT contain the forloop `{% for %}` tag,
/// which is a special tag type `ForLoopTag`.
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct GenericTag {
    /// Common tag metadata (token, name, used/assigned variables)
    #[pyo3(get)]
    pub meta: TagMeta,

    /// A list of attributes passed to the tag.
    #[pyo3(get)]
    pub attrs: Vec<TagAttr>,
    /// Whether the tag is self-closing.
    /// E.g. `{% my_tag / %}` or `<my_tag />`.
    #[pyo3(get)]
    pub is_self_closing: bool,
}

#[pymethods]
impl GenericTag {
    #[new]
    fn new(
        token: Token,
        name: Token,
        attrs: Vec<TagAttr>,
        is_self_closing: bool,
        used_variables: Vec<Token>,
        assigned_variables: Vec<Token>,
    ) -> Self {
        Self {
            meta: TagMeta {
                token,
                name,
                used_variables,
                assigned_variables,
            },
            attrs,
            is_self_closing,
        }
    }

    fn __eq__(&self, other: &GenericTag) -> bool {
        self.meta == other.meta
            && self.attrs == other.attrs
            && self.is_self_closing == other.is_self_closing
    }

    fn __repr__(&self) -> String {
        format!(
            "GenericTag(meta={:?}, attrs={:?}, is_self_closing={})",
            self.meta, self.attrs, self.is_self_closing
        )
    }
}

/// Represents a for loop tag: `{% for item in items %}`
/// This is a special tag type that cannot be self-closing and has a specific structure.
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct ForLoopTag {
    /// Common tag metadata (token, name, used/assigned variables)
    #[pyo3(get)]
    pub meta: TagMeta,

    /// The loop variable names (e.g., ["item"] or ["x", "y", "z"])
    #[pyo3(get)]
    pub targets: Vec<Token>,
    /// The iterable expression (can be a variable, Python expression, etc.)
    #[pyo3(get)]
    pub iterable: TagValue,
}

#[pymethods]
impl ForLoopTag {
    #[new]
    fn new(
        token: Token,
        name: Token,
        targets: Vec<Token>,
        iterable: TagValue,
        used_variables: Vec<Token>,
        assigned_variables: Vec<Token>,
    ) -> Self {
        Self {
            meta: TagMeta {
                token,
                name,
                used_variables,
                assigned_variables,
            },
            targets,
            iterable,
        }
    }

    fn __eq__(&self, other: &ForLoopTag) -> bool {
        self.meta == other.meta && self.targets == other.targets && self.iterable == other.iterable
    }

    fn __repr__(&self) -> String {
        format!(
            "ForLoopTag(meta={:?}, targets={:?}, iterable={:?})",
            self.meta, self.targets, self.iterable
        )
    }
}

/// Represents an end tag (e.g., `{% endif %}`, `{% endfor %}`, `</slot>`)
/// End tags cannot have attributes or be self-closing - they only contain the tag name.
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct EndTag {
    /// Common tag metadata (token, name, used/assigned variables)
    /// Note: used_variables and assigned_variables are always empty for end tags
    #[pyo3(get)]
    pub meta: TagMeta,
}

#[pymethods]
impl EndTag {
    #[new]
    fn new(token: Token, name: Token) -> Self {
        Self {
            meta: TagMeta {
                token,
                name,
                used_variables: vec![],
                assigned_variables: vec![],
            },
        }
    }

    fn __eq__(&self, other: &EndTag) -> bool {
        self.meta == other.meta
    }

    fn __repr__(&self) -> String {
        format!("EndTag(meta={:?})", self.meta)
    }
}

/// Represents a template tag - either a generic tag, a for loop tag, or an end tag
#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub enum Tag {
    Generic(GenericTag),
    ForLoop(ForLoopTag),
    End(EndTag),
}

#[pymethods]
impl Tag {
    #[new]
    fn new(
        token: Token,
        name: Token,
        attrs: Vec<TagAttr>,
        is_self_closing: bool,
        used_variables: Vec<Token>,
        assigned_variables: Vec<Token>,
    ) -> Self {
        Self::Generic(GenericTag {
            meta: TagMeta {
                token,
                name,
                used_variables,
                assigned_variables,
            },
            attrs,
            is_self_closing,
        })
    }

    fn __eq__(&self, other: &Tag) -> bool {
        match (self, other) {
            (Tag::Generic(a), Tag::Generic(b)) => a == b,
            (Tag::ForLoop(a), Tag::ForLoop(b)) => a == b,
            (Tag::End(a), Tag::End(b)) => a == b,
            _ => false,
        }
    }

    fn __repr__(&self) -> String {
        match self {
            Tag::Generic(tag) => format!("Tag::Generic({:?})", tag),
            Tag::ForLoop(tag) => format!("Tag::ForLoop({:?})", tag),
            Tag::End(tag) => format!("Tag::End({:?})", tag),
        }
    }
}

// Private Rust-only methods for Tag
impl Tag {
    pub fn name(&self) -> String {
        let tag_name = match self {
            Tag::Generic(generic_tag) => generic_tag.meta.name.content.clone(),
            Tag::ForLoop(for_loop_tag) => for_loop_tag.meta.name.content.clone(),
            Tag::End(end_tag) => end_tag.meta.name.content.clone(),
        };
        tag_name
    }

    pub fn token(&self) -> &Token {
        let token = match self {
            Tag::Generic(generic_tag) => &generic_tag.meta.token,
            Tag::ForLoop(for_loop_tag) => &for_loop_tag.meta.token,
            Tag::End(end_tag) => &end_tag.meta.token,
        };
        token
    }

    pub fn as_generic(&self) -> Option<&GenericTag> {
        match self {
            Tag::Generic(generic_tag) => Some(generic_tag),
            Tag::ForLoop(_) | Tag::End(_) => None,
        }
    }

    pub fn as_forloop(&self) -> Option<&ForLoopTag> {
        match self {
            Tag::ForLoop(for_loop_tag) => Some(for_loop_tag),
            Tag::Generic(_) | Tag::End(_) => None,
        }
    }

    pub fn as_end(&self) -> Option<&EndTag> {
        match self {
            Tag::End(end_tag) => Some(end_tag),
            Tag::Generic(_) | Tag::ForLoop(_) => None,
        }
    }
}

// #########################################################
// TEMPLATE
// #########################################################

/// Template version enum
/// - V1: Current implementation - Template parsed by Django, we parse only component tags
/// - V2: We parse the entire template. Only BaseNode tags are allowed.
///       Django variables, filters, and translations (AKA Django template data types) are allowed
/// - V3: We parse the entire template. Only BaseNode tags are allowed.
///       BUT only Python expressions and TemplateStrings are allowed. They no longer need to be wrapped in () in `{{ }}`
///       So syntax looks a bit like React, but with () instead of {}:
///       ```
///       {% table data=([[1, 2, 3], [4, 5, 6]]) %}
///       ```
///       Other literal data types that in V1 and V2 could've been used without parentheses,
///       like variables, lists, dicts, strings, numbers, translations, etc are now assumed
///       to be python expressions. So this:
///       ```
///       {% table data=[[1, 2, 3], [4, 5, 6]] %}
///       ```
///       is now interpreted as:
///       ```
///       {% table data=([[1, 2, 3], [4, 5, 6]]) %}
///       ```
///       So the logic for handling tag attributes is:
///       1. Does it start with a parenthesis, string, or something else?
///         1.1 parenthesis - It's a Python expression ✅
///         1.2 string - Is it regular string or TemplateString?
///           1.2.1 regular (no `{{ }}`, `{% %}`, `{# #}`) - Wrap in parenthesis and treat as Python expression ✅
///           1.2.2 TemplateString - parse with `parse_template()` ✅
///         1.3 other (e.g. literal list or dict) - Wrap in parentheses
///           1.3.1 literal list or dict - Wrap in parentheses until the closing `]` or `}` ✅
///           1.3.2 variable - Wrap in parentheses until whitespace or the end of the tag ✅
///           1.3.3 other - Wrap in parentheses until whitespace or the end of the tag ✅
#[pyclass(eq, eq_int)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TemplateVersion {
    V1,
    V2, // TODO - NOT IMPLEMENTED YET
    V3, // TODO - NOT IMPLEMENTED YET
}

#[pymethods]
impl TemplateVersion {
    // This is for interop with Python, so that in Python we can do `TemplateVersion("1")` or `TemplateVersion("v1")`
    #[new]
    fn new(version: &str) -> PyResult<Self> {
        match version {
            "1" | "v1" => Ok(TemplateVersion::V1),
            "2" | "v2" => Ok(TemplateVersion::V2),
            "3" | "v3" => Ok(TemplateVersion::V3),
            _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid TemplateVersion: {}. Only '1'/'v1', '2'/'v2', and '3'/'v3' are supported.",
                version
            ))),
        }
    }

    // Allow to use in Python as `TemplateVersion.v1` and `TemplateVersion.v2`
    #[classattr]
    fn v1() -> Self {
        TemplateVersion::V1
    }

    #[classattr]
    fn v2() -> Self {
        TemplateVersion::V2
    }

    #[classattr]
    fn v3() -> Self {
        TemplateVersion::V3
    }

    fn __str__(&self) -> String {
        match self {
            TemplateVersion::V1 => "1".to_string(),
            TemplateVersion::V2 => "2".to_string(),
            TemplateVersion::V3 => "3".to_string(),
        }
    }
}
