//! # Django Template Tag Compiler
//!
//! This module translates parsed AST representations of Django template tags (e.g. `{% component %}`)
//! into a code definition of a callable Python function (e.g. `def func(context, ...):\n    ...`)
//!
//! The generated function takes a `context` object and returns a tuple of (arguments, keyword arguments).
//!
//! ## Value handling
//!
//! - Variables: `my_var` -> `variable(context, source, ..., 'my_var')`
//! - Filters: `my_var|filter1|filter2:arg` -> `filter(context, source, ..., 'filter1', 'filter2', 'arg', my_var)`
//! - Translations: `_('my_str')` -> `translation(context, source, ..., 'my_str')`
//! - Template strings: `{{ my_var }}` -> `template_string(context, source, ..., '{{ my_var }}')`
//! - Python expressions: `(my_var + 1)` -> `expr(context, source, ..., 'my_var + 1')`
//! - Lists: `[1, 2, my_var]` -> `[1, 2, variable(..., 'my_var')]`
//! - Dicts: `{"key": my_var}` -> `{"key": variable(..., 'my_var')}`
//!
//! ## Other features
//!
//! - Maintains Python-like behavior with positional args before keyword args
//! - `...my_var` is treated as positional args if a list, or as kwargs if a dict
//! - Compile-time detection of invalid argument ordering

pub use crate::ast::{TagAttr, TagValue, ValueChild, ValueKind};
use crate::error::CompileError;
use crate::utils::text::indent_body;

/// Compile a list of parsed tag attributes into a Python code defining a function.
pub fn compile_tag_attrs(attributes: &[TagAttr]) -> Result<String, CompileError> {
    let mut body = String::new();
    // We want to keep Python-like behaviour with args having to come before kwargs.
    // When we have only args and kwargs, we can check at compile-time whether
    // there are any args after kwargs, and raise an error if so.
    // But if there is a spread (`...var`) then this has to be handled at runtime,
    // because we don't know if `var` is a mapping or an iterable.
    //
    // So what we do is that we preferentially raise an error at compile-time.
    // And once we come across a spread (`...var`), then we set `kwarg_seen` also in Python,
    // and run the checks in both Python and Rust.
    let mut has_spread = false;
    let mut kwarg_seen = false;

    for attr in attributes {
        if attr.is_flag {
            continue;
        }

        if let Some(key) = &attr.key {
            // It's a kwarg: key=value
            // Kwargs are stored as tuples in the kwargs list so that there can be
            // multiple kwargs with the same key.
            let value_str = compile_value(&attr.value)?;
            body.push_str(&format!(
                "kwargs.append(('{}', {}))\n",
                key.content, value_str
            ));
            // Spreads have to be handled at runtime. But before we come across a spread,
            // we can check solely at compile-time whether there are any args after kwargs,
            // which should raise an error.
            if !kwarg_seen {
                if has_spread {
                    body.push_str("kwarg_seen = True\n");
                }
                kwarg_seen = true;
            }
        } else if attr.value.spread.is_some() {
            // It's a spread: ...value
            if !has_spread {
                has_spread = true;
                // First time we come across a spread,
                // start tracking arg/kwarg orders at run time,
                // because we need the Context to know if this spread is a dict or an iterable.
                body.push_str(&format!(
                    "kwarg_seen = {}\n",
                    if kwarg_seen { "True" } else { "False" }
                ));
            }
            let value_str = compile_value(&attr.value)?;
            let raw_token_str = escape_and_wrap_triple_quotes(&attr.value.value.content);
            body.push_str(&format!(
                // NOTE: `_handle_spread()` is defined in Python side. It checks at runtime if
                //       the value is a mapping or an iterable, and handles it accordingly.
                //       So that if the spread is a list, it will be treated as a positional arg,
                //       and if it's a dict, it will be treated as a keyword arg.
                //       Thus, if positional args are after kwargs, we raise an error at runtime.
                // NOTE: Wrap the raw token in triple quotes because it may contain newlines
                "kwarg_seen = _handle_spread({}, {}, args, kwargs, kwarg_seen)\n",
                value_str, raw_token_str
            ));
        } else {
            // This is a positional arg: value
            // Capture args after kwargs at compile time
            if kwarg_seen {
                return Err(CompileError::Syntax(
                    "positional argument follows keyword argument".to_string(),
                ));
            }
            // Capture args after kwargs at run time
            if has_spread {
                body.push_str("if kwarg_seen:\n");
                body.push_str(
                    "    raise SyntaxError(\"positional argument follows keyword argument\")\n",
                );
            }
            let value_str = compile_value(&attr.value)?;
            body.push_str(&format!("args.append({})\n", value_str));
        }
    }

    let mut final_code = String::new();
    final_code.push_str("def compiled_func(context):");
    final_code.push_str("\n");
    final_code.push_str("    args = []\n");
    final_code.push_str("    kwargs = []\n");
    if !body.trim().is_empty() {
        final_code.push_str(&indent_body(&body, 4));
        final_code.push_str("\n");
    }
    final_code.push_str("    return args, kwargs");

    Ok(final_code)
}

/// Escape backslashes and double quotes, and wrap in triple quotes for Python string literals.
/// This handles newlines and special characters safely.
fn escape_and_wrap_triple_quotes(content: &str) -> String {
    let escaped = content.replace("\\", "\\\\").replace("\"", "\\\"");
    format!("\"\"\"{}\"\"\"", escaped)
}

pub fn compile_value(value: &TagValue) -> Result<String, CompileError> {
    // Helper to format token tuple: (start_index, end_index)
    let token_tuple = format!("({}, {})", value.token.start_index, value.token.end_index);

    let compiled_value = match value.kind {
        ValueKind::Int | ValueKind::Float => Ok(value.value.content.clone()),
        ValueKind::String => {
            // The token includes quotes, which is what we want for a Python string literal
            Ok(value.value.content.clone())
        }
        ValueKind::Variable => {
            let wrapped = escape_and_wrap_triple_quotes(&value.value.content);
            Ok(format!(
                "variable(context, source, {}, filters, tags, {})",
                token_tuple, wrapped
            ))
        }
        ValueKind::TemplateString => {
            // Strip surrounding quotes if present
            let content = value.value.content.trim();
            let content = if (content.starts_with('"') && content.ends_with('"'))
                || (content.starts_with('\'') && content.ends_with('\''))
            {
                &content[1..content.len() - 1]
            } else {
                content
            };
            let wrapped = escape_and_wrap_triple_quotes(content);
            Ok(format!(
                "template_string(context, source, {}, filters, tags, {})",
                token_tuple, wrapped
            ))
        }
        ValueKind::Translation => {
            let inner_string_start = value.value.content.find('(').map(|i| i + 1).unwrap_or(0);
            let inner_string_end = value
                .value
                .content
                .rfind(')')
                .unwrap_or(value.value.content.len());
            if inner_string_start > 0 && inner_string_end > inner_string_start {
                let inner_string = &value.value.content[inner_string_start..inner_string_end];
                // Strip surrounding quotes if present
                let content = inner_string.trim();
                let content = if (content.starts_with('"') && content.ends_with('"'))
                    || (content.starts_with('\'') && content.ends_with('\''))
                {
                    &content[1..content.len() - 1]
                } else {
                    content
                };
                let wrapped = escape_and_wrap_triple_quotes(content);
                Ok(format!(
                    "translation(context, source, {}, filters, tags, {})",
                    token_tuple, wrapped
                ))
            } else {
                Err(CompileError::from(format!(
                    "Invalid translation string format: {}",
                    value.value.content
                )))
            }
        }
        ValueKind::PythonExpr => {
            // Python expression includes parentheses - take entire expression as-is
            // Escape double quotes and wrap in triple quotes to handle newlines
            let wrapped = escape_and_wrap_triple_quotes(&value.value.content);
            Ok(format!(
                "expr(context, source, {}, filters, tags, {})",
                token_tuple, wrapped
            ))
        }
        ValueKind::List => {
            let mut items = Vec::new();
            for child in &value.children {
                let item = child.as_value().ok_or_else(|| {
                    CompileError::from("Can't extract value from Template structure")
                })?;
                let compiled_item = compile_value(&item)?;
                if item.spread.is_some() {
                    items.push(format!("*{}", compiled_item));
                } else {
                    items.push(compiled_item);
                }
            }
            Ok(format!("[{}]", items.join(", ")))
        }
        ValueKind::Dict => {
            let mut items = Vec::new();
            let mut children_iter = value.children.iter();
            while let Some(child) = children_iter.next() {
                let item = child.as_value().ok_or_else(|| {
                    CompileError::from("Can't extract value from Template structure")
                })?;

                if item.spread.is_some() {
                    items.push(format!("**{}", compile_value(&item)?));
                } else {
                    // This is a key, next must be value
                    let key = item;
                    let value_child = children_iter.next().ok_or_else(|| {
                        CompileError::from("Dict AST has uneven number of key-value children")
                    })?;
                    let value = value_child.as_value().ok_or_else(|| {
                        CompileError::from("Can't extract value from Template structure")
                    })?;

                    let compiled_key = compile_value(key)?;
                    let compiled_value = compile_value(value)?;
                    items.push(format!("{}: {}", compiled_key, compiled_value));
                }
            }
            Ok(format!("{{{}}}", items.join(", ")))
        }
    };

    let mut result = compiled_value?;

    // Apply filters
    for filter in &value.filters {
        let filter_name = &filter.name.content;
        let filter_token_tuple =
            format!("({}, {})", filter.token.start_index, filter.token.end_index);
        if let Some(arg) = &filter.arg {
            let compiled_arg = compile_value(arg)?;
            result = format!(
                "filter(context, source, {}, filters, tags, '{}', {}, {})",
                filter_token_tuple, filter_name, result, compiled_arg
            );
        } else {
            result = format!(
                "filter(context, source, {}, filters, tags, '{}', {}, None)",
                filter_token_tuple, filter_name, result
            );
        }
    }

    Ok(result)
}
