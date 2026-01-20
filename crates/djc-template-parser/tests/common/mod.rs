use djc_template_parser::ast::{
    Tag, TagAttr, TagValue, TagValueFilter, TemplateVersion, Token, ValueKind,
};
use djc_template_parser::tag_parser::TagParser;
use djc_template_parser::{ParseError, ParserConfig, ParserContext};

/// Helper function to create a Token struct
/// Takes content, start_index, line number, and column number
/// Calculates end_index automatically as start_index + content.len()
pub fn token(content: &str, start_index: usize, line: usize, col: usize) -> Token {
    Token {
        content: content.to_string(),
        start_index,
        end_index: start_index + content.len(),
        line_col: (line, col),
    }
}

/// Helper function to create a TagAttr
/// Takes key (optional), value, and is_flag
/// Calculates the token field internally from key token + "=" + value token
/// If key is None, the token is just the value token
pub fn tag_attr(key: Option<Token>, value: TagValue, is_flag: bool) -> TagAttr {
    let attr_token = if let Some(ref key_token) = key {
        // Calculate token content: key + "=" + value.token.content
        let token_content = format!("{}={}", key_token.content, value.token.content);
        Token {
            content: token_content,
            start_index: key_token.start_index,
            end_index: value.token.end_index,
            line_col: key_token.line_col,
        }
    } else {
        // If no key, token is just the value token
        value.token.clone()
    };
    TagAttr {
        token: attr_token,
        key,
        value,
        is_flag,
    }
}

/// Helper function to create a plain TagValue with ValueKind::String.
/// No filters, no children, and no used/assigned variables
/// If spread is provided, the token includes the spread prefix, but value does not
pub fn plain_string_value(
    content: &str,
    start_index: usize,
    line: usize,
    col: usize,
    spread: Option<&str>,
) -> TagValue {
    let (token_val, value_token) = if let Some(spread_str) = spread {
        let token_content = format!("{}{}", spread_str, content);
        let value_start_index = start_index + spread_str.len();
        let value_col = col + spread_str.len();
        (
            token(&token_content, start_index, line, col),
            token(content, value_start_index, line, value_col),
        )
    } else {
        let token_val = token(content, start_index, line, col);
        (token_val.clone(), token_val)
    };
    TagValue {
        token: token_val,
        value: value_token,
        children: vec![],
        kind: ValueKind::String,
        spread: spread.map(|s| s.to_string()),
        filters: vec![],
        used_variables: vec![],
        assigned_variables: vec![],
    }
}

/// Helper function to create a plain TagValue with ValueKind::Int.
/// No filters, no children, and no used/assigned variables
/// If spread is provided, the token includes the spread prefix, but value does not
pub fn plain_int_value(
    content: &str,
    start_index: usize,
    line: usize,
    col: usize,
    spread: Option<&str>,
) -> TagValue {
    let (token_val, value_token) = if let Some(spread_str) = spread {
        let token_content = format!("{}{}", spread_str, content);
        let value_start_index = start_index + spread_str.len();
        let value_col = col + spread_str.len();
        (
            token(&token_content, start_index, line, col),
            token(content, value_start_index, line, value_col),
        )
    } else {
        let token_val = token(content, start_index, line, col);
        (token_val.clone(), token_val)
    };
    TagValue {
        token: token_val,
        value: value_token,
        children: vec![],
        kind: ValueKind::Int,
        spread: spread.map(|s| s.to_string()),
        filters: vec![],
        used_variables: vec![],
        assigned_variables: vec![],
    }
}

/// Helper function to create a plain TagValue with ValueKind::Float.
/// No filters, no children, and no used/assigned variables
/// If spread is provided, the token includes the spread prefix, but value does not
pub fn plain_float_value(
    content: &str,
    start_index: usize,
    line: usize,
    col: usize,
    spread: Option<&str>,
) -> TagValue {
    let (token_val, value_token) = if let Some(spread_str) = spread {
        let token_content = format!("{}{}", spread_str, content);
        let value_start_index = start_index + spread_str.len();
        let value_col = col + spread_str.len();
        (
            token(&token_content, start_index, line, col),
            token(content, value_start_index, line, value_col),
        )
    } else {
        let token_val = token(content, start_index, line, col);
        (token_val.clone(), token_val)
    };
    TagValue {
        token: token_val,
        value: value_token,
        children: vec![],
        kind: ValueKind::Float,
        spread: spread.map(|s| s.to_string()),
        filters: vec![],
        used_variables: vec![],
        assigned_variables: vec![],
    }
}

/// Helper function to create a plain TagValue with ValueKind::Translation.
/// No filters, no children, and no used/assigned variables
/// If spread is provided, the token includes the spread prefix, but value does not
pub fn plain_translation_value(
    content: &str,
    start_index: usize,
    line: usize,
    col: usize,
    spread: Option<&str>,
) -> TagValue {
    let (token_val, value_token) = if let Some(spread_str) = spread {
        let token_content = format!("{}{}", spread_str, content);
        let value_start_index = start_index + spread_str.len();
        let value_col = col + spread_str.len();
        (
            token(&token_content, start_index, line, col),
            token(content, value_start_index, line, value_col),
        )
    } else {
        let token_val = token(content, start_index, line, col);
        (token_val.clone(), token_val)
    };
    TagValue {
        token: token_val,
        value: value_token,
        children: vec![],
        kind: ValueKind::Translation,
        spread: spread.map(|s| s.to_string()),
        filters: vec![],
        used_variables: vec![],
        assigned_variables: vec![],
    }
}

/// Helper function to create a plain TagValue with ValueKind::Variable.
/// No filters, no children, and no assigned_variables
/// Populates used_variables with a single token for the root variable name
/// (the part before the first dot, or the entire variable if no dots)
/// If spread is provided, the token includes the spread prefix, but value does not
pub fn plain_variable_value(
    content: &str,
    start_index: usize,
    line: usize,
    col: usize,
    spread: Option<&str>,
) -> TagValue {
    let (token_val, value_token) = if let Some(spread_str) = spread {
        let token_content = format!("{}{}", spread_str, content);
        let value_start_index = start_index + spread_str.len();
        let value_col = col + spread_str.len();
        (
            token(&token_content, start_index, line, col),
            token(content, value_start_index, line, value_col),
        )
    } else {
        let token_val = token(content, start_index, line, col);
        (token_val.clone(), token_val)
    };
    // Extract root variable name (everything before first dot, or entire content if no dot)
    let root_var = content.split('.').next().unwrap_or(content);
    let used_var_start_index = if let Some(spread_str) = spread {
        start_index + spread_str.len()
    } else {
        start_index
    };
    let used_var_col = if let Some(spread_str) = spread {
        col + spread_str.len()
    } else {
        col
    };
    let used_var_token = token(root_var, used_var_start_index, line, used_var_col);
    TagValue {
        token: token_val,
        value: value_token,
        children: vec![],
        kind: ValueKind::Variable,
        spread: spread.map(|s| s.to_string()),
        filters: vec![],
        used_variables: vec![used_var_token],
        assigned_variables: vec![],
    }
}

/// Helper function to create a TagValue with ValueKind::String
/// Creates a TagValue with empty children
pub fn string_value(
    token: Token,
    value: Token,
    spread: Option<&str>,
    filters: Vec<TagValueFilter>,
    used_variables: Vec<Token>,
    assigned_variables: Vec<Token>,
) -> TagValue {
    TagValue {
        token,
        value,
        children: vec![],
        kind: ValueKind::String,
        spread: spread.map(|s| s.to_string()),
        filters,
        used_variables,
        assigned_variables,
    }
}

/// Helper function to create a TagValue with ValueKind::Int
/// Creates a TagValue with empty children
pub fn int_value(
    token: Token,
    value: Token,
    spread: Option<&str>,
    filters: Vec<TagValueFilter>,
    used_variables: Vec<Token>,
    assigned_variables: Vec<Token>,
) -> TagValue {
    TagValue {
        token,
        value,
        children: vec![],
        kind: ValueKind::Int,
        spread: spread.map(|s| s.to_string()),
        filters,
        used_variables,
        assigned_variables,
    }
}

/// Helper function to create a TagValue with ValueKind::Variable
/// Creates a TagValue with empty children
/// Automatically computes and adds the root variable name (before first dot) to used_variables
pub fn variable_value(
    full_token: Token,
    value: Token,
    spread: Option<&str>,
    filters: Vec<TagValueFilter>,
    mut used_variables: Vec<Token>,
    assigned_variables: Vec<Token>,
) -> TagValue {
    // Extract root variable name (everything before first dot, or entire value if no dot)
    let root_var = value
        .content
        .split('.')
        .next()
        .unwrap_or(value.content.as_str());
    let used_var_token = token(
        root_var,
        value.start_index,
        value.line_col.0,
        value.line_col.1,
    );
    used_variables.push(used_var_token);
    TagValue {
        token: full_token,
        value,
        children: vec![],
        kind: ValueKind::Variable,
        spread: spread.map(|s| s.to_string()),
        filters,
        used_variables,
        assigned_variables,
    }
}

/// Helper function to create a TagValue with ValueKind::Float
/// Creates a TagValue with empty children
pub fn float_value(
    token: Token,
    value: Token,
    spread: Option<&str>,
    filters: Vec<TagValueFilter>,
    used_variables: Vec<Token>,
    assigned_variables: Vec<Token>,
) -> TagValue {
    TagValue {
        token,
        value,
        children: vec![],
        kind: ValueKind::Float,
        spread: spread.map(|s| s.to_string()),
        filters,
        used_variables,
        assigned_variables,
    }
}

/// Helper function to create a TagValue with ValueKind::Translation
/// Creates a TagValue with empty children
pub fn translation_value(
    token: Token,
    value: Token,
    spread: Option<&str>,
    filters: Vec<TagValueFilter>,
    used_variables: Vec<Token>,
    assigned_variables: Vec<Token>,
) -> TagValue {
    TagValue {
        token,
        value,
        children: vec![],
        kind: ValueKind::Translation,
        spread: spread.map(|s| s.to_string()),
        filters,
        used_variables,
        assigned_variables,
    }
}

/// Helper function to create a plain TagValue with ValueKind::TemplateString.
/// No filters, no children, and no used/assigned variables
/// If spread is provided, the token includes the spread prefix, but value does not
pub fn plain_template_string_value(
    content: &str,
    start_index: usize,
    line: usize,
    col: usize,
    spread: Option<&str>,
) -> TagValue {
    let (token_val, value_token) = if let Some(spread_str) = spread {
        let token_content = format!("{}{}", spread_str, content);
        let value_start_index = start_index + spread_str.len();
        let value_col = col + spread_str.len();
        (
            token(&token_content, start_index, line, col),
            token(content, value_start_index, line, value_col),
        )
    } else {
        let token_val = token(content, start_index, line, col);
        (token_val.clone(), token_val)
    };
    TagValue {
        token: token_val,
        value: value_token,
        children: vec![],
        kind: ValueKind::TemplateString,
        spread: spread.map(|s| s.to_string()),
        filters: vec![],
        used_variables: vec![],
        assigned_variables: vec![],
    }
}

/// Helper function to create a TagValue with ValueKind::TemplateString
/// Creates a TagValue with empty children
pub fn template_string_value(
    token: Token,
    value: Token,
    spread: Option<&str>,
    filters: Vec<TagValueFilter>,
    used_variables: Vec<Token>,
    assigned_variables: Vec<Token>,
) -> TagValue {
    TagValue {
        token,
        value,
        children: vec![],
        kind: ValueKind::TemplateString,
        spread: spread.map(|s| s.to_string()),
        filters,
        used_variables,
        assigned_variables,
    }
}

/// Helper function to create a plain TagValue with ValueKind::PythonExpr.
/// No filters, no children, and no used/assigned variables
/// If spread is provided, the token includes the spread prefix, but value does not
pub fn plain_python_expr_value(
    content: &str,
    start_index: usize,
    line: usize,
    col: usize,
    spread: Option<&str>,
) -> TagValue {
    let (token_val, value_token) = if let Some(spread_str) = spread {
        let token_content = format!("{}{}", spread_str, content);
        let value_start_index = start_index + spread_str.len();
        let value_col = col + spread_str.len();
        (
            token(&token_content, start_index, line, col),
            token(content, value_start_index, line, value_col),
        )
    } else {
        let token_val = token(content, start_index, line, col);
        (token_val.clone(), token_val)
    };
    TagValue {
        token: token_val,
        value: value_token,
        children: vec![],
        kind: ValueKind::PythonExpr,
        spread: spread.map(|s| s.to_string()),
        filters: vec![],
        used_variables: vec![],
        assigned_variables: vec![],
    }
}

/// Helper function to create a TagValue with ValueKind::PythonExpr
/// Creates a TagValue with empty children
pub fn python_expr_value(
    token: Token,
    value: Token,
    spread: Option<&str>,
    filters: Vec<TagValueFilter>,
    used_variables: Vec<Token>,
    assigned_variables: Vec<Token>,
) -> TagValue {
    TagValue {
        token,
        value,
        children: vec![],
        kind: ValueKind::PythonExpr,
        spread: spread.map(|s| s.to_string()),
        filters,
        used_variables,
        assigned_variables,
    }
}

pub fn plain_parse_tag_v1(input: &str) -> Result<(Tag, ParserContext), ParseError> {
    TagParser::parse_tag(input, &ParserConfig::new(TemplateVersion::V1))
}

pub fn plain_parse_tag_v2(input: &str) -> Result<(Tag, ParserContext), ParseError> {
    TagParser::parse_tag(input, &ParserConfig::new(TemplateVersion::V2))
}
