//! # Django Template Tag Parser
//!
//! This module converts Django template tag strings (e.g. `{% component %}`) into an Abstract Syntax Tree (AST).
//! using [Pest](https://pest.rs/) parsing library.
//!
//! The parsing grammar is defined in `grammar.pest` and supports:
//!
//! ## Features
//!
//! - **Complex value types**: strings, numbers, variables, template_strings, translations, lists, dicts
//! - **Filter chains**: `value|filter1|filter2:arg`
//! - **Spread operators**: `...list` and `**dict`
//! - **Comments**: `{# comment #}` within tag content
//! - **Position tracking**: line/column information for error reporting
//! - **Template string detection**: identifies strings with Django template tags inside them
//! - **Special tag variants**: `{% for ... %}` becomes `ForLoop`, `{% end... %}` becomes `EndTag`,
//!   all other tags are parsed into `GenericTag`.
//!
//! ## Error Handling
//!
//! The parser returns `ParseError` for invalid input, which includes:
//! - Pest parsing errors (syntax violations)
//! - Invalid key errors (for malformed attributes)
//! - Automatic conversion to Python `ValueError` for PyO3 integration

use std::collections::HashSet;

use djc_safe_eval::transformer::{transform_expression_string, Token as SafeEvalToken};
use lazy_static;
use pest::Parser;
use regex;

use crate::ast::{
    Comment, EndTag, ForLoopTag, GenericTag, Tag, TagAttr, TagMeta, TagValue, TagValueFilter,
    TemplateVersion, Token, ValueChild, ValueKind,
};
use crate::error::{assert_rule, assert_rules, ParseError};
use crate::grammar::{GrammarParser, Rule};
use crate::parser_context::ParserContext;
use crate::utils::pest::span_from_str;

pub struct TagParser;

impl TagParser {
    // This is the entrypoint for tag parsing.
    pub fn parse_tag(
        input: &str,
        // Parser config containing information about tags (flags, sections, etc.)
        config: &crate::parser_config::ParserConfig,
    ) -> Result<(Tag, ParserContext), ParseError> {
        let context = ParserContext::new(config)
            .map_err(|e| ParseError::Value(format!("Invalid parser config: {}", e)))?;

        // tag_wrapper
        let wrapper_pair = GrammarParser::parse(Rule::tag_wrapper, input)?
            .next()
            .ok_or_else(|| {
                ParseError::from_span(span_from_str(input), "Empty tag content".to_string())
            })?;
        let wrapper_span = wrapper_pair.as_span();

        // tag_wrapper -> (django_tag | html_tag)
        let tag_pair = wrapper_pair.into_inner().next().ok_or_else(|| {
            ParseError::from_span(wrapper_span, "Tag wrapper is empty".to_string())
        })?;

        let tag = Self::parse_tag_inner(tag_pair, &context)?;
        Ok((tag, context))
    }

    // Common path for both parsing entire template and single tag
    pub fn parse_tag_inner(
        tag_pair: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<Tag, ParseError> {
        // Create token for the entire tag span (which includes delimiters like {% %})
        let tag_token = context.create_token(&tag_pair);
        let tag_span = tag_pair.as_span();

        // (django_tag | html_tag) -> tag_content | spacing
        let tag_content_or_spacing = tag_pair.into_inner();

        let mut tag_content_pairs = context.extract_comments_from_pairs(tag_content_or_spacing)?;
        let tag_content_pair = tag_content_pairs
            .next()
            .ok_or_else(|| ParseError::from_span(tag_span, "Tag content is empty".to_string()))?;
        assert_rule(&tag_content_pair, Rule::tag_content)?;
        let tag_content_span = tag_content_pair.as_span();

        // tag_content -> (tag_name | spacing_with_whitespace | attribute* | self_closing_slash?)
        //          OR -> (forloop_tag_name | spacing_with_whitespace | forloop_tag_content)
        let inner_pairs_with_comments = tag_content_pair.into_inner();

        // Note: spacing_with_whitespace should contain only COMMENT pairs.
        let mut inner_pairs = context.extract_comments_from_pairs(inner_pairs_with_comments)?;

        // First item in a tag is always the tag name (either tag_name or forloop_tag_name)
        let name_pair = inner_pairs
            .next()
            .ok_or_else(|| ParseError::from_span(tag_content_span, "Tag is empty".to_string()))?;
        assert_rules(&name_pair, &[Rule::tag_name, Rule::forloop_tag_name])?;

        let name_token = context.create_token(&name_pair);
        let tag_name: &String = &name_token.content;

        // Start collecting variables for this tag
        context.start_tag().map_err(|e| {
            ParseError::from_span(tag_content_span, format!("Internal error: {}", e))
        })?;

        // Special handling for 'for' tag
        if tag_name == "for" {
            Self::parse_forloop_tag(
                inner_pairs,
                tag_token,
                name_token,
                tag_content_span,
                context,
            )
        } else if tag_name.starts_with("end") && tag_name != "end" {
            Self::parse_end_tag(inner_pairs, tag_token, name_token, context)
        } else {
            Self::parse_generic_tag(inner_pairs, tag_token, name_token, context)
        }
    }

    fn parse_generic_tag<'i>(
        tag_content_inner_pairs: impl Iterator<Item = pest::iterators::Pair<'i, Rule>>,
        tag_token: Token,
        name_token: Token,
        context: &ParserContext,
    ) -> Result<Tag, ParseError> {
        let mut attributes = Vec::new();
        let mut seen_flags = HashSet::new();
        let mut flag_tokens_start_indices = HashSet::new();
        let mut is_self_closing = false;

        // Look up flags for this specific tag
        let tag_name: &String = &name_token.content;
        let flags_for_tag = context.flags.get(tag_name);

        // Parse regular attributes for non-for tags
        for pair in tag_content_inner_pairs {
            match pair.as_rule() {
                Rule::attribute => {
                    let attr_span = pair.as_span(); // Save span before moving pair
                    let mut attr = Self::process_attribute(pair, context)?;

                    // Check if this attribute is a flag or a variable name
                    if attr.key.is_none() && attr.value.spread.is_none() {
                        let content = &attr.value.value.content;
                        if flags_for_tag.map_or(false, |f| f.contains(content)) {
                            attr.is_flag = true;
                            if !seen_flags.insert(content.clone()) {
                                return Err(ParseError::from_span(
                                    attr_span,
                                    format!("Flag '{}' may be specified only once.", content),
                                ));
                            }
                            flag_tokens_start_indices.insert(attr.value.token.start_index);
                        }
                    }

                    attributes.push(attr);
                }
                Rule::self_closing_slash => {
                    is_self_closing = true;
                }
                other => {
                    return Err(ParseError::from_span(
                        pair.as_span(),
                        format!("Expected attribute or self_closing_slash, got {:?}", other),
                    ))
                }
            }
        }

        // Flush the used and assigned variables we collected while parsing the tag
        let (mut used_variables, assigned_variables) = context.finish_tag();

        // Remove used_variables that turned out to be flags
        used_variables.retain(|var| !flag_tokens_start_indices.contains(&var.start_index));

        Ok(Tag::Generic(GenericTag {
            meta: TagMeta {
                token: tag_token,
                name: name_token,
                used_variables,
                assigned_variables,
            },
            attrs: attributes,
            is_self_closing,
        }))
    }

    fn parse_forloop_tag<'i>(
        mut tag_content_inner_pairs: impl Iterator<Item = pest::iterators::Pair<'i, Rule>>,
        tag_token: Token,
        name_token: Token,
        tag_span: pest::Span,
        context: &ParserContext,
    ) -> Result<Tag, ParseError> {
        // Parse forloop_tag_content instead of regular attributes
        let forloop_content_pair = tag_content_inner_pairs.next().ok_or_else(|| {
            ParseError::from_span(
                tag_span,
                "Expected for loop specification after 'for' tag name".to_string(),
            )
        })?;
        assert_rule(&forloop_content_pair, Rule::forloop_tag_content)?;

        let spec_span = forloop_content_pair.as_span();

        // forloop_tag_content -> forloop_vars ~ "in" ~ filtered_value
        let forloop_content_inner_pairs_with_comments = forloop_content_pair.into_inner();
        let mut forloop_content_inner_pairs =
            context.extract_comments_from_pairs(forloop_content_inner_pairs_with_comments)?;

        // forloop_vars
        let for_loop_vars_pair = forloop_content_inner_pairs
            .next()
            .ok_or_else(|| ParseError::from_span(spec_span, "Expected forloop_vars".to_string()))?;
        assert_rule(&for_loop_vars_pair, Rule::forloop_vars)?;

        // Extract loop variable names
        // forloop_vars -> forloop_var ~ (spacing* ~ "," ~ spacing* ~ forloop_var)*
        let forloop_vars_inner_pairs_with_comments = for_loop_vars_pair.clone().into_inner();
        let forloop_vars_inner_pairs =
            context.extract_comments_from_pairs(forloop_vars_inner_pairs_with_comments)?;

        let mut targets = Vec::new();
        for var_pair in forloop_vars_inner_pairs {
            assert_rule(&var_pair, Rule::forloop_var)?;
            let var_token = context.create_token(&var_pair);
            targets.push(var_token);
        }

        // Get the iterable (filtered_value)
        let iterable_pair = forloop_content_inner_pairs.next().ok_or_else(|| {
            ParseError::from_span(spec_span, "Expected iterable expression".to_string())
        })?;
        assert_rule(&iterable_pair, Rule::filtered_value)?;

        let iterable_value = Self::process_filtered_value(iterable_pair, context)?;

        // Flush the used and assigned variables we collected while parsing the tag
        let (used_variables, assigned_variables) = context.finish_tag();

        return Ok(Tag::ForLoop(ForLoopTag {
            meta: TagMeta {
                token: tag_token,
                name: name_token,
                used_variables,
                assigned_variables,
            },
            targets,
            iterable: iterable_value,
        }));
    }

    // While the grammar recognizes only "for" tag and "generic" tag,
    // we further distinguishes between "end" tags and "generic" tags.
    //
    // End tags should only contain the tag name - no attributes, no self-closing slash, nothing else.
    fn parse_end_tag<'i>(
        mut tag_content_inner_pairs: impl Iterator<Item = pest::iterators::Pair<'i, Rule>>,
        tag_token: Token,
        name_token: Token,
        context: &ParserContext,
    ) -> Result<Tag, ParseError> {
        if let Some(pair) = tag_content_inner_pairs.next() {
            return Err(ParseError::from_span(
                pair.as_span(),
                format!(
                    "End tags can only contain the tag name, found unexpected: {:?}",
                    pair.as_rule()
                ),
            ));
        }

        // Flush the used and assigned variables we collected while parsing the tag
        // (should be empty for end tags, but we still need to call finish_tag)
        let (used_variables, assigned_variables) = context.finish_tag();

        Ok(Tag::End(EndTag {
            meta: TagMeta {
                token: tag_token,
                name: name_token,
                used_variables,
                assigned_variables,
            },
        }))
    }

    fn process_attribute(
        attr_pair: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<TagAttr, ParseError> {
        let attr_token = context.create_token(&attr_pair);
        let attr_span = attr_pair.as_span();

        // attribute -> (key ~ "=" ~ filtered_value) | spread_value | filtered_value
        let mut inner_pairs = attr_pair.into_inner().peekable();

        // Check if this is a key-value pair or just a value
        match inner_pairs.peek().map(|p| p.as_rule()) {
            Some(Rule::key) => {
                // Key-value pair - NO whitespace allowed around =
                let key_pair = inner_pairs
                    .next()
                    .ok_or_else(|| ParseError::from_span(attr_span, "Key is empty".to_string()))?;
                assert_rule(&key_pair, Rule::key)?;
                let key_token = context.create_token(&key_pair);

                // Value
                let value_pair = inner_pairs.next().ok_or_else(|| {
                    ParseError::from_span(
                        key_pair.as_span(),
                        format!("Missing value for key: {}", key_token.content),
                    )
                })?;
                assert_rule(&value_pair, Rule::filtered_value)?;

                let value = Self::process_filtered_value(value_pair, context)?;

                Ok(TagAttr {
                    token: attr_token,
                    key: Some(key_token),
                    value,
                    is_flag: false,
                })
            }
            Some(Rule::spread_value) => {
                // spread_value
                let spread_value = inner_pairs.next().ok_or_else(|| {
                    ParseError::from_span(attr_span, "Spread is empty".to_string())
                })?;
                assert_rule(&spread_value, Rule::spread_value)?;

                let spread_span = spread_value.as_span();

                // Get the value part after the ... operator - NO WHITESPACE ALLOWED
                // spread_value -> filtered_value
                let value_pair = spread_value.into_inner().next().ok_or_else(|| {
                    ParseError::from_span(spread_span, "Spread value is empty".to_string())
                })?;
                assert_rule(&value_pair, Rule::filtered_value)?;

                // Process the value part
                let mut value = Self::process_filtered_value(value_pair, context)?;

                // Update spread and indices
                value.spread = Some("...".to_string());

                // Update the token to include the spread operator
                let new_token_start = value.token.start_index - 3;
                let new_token_col = (value.token.line_col.0, value.token.line_col.1 - 3);
                value.token = Token {
                    content: format!("...{}", value.token.content),
                    start_index: new_token_start,
                    end_index: value.token.end_index,
                    line_col: new_token_col,
                };

                Ok(TagAttr {
                    token: attr_token,
                    key: None,
                    value,
                    is_flag: false,
                })
            }
            Some(Rule::filtered_value) => {
                // filtered_value
                let value_pair = inner_pairs.next().ok_or_else(|| {
                    ParseError::from_span(attr_span, "Filtered value is empty".to_string())
                })?;
                let value = Self::process_filtered_value(value_pair, context)?;

                Ok(TagAttr {
                    token: attr_token,
                    key: None,
                    value,
                    is_flag: false,
                })
            }
            other => {
                return Err(ParseError::from_span(
                    attr_span,
                    format!(
                        "Expected key, spread_value, or filtered_value, got {:?}",
                        other
                    ),
                ))
            }
        }
    }

    // Filtered value means that:
    // 1. It is "value" - meaning that it is the same as "basic value" + list and dict
    // 2. It may have a filter chain after it
    //
    // E.g. `my_var`, `my_var|filter`, `[1, 2, 3]|filter1|filter2` are all filtered values
    pub fn process_filtered_value(
        value_pair: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<TagValue, ParseError> {
        // Get total span (including filters if present)
        let token = context.create_token(&value_pair);
        let value_span = value_pair.as_span();

        // filtered_value -> value ~ filter_chain?
        let mut value_and_filter_pairs = value_pair.into_inner();

        // Get the main value part (without filters)
        // value
        let value_part = value_and_filter_pairs
            .next()
            .ok_or_else(|| ParseError::from_span(value_span, "Value is empty".to_string()))?;
        assert_rule(&value_part, Rule::value)?;

        // Get the actual value (stripping the * if present)
        // value -> dict | list | translation | python_expr | variable | int | float | string_literal
        let inner_value =
            value_part.clone().into_inner().next().ok_or_else(|| {
                ParseError::from_span(value_span, "Inner value is empty".to_string())
            })?;

        // Process the value
        let mut tag_value = match inner_value.as_rule() {
            Rule::list => {
                let value_token = context.create_token(&inner_value);
                let children = Self::process_list(inner_value, context)?;

                Ok::<TagValue, ParseError>(TagValue {
                    token,
                    value: value_token,
                    spread: None,
                    filters: vec![],
                    kind: ValueKind::List,
                    children,
                    used_variables: vec![], // Variables defined by list children, not list itself
                    assigned_variables: vec![], // Variables defined by list children, not list itself
                })
            }
            Rule::dict => {
                let value_token = context.create_token(&inner_value);
                let children = Self::process_dict(inner_value, context)?;

                Ok(TagValue {
                    token,
                    value: value_token,
                    spread: None,
                    filters: vec![],
                    kind: ValueKind::Dict,
                    children,
                    used_variables: vec![], // Variables defined by dict children, not dict itself
                    assigned_variables: vec![], // Variables defined by dict children, not dict itself
                })
            }
            // translation | python_expr | string_literal | int | float | variable
            _ => {
                let mut simple_value = Self::process_simple_value(inner_value, context)?;

                // Update token to include filters if present
                simple_value.token = token;

                Ok(simple_value)
            }
        }?;

        // Process any filters
        // filter_chain
        if let Some(filter_chain) = value_and_filter_pairs.next() {
            assert_rule(&filter_chain, Rule::filter_chain)?;
            // Process the filters and assign them to the TagValue struct
            tag_value.filters = Self::process_filters(filter_chain, context)?;
        }

        Ok(tag_value)
    }

    // This "simple value" is a value that is not a list or dict,
    // nor doesn't have filters nor spreads. This value can be a valid dict key
    // e.g. a string, int, float, or translation string.
    //
    // It cannot be dicts nor lists because keys must be hashable.
    //
    // E.g. `my_var`, `42`, `"hello world"`, `_("hello world")` are all simple values
    fn process_simple_value(
        value_pair: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<TagValue, ParseError> {
        let mut value_token = context.create_token(&value_pair);

        // Determine the value kind, so that downstream processing doesn't need to
        let text = value_token.content.clone();
        // translation | python_expr | string_literal | int | float | variable
        let kind = match value_pair.as_rule() {
            Rule::translation => ValueKind::Translation,
            Rule::python_expr => ValueKind::PythonExpr,
            Rule::string_literal => {
                if has_template_string(&text) {
                    ValueKind::TemplateString
                } else {
                    ValueKind::String
                }
            }
            Rule::int => ValueKind::Int,
            Rule::float => ValueKind::Float,
            Rule::variable => ValueKind::Variable,
            other => return Err(ParseError::from_span(
                value_pair.as_span(),
                format!("Expected translation, python_expr, string_literal, int, float, or variable, got {:?}", other),
            )),
        };

        // If this is an translation string, extract the comments, and then re-format
        // the entire expression, removing whitespace from around the quoted string, as Django
        // doesn't handle that.
        if kind == ValueKind::Translation {
            // translation -> "_(" ~ spacing* ~ string_literal ~ spacing* ~ ")"
            let translation_inner_pairs = value_pair.clone().into_inner();

            // Extract comments from spacing pairs and find the string literal
            let mut filtered_pairs =
                context.extract_comments_from_pairs(translation_inner_pairs)?;

            // Find the string literal pair
            let string_pair = filtered_pairs.next().ok_or_else(|| {
                ParseError::from_span(
                    value_pair.as_span(),
                    "No quoted string found in translation string".to_string(),
                )
            })?;
            assert_rule(&string_pair, Rule::string_literal)?;

            // Get the quoted string content (including the quotes)
            let quoted_part = string_pair.as_str();
            value_token.content = format!("_({})", quoted_part);
        }

        // If this is a template string, parse its content to extract nested template tags
        let children = if kind == ValueKind::TemplateString {
            match context.config.version {
                // Version 1: TemplateString is parsed by Django, and may contain tags
                //            that we don't know about yet, so we can't get deeper metadata.
                TemplateVersion::V1 => vec![],
                // In version 2 and 3, recursively parse the template string to get deeper metadata.
                TemplateVersion::V2 | TemplateVersion::V3 => {
                    // TODO IMPLEMENT THIS
                    vec![]
                }
            }
        } else {
            vec![]
        };

        // Determine used_variables, assigned_variables, and comments based on kind
        let extracted_data: Result<(Vec<Token>, Vec<Token>, Vec<Comment>), ParseError> = match kind
        {
            // Lists and Dicts themselves do not introduce or use variables (but their children may)
            ValueKind::List
            | ValueKind::Dict
            // Literals - no variables needed or introduced
            | ValueKind::Int
            | ValueKind::Float
            | ValueKind::String
            // Translation doesn't introduce any variables. Comments were already extracted
            | ValueKind::Translation => {
                Ok((vec![], vec![], vec![]))
            }
            ValueKind::TemplateString => {
                match context.config.version {
                    // Version 1: TemplateString is parsed by Django, and may contain tags
                    //            that we don't know about yet, so we can't extract variables from it
                    TemplateVersion::V1 => Ok((vec![], vec![], vec![])),
                    // In version 2 and 3, recursively parse the template string to extract variables
                    TemplateVersion::V2 | TemplateVersion::V3 => {
                        // TODO IMPLEMENT THIS
                        Ok((vec![], vec![], vec![]))
                    }
                }
            }
            ValueKind::Variable => {
                // Extract the first part before the first dot as the context variable
                // `my_var.some.attr` -> `my_var`
                let var_name = value_token.content.split('.').next().unwrap_or("");
                if var_name.is_empty() {
                    Ok((vec![], vec![], vec![]))
                } else {
                    // Create a token for the variable name (just the first part)
                    let var_token = Token {
                        content: var_name.to_string(),
                        start_index: value_token.start_index,
                        end_index: value_token.start_index + var_name.len(),
                        line_col: value_token.line_col,
                    };
                    Ok((vec![var_token], vec![], vec![]))
                }
            }
            // In case of Python expression, delegate to `safe_eval()` to collect used and assigned variables.
            ValueKind::PythonExpr => {
                // Strip the encapsulating parentheses before passing to transform_expression_string
                // We do this so that we can have trailing comments in expressions.
                let content_without_parens = &value_token.content[1..value_token.content.len() - 1];

                let transform_result = transform_expression_string(&content_without_parens)
                    .map_err(|e| {
                        ParseError::from_span(
                            value_pair.as_span(),
                            format!("Failed to collect used and assigned variables from Python expression: {}", e),
                        )
                    })?;

                // Calculate offsets for adjusting token positions
                // +1 for removed opening parenthesis
                let index_offset = value_token.start_index + 1;
                let (value_line, value_col) = value_token.line_col;
                // line_offset: value_line - 1 (because lines are 1-indexed)
                let line_offset = value_line - 1;
                // col_offset: value_col - 1 + 1 = value_col (the +1 for skipped opening parenthesis, -1 because cols are 1-indexed)
                let col_offset = value_col;

                let used_vars: Vec<Token> = transform_result
                    .used_vars
                    .into_iter()
                    .map(|safe_token| {
                        convert_safe_eval_token(safe_token).offset(
                            index_offset,
                            line_offset,
                            col_offset,
                        )
                    })
                    .collect();
                let assigned_vars: Vec<Token> = transform_result
                    .assigned_vars
                    .into_iter()
                    .map(|safe_token| {
                        convert_safe_eval_token(safe_token).offset(
                            index_offset,
                            line_offset,
                            col_offset,
                        )
                    })
                    .collect();

                let comments: Vec<Comment> = transform_result
                    .comments
                    .into_iter()
                    .map(|comment| Comment {
                        token: convert_safe_eval_token(comment.token).offset(
                            index_offset,
                            line_offset,
                            col_offset,
                        ),
                        value: convert_safe_eval_token(comment.value).offset(
                            index_offset,
                            line_offset,
                            col_offset,
                        ),
                    })
                    .collect();

                Ok((used_vars, assigned_vars, comments))
            }
        };

        // Collect variables to context's current tag variables
        let (used_variables, assigned_variables, comments) = extracted_data?;
        context.collect_variables(&used_variables, &assigned_variables);
        context.append_comments(comments);

        Ok(TagValue {
            token: value_token.clone(), // Initially same as value, will be updated if filters present
            value: value_token,
            spread: None,
            filters: vec![],
            kind,
            children,
            used_variables,
            assigned_variables,
        })
    }

    // Process a key in a dict that may have filters
    fn process_filtered_dict_key(
        key_pair: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<TagValue, ParseError> {
        let key_span = key_pair.as_span();
        let key_token = context.create_token(&key_pair);

        // dict_key -> dict_key_inner ~ filter_chain_noarg?
        let mut inner_pairs = key_pair.into_inner();

        // dict_key_inner
        let dict_key_inner = inner_pairs.next().ok_or_else(|| {
            ParseError::from_span(key_span, "Dict key inner is empty".to_string())
        })?;
        assert_rules(
            &dict_key_inner,
            &[
                Rule::translation,
                Rule::python_expr,
                Rule::variable,
                Rule::float,
                Rule::int,
                Rule::string_literal,
            ],
        )?;

        let mut tag_value = Self::process_simple_value(dict_key_inner, context)?;

        // Update token to include filters if present
        tag_value.token = key_token;

        // Process any filters
        // filter_chain_noarg
        if let Some(filter_chain) = inner_pairs.next() {
            assert_rule(&filter_chain, Rule::filter_chain_noarg)?;
            // Process the filters and assign them to the TagValue struct
            tag_value.filters = Self::process_filters(filter_chain, context)?;
        }

        Ok(tag_value)
    }

    fn process_list(
        inner_value: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<Vec<ValueChild>, ParseError> {
        let mut items = Vec::new();

        // list -> list_item ~ spacing*
        let list_items = context.extract_comments_from_pairs(inner_value.into_inner())?;
        for item in list_items {
            assert_rule(&item, Rule::list_item)?;
            let item_span = item.as_span();
            let item_token = context.create_token(&item);

            // list_item -> list_item_spread? ~ spacing* ~ filtered_value
            let list_item_parts: Vec<_> = context
                .extract_comments_from_pairs(item.into_inner())?
                .collect();

            // Figure out if there is also a spread operator.
            // We expect 1 or 2 pairs: either [filtered_value] or [list_item_spread, filtered_value]
            let (spread_op_pair, filtered_value_pair) = match list_item_parts.len() {
                1 => {
                    let pair = list_item_parts.into_iter().next().unwrap();
                    assert_rule(&pair, Rule::filtered_value)?;
                    (None, pair)
                }
                2 => {
                    let mut iter = list_item_parts.into_iter();
                    let first = iter.next().unwrap();
                    let second = iter.next().unwrap();

                    match (first.as_rule(), second.as_rule()) {
                        (Rule::list_item_spread, Rule::filtered_value) => (Some(first), second),
                        _ => {
                            return Err(ParseError::from_span(
                                item_span,
                                format!(
                                    "Unexpected rules in list_item: {:?}, {:?}",
                                    first.as_rule(),
                                    second.as_rule()
                                ),
                            ));
                        }
                    }
                }
                _ => {
                    return Err(ParseError::from_span(
                        item_span,
                        format!(
                            "Expected 1 or 2 pairs in list_item, got {}",
                            list_item_parts.len()
                        ),
                    ));
                }
            };

            let mut tag_value = Self::process_filtered_value(filtered_value_pair, context)?;

            // If there is a spread operator, update the token to include the spread operator
            if spread_op_pair.is_some() {
                tag_value.spread = Some("*".to_string());
                tag_value.token = item_token;
            }

            items.push(ValueChild::Value(tag_value));
        }
        Ok(items)
    }

    fn process_dict(
        dict_pair: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<Vec<ValueChild>, ParseError> {
        // dict -> spacing* ~ dict_item ~ spacing*
        let dict_pairs = context.extract_comments_from_pairs(dict_pair.into_inner())?;

        let mut items = Vec::new();
        for item in dict_pairs {
            let item_span = item.as_span();

            match item.as_rule() {
                Rule::dict_item_pair => {
                    // dict_item_pair -> dict_key ~ spacing* ~ ":" ~ spacing* ~ filtered_value
                    let mut dict_item_pair_parts =
                        context.extract_comments_from_pairs(item.into_inner())?;

                    // dict_key
                    let key_pair = dict_item_pair_parts.next().ok_or_else(|| {
                        ParseError::from_span(item_span, "Dict item pair key is empty".to_string())
                    })?;
                    assert_rule(&key_pair, Rule::dict_key)?;
                    let key_span = key_pair.as_span(); // Save span for error reporting

                    // filtered_value
                    let value_pair = dict_item_pair_parts.next().ok_or_else(|| {
                        ParseError::from_span(
                            item_span,
                            "Dict item pair value is empty".to_string(),
                        )
                    })?;
                    assert_rule(&value_pair, Rule::filtered_value)?;

                    let key = Self::process_filtered_dict_key(key_pair, context)?;
                    let value = Self::process_filtered_value(value_pair, context)?;

                    // Check that key is not a list or dict
                    match key.kind {
                        ValueKind::List | ValueKind::Dict => {
                            return Err(ParseError::from_span(
                                key_span,
                                "Dictionary keys cannot be lists or dictionaries".to_string(),
                            ));
                        }
                        _ => {}
                    }
                    items.push(ValueChild::Value(key));
                    items.push(ValueChild::Value(value));
                }
                Rule::dict_item_spread => {
                    // dict_item_spread -> dict_item_spread_op ~ spacing* ~ filtered_value
                    let item_token = context.create_token(&item);
                    let dict_item_spread_parts: Vec<_> = context
                        .extract_comments_from_pairs(item.into_inner())?
                        .collect();

                    // Figure out if there is also a spread operator.
                    // We expect 1 or 2 pairs: either [filtered_value] or [dict_item_spread_op, filtered_value]
                    let (spread_op_pair, filtered_value_pair) = match dict_item_spread_parts.len() {
                        1 => {
                            let pair = dict_item_spread_parts.into_iter().next().unwrap();
                            assert_rule(&pair, Rule::filtered_value)?;
                            (None, pair)
                        }
                        2 => {
                            let mut iter = dict_item_spread_parts.into_iter();
                            let first = iter.next().unwrap();
                            let second = iter.next().unwrap();

                            match (first.as_rule(), second.as_rule()) {
                                (Rule::dict_item_spread_op, Rule::filtered_value) => {
                                    (Some(first), second)
                                }
                                _ => {
                                    return Err(ParseError::from_span(
                                        item_span,
                                        format!(
                                            "Unexpected rules in dict_item_spread: {:?}, {:?}",
                                            first.as_rule(),
                                            second.as_rule()
                                        ),
                                    ));
                                }
                            }
                        }
                        _ => {
                            return Err(ParseError::from_span(
                                item_span,
                                format!(
                                    "Expected 1 or 2 pairs in dict_item_spread, got {}",
                                    dict_item_spread_parts.len()
                                ),
                            ));
                        }
                    };

                    let mut value = Self::process_filtered_value(filtered_value_pair, context)?;

                    // If there is a spread operator, update the token to include the spread operator
                    if spread_op_pair.is_some() {
                        value.spread = Some("**".to_string());
                        value.token = item_token;
                    }

                    items.push(ValueChild::Value(value));
                }
                other => {
                    return Err(ParseError::from_span(
                        item.as_span(),
                        format!("Invalid dictionary item {:?}", other),
                    ))
                }
            }
        }
        Ok(items)
    }

    fn process_filters(
        filter_chain: pest::iterators::Pair<Rule>,
        context: &ParserContext,
    ) -> Result<Vec<TagValueFilter>, ParseError> {
        // Return error if not a filter chain rule
        assert_rules(
            &filter_chain,
            &[Rule::filter_chain, Rule::filter_chain_noarg],
        )?;

        let mut filters = Vec::new();

        // filter_chain -> spacing* ~ filter ~ (spacing* ~ filter)*
        let inner_pairs = filter_chain.into_inner();
        let filter_chain_pairs = context.extract_comments_from_pairs(inner_pairs)?;

        for filter in filter_chain_pairs {
            assert_rules(&filter, &[Rule::filter, Rule::filter_noarg])?;

            let filter_span = filter.as_span();
            let filter_token = context.create_token(&filter);

            // Find the filter name (skipping the pipe token)
            // filter -> "|" ~ spacing* ~ filter_name ~ filter_arg_part?
            let filter_parts_with_comments = filter.into_inner();
            let mut filter_parts =
                context.extract_comments_from_pairs(filter_parts_with_comments)?;

            // filter_name
            let filter_pair = filter_parts.next().ok_or_else(|| {
                ParseError::from_span(filter_span, "Filter name is empty".to_string())
            })?;
            assert_rule(&filter_pair, Rule::filter_name)?;
            let name_token = context.create_token(&filter_pair);

            // filter_arg_part
            let filter_arg_part = filter_parts.next();
            let mut filter_arg = None;
            if let Some(arg_part) = filter_arg_part {
                assert_rule(&arg_part, Rule::filter_arg_part)?;

                let arg_part_span = arg_part.as_span();

                // filter_arg_part -> spacing* ~ ":" ~ spacing* ~ filter_arg
                let arg_part_pairs_with_comments = arg_part.into_inner();
                let mut arg_part_pairs =
                    context.extract_comments_from_pairs(arg_part_pairs_with_comments)?;

                // filter_arg
                let arg_value_pair = arg_part_pairs.next().ok_or_else(|| {
                    ParseError::from_span(arg_part_span, "Filter argument is empty".to_string())
                })?;
                assert_rule(&arg_value_pair, Rule::filter_arg)?;

                // Process the filter argument as a TagValue
                filter_arg = Some(Self::process_filtered_value(arg_value_pair, context)?);
            }

            filters.push(TagValueFilter {
                token: filter_token,
                name: name_token,
                arg: filter_arg,
            });
        }

        Ok(filters)
    }
}

// #####################
// HELPERS
// #####################

/// Check if a string contains a Django template syntax like `{{ }}`, `{% %}`, or `{# %}`
/// in which case we assume that this string is a nested template.
fn has_template_string(s: &str) -> bool {
    // Don't check for template strings in translation strings
    if s.starts_with("_(") {
        return false;
    }

    // Check for any of the Django template tags with their closing tags
    // The pattern ensures that:
    // 1. Opening and closing tags are properly paired
    // 2. Tags are in the correct order (no closing before opening)
    lazy_static::lazy_static! {
        static ref VAR_TAG: regex::Regex = regex::Regex::new(r"\{\{.*?\}\}").unwrap();
        static ref BLOCK_TAG: regex::Regex = regex::Regex::new(r"\{%.*?%\}").unwrap();
        static ref COMMENT_TAG: regex::Regex = regex::Regex::new(r"\{#.*?#\}").unwrap();
    }

    VAR_TAG.is_match(s) || BLOCK_TAG.is_match(s) || COMMENT_TAG.is_match(s)
}

/// Convert a SafeEvalToken to a Token
fn convert_safe_eval_token(safe_eval_token: SafeEvalToken) -> Token {
    Token {
        content: safe_eval_token.content,
        start_index: safe_eval_token.start_index,
        end_index: safe_eval_token.end_index,
        line_col: safe_eval_token.line_col,
    }
}
