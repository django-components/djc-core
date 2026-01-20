// ============================================================================
// COMMENT PLACEMENT LOCATIONS
// ============================================================================
//
// Based on grammar.pest analysis, comments {# ... #} can appear in the following locations:
//
// 1. TEMPLATE LEVEL (SKIPPED - requires template_parser):
//    - Between template elements (text, tags, expressions)
//    - Inside expressions: {{ {# comment #} value {# comment #} }}
//    - In verbatim start/end tags: {% {# comment #} verbatim {# comment #} %}
//    - In comment start/end tags: {% {# comment #} comment {# comment #} %}
//
// 2. TAG DELIMITERS:
//    - Before tag_content: {% {# comment #} tag_name ... %}
//    - After tag_content: {% ... tag_name {# comment #} %}
//
// 3. TAG CONTENT (Generic Tags):
//    - Between tag_name and first attribute: tag_name {# comment #} key=val
//    - Between attributes: key1=val1 {# comment #} key2=val2
//    - After last attribute, before self-closing slash: key=val {# comment #} /
//    - After self-closing slash, before closing %}: / {# comment #} %}
//
// 4. FOR LOOP TAGS:
//    - Between "for" and forloop_tag_content: for {# comment #} item in items
//    - Between loop variables: for x {# comment #}, {# comment #} y in items
//    - Between forloop_vars and "in": for x, y {# comment #} in items
//    - Between "in" and iterable: for x in {# comment #} items
//
// 5. ATTRIBUTES:
//    - NOT ALLOWED: Around spread operator: ...{# comment #}value
//    - NOT ALLOWED: Between key and "=" (atomic rule: key = @{ ... })
//    - NOT ALLOWED: Between "=" and value (atomic rule: key ~ "=" ~ filtered_value)
//
// 6. FILTERS:
//    - Between value and filter chain: value {# comment #} |filter
//    - Between filters: value|filter1 {# comment #} |filter2
//    - Around filter pipe: value {# comment #} | {# comment #} filter
//    - Around filter name: | {# comment #} filter_name {# comment #}
//    - Around filter arg colon: filter {# comment #} : {# comment #} arg
//    - Around filter argument: |filter: {# comment #} arg {# comment #}
//
// 7. LISTS:
//    - After opening bracket: [ {# comment #} item1, item2 ]
//    - Between list items: [ item1 {# comment #}, {# comment #} item2 ]
//    - Around list item spread operator: [ {# comment #} * {# comment #} item ]
//    - Before closing bracket: [ item1, item2 {# comment #} ]
//    - Around trailing comma: [ item1, {# comment #}, ]
//
// 8. DICTIONARIES:
//    - After opening brace: { {# comment #} "key": "val" }
//    - Between dict items: { "key1": "val1" {# comment #}, {# comment #} "key2": "val2" }
//    - Around dict_item_pair colon: { "key" {# comment #} : {# comment #} "val" }
//    - Around dict_item_spread: { {# comment #} ** {# comment #} value }
//    - Before closing brace: { "key": "val" {# comment #} }
//    - Around trailing comma: { "key": "val", {# comment #} }
//
// 9. TRANSLATION STRINGS:
//    - Around string literal in _("..."): _( {# comment #} "string" {# comment #} )
//
// 10. PYTHON EXPRESSIONS:
//     - NOT ALLOWED: Comments cannot appear inside Python expressions: ( {# comment #} items + other_items )
//
// 11. VALUES (General):
//     - Around any value type (string, int, float, variable, etc.) when used in contexts
//       that allow spacing (not in atomic contexts like key names)
//
// ============================================================================

mod common;

#[cfg(test)]
mod tests {
    use std::vec;

    use djc_template_parser::ast::Comment;

    use super::common::{plain_parse_tag_v1, token};

    // ============================================
    // TAG DELIMITERS
    // ============================================

    #[test]
    fn test_comment_tag_before_name() {
        let input = "{% {# before #} my_tag key=val %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# before #}", 3, 1, 4),
                value: token(" before ", 5, 1, 6),
            }]
        );
    }

    #[test]
    fn test_comment_tag_after_attrs() {
        let input = "{% my_tag key=val {# after #} %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# after #}", 18, 1, 19),
                value: token(" after ", 20, 1, 21),
            }]
        );
    }

    #[test]
    fn test_comment_tag_multiple() {
        let input = "{% my_tag {# c1 #} key1=val1 {# c2 #} key2=val2 {# c3 #} / %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 10, 1, 11),
                    value: token(" c1 ", 12, 1, 13),
                },
                Comment {
                    token: token("{# c2 #}", 29, 1, 30),
                    value: token(" c2 ", 31, 1, 32),
                },
                Comment {
                    token: token("{# c3 #}", 48, 1, 49),
                    value: token(" c3 ", 50, 1, 51),
                },
            ]
        );
    }

    #[test]
    fn test_comment_kwarg_attr_not_allowed() {
        let input = "{% my_tag key{# comment #}=val %}";
        assert!(plain_parse_tag_v1(input).is_err());

        let input = "{% my_tag key={# comment #}val %}";
        assert!(plain_parse_tag_v1(input).is_err());
    }

    #[test]
    fn test_comment_requires_whitespace_between_tag_name_and_attributes() {
        let input = "{% my_tag{# comment #}key=val %}";
        let result = plain_parse_tag_v1(input);
        assert!(result.is_err());
    }

    // ============================================
    // TAG - GENERIC
    // ============================================

    #[test]
    fn test_comment_tag_between_name_and_attr() {
        let input = "{% my_tag {# comment #} key=val %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 10, 1, 11),
                value: token(" comment ", 12, 1, 13),
            }]
        );
    }

    #[test]
    fn test_comment_tag_between_attrs() {
        let input = "{% my_tag key1=val1 {# comment #} key2=val2 %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 20, 1, 21),
                value: token(" comment ", 22, 1, 23),
            }]
        );
    }

    #[test]
    fn test_comment_tag_before_self_closing_slash() {
        let input = "{% my_tag key=val {# comment #} / %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 18, 1, 19),
                value: token(" comment ", 20, 1, 21),
            }]
        );
    }

    #[test]
    fn test_comment_tag_after_self_closing_slash() {
        let input = "{% my_tag key=val / {# comment #} %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 20, 1, 21),
                value: token(" comment ", 22, 1, 23),
            }]
        );
    }

    // ============================================
    // TAG - FORLOOOP
    // ============================================

    #[test]
    fn test_comment_forloop_before_tag_name() {
        let input = "{% {# comment #} for item in items %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 3, 1, 4),
                value: token(" comment ", 5, 1, 6),
            }]
        );
    }

    #[test]
    fn test_comment_forloop_between_for_and_content() {
        let input = "{% for {# comment #} item in items %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 7, 1, 8),
                value: token(" comment ", 9, 1, 10),
            }]
        );
    }

    #[test]
    fn test_comment_forloop_between_loop_variables() {
        let input = "{% for x {# c1 #}, {# c2 #} y in items %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 9, 1, 10),
                    value: token(" c1 ", 11, 1, 12),
                },
                Comment {
                    token: token("{# c2 #}", 19, 1, 20),
                    value: token(" c2 ", 21, 1, 22),
                },
            ]
        );
    }

    #[test]
    fn test_comment_forloop_between_forloop_vars_and_in() {
        let input = "{% for x, y {# comment #} in items %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 12, 1, 13),
                value: token(" comment ", 14, 1, 15),
            }]
        );
    }

    #[test]
    fn test_comment_forloop_between_in_and_iterable() {
        let input = "{% for x in {# comment #} items %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 12, 1, 13),
                value: token(" comment ", 14, 1, 15),
            }]
        );
    }

    // ============================================
    // TAG - END
    // ============================================

    #[test]
    fn test_comment_endtag_with_whitespace() {
        let input = "{% {# c1 #} endslot {# c2 #} %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            context.take_comments(),
            vec![
                Comment {
                    token: token("{# c1 #}", 3, 1, 4),
                    value: token(" c1 ", 5, 1, 6),
                },
                Comment {
                    token: token("{# c2 #}", 20, 1, 21),
                    value: token(" c2 ", 22, 1, 23),
                },
            ]
        );
    }

    #[test]
    fn test_comment_endtag_no_spaces() {
        let input = "{%{# c1 #}endslot{# c2 #}%}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            context.take_comments(),
            vec![
                Comment {
                    token: token("{# c1 #}", 2, 1, 3),
                    value: token(" c1 ", 4, 1, 5),
                },
                Comment {
                    token: token("{# c2 #}", 17, 1, 18),
                    value: token(" c2 ", 19, 1, 20),
                },
            ]
        );
    }

    // ============================================
    // ATTRIBUTES
    // ============================================

    #[test]
    fn test_comment_not_allowed_around_spread_operator() {
        let input = "{% my_tag ...{# comment #}myvalue %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);
    }

    // ============================================
    // FILTERS
    // ============================================

    #[test]
    fn test_comment_filter_between_value_and_pipe() {
        let input = "{% my_tag value {# comment #} |filter %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 16, 1, 17),
                value: token(" comment ", 18, 1, 19),
            }]
        );
    }

    #[test]
    fn test_comment_filter_between_next_filter() {
        let input = "{% my_tag value|filter1 {# comment #} |filter2 %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 24, 1, 25),
                value: token(" comment ", 26, 1, 27),
            }]
        );
    }

    #[test]
    fn test_comment_filter_around_pipe() {
        let input = "{% my_tag value {# c1 #} | {# c2 #} filter %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 16, 1, 17),
                    value: token(" c1 ", 18, 1, 19),
                },
                Comment {
                    token: token("{# c2 #}", 27, 1, 28),
                    value: token(" c2 ", 29, 1, 30),
                }
            ]
        );
    }

    #[test]
    fn test_comment_filter_around_name() {
        let input = "{% my_tag value| {# c1 #} filter {# c2 #} %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c2 #}", 33, 1, 34),
                    value: token(" c2 ", 35, 1, 36),
                },
                Comment {
                    token: token("{# c1 #}", 17, 1, 18),
                    value: token(" c1 ", 19, 1, 20),
                },
            ]
        );
    }

    #[test]
    fn test_comment_filter_around_filter_arg_colon() {
        let input = "{% my_tag value|filter {# c1 #} : {# c2 #} arg %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 23, 1, 24),
                    value: token(" c1 ", 25, 1, 26),
                },
                Comment {
                    token: token("{# c2 #}", 34, 1, 35),
                    value: token(" c2 ", 36, 1, 37),
                }
            ]
        );
    }

    #[test]
    fn test_comment_filter_around_filter_arg() {
        let input = "{% my_tag value|filter: {# c1 #} arg {# c2 #} %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c2 #}", 37, 1, 38),
                    value: token(" c2 ", 39, 1, 40),
                },
                Comment {
                    token: token("{# c1 #}", 24, 1, 25),
                    value: token(" c1 ", 26, 1, 27),
                },
            ]
        );
    }

    // ============================================
    // LISTS
    // ============================================

    #[test]
    fn test_comment_list_after_opening_bracket() {
        let input = "{% my_tag [ {# comment #} item1, item2 ] %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 12, 1, 13),
                value: token(" comment ", 14, 1, 15),
            }]
        );
    }

    #[test]
    fn test_comment_list_between_items() {
        let input = "{% my_tag [ item1 {# c1 #}, {# c2 #} item2 ] %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 18, 1, 19),
                    value: token(" c1 ", 20, 1, 21),
                },
                Comment {
                    token: token("{# c2 #}", 28, 1, 29),
                    value: token(" c2 ", 30, 1, 31),
                }
            ]
        );
    }

    #[test]
    fn test_comment_list_around_spread_operator() {
        let input = "{% my_tag [ {# c1 #} * {# c2 #} item ] %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 12, 1, 13),
                    value: token(" c1 ", 14, 1, 15),
                },
                Comment {
                    token: token("{# c2 #}", 23, 1, 24),
                    value: token(" c2 ", 25, 1, 26),
                }
            ]
        );
    }

    #[test]
    fn test_comment_list_before_closing_bracket() {
        let input = "{% my_tag [ item1, item2 {# comment #} ] %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 25, 1, 26),
                value: token(" comment ", 27, 1, 28),
            }]
        );
    }

    #[test]
    fn test_comment_list_around_trailing_comma() {
        let input = "{% my_tag [ item1{# c1 #},{# c2 #} ] %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 17, 1, 18),
                    value: token(" c1 ", 19, 1, 20),
                },
                Comment {
                    token: token("{# c2 #}", 26, 1, 27),
                    value: token(" c2 ", 28, 1, 29),
                }
            ]
        );
    }

    #[test]
    fn test_comment_list_raises_on_multiple_commas_despite_comment() {
        let input = "{% my_tag [ item1, {# comment #}, ] %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);
    }

    // ============================================
    // DICTIONARIES
    // ============================================

    #[test]
    fn test_comment_dict_after_opening_brace() {
        let input = r#"{% my_tag { {# comment #} "key": "val" } %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 12, 1, 13),
                value: token(" comment ", 14, 1, 15),
            }]
        );
    }

    #[test]
    fn test_comment_dict_between_items() {
        let input = r#"{% my_tag { "key1": "val1" {# c1 #}, {# c2 #} "key2": "val2" } %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 27, 1, 28),
                    value: token(" c1 ", 29, 1, 30),
                },
                Comment {
                    token: token("{# c2 #}", 37, 1, 38),
                    value: token(" c2 ", 39, 1, 40),
                }
            ]
        );
    }

    #[test]
    fn test_comment_dict_around_colon() {
        let input = r#"{% my_tag { "key" {# c1 #} : {# c2 #} "val" } %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 18, 1, 19),
                    value: token(" c1 ", 20, 1, 21),
                },
                Comment {
                    token: token("{# c2 #}", 29, 1, 30),
                    value: token(" c2 ", 31, 1, 32),
                }
            ]
        );
    }

    #[test]
    fn test_comment_dict_around_spread() {
        let input = "{% my_tag { {# c1 #} ** {# c2 #} value } %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 12, 1, 13),
                    value: token(" c1 ", 14, 1, 15),
                },
                Comment {
                    token: token("{# c2 #}", 24, 1, 25),
                    value: token(" c2 ", 26, 1, 27),
                }
            ]
        );
    }

    #[test]
    fn test_comment_dict_before_closing_brace() {
        let input = r#"{% my_tag { "key": "val" {# comment #} } %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("{# comment #}", 25, 1, 26),
                value: token(" comment ", 27, 1, 28),
            }]
        );
    }

    #[test]
    fn test_comment_dict_around_trailing_comma() {
        let input = r#"{% my_tag { "key": "val"{# c1 #},{# c2 #} } %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 24, 1, 25),
                    value: token(" c1 ", 26, 1, 27),
                },
                Comment {
                    token: token("{# c2 #}", 33, 1, 34),
                    value: token(" c2 ", 35, 1, 36),
                }
            ]
        );
    }

    #[test]
    fn test_comment_dict_raises_on_multiple_commas_despite_comment() {
        let input = r#"{% my_tag { "key": "val",{# c1 #},{# c2 #} } %}"#;
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);
    }

    // ============================================
    // TRANSLATION STRINGS
    // ============================================

    #[test]
    fn test_comment_translation_around_string() {
        let input = r#"{% my_tag _( {# c1 #} "hello" {# c2 #} ) %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 13, 1, 14),
                    value: token(" c1 ", 15, 1, 16),
                },
                Comment {
                    token: token("{# c2 #}", 30, 1, 31),
                    value: token(" c2 ", 32, 1, 33),
                }
            ]
        );
    }

    // ============================================
    // PYTHON EXPRESSIONS
    // ============================================

    #[test]
    fn test_comment_python_expr_django_comment() {
        // Inside Python expressions we expect python comments, NOT {# ... #}
        // So the below will be interpreted as dict opening bracket folowed by comment
        // `# comment #} items + other_items `
        // Since it's an unclosed curly brace, it will be raise error
        let input = "{% my_tag ( {# comment #} items + other_items ) %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Parse error:  --> 1:11\n  |\n1 | {% my_tag ( {# comment #} items + other_items ) %}\n  |           ^-----------------------------------^\n  |\n  = Failed to collect used and assigned variables from Python expression: Parse error: Expected an expression at byte range 36..37",
        );
    }

    #[test]
    fn test_comment_python_expr_python_comment() {
        let input = "{% my_tag ( items # COMMENT + other_items ) %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![Comment {
                token: token("# COMMENT + other_items ", 18, 1, 19),
                value: token(" COMMENT + other_items ", 19, 1, 20),
            }]
        );
    }

    #[test]
    fn test_comment_python_expr_python_comment_multiline() {
        let input = "{% my_tag ( [1, # c1\n# c2\n2, # c3\n3] #c4) %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("# c1", 16, 1, 17),
                    value: token(" c1", 17, 1, 18),
                },
                Comment {
                    token: token("# c2", 21, 2, 1),
                    value: token(" c2", 22, 2, 2),
                },
                Comment {
                    token: token("# c3", 29, 3, 4),
                    value: token(" c3", 30, 3, 5),
                },
                Comment {
                    token: token("#c4", 37, 4, 4),
                    value: token("c4", 38, 4, 5),
                }
            ],
        )
    }

    // ============================================
    // VALUES
    // ============================================

    #[test]
    fn test_comment_variable_around() {
        let input = "{% my_tag {# c1 #}myvar{# c2 #} %}";
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 10, 1, 11),
                    value: token(" c1 ", 12, 1, 13),
                },
                Comment {
                    token: token("{# c2 #}", 23, 1, 24),
                    value: token(" c2 ", 25, 1, 26),
                }
            ]
        );
    }

    #[test]
    fn test_comment_variable_inside_not_allowed() {
        let input = "{% my_tag my{# c1 #}var %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag my.{# c1 #}var %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn test_comment_string_around() {
        let input = r#"{% my_tag {# c1 #}"hello"{# c2 #} %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 10, 1, 11),
                    value: token(" c1 ", 12, 1, 13),
                },
                Comment {
                    token: token("{# c2 #}", 25, 1, 26),
                    value: token(" c2 ", 27, 1, 28),
                }
            ]
        );
    }

    #[test]
    fn test_comment_string_inside_not_allowed() {
        let input = r#"{% my_tag "hello{# c1 #}world" %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(comments, vec![]);
    }

    #[test]
    fn test_comment_template_string_around() {
        let input = r#"{% my_tag {# c1 #}"hello {{ name }}"{# c2 #} %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 10, 1, 11),
                    value: token(" c1 ", 12, 1, 13),
                },
                Comment {
                    token: token("{# c2 #}", 36, 1, 37),
                    value: token(" c2 ", 38, 1, 39),
                }
            ]
        );
    }

    #[test]
    fn test_comment_template_string_v1_inside_not_allowed() {
        let input = r#"{% my_tag "hello{# c1 #} {{ name }}" %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(comments, vec![]);
    }

    #[test]
    fn test_comment_int_around() {
        let input = r#"{% my_tag {# c1 #}42{# c2 #} %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 10, 1, 11),
                    value: token(" c1 ", 12, 1, 13),
                },
                Comment {
                    token: token("{# c2 #}", 20, 1, 21),
                    value: token(" c2 ", 22, 1, 23),
                }
            ]
        );
    }

    #[test]
    fn test_comment_int_inside_not_allowed() {
        let input = "{% my_tag 4{# c1 #}2 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn test_comment_float_around() {
        let input = r#"{% my_tag {# c1 #}4.2{# c2 #} %}"#;
        let (_result, context) = plain_parse_tag_v1(input).unwrap();
        let comments = context.take_comments();
        assert_eq!(
            comments,
            vec![
                Comment {
                    token: token("{# c1 #}", 10, 1, 11),
                    value: token(" c1 ", 12, 1, 13),
                },
                Comment {
                    token: token("{# c2 #}", 21, 1, 22),
                    value: token(" c2 ", 23, 1, 24),
                }
            ]
        );
    }

    #[test]
    fn test_comment_float_inside_not_allowed() {
        let input = "{% my_tag 4.{# c1 #}2 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag 4{# c1 #}.2 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag .{# c1 #}2 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag -{# c1 #}1.5 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag +{# c1 #}1.5 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag -1.2{# c1 #}e2 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag -1.2e{# c1 #}2 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);

        let input = "{% my_tag -1.2e-0{# c1 #}2 %}";
        let result = plain_parse_tag_v1(input);
        assert_eq!(result.is_err(), true);
    }
}
