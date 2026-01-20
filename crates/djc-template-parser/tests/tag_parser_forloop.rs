mod common;

#[cfg(test)]
mod tests {
    use std::vec;

    use djc_template_parser::ast::{
        ForLoopTag, Tag, TagMeta, TagValue, TagValueFilter, ValueKind,
    };

    use super::common::{plain_parse_tag_v1, plain_variable_value, token};

    // ============================================
    // Basic for loop tests
    // ============================================

    #[test]
    fn test_basic_for_loop() {
        // Basic for loop: {% for item in items %}
        let input = "{% for item in items %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::ForLoop(ForLoopTag {
                meta: TagMeta {
                    token: token("{% for item in items %}", 0, 1, 1),
                    name: token("for", 3, 1, 4),
                    used_variables: vec![token("items", 15, 1, 16)],
                    assigned_variables: vec![],
                },
                targets: vec![token("item", 7, 1, 8)],
                iterable: plain_variable_value("items", 15, 1, 16, None),
            })
        );
    }

    #[test]
    fn test_multiple_loop_variables() {
        let input = "{% for x, y, z in matrix %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::ForLoop(ForLoopTag {
                meta: TagMeta {
                    token: token("{% for x, y, z in matrix %}", 0, 1, 1),
                    name: token("for", 3, 1, 4),
                    used_variables: vec![token("matrix", 18, 1, 19)],
                    assigned_variables: vec![],
                },
                targets: vec![
                    token("x", 7, 1, 8),
                    token("y", 10, 1, 11),
                    token("z", 13, 1, 14),
                ],
                iterable: plain_variable_value("matrix", 18, 1, 19, None),
            })
        );
    }

    #[test]
    fn test_for_loop_with_filters_on_iterable() {
        let input = "{% for item in items|filter:arg %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::ForLoop(ForLoopTag {
                meta: TagMeta {
                    token: token("{% for item in items|filter:arg %}", 0, 1, 1),
                    name: token("for", 3, 1, 4),
                    used_variables: vec![token("items", 15, 1, 16), token("arg", 28, 1, 29),],
                    assigned_variables: vec![],
                },
                targets: vec![token("item", 7, 1, 8)],
                iterable: TagValue {
                    token: token("items|filter:arg", 15, 1, 16),
                    value: token("items", 15, 1, 16),
                    children: vec![],
                    kind: ValueKind::Variable,
                    spread: None,
                    filters: vec![TagValueFilter {
                        name: token("filter", 21, 1, 22),
                        token: token("|filter:arg", 20, 1, 21),
                        arg: Some(plain_variable_value("arg", 28, 1, 29, None)),
                    }],
                    used_variables: vec![token("items", 15, 1, 16)],
                    assigned_variables: vec![],
                },
            })
        );
    }

    #[test]
    fn test_for_loop_with_python_expression_iterable() {
        let input = "{% for item in (items + other_items) %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        // The iterable should be parsed as a Python expression
        assert_eq!(
            result,
            Tag::ForLoop(ForLoopTag {
                meta: TagMeta {
                    token: token("{% for item in (items + other_items) %}", 0, 1, 1),
                    name: token("for", 3, 1, 4),
                    used_variables: vec![token("items", 16, 1, 17), token("other_items", 24, 1, 25),],
                    assigned_variables: vec![],
                },
                targets: vec![token("item", 7, 1, 8)],
                iterable: TagValue {
                    token: token("(items + other_items)", 15, 1, 16),
                    value: token("(items + other_items)", 15, 1, 16),
                    children: vec![],
                    kind: ValueKind::PythonExpr,
                    spread: None,
                    filters: vec![],
                    used_variables: vec![token("items", 16, 1, 17), token("other_items", 24, 1, 25),],
                    assigned_variables: vec![],
                },
            })
        );
    }

    #[test]
    fn test_for_loop_with_variable_iterable() {
        let input = "{% for item in my_list %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::ForLoop(ForLoopTag {
                meta: TagMeta {
                    token: token("{% for item in my_list %}", 0, 1, 1),
                    name: token("for", 3, 1, 4),
                    used_variables: vec![token("my_list", 15, 1, 16)],
                    assigned_variables: vec![],
                },
                targets: vec![token("item", 7, 1, 8)],
                iterable: plain_variable_value("my_list", 15, 1, 16, None),
            })
        );
    }

    // ============================================
    // Error handling tests
    // ============================================

    #[test]
    fn test_for_loop_missing_in_keyword() {
        // Missing "in" keyword: {% for item items %} should error
        let input = "{% for item items %}";
        let result = plain_parse_tag_v1(input);
        assert!(result.is_err(), "Should error when 'in' keyword is missing");
    }

    #[test]
    fn test_for_loop_missing_iterable() {
        // Missing iterable: {% for item in %} should error
        let input = "{% for item in %}";
        let result = plain_parse_tag_v1(input);
        assert!(result.is_err(), "Should error when iterable is missing");
    }

    #[test]
    fn test_for_loop_missing_targets() {
        // Missing targets: {% for in items %} should error
        let input = "{% for in items %}";
        let result = plain_parse_tag_v1(input);
        assert!(
            result.is_err(),
            "Should error when loop variables are missing"
        );
    }

    #[test]
    fn test_for_loop_self_closing_error() {
        // Self-closing for loop: {% for item in items / %} should error
        let input = "{% for item in items / %}";
        let result = plain_parse_tag_v1(input);
        assert!(
            result.is_err(),
            "Should error when for loop is self-closing"
        );
    }

    #[test]
    fn test_for_loop_invalid_syntax_no_space_after_for() {
        // Invalid syntax: no space after "for"
        // Note: This actually parses as a generic tag with name "foritem", not an error
        // The grammar allows this, so we test that it's not a for loop
        let input = "{% foritem in items %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        // This should parse as a generic tag, not a for loop
        assert!(
            matches!(result, Tag::Generic(_)),
            "Should parse as a generic tag"
        );
    }

    #[test]
    fn test_for_loop_invalid_syntax_no_space_before_in() {
        // Invalid syntax: no space before "in"
        let input = "{% for itemin items %}";
        let result = plain_parse_tag_v1(input);
        assert!(
            result.is_err(),
            "Should error when there's no space before 'in'"
        );
    }

    #[test]
    fn test_for_loop_invalid_syntax_no_space_after_in() {
        // Invalid syntax: no space after "in"
        let input = "{% for item initems %}";
        let result = plain_parse_tag_v1(input);
        assert!(
            result.is_err(),
            "Should error when there's no space after 'in'"
        );
    }

    #[test]
    fn test_for_loop_empty_targets() {
        // Empty targets (just comma)
        let input = "{% for , in items %}";
        let result = plain_parse_tag_v1(input);
        assert!(result.is_err(), "Should error when targets are empty");
    }

    #[test]
    fn test_for_loop_trailing_comma() {
        // Trailing comma in targets
        let input = "{% for x, y, in items %}";
        let result = plain_parse_tag_v1(input);
        assert!(
            result.is_err(),
            "Should error when there's a trailing comma in targets"
        );
    }
}
