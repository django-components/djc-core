// Each of the `tag_parser_<data_type>.rs` file tests following cases:
//  1. as arg
//  2. as multiple args
//  3. as arg with filter without filter arg
//  4. as arg with filter with filter arg
//  5. as arg with `...` spread
//  6. as kwarg
//  7. as multiple kwargs
//  8. as kwarg with filter without filter arg
//  9. as kwarg with filter with filter arg
// 10. as both arg and kwarg with filters
// 11. as both arg and kwarg with filters and arg with `...` spreads
// 12. inside list
// 13. inside list with filter without filter arg
// 14. inside list with filter with filter arg
// 15. inside list with filter with filter arg and `*` spread.
// 16. inside list with `*` spread.
// 17. inside dict as value
// 18. inside dict as value with filter with filter arg
// 19. inside dict as key and value
// 20. inside dict as key and value, both with filters, and value with filter arg.
// 21. inside dict as neither key nor value, with `**` spread and filter without arg

mod common;

#[cfg(test)]
mod tests {
    use std::vec;

    use djc_template_parser::ast::{
        GenericTag, Tag, TagMeta, TagValue, TagValueFilter, Token, ValueChild, ValueKind,
    };

    use super::common::{
        plain_int_value, plain_parse_tag_v1, plain_string_value, plain_variable_value,
        string_value, tag_attr, template_string_value, token, translation_value, variable_value,
    };

    #[test]
    fn test_dict_as_arg() {
        let input = r#"{% my_tag {42: 'hello', **my_var} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}"#, 10, 1, 11),
            value: token(r#"{42: 'hello', **my_var}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag {42: 'hello', **my_var} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 26, 1, 27)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_multiple_args() {
        let input = r#"{% my_tag {42: 'hello', **my_var} {100: 'world', **other_var} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value1 = TagValue {
            token: token(r#"{42: 'hello', **my_var}"#, 10, 1, 11),
            value: token(r#"{42: 'hello', **my_var}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value2 = TagValue {
            token: token(r#"{100: 'world', **other_var}"#, 34, 1, 35),
            value: token(r#"{100: 'world', **other_var}"#, 34, 1, 35),
            children: vec![
                ValueChild::Value(plain_int_value("100", 35, 1, 36, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 40, 1, 41, None)),
                ValueChild::Value(plain_variable_value("other_var", 49, 1, 50, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {42: 'hello', **my_var} {100: 'world', **other_var} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 26, 1, 27), token("other_var", 51, 1, 52)],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, dict_value1, false),
                    tag_attr(None, dict_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag {42: 'hello', **my_var}|keys %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}|keys"#, 10, 1, 11),
            value: token(r#"{42: 'hello', **my_var}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|keys", 33, 1, 34),
                name: token("keys", 34, 1, 35),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag {42: 'hello', **my_var}|keys %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 26, 1, 27)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag {42: 'hello', **my_var}|get:{1: test} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_dict = TagValue {
            token: token(r#"{1: test}"#, 38, 1, 39),
            value: token(r#"{1: test}"#, 38, 1, 39),
            children: vec![
                ValueChild::Value(plain_int_value("1", 39, 1, 40, None)),
                ValueChild::Value(plain_variable_value("test", 42, 1, 43, None)),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}|get:{1: test}"#, 10, 1, 11),
            value: token(r#"{42: 'hello', **my_var}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token(r#"|get:{1: test}"#, 33, 1, 34),
                name: token("get", 34, 1, 35),
                arg: Some(filter_arg_dict),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {42: 'hello', **my_var}|get:{1: test} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 26, 1, 27), token("test", 42, 1, 43)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_arg_with_spread() {
        let input = r#"{% my_tag ...{42: 'hello', **my_var} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"...{42: 'hello', **my_var}"#, 10, 1, 11),
            value: token(r#"{42: 'hello', **my_var}"#, 13, 1, 14),
            children: vec![
                ValueChild::Value(plain_int_value("42", 14, 1, 15, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 18, 1, 19, None)),
                ValueChild::Value(plain_variable_value("my_var", 27, 1, 28, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: Some("...".to_string()),
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ...{42: 'hello', **my_var} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 29, 1, 30)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_kwarg() {
        let input = r#"{% my_tag key={42: 'hello', **my_var} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}"#, 14, 1, 15),
            value: token(r#"{42: 'hello', **my_var}"#, 14, 1, 15),
            children: vec![
                ValueChild::Value(plain_int_value("42", 15, 1, 16, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 19, 1, 20, None)),
                ValueChild::Value(plain_variable_value("my_var", 28, 1, 29, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key={42: 'hello', **my_var} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 30, 1, 31)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(Some(token("key", 10, 1, 11)), dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_multiple_kwargs() {
        let input = r#"{% my_tag key1={42: 'hello', **my_var} key2={100: 'world', **other_var} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value1 = TagValue {
            token: token(r#"{42: 'hello', **my_var}"#, 15, 1, 16),
            value: token(r#"{42: 'hello', **my_var}"#, 15, 1, 16),
            children: vec![
                ValueChild::Value(plain_int_value("42", 16, 1, 17, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 20, 1, 21, None)),
                ValueChild::Value(plain_variable_value("my_var", 29, 1, 30, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value2 = TagValue {
            token: token(r#"{100: 'world', **other_var}"#, 44, 1, 45),
            value: token(r#"{100: 'world', **other_var}"#, 44, 1, 45),
            children: vec![
                ValueChild::Value(plain_int_value("100", 45, 1, 46, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 50, 1, 51, None)),
                ValueChild::Value(plain_variable_value("other_var", 59, 1, 60, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key1={42: 'hello', **my_var} key2={100: 'world', **other_var} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 31, 1, 32), token("other_var", 61, 1, 62)],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(Some(token("key1", 10, 1, 11)), dict_value1, false),
                    tag_attr(Some(token("key2", 39, 1, 40)), dict_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key={42: 'hello', **my_var}|keys %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}|keys"#, 14, 1, 15),
            value: token(r#"{42: 'hello', **my_var}"#, 14, 1, 15),
            children: vec![
                ValueChild::Value(plain_int_value("42", 15, 1, 16, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 19, 1, 20, None)),
                ValueChild::Value(plain_variable_value("my_var", 28, 1, 29, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|keys", 37, 1, 38),
                name: token("keys", 38, 1, 39),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key={42: 'hello', **my_var}|keys %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 30, 1, 31)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(Some(token("key", 10, 1, 11)), dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_kwarg_with_filter_with_arg() {
        let input = r#"{% my_tag key={42: 'hello', **my_var}|get:{1: test} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_dict = TagValue {
            token: token(r#"{1: test}"#, 42, 1, 43),
            value: token(r#"{1: test}"#, 42, 1, 43),
            children: vec![
                ValueChild::Value(plain_int_value("1", 43, 1, 44, None)),
                ValueChild::Value(plain_variable_value("test", 46, 1, 47, None)),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}|get:{1: test}"#, 14, 1, 15),
            value: token(r#"{42: 'hello', **my_var}"#, 14, 1, 15),
            children: vec![
                ValueChild::Value(plain_int_value("42", 15, 1, 16, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 19, 1, 20, None)),
                ValueChild::Value(plain_variable_value("my_var", 28, 1, 29, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token(r#"|get:{1: test}"#, 37, 1, 38),
                name: token("get", 38, 1, 39),
                arg: Some(filter_arg_dict),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key={42: 'hello', **my_var}|get:{1: test} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 30, 1, 31), token("test", 46, 1, 47)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(Some(token("key", 10, 1, 11)), dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag {42: 'hello', **my_var}|keys key={100: 'world', **other_var}|get:{1: test} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value1 = TagValue {
            token: token(r#"{42: 'hello', **my_var}|keys"#, 10, 1, 11),
            value: token(r#"{42: 'hello', **my_var}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|keys", 33, 1, 34),
                name: token("keys", 34, 1, 35),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let filter_arg_dict = TagValue {
            token: token(r#"{1: test}"#, 75, 1, 76),
            value: token(r#"{1: test}"#, 75, 1, 76),
            children: vec![
                ValueChild::Value(plain_int_value("1", 76, 1, 77, None)),
                ValueChild::Value(plain_variable_value("test", 79, 1, 80, None)),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value2 = TagValue {
            token: token(r#"{100: 'world', **other_var}|get:{1: test}"#, 43, 1, 44),
            value: token(r#"{100: 'world', **other_var}"#, 43, 1, 44),
            children: vec![
                ValueChild::Value(plain_int_value("100", 44, 1, 45, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 49, 1, 50, None)),
                ValueChild::Value(plain_variable_value("other_var", 58, 1, 59, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token(r#"|get:{1: test}"#, 70, 1, 71),
                name: token("get", 71, 1, 72),
                arg: Some(filter_arg_dict),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {42: 'hello', **my_var}|keys key={100: 'world', **other_var}|get:{1: test} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("my_var", 26, 1, 27),
                        token("other_var", 60, 1, 61),
                        token("test", 79, 1, 80)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, dict_value1, false),
                    tag_attr(Some(token("key", 39, 1, 40)), dict_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ...{42: 'hello', **my_var}|keys key={100: 'world', **other_var}|get:{1: test} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value1 = TagValue {
            token: token(r#"...{42: 'hello', **my_var}|keys"#, 10, 1, 11),
            value: token(r#"{42: 'hello', **my_var}"#, 13, 1, 14),
            children: vec![
                ValueChild::Value(plain_int_value("42", 14, 1, 15, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 18, 1, 19, None)),
                ValueChild::Value(plain_variable_value("my_var", 27, 1, 28, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: Some("...".to_string()),
            filters: vec![TagValueFilter {
                token: token("|keys", 36, 1, 37),
                name: token("keys", 37, 1, 38),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let filter_arg_dict = TagValue {
            token: token(r#"{1: test}"#, 78, 1, 79),
            value: token(r#"{1: test}"#, 78, 1, 79),
            children: vec![
                ValueChild::Value(plain_int_value("1", 79, 1, 80, None)),
                ValueChild::Value(plain_variable_value("test", 82, 1, 83, None)),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value2 = TagValue {
            token: token(r#"{100: 'world', **other_var}|get:{1: test}"#, 46, 1, 47),
            value: token(r#"{100: 'world', **other_var}"#, 46, 1, 47),
            children: vec![
                ValueChild::Value(plain_int_value("100", 47, 1, 48, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 52, 1, 53, None)),
                ValueChild::Value(plain_variable_value("other_var", 61, 1, 62, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token(r#"|get:{1: test}"#, 73, 1, 74),
                name: token("get", 74, 1, 75),
                arg: Some(filter_arg_dict),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ...{42: 'hello', **my_var}|keys key={100: 'world', **other_var}|get:{1: test} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("my_var", 29, 1, 30),
                        token("other_var", 63, 1, 64),
                        token("test", 82, 1, 83)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, dict_value1, false),
                    tag_attr(Some(token("key", 42, 1, 43)), dict_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_inside_list() {
        let input = r#"{% my_tag [{42: 'hello', **my_var}] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}"#, 11, 1, 12),
            value: token(r#"{42: 'hello', **my_var}"#, 11, 1, 12),
            children: vec![
                ValueChild::Value(plain_int_value("42", 12, 1, 13, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 16, 1, 17, None)),
                ValueChild::Value(plain_variable_value("my_var", 25, 1, 26, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[{42: 'hello', **my_var}]"#, 10, 1, 11),
            value: token(r#"[{42: 'hello', **my_var}]"#, 10, 1, 11),
            children: vec![ValueChild::Value(dict_value)],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag [{42: 'hello', **my_var}] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 27, 1, 28)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag [{42: 'hello', **my_var}|keys] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}|keys"#, 11, 1, 12),
            value: token(r#"{42: 'hello', **my_var}"#, 11, 1, 12),
            children: vec![
                ValueChild::Value(plain_int_value("42", 12, 1, 13, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 16, 1, 17, None)),
                ValueChild::Value(plain_variable_value("my_var", 25, 1, 26, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|keys", 34, 1, 35),
                name: token("keys", 35, 1, 36),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[{42: 'hello', **my_var}|keys]"#, 10, 1, 11),
            value: token(r#"[{42: 'hello', **my_var}|keys]"#, 10, 1, 11),
            children: vec![ValueChild::Value(dict_value)],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag [{42: 'hello', **my_var}|keys] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 27, 1, 28)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag [{42: 'hello', **my_var}|get:{1: test}] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_dict = TagValue {
            token: token(r#"{1: test}"#, 39, 1, 40),
            value: token(r#"{1: test}"#, 39, 1, 40),
            children: vec![
                ValueChild::Value(plain_int_value("1", 40, 1, 41, None)),
                ValueChild::Value(plain_variable_value("test", 43, 1, 44, None)),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value = TagValue {
            token: token(r#"{42: 'hello', **my_var}|get:{1: test}"#, 11, 1, 12),
            value: token(r#"{42: 'hello', **my_var}"#, 11, 1, 12),
            children: vec![
                ValueChild::Value(plain_int_value("42", 12, 1, 13, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 16, 1, 17, None)),
                ValueChild::Value(plain_variable_value("my_var", 25, 1, 26, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token(r#"|get:{1: test}"#, 34, 1, 35),
                name: token("get", 35, 1, 36),
                arg: Some(filter_arg_dict),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[{42: 'hello', **my_var}|get:{1: test}]"#, 10, 1, 11),
            value: token(r#"[{42: 'hello', **my_var}|get:{1: test}]"#, 10, 1, 11),
            children: vec![ValueChild::Value(dict_value)],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag [{42: 'hello', **my_var}|get:{1: test}] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 27, 1, 28), token("test", 43, 1, 44)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_inside_list_with_filter_with_arg_and_spread() {
        let input = r#"{% my_tag [*{42: 'hello', **my_var}|get:{1: test}] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_dict = TagValue {
            token: token(r#"{1: test}"#, 40, 1, 41),
            value: token(r#"{1: test}"#, 40, 1, 41),
            children: vec![
                ValueChild::Value(plain_int_value("1", 41, 1, 42, None)),
                ValueChild::Value(plain_variable_value("test", 44, 1, 45, None)),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value = TagValue {
            token: token(r#"*{42: 'hello', **my_var}|get:{1: test}"#, 11, 1, 12),
            value: token(r#"{42: 'hello', **my_var}"#, 12, 1, 13),
            children: vec![
                ValueChild::Value(plain_int_value("42", 13, 1, 14, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 17, 1, 18, None)),
                ValueChild::Value(plain_variable_value("my_var", 26, 1, 27, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: Some("*".to_string()),
            filters: vec![TagValueFilter {
                token: token(r#"|get:{1: test}"#, 35, 1, 36),
                name: token("get", 36, 1, 37),
                arg: Some(filter_arg_dict),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[*{42: 'hello', **my_var}|get:{1: test}]"#, 10, 1, 11),
            value: token(r#"[*{42: 'hello', **my_var}|get:{1: test}]"#, 10, 1, 11),
            children: vec![ValueChild::Value(dict_value)],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag [*{42: 'hello', **my_var}|get:{1: test}] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 28, 1, 29), token("test", 44, 1, 45)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_inside_list_with_spread() {
        let input = r#"{% my_tag [*{42: 'hello', **my_var}] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"*{42: 'hello', **my_var}"#, 11, 1, 12),
            value: token(r#"{42: 'hello', **my_var}"#, 12, 1, 13),
            children: vec![
                ValueChild::Value(plain_int_value("42", 13, 1, 14, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 17, 1, 18, None)),
                ValueChild::Value(plain_variable_value("my_var", 26, 1, 27, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: Some("*".to_string()),
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[*{42: 'hello', **my_var}]"#, 10, 1, 11),
            value: token(r#"[*{42: 'hello', **my_var}]"#, 10, 1, 11),
            children: vec![ValueChild::Value(dict_value)],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag [*{42: 'hello', **my_var}] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 28, 1, 29)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_inside_dict_as_value() {
        let input = r#"{% my_tag {key: {42: 'hello', **my_var}} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let inner_dict = TagValue {
            token: token(r#"{42: 'hello', **my_var}"#, 16, 1, 17),
            value: token(r#"{42: 'hello', **my_var}"#, 16, 1, 17),
            children: vec![
                ValueChild::Value(plain_int_value("42", 17, 1, 18, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 21, 1, 22, None)),
                ValueChild::Value(plain_variable_value("my_var", 30, 1, 31, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_dict = TagValue {
            token: token(r#"{key: {42: 'hello', **my_var}}"#, 10, 1, 11),
            value: token(r#"{key: {42: 'hello', **my_var}}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(inner_dict),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag {key: {42: 'hello', **my_var}} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("key", 11, 1, 12), token("my_var", 32, 1, 33)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_dict, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_inside_dict_as_value_with_filter_with_arg() {
        let input = r#"{% my_tag {key: {42: 'hello', **my_var}|get:{1: test}} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_dict = TagValue {
            token: token(r#"{1: test}"#, 44, 1, 45),
            value: token(r#"{1: test}"#, 44, 1, 45),
            children: vec![
                ValueChild::Value(plain_int_value("1", 45, 1, 46, None)),
                ValueChild::Value(plain_variable_value("test", 48, 1, 49, None)),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let inner_dict = TagValue {
            token: token(r#"{42: 'hello', **my_var}|get:{1: test}"#, 16, 1, 17),
            value: token(r#"{42: 'hello', **my_var}"#, 16, 1, 17),
            children: vec![
                ValueChild::Value(plain_int_value("42", 17, 1, 18, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 21, 1, 22, None)),
                ValueChild::Value(plain_variable_value("my_var", 30, 1, 31, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![TagValueFilter {
                token: token(r#"|get:{1: test}"#, 39, 1, 40),
                name: token("get", 40, 1, 41),
                arg: Some(filter_arg_dict),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_dict = TagValue {
            token: token(r#"{key: {42: 'hello', **my_var}|get:{1: test}}"#, 10, 1, 11),
            value: token(r#"{key: {42: 'hello', **my_var}|get:{1: test}}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(inner_dict),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {key: {42: 'hello', **my_var}|get:{1: test}} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("key", 11, 1, 12),
                        token("my_var", 32, 1, 33),
                        token("test", 48, 1, 49)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_dict, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    #[should_panic(expected = "ParsingError")]
    fn test_dict_inside_dict_as_key_and_value() {
        // Dictionaries cannot be used as dictionary keys - this should fail to parse
        let input = r#"{% my_tag {{42: 'hello', **my_var}: {100: 'world', **other_var}} %}"#;
        let (_result, _context) = plain_parse_tag_v1(input).unwrap();
    }

    #[test]
    #[should_panic(expected = "ParsingError")]
    fn test_dict_inside_dict_as_key_and_value_with_filters_and_arg() {
        // Dictionaries cannot be used as dictionary keys - this should fail to parse
        let input = r#"{% my_tag {{42: 'hello', **my_var}|keys: {100: 'world', **other_var}|get:{1: test}} %}"#;
        let (_result, _context) = plain_parse_tag_v1(input).unwrap();
    }

    #[test]
    fn test_dict_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**{42: 'hello', **my_var}|keys} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let inner_dict = TagValue {
            token: token(r#"**{42: 'hello', **my_var}|keys"#, 11, 1, 12),
            value: token(r#"{42: 'hello', **my_var}"#, 13, 1, 14),
            children: vec![
                ValueChild::Value(plain_int_value("42", 14, 1, 15, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 18, 1, 19, None)),
                ValueChild::Value(plain_variable_value("my_var", 27, 1, 28, Some("**"))),
            ],
            kind: ValueKind::Dict,
            spread: Some("**".to_string()),
            filters: vec![TagValueFilter {
                token: token("|keys", 36, 1, 37),
                name: token("keys", 37, 1, 38),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_dict = TagValue {
            token: token(r#"{**{42: 'hello', **my_var}|keys}"#, 10, 1, 11),
            value: token(r#"{**{42: 'hello', **my_var}|keys}"#, 10, 1, 11),
            children: vec![ValueChild::Value(inner_dict)],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag {**{42: 'hello', **my_var}|keys} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 29, 1, 30)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_dict, false)],
                is_self_closing: false,
            })
        );
    }

    // #######################################
    // DICT EDGE CASES
    // #######################################

    #[test]
    fn test_dict_filters_key() {
        // Test filters on keys
        let input = r#"{% my_tag {"key"|upper|lower: "value"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag {"key"|upper|lower: "value"} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(r#"{"key"|upper|lower: "value"}"#, 10, 1, 11),
                        value: token(r#"{"key"|upper|lower: "value"}"#, 10, 1, 11),
                        children: vec![
                            ValueChild::Value(string_value(
                                token(r#""key"|upper|lower"#, 11, 1, 12),
                                token(r#""key""#, 11, 1, 12),
                                None,
                                vec![
                                    TagValueFilter {
                                        name: token("upper", 17, 1, 18),
                                        token: token("|upper", 16, 1, 17),
                                        arg: None,
                                    },
                                    TagValueFilter {
                                        name: token("lower", 23, 1, 24),
                                        token: token("|lower", 22, 1, 23),
                                        arg: None,
                                    },
                                ],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(plain_string_value(r#""value""#, 30, 1, 31, None)),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_filters_value() {
        // Test filters on values
        let input = r#"{% my_tag {"key": "value"|upper|lower} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag {"key": "value"|upper|lower} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(r#"{"key": "value"|upper|lower}"#, 10, 1, 11),
                        value: token(r#"{"key": "value"|upper|lower}"#, 10, 1, 11),
                        children: vec![
                            ValueChild::Value(plain_string_value(r#""key""#, 11, 1, 12, None)),
                            ValueChild::Value(string_value(
                                token(r#""value"|upper|lower"#, 18, 1, 19),
                                token(r#""value""#, 18, 1, 19),
                                None,
                                vec![
                                    TagValueFilter {
                                        name: token("upper", 26, 1, 27),
                                        token: token("|upper", 25, 1, 26),
                                        arg: None,
                                    },
                                    TagValueFilter {
                                        name: token("lower", 32, 1, 33),
                                        token: token("|lower", 31, 1, 32),
                                        arg: None,
                                    },
                                ],
                                vec![],
                                vec![],
                            )),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_filters_whitespace() {
        // Test filter on all dict
        let input = r#"{% my_tag {"key" | default: "value" | default : empty_dict} | default : empty_dict %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {"key" | default: "value" | default : empty_dict} | default : empty_dict %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("empty_dict", 48, 1, 49),
                        token("empty_dict", 72, 1, 73)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"{"key" | default: "value" | default : empty_dict} | default : empty_dict"#,
                            10,
                            1,
                            11
                        ),
                        value: token(
                            r#"{"key" | default: "value" | default : empty_dict}"#,
                            10,
                            1,
                            11
                        ),
                        children: vec![
                            ValueChild::Value(string_value(
                                token(r#""key" | default"#, 11, 1, 12),
                                token(r#""key""#, 11, 1, 12),
                                None,
                                vec![TagValueFilter {
                                    name: token("default", 19, 1, 20),
                                    token: token("| default", 17, 1, 18),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(string_value(
                                token(r#""value" | default : empty_dict"#, 28, 1, 29),
                                token(r#""value""#, 28, 1, 29),
                                None,
                                vec![TagValueFilter {
                                    name: token("default", 38, 1, 39),
                                    token: token("| default : empty_dict", 36, 1, 37),
                                    arg: Some(plain_variable_value("empty_dict", 48, 1, 49, None)),
                                }],
                                vec![],
                                vec![],
                            )),
                        ],
                        spread: None,
                        filters: vec![TagValueFilter {
                            name: token("default", 62, 1, 63),
                            token: token("| default : empty_dict", 60, 1, 61),
                            arg: Some(plain_variable_value("empty_dict", 72, 1, 73, None)),
                        }],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_nested() {
        // Test dict in list
        let input = r#"{% my_tag [1, {"key": "val"}, 2] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag [1, {"key": "val"}, 2] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(r#"[1, {"key": "val"}, 2]"#, 10, 1, 11),
                        value: token(r#"[1, {"key": "val"}, 2]"#, 10, 1, 11),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 11, 1, 12, None)),
                            ValueChild::Value(TagValue {
                                token: token(r#"{"key": "val"}"#, 14, 1, 15),
                                value: token(r#"{"key": "val"}"#, 14, 1, 15),
                                children: vec![
                                    ValueChild::Value(plain_string_value(
                                        r#""key""#, 15, 1, 16, None
                                    )),
                                    ValueChild::Value(plain_string_value(
                                        r#""val""#, 22, 1, 23, None
                                    )),
                                ],
                                spread: None,
                                filters: vec![],
                                kind: ValueKind::Dict,
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(plain_int_value("2", 30, 1, 31, None)),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::List,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_invalid() {
        let invalid_inputs = vec![
            (
                r#"{% my_tag {key|lower:my_arg: 123} %}"#,
                "filter arguments in dictionary keys",
            ),
            (
                r#"{% my_tag {"key"|default:empty_dict: "value"|default:empty_dict} %}"#,
                "filter arguments in dictionary keys",
            ),
            ("{% my_tag {key} %}", "missing value"),
            ("{% my_tag {key,} %}", "missing value with comma"),
            ("{% my_tag {key:} %}", "missing value after colon"),
            ("{% my_tag {:value} %}", "missing key"),
            ("{% my_tag {key: key:} %}", "double colon"),
            ("{% my_tag {:key :key} %}", "double key"),
        ];

        for (input, msg) in invalid_inputs {
            assert!(
                plain_parse_tag_v1(input).is_err(),
                "Should not allow {}: {}",
                msg,
                input
            );
        }
    }

    #[test]
    fn test_dict_spread() {
        // Test spreading into dict
        let input = r#"{% my_tag {"key1": "val1", **other_dict, "key2": "val2", **"{{ key3 }}", **_( " key4 ")} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {"key1": "val1", **other_dict, "key2": "val2", **"{{ key3 }}", **_( " key4 ")} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("other_dict", 29, 1, 30)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"{"key1": "val1", **other_dict, "key2": "val2", **"{{ key3 }}", **_( " key4 ")}"#,
                            10,
                            1,
                            11
                        ),
                        value: token(
                            r#"{"key1": "val1", **other_dict, "key2": "val2", **"{{ key3 }}", **_( " key4 ")}"#,
                            10,
                            1,
                            11
                        ),
                        children: vec![
                            ValueChild::Value(plain_string_value(r#""key1""#, 11, 1, 12, None)),
                            ValueChild::Value(plain_string_value(r#""val1""#, 19, 1, 20, None)),
                            ValueChild::Value(plain_variable_value(
                                "other_dict",
                                27,
                                1,
                                28,
                                Some("**")
                            )),
                            ValueChild::Value(plain_string_value(r#""key2""#, 41, 1, 42, None)),
                            ValueChild::Value(plain_string_value(r#""val2""#, 49, 1, 50, None)),
                            ValueChild::Value(template_string_value(
                                token(r#"**"{{ key3 }}""#, 57, 1, 58),
                                token(r#""{{ key3 }}""#, 59, 1, 60),
                                Some("**"),
                                vec![],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(translation_value(
                                token(r#"**_( " key4 ")"#, 73, 1, 74),
                                Token {
                                    content: r#"_(" key4 ")"#.to_string(),
                                    start_index: 75,
                                    end_index: 87,
                                    line_col: (1, 76),
                                },
                                Some("**"),
                                vec![],
                                vec![],
                                vec![],
                            )),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_spread_filters() {
        // Test spreading into dict + filters
        let input = r#"{% my_tag {"key1": "val1"|upper, **other_dict|join:my_var, "key2": "val2"|lower, **"{{ key3 }}", **_( " key4 ")|escape} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {"key1": "val1"|upper, **other_dict|join:my_var, "key2": "val2"|lower, **"{{ key3 }}", **_( " key4 ")|escape} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("other_dict", 35, 1, 36),
                        token("my_var", 51, 1, 52)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"{"key1": "val1"|upper, **other_dict|join:my_var, "key2": "val2"|lower, **"{{ key3 }}", **_( " key4 ")|escape}"#,
                            10,
                            1,
                            11
                        ),
                        value: token(
                            r#"{"key1": "val1"|upper, **other_dict|join:my_var, "key2": "val2"|lower, **"{{ key3 }}", **_( " key4 ")|escape}"#,
                            10,
                            1,
                            11
                        ),
                        children: vec![
                            ValueChild::Value(plain_string_value(r#""key1""#, 11, 1, 12, None)),
                            ValueChild::Value(string_value(
                                token(r#""val1"|upper"#, 19, 1, 20),
                                token(r#""val1""#, 19, 1, 20),
                                None,
                                vec![TagValueFilter {
                                    name: token("upper", 26, 1, 27),
                                    token: token("|upper", 25, 1, 26),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(variable_value(
                                token(r#"**other_dict|join:my_var"#, 33, 1, 34),
                                token("other_dict", 35, 1, 36),
                                Some("**"),
                                vec![TagValueFilter {
                                    name: token("join", 46, 1, 47),
                                    token: token("|join:my_var", 45, 1, 46),
                                    arg: Some(plain_variable_value("my_var", 51, 1, 52, None)),
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(plain_string_value(r#""key2""#, 59, 1, 60, None)),
                            ValueChild::Value(string_value(
                                token(r#""val2"|lower"#, 67, 1, 68),
                                token(r#""val2""#, 67, 1, 68),
                                None,
                                vec![TagValueFilter {
                                    name: token("lower", 74, 1, 75),
                                    token: token("|lower", 73, 1, 74),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(template_string_value(
                                token(r#"**"{{ key3 }}""#, 81, 1, 82),
                                token(r#""{{ key3 }}""#, 83, 1, 84),
                                Some("**"),
                                vec![],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(translation_value(
                                token(r#"**_( " key4 ")|escape"#, 97, 1, 98),
                                Token {
                                    content: r#"_(" key4 ")"#.to_string(),
                                    start_index: 99,
                                    end_index: 111,
                                    line_col: (1, 100),
                                },
                                Some("**"),
                                vec![TagValueFilter {
                                    name: token("escape", 112, 1, 113),
                                    token: token("|escape", 111, 1, 112),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_spread_in_dict() {
        // Test spreading literal dict
        let input = r#"{% my_tag {"key1": "val1", **{"inner": "value"}, "key2": "val2"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {"key1": "val1", **{"inner": "value"}, "key2": "val2"} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"{"key1": "val1", **{"inner": "value"}, "key2": "val2"}"#,
                            10,
                            1,
                            11
                        ),
                        value: token(
                            r#"{"key1": "val1", **{"inner": "value"}, "key2": "val2"}"#,
                            10,
                            1,
                            11
                        ),
                        children: vec![
                            ValueChild::Value(plain_string_value(r#""key1""#, 11, 1, 12, None)),
                            ValueChild::Value(plain_string_value(r#""val1""#, 19, 1, 20, None)),
                            ValueChild::Value(TagValue {
                                token: token(r#"**{"inner": "value"}"#, 27, 1, 28),
                                value: token(r#"{"inner": "value"}"#, 29, 1, 30),
                                children: vec![
                                    ValueChild::Value(plain_string_value(
                                        r#""inner""#,
                                        30,
                                        1,
                                        31,
                                        None
                                    )),
                                    ValueChild::Value(plain_string_value(
                                        r#""value""#,
                                        39,
                                        1,
                                        40,
                                        None
                                    )),
                                ],
                                spread: Some("**".to_string()),
                                filters: vec![],
                                kind: ValueKind::Dict,
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(plain_string_value(r#""key2""#, 49, 1, 50, None)),
                            ValueChild::Value(plain_string_value(r#""val2""#, 57, 1, 58, None)),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_with_comments() {
        // Test comments after values
        let input = r#"{% my_tag {# comment before dict #}{{# comment after dict start #}
            "key1": "value1", {# comment after first value #}
            "key2": "value2"
        {# comment before dict end #}}{# comment after dict #} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {# comment before dict #}{{# comment after dict start #}
            "key1": "value1", {# comment after first value #}
            "key2": "value2"
        {# comment before dict end #}}{# comment after dict #} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"{{# comment after dict start #}
            "key1": "value1", {# comment after first value #}
            "key2": "value2"
        {# comment before dict end #}}"#,
                            35,
                            1,
                            36
                        ),
                        value: token(
                            r#"{{# comment after dict start #}
            "key1": "value1", {# comment after first value #}
            "key2": "value2"
        {# comment before dict end #}}"#,
                            35,
                            1,
                            36
                        ),
                        children: vec![
                            ValueChild::Value(plain_string_value(r#""key1""#, 79, 2, 13, None)),
                            ValueChild::Value(plain_string_value(r#""value1""#, 87, 2, 21, None)),
                            ValueChild::Value(plain_string_value(r#""key2""#, 141, 3, 13, None)),
                            ValueChild::Value(plain_string_value(r#""value2""#, 149, 3, 21, None)),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_comments_colons_commas() {
        // Test comments around colons and commas
        let input = r#"{% my_tag {
            "key1" {# comment before colon #}: {# comment after colon #} "value1" {# comment before comma #}, {# comment after comma #}
            "key2": "value2"
        } %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {
            "key1" {# comment before colon #}: {# comment after colon #} "value1" {# comment before comma #}, {# comment after comma #}
            "key2": "value2"
        } %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"{
            "key1" {# comment before colon #}: {# comment after colon #} "value1" {# comment before comma #}, {# comment after comma #}
            "key2": "value2"
        }"#,
                            10,
                            1,
                            11
                        ),
                        value: token(
                            r#"{
            "key1" {# comment before colon #}: {# comment after colon #} "value1" {# comment before comma #}, {# comment after comma #}
            "key2": "value2"
        }"#,
                            10,
                            1,
                            11
                        ),
                        children: vec![
                            ValueChild::Value(plain_string_value(r#""key1""#, 24, 2, 13, None)),
                            ValueChild::Value(plain_string_value(r#""value1""#, 85, 2, 74, None)),
                            ValueChild::Value(plain_string_value(r#""key2""#, 160, 3, 13, None)),
                            ValueChild::Value(plain_string_value(r#""value2""#, 168, 3, 21, None)),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_dict_comments_spread() {
        // Test comments around spread operator
        let input = r#"{% my_tag {
            "key1": "value1",
            {# comment before spread #}**{# comment after spread #}{"key2": "value2"}
        } %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag {
            "key1": "value1",
            {# comment before spread #}**{# comment after spread #}{"key2": "value2"}
        } %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"{
            "key1": "value1",
            {# comment before spread #}**{# comment after spread #}{"key2": "value2"}
        }"#,
                            10,
                            1,
                            11
                        ),
                        value: token(
                            r#"{
            "key1": "value1",
            {# comment before spread #}**{# comment after spread #}{"key2": "value2"}
        }"#,
                            10,
                            1,
                            11
                        ),
                        children: vec![
                            ValueChild::Value(plain_string_value(r#""key1""#, 24, 2, 13, None)),
                            ValueChild::Value(plain_string_value(r#""value1""#, 32, 2, 21, None)),
                            ValueChild::Value(TagValue {
                                token: token(r#"**{# comment after spread #}{"key2": "value2"}"#, 81, 3, 40),
                                value: token(r#"{"key2": "value2"}"#, 109, 3, 68),
                                children: vec![
                                    ValueChild::Value(plain_string_value(
                                        r#""key2""#,
                                        110,
                                        3,
                                        69,
                                        None
                                    )),
                                    ValueChild::Value(plain_string_value(
                                        r#""value2""#,
                                        118,
                                        3,
                                        77,
                                        None
                                    )),
                                ],
                                spread: Some("**".to_string()),
                                filters: vec![],
                                kind: ValueKind::Dict,
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                        ],
                        spread: None,
                        filters: vec![],
                        kind: ValueKind::Dict,
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    false,
                )],
                is_self_closing: false,
            })
        );
    }
}
