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
        GenericTag, Tag, TagMeta, TagValue, TagValueFilter, ValueChild, ValueKind,
    };

    use super::common::{
        float_value, int_value, plain_float_value, plain_int_value, plain_parse_tag_v1,
        plain_string_value, plain_translation_value, plain_variable_value, string_value, tag_attr,
        template_string_value, token, translation_value, variable_value,
    };

    #[test]
    fn test_list_as_arg() {
        let input = r#"{% my_tag [42, 'hello', my_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]"#, 10, 1, 11),
            value: token(r#"[42, 'hello', my_var]"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, None)),
            ],
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
                    token: token(r#"{% my_tag [42, 'hello', my_var] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 24, 1, 25)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_multiple_args() {
        let input = r#"{% my_tag [42, 'hello', my_var] [100, 'world', other_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value1 = TagValue {
            token: token(r#"[42, 'hello', my_var]"#, 10, 1, 11),
            value: token(r#"[42, 'hello', my_var]"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value2 = TagValue {
            token: token(r#"[100, 'world', other_var]"#, 32, 1, 33),
            value: token(r#"[100, 'world', other_var]"#, 32, 1, 33),
            children: vec![
                ValueChild::Value(plain_int_value("100", 33, 1, 34, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 38, 1, 39, None)),
                ValueChild::Value(plain_variable_value("other_var", 47, 1, 48, None)),
            ],
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
                        r#"{% my_tag [42, 'hello', my_var] [100, 'world', other_var] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 24, 1, 25), token("other_var", 47, 1, 48)],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, list_value1, false),
                    tag_attr(None, list_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag [42, 'hello', my_var]|length %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]|length"#, 10, 1, 11),
            value: token(r#"[42, 'hello', my_var]"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|length", 31, 1, 32),
                name: token("length", 32, 1, 33),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag [42, 'hello', my_var]|length %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 24, 1, 25)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag [42, 'hello', my_var]|first:['a', other_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_list = TagValue {
            token: token(r#"['a', other_var]"#, 38, 1, 39),
            value: token(r#"['a', other_var]"#, 38, 1, 39),
            children: vec![
                ValueChild::Value(plain_string_value(r#"'a'"#, 39, 1, 40, None)),
                ValueChild::Value(plain_variable_value("other_var", 44, 1, 45, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]|first:['a', other_var]"#, 10, 1, 11),
            value: token(r#"[42, 'hello', my_var]"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|first:['a', other_var]", 31, 1, 32),
                name: token("first", 32, 1, 33),
                arg: Some(filter_arg_list),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag [42, 'hello', my_var]|first:['a', other_var] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 24, 1, 25), token("other_var", 44, 1, 45)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_arg_with_spread() {
        let input = r#"{% my_tag ...[42, 'hello', my_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"...[42, 'hello', my_var]"#, 10, 1, 11),
            value: token(r#"[42, 'hello', my_var]"#, 13, 1, 14),
            children: vec![
                ValueChild::Value(plain_int_value("42", 14, 1, 15, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 18, 1, 19, None)),
                ValueChild::Value(plain_variable_value("my_var", 27, 1, 28, None)),
            ],
            kind: ValueKind::List,
            spread: Some("...".to_string()),
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ...[42, 'hello', my_var] %}"#, 0, 1, 1),
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
    fn test_list_as_kwarg() {
        let input = r#"{% my_tag key=[42, 'hello', my_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]"#, 14, 1, 15),
            value: token(r#"[42, 'hello', my_var]"#, 14, 1, 15),
            children: vec![
                ValueChild::Value(plain_int_value("42", 15, 1, 16, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 19, 1, 20, None)),
                ValueChild::Value(plain_variable_value("my_var", 28, 1, 29, None)),
            ],
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
                    token: token(r#"{% my_tag key=[42, 'hello', my_var] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 28, 1, 29)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(Some(token("key", 10, 1, 11)), list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_multiple_kwargs() {
        let input = r#"{% my_tag key1=[42, 'hello', my_var] key2=[100, 'world', other_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value1 = TagValue {
            token: token(r#"[42, 'hello', my_var]"#, 15, 1, 16),
            value: token(r#"[42, 'hello', my_var]"#, 15, 1, 16),
            children: vec![
                ValueChild::Value(plain_int_value("42", 16, 1, 17, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 20, 1, 21, None)),
                ValueChild::Value(plain_variable_value("my_var", 29, 1, 30, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value2 = TagValue {
            token: token(r#"[100, 'world', other_var]"#, 42, 1, 43),
            value: token(r#"[100, 'world', other_var]"#, 42, 1, 43),
            children: vec![
                ValueChild::Value(plain_int_value("100", 43, 1, 44, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 48, 1, 49, None)),
                ValueChild::Value(plain_variable_value("other_var", 57, 1, 58, None)),
            ],
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
                        r#"{% my_tag key1=[42, 'hello', my_var] key2=[100, 'world', other_var] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 29, 1, 30), token("other_var", 57, 1, 58)],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(Some(token("key1", 10, 1, 11)), list_value1, false),
                    tag_attr(Some(token("key2", 37, 1, 38)), list_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key=[42, 'hello', my_var]|length %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]|length"#, 14, 1, 15),
            value: token(r#"[42, 'hello', my_var]"#, 14, 1, 15),
            children: vec![
                ValueChild::Value(plain_int_value("42", 15, 1, 16, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 19, 1, 20, None)),
                ValueChild::Value(plain_variable_value("my_var", 28, 1, 29, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|length", 35, 1, 36),
                name: token("length", 36, 1, 37),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=[42, 'hello', my_var]|length %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 28, 1, 29)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(Some(token("key", 10, 1, 11)), list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_kwarg_with_filter_with_arg() {
        let input = r#"{% my_tag key=[42, 'hello', my_var]|first:['a', other_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_list = TagValue {
            token: token(r#"['a', other_var]"#, 42, 1, 43),
            value: token(r#"['a', other_var]"#, 42, 1, 43),
            children: vec![
                ValueChild::Value(plain_string_value(r#"'a'"#, 43, 1, 44, None)),
                ValueChild::Value(plain_variable_value("other_var", 48, 1, 49, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]|first:['a', other_var]"#, 14, 1, 15),
            value: token(r#"[42, 'hello', my_var]"#, 14, 1, 15),
            children: vec![
                ValueChild::Value(plain_int_value("42", 15, 1, 16, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 19, 1, 20, None)),
                ValueChild::Value(plain_variable_value("my_var", 28, 1, 29, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|first:['a', other_var]", 35, 1, 36),
                name: token("first", 36, 1, 37),
                arg: Some(filter_arg_list),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key=[42, 'hello', my_var]|first:['a', other_var] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 28, 1, 29), token("other_var", 48, 1, 49)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(Some(token("key", 10, 1, 11)), list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag [42, 'hello', my_var]|length key=[100, 'world', other_var]|first:['a', third_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value1 = TagValue {
            token: token(r#"[42, 'hello', my_var]|length"#, 10, 1, 11),
            value: token(r#"[42, 'hello', my_var]"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 15, 1, 16, None)),
                ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|length", 31, 1, 32),
                name: token("length", 32, 1, 33),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let filter_arg_list2 = TagValue {
            token: token(r#"['a', third_var]"#, 75, 1, 76),
            value: token(r#"['a', third_var]"#, 75, 1, 76),
            children: vec![
                ValueChild::Value(plain_string_value(r#"'a'"#, 76, 1, 77, None)),
                ValueChild::Value(plain_variable_value("third_var", 81, 1, 82, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value2 = TagValue {
            token: token(
                r#"[100, 'world', other_var]|first:['a', third_var]"#,
                43,
                1,
                44,
            ),
            value: token(r#"[100, 'world', other_var]"#, 43, 1, 44),
            children: vec![
                ValueChild::Value(plain_int_value("100", 44, 1, 45, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 49, 1, 50, None)),
                ValueChild::Value(plain_variable_value("other_var", 58, 1, 59, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|first:['a', third_var]", 68, 1, 69),
                name: token("first", 69, 1, 70),
                arg: Some(filter_arg_list2),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag [42, 'hello', my_var]|length key=[100, 'world', other_var]|first:['a', third_var] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("my_var", 24, 1, 25),
                        token("other_var", 58, 1, 59),
                        token("third_var", 81, 1, 82)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, list_value1, false),
                    tag_attr(Some(token("key", 39, 1, 40)), list_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ...[42, 'hello', my_var]|length key=[100, 'world', other_var]|first:['a', third_var] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value1 = TagValue {
            token: token(r#"...[42, 'hello', my_var]|length"#, 10, 1, 11),
            value: token(r#"[42, 'hello', my_var]"#, 13, 1, 14),
            children: vec![
                ValueChild::Value(plain_int_value("42", 14, 1, 15, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 18, 1, 19, None)),
                ValueChild::Value(plain_variable_value("my_var", 27, 1, 28, None)),
            ],
            kind: ValueKind::List,
            spread: Some("...".to_string()),
            filters: vec![TagValueFilter {
                token: token("|length", 34, 1, 35),
                name: token("length", 35, 1, 36),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value2 = TagValue {
            token: token(
                r#"[100, 'world', other_var]|first:['a', third_var]"#,
                46,
                1,
                47,
            ),
            value: token(r#"[100, 'world', other_var]"#, 46, 1, 47),
            children: vec![
                ValueChild::Value(plain_int_value("100", 47, 1, 48, None)),
                ValueChild::Value(plain_string_value(r#"'world'"#, 52, 1, 53, None)),
                ValueChild::Value(plain_variable_value("other_var", 61, 1, 62, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|first:['a', third_var]", 71, 1, 72),
                name: token("first", 72, 1, 73),
                arg: Some(TagValue {
                    token: token(r#"['a', third_var]"#, 78, 1, 79),
                    value: token(r#"['a', third_var]"#, 78, 1, 79),
                    children: vec![
                        ValueChild::Value(plain_string_value(r#"'a'"#, 79, 1, 80, None)),
                        ValueChild::Value(plain_variable_value("third_var", 84, 1, 85, None)),
                    ],
                    kind: ValueKind::List,
                    spread: None,
                    filters: vec![],
                    used_variables: vec![],
                    assigned_variables: vec![],
                }),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ...[42, 'hello', my_var]|length key=[100, 'world', other_var]|first:['a', third_var] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("my_var", 27, 1, 28),
                        token("other_var", 61, 1, 62),
                        token("third_var", 84, 1, 85)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, list_value1, false),
                    tag_attr(Some(token("key", 42, 1, 43)), list_value2, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_inside_list() {
        let input = r#"{% my_tag [[42, 'hello', my_var]] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let inner_list = TagValue {
            token: token(r#"[42, 'hello', my_var]"#, 11, 1, 12),
            value: token(r#"[42, 'hello', my_var]"#, 11, 1, 12),
            children: vec![
                ValueChild::Value(plain_int_value("42", 12, 1, 13, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 16, 1, 17, None)),
                ValueChild::Value(plain_variable_value("my_var", 25, 1, 26, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_list = TagValue {
            token: token(r#"[[42, 'hello', my_var]]"#, 10, 1, 11),
            value: token(r#"[[42, 'hello', my_var]]"#, 10, 1, 11),
            children: vec![ValueChild::Value(inner_list)],
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
                    token: token(r#"{% my_tag [[42, 'hello', my_var]] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 25, 1, 26)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_list, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag [[42, 'hello', my_var]|length] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let inner_list = TagValue {
            token: token(r#"[42, 'hello', my_var]|length"#, 11, 1, 12),
            value: token(r#"[42, 'hello', my_var]"#, 11, 1, 12),
            children: vec![
                ValueChild::Value(plain_int_value("42", 12, 1, 13, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 16, 1, 17, None)),
                ValueChild::Value(plain_variable_value("my_var", 25, 1, 26, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|length", 32, 1, 33),
                name: token("length", 33, 1, 34),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_list = TagValue {
            token: token(r#"[[42, 'hello', my_var]|length]"#, 10, 1, 11),
            value: token(r#"[[42, 'hello', my_var]|length]"#, 10, 1, 11),
            children: vec![ValueChild::Value(inner_list)],
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
                    token: token(r#"{% my_tag [[42, 'hello', my_var]|length] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 25, 1, 26)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_list, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag [[42, 'hello', my_var]|first:['a', third_var]] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_list = TagValue {
            token: token(r#"['a', third_var]"#, 39, 1, 40),
            value: token(r#"['a', third_var]"#, 39, 1, 40),
            children: vec![
                ValueChild::Value(plain_string_value(r#"'a'"#, 40, 1, 41, None)),
                ValueChild::Value(plain_variable_value("third_var", 45, 1, 46, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let inner_list = TagValue {
            token: token(r#"[42, 'hello', my_var]|first:['a', third_var]"#, 11, 1, 12),
            value: token(r#"[42, 'hello', my_var]"#, 11, 1, 12),
            children: vec![
                ValueChild::Value(plain_int_value("42", 12, 1, 13, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 16, 1, 17, None)),
                ValueChild::Value(plain_variable_value("my_var", 25, 1, 26, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|first:['a', third_var]", 32, 1, 33),
                name: token("first", 33, 1, 34),
                arg: Some(filter_arg_list),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_list = TagValue {
            token: token(
                r#"[[42, 'hello', my_var]|first:['a', third_var]]"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"[[42, 'hello', my_var]|first:['a', third_var]]"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(inner_list)],
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
                        r#"{% my_tag [[42, 'hello', my_var]|first:['a', third_var]] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 25, 1, 26), token("third_var", 45, 1, 46)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_list, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_inside_list_with_filter_with_arg_and_spread() {
        let input = r#"{% my_tag [*[42, 'hello', my_var]|first:['a', third_var]] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_list = TagValue {
            token: token(r#"['a', third_var]"#, 40, 1, 41),
            value: token(r#"['a', third_var]"#, 40, 1, 41),
            children: vec![
                ValueChild::Value(plain_string_value(r#"'a'"#, 41, 1, 42, None)),
                ValueChild::Value(plain_variable_value("third_var", 46, 1, 47, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let inner_list = TagValue {
            token: token(
                r#"*[42, 'hello', my_var]|first:['a', third_var]"#,
                11,
                1,
                12,
            ),
            value: token(r#"[42, 'hello', my_var]"#, 12, 1, 13),
            children: vec![
                ValueChild::Value(plain_int_value("42", 13, 1, 14, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 17, 1, 18, None)),
                ValueChild::Value(plain_variable_value("my_var", 26, 1, 27, None)),
            ],
            kind: ValueKind::List,
            spread: Some("*".to_string()),
            filters: vec![TagValueFilter {
                token: token("|first:['a', third_var]", 33, 1, 34),
                name: token("first", 34, 1, 35),
                arg: Some(filter_arg_list),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_list = TagValue {
            token: token(
                r#"[*[42, 'hello', my_var]|first:['a', third_var]]"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"[*[42, 'hello', my_var]|first:['a', third_var]]"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(inner_list)],
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
                        r#"{% my_tag [*[42, 'hello', my_var]|first:['a', third_var]] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 26, 1, 27), token("third_var", 46, 1, 47)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_list, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_inside_list_with_spread() {
        let input = r#"{% my_tag [*[42, 'hello', my_var]] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let inner_list = TagValue {
            token: token(r#"*[42, 'hello', my_var]"#, 11, 1, 12),
            value: token(r#"[42, 'hello', my_var]"#, 12, 1, 13),
            children: vec![
                ValueChild::Value(plain_int_value("42", 13, 1, 14, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 17, 1, 18, None)),
                ValueChild::Value(plain_variable_value("my_var", 26, 1, 27, None)),
            ],
            kind: ValueKind::List,
            spread: Some("*".to_string()),
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let outer_list = TagValue {
            token: token(r#"[*[42, 'hello', my_var]]"#, 10, 1, 11),
            value: token(r#"[*[42, 'hello', my_var]]"#, 10, 1, 11),
            children: vec![ValueChild::Value(inner_list)],
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
                    token: token(r#"{% my_tag [*[42, 'hello', my_var]] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 26, 1, 27)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, outer_list, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_inside_dict_as_value() {
        let input = r#"{% my_tag {key: [42, 'hello', my_var]} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]"#, 16, 1, 17),
            value: token(r#"[42, 'hello', my_var]"#, 16, 1, 17),
            children: vec![
                ValueChild::Value(plain_int_value("42", 17, 1, 18, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 21, 1, 22, None)),
                ValueChild::Value(plain_variable_value("my_var", 30, 1, 31, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value = TagValue {
            token: token(r#"{key: [42, 'hello', my_var]}"#, 10, 1, 11),
            value: token(r#"{key: [42, 'hello', my_var]}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(list_value),
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
                    token: token(r#"{% my_tag {key: [42, 'hello', my_var]} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("key", 11, 1, 12), token("my_var", 30, 1, 31)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_list_inside_dict_as_value_with_filter_with_arg() {
        let input = r#"{% my_tag {key: [42, 'hello', my_var]|first:['a', third_var]} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let filter_arg_list = TagValue {
            token: token(r#"['a', third_var]"#, 44, 1, 45),
            value: token(r#"['a', third_var]"#, 44, 1, 45),
            children: vec![
                ValueChild::Value(plain_string_value(r#"'a'"#, 45, 1, 46, None)),
                ValueChild::Value(plain_variable_value("third_var", 50, 1, 51, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let list_value = TagValue {
            token: token(r#"[42, 'hello', my_var]|first:['a', third_var]"#, 16, 1, 17),
            value: token(r#"[42, 'hello', my_var]"#, 16, 1, 17),
            children: vec![
                ValueChild::Value(plain_int_value("42", 17, 1, 18, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 21, 1, 22, None)),
                ValueChild::Value(plain_variable_value("my_var", 30, 1, 31, None)),
            ],
            kind: ValueKind::List,
            spread: None,
            filters: vec![TagValueFilter {
                token: token("|first:['a', third_var]", 37, 1, 38),
                name: token("first", 38, 1, 39),
                arg: Some(filter_arg_list),
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value = TagValue {
            token: token(
                r#"{key: [42, 'hello', my_var]|first:['a', third_var]}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{key: [42, 'hello', my_var]|first:['a', third_var]}"#,
                10,
                1,
                11,
            ),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(list_value),
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
                        r#"{% my_tag {key: [42, 'hello', my_var]|first:['a', third_var]} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("key", 11, 1, 12),
                        token("my_var", 30, 1, 31),
                        token("third_var", 50, 1, 51)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    #[should_panic(expected = "ParsingError")]
    fn test_list_inside_dict_as_key_and_value() {
        // Lists cannot be used as dictionary keys - this should fail to parse
        let input = r#"{% my_tag {[42, 'hello', my_var]: [100, 'world', other_var]} %}"#;
        let (_result, _context) = plain_parse_tag_v1(input).unwrap();
    }

    #[test]
    #[should_panic(expected = "ParsingError")]
    fn test_list_inside_dict_as_key_and_value_with_filters_and_arg() {
        // Lists cannot be used as dictionary keys - this should fail to parse
        let input = r#"{% my_tag {[42, 'hello', my_var]|length: [100, 'world', other_var]|first:['a', third_var]} %}"#;
        let (_result, _context) = plain_parse_tag_v1(input).unwrap();
    }

    #[test]
    fn test_list_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**[42, 'hello', my_var]|length} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"**[42, 'hello', my_var]|length"#, 11, 1, 12),
            value: token(r#"[42, 'hello', my_var]"#, 13, 1, 14),
            children: vec![
                ValueChild::Value(plain_int_value("42", 14, 1, 15, None)),
                ValueChild::Value(plain_string_value(r#"'hello'"#, 18, 1, 19, None)),
                ValueChild::Value(plain_variable_value("my_var", 27, 1, 28, None)),
            ],
            kind: ValueKind::List,
            spread: Some("**".to_string()),
            filters: vec![TagValueFilter {
                token: token("|length", 34, 1, 35),
                name: token("length", 35, 1, 36),
                arg: None,
            }],
            used_variables: vec![],
            assigned_variables: vec![],
        };
        let dict_value = TagValue {
            token: token(r#"{**[42, 'hello', my_var]|length}"#, 10, 1, 11),
            value: token(r#"{**[42, 'hello', my_var]|length}"#, 10, 1, 11),
            children: vec![ValueChild::Value(list_value)],
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
                    token: token(r#"{% my_tag {**[42, 'hello', my_var]|length} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 27, 1, 28)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    // #######################################
    // LIST EDGE CASES
    // #######################################

    #[test]
    fn test_list_empty() {
        // Empty list
        let input = "{% my_tag [] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag [] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("[]", 10, 1, 11),
                        value: token("[]", 10, 1, 11),
                        children: vec![],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_mixed() {
        // List with mixed types
        let input = "{% my_tag [42, 'hello', my_var] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag [42, 'hello', my_var] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 24, 1, 25)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("[42, 'hello', my_var]", 10, 1, 11),
                        value: token("[42, 'hello', my_var]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                            ValueChild::Value(plain_string_value("'hello'", 15, 1, 16, None)),
                            ValueChild::Value(plain_variable_value("my_var", 24, 1, 25, None)),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_filter_item() {
        // List with filters on individual items
        let input = "{% my_tag ['hello'|upper, 'world'|title] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag ['hello'|upper, 'world'|title] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("['hello'|upper, 'world'|title]", 10, 1, 11),
                        value: token("['hello'|upper, 'world'|title]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(string_value(
                                token("'hello'|upper", 11, 1, 12),
                                token("'hello'", 11, 1, 12),
                                None,
                                vec![TagValueFilter {
                                    name: token("upper", 19, 1, 20),
                                    token: token("|upper", 18, 1, 19),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(string_value(
                                token("'world'|title", 26, 1, 27),
                                token("'world'", 26, 1, 27),
                                None,
                                vec![TagValueFilter {
                                    name: token("title", 34, 1, 35),
                                    token: token("|title", 33, 1, 34),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_filter_everywhere() {
        // List with both item filters and list filter
        let input = "{% my_tag ['a'|upper, 'b'|upper]|join:',' %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag ['a'|upper, 'b'|upper]|join:',' %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("['a'|upper, 'b'|upper]|join:','", 10, 1, 11),
                        value: token("['a'|upper, 'b'|upper]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(string_value(
                                token("'a'|upper", 11, 1, 12),
                                token("'a'", 11, 1, 12),
                                None,
                                vec![TagValueFilter {
                                    name: token("upper", 15, 1, 16),
                                    token: token("|upper", 14, 1, 15),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(string_value(
                                token("'b'|upper", 22, 1, 23),
                                token("'b'", 22, 1, 23),
                                None,
                                vec![TagValueFilter {
                                    name: token("upper", 26, 1, 27),
                                    token: token("|upper", 25, 1, 26),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![TagValueFilter {
                            name: token("join", 33, 1, 34),
                            token: token("|join:','", 32, 1, 33),
                            arg: Some(plain_string_value("','", 38, 1, 39, None)),
                        }],
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
    fn test_list_nested() {
        // Simple nested list
        let input = "{% my_tag [1, [2, 3], 4] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag [1, [2, 3], 4] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("[1, [2, 3], 4]", 10, 1, 11),
                        value: token("[1, [2, 3], 4]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 11, 1, 12, None)),
                            ValueChild::Value(TagValue {
                                token: token("[2, 3]", 14, 1, 15),
                                value: token("[2, 3]", 14, 1, 15),
                                children: vec![
                                    ValueChild::Value(plain_int_value("2", 15, 1, 16, None)),
                                    ValueChild::Value(plain_int_value("3", 18, 1, 19, None)),
                                ],
                                kind: ValueKind::List,
                                spread: None,
                                filters: vec![],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(plain_int_value("4", 22, 1, 23, None)),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_nested_filter() {
        // Nested list with filters
        let input = "{% my_tag [[1, 2]|first, [3, 4]|last]|join:',' %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag [[1, 2]|first, [3, 4]|last]|join:',' %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("[[1, 2]|first, [3, 4]|last]|join:','", 10, 1, 11),
                        value: token("[[1, 2]|first, [3, 4]|last]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(TagValue {
                                token: token("[1, 2]|first", 11, 1, 12),
                                value: token("[1, 2]", 11, 1, 12),
                                children: vec![
                                    ValueChild::Value(plain_int_value("1", 12, 1, 13, None)),
                                    ValueChild::Value(plain_int_value("2", 15, 1, 16, None)),
                                ],
                                kind: ValueKind::List,
                                spread: None,
                                filters: vec![TagValueFilter {
                                    name: token("first", 18, 1, 19),
                                    token: token("|first", 17, 1, 18),
                                    arg: None,
                                }],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(TagValue {
                                token: token("[3, 4]|last", 25, 1, 26),
                                value: token("[3, 4]", 25, 1, 26),
                                children: vec![
                                    ValueChild::Value(plain_int_value("3", 26, 1, 27, None)),
                                    ValueChild::Value(plain_int_value("4", 29, 1, 30, None)),
                                ],
                                kind: ValueKind::List,
                                spread: None,
                                filters: vec![TagValueFilter {
                                    name: token("last", 32, 1, 33),
                                    token: token("|last", 31, 1, 32),
                                    arg: None,
                                }],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![TagValueFilter {
                            name: token("join", 38, 1, 39),
                            token: token("|join:','", 37, 1, 38),
                            arg: Some(plain_string_value("','", 43, 1, 44, None)),
                        }],
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
    fn test_list_whitespace() {
        // Test whitespace in list
        let input = "{% my_tag [ 1 , 2 , 3 ] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag [ 1 , 2 , 3 ] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("[ 1 , 2 , 3 ]", 10, 1, 11),
                        value: token("[ 1 , 2 , 3 ]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 12, 1, 13, None)),
                            ValueChild::Value(plain_int_value("2", 16, 1, 17, None)),
                            ValueChild::Value(plain_int_value("3", 20, 1, 21, None)),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_comments() {
        // Test comments in list
        let input =
            "{% my_tag {# before start #}[{# first #}1,{# second #}2,{# third #}3{# end #}]{# after end #} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        "{% my_tag {# before start #}[{# first #}1,{# second #}2,{# third #}3{# end #}]{# after end #} %}",
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
                            "[{# first #}1,{# second #}2,{# third #}3{# end #}]",
                            28,
                            1,
                            29
                        ),
                        value: token(
                            "[{# first #}1,{# second #}2,{# third #}3{# end #}]",
                            28,
                            1,
                            29
                        ),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 40, 1, 41, None)),
                            ValueChild::Value(plain_int_value("2", 54, 1, 55, None)),
                            ValueChild::Value(plain_int_value("3", 67, 1, 68, None)),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_trailing_comma() {
        let input = "{% my_tag [1, 2, 3,] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag [1, 2, 3,] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("[1, 2, 3,]", 10, 1, 11),
                        value: token("[1, 2, 3,]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 11, 1, 12, None)),
                            ValueChild::Value(plain_int_value("2", 14, 1, 15, None)),
                            ValueChild::Value(plain_int_value("3", 17, 1, 18, None)),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_spread() {
        let input =
            "{% my_tag [1, *[2, 3], *{'a': 1}, *my_list, *'xyz', *_('hello'), *'{{ var }}', *3.14, 4] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        "{% my_tag [1, *[2, 3], *{'a': 1}, *my_list, *'xyz', *_('hello'), *'{{ var }}', *3.14, 4] %}",
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_list", 35, 1, 36)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token("[1, *[2, 3], *{'a': 1}, *my_list, *'xyz', *_('hello'), *'{{ var }}', *3.14, 4]", 10, 1, 11),
                        value: token("[1, *[2, 3], *{'a': 1}, *my_list, *'xyz', *_('hello'), *'{{ var }}', *3.14, 4]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 11, 1, 12, None)),
                            ValueChild::Value(TagValue {
                                token: token("*[2, 3]", 14, 1, 15),
                                value: token("[2, 3]", 15, 1, 16),
                                children: vec![
                                    ValueChild::Value(plain_int_value("2", 16, 1, 17, None)),
                                    ValueChild::Value(plain_int_value("3", 19, 1, 20, None)),
                                ],
                                kind: ValueKind::List,
                                spread: Some("*".to_string()),
                                filters: vec![],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(TagValue {
                                token: token("*{'a': 1}", 23, 1, 24),
                                value: token("{'a': 1}", 24, 1, 25),
                                children: vec![
                                    ValueChild::Value(plain_string_value("'a'", 25, 1, 26, None)),
                                    ValueChild::Value(plain_int_value("1", 30, 1, 31, None)),
                                ],
                                kind: ValueKind::Dict,
                                spread: Some("*".to_string()),
                                filters: vec![],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(plain_variable_value("my_list", 34, 1, 35, Some("*"))),
                            ValueChild::Value(plain_string_value("'xyz'", 44, 1, 45, Some("*"))),
                            ValueChild::Value(plain_translation_value("_('hello')", 52, 1, 53, Some("*"))),
                            ValueChild::Value(template_string_value(
                                token("*'{{ var }}'", 65, 1, 66),
                                token("'{{ var }}'", 66, 1, 67),
                                Some("*"),
                                vec![],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(plain_float_value("3.14", 79, 1, 80, Some("*"))),
                            ValueChild::Value(plain_int_value("4", 86, 1, 87, None)),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_spread_filter() {
        let input = r#"{% my_tag [1, *[2|upper, 3|lower], *{'a': 1}|default:empty, *my_list|join:",", *'xyz'|upper, *_('hello')|escape, *'{{ var }}'|safe, *3.14|round, 4|default:0] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag [1, *[2|upper, 3|lower], *{'a': 1}|default:empty, *my_list|join:",", *'xyz'|upper, *_('hello')|escape, *'{{ var }}'|safe, *3.14|round, 4|default:0] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("empty", 53, 1, 54), token("my_list", 61, 1, 62)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    TagValue {
                        token: token(
                            r#"[1, *[2|upper, 3|lower], *{'a': 1}|default:empty, *my_list|join:",", *'xyz'|upper, *_('hello')|escape, *'{{ var }}'|safe, *3.14|round, 4|default:0]"#,
                            10,
                            1,
                            11
                        ),
                        value: token(
                            r#"[1, *[2|upper, 3|lower], *{'a': 1}|default:empty, *my_list|join:",", *'xyz'|upper, *_('hello')|escape, *'{{ var }}'|safe, *3.14|round, 4|default:0]"#,
                            10,
                            1,
                            11
                        ),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 11, 1, 12, None)),
                            ValueChild::Value(TagValue {
                                token: token("*[2|upper, 3|lower]", 14, 1, 15),
                                value: token("[2|upper, 3|lower]", 15, 1, 16),
                                children: vec![
                                    ValueChild::Value(int_value(
                                        token("2|upper", 16, 1, 17),
                                        token("2", 16, 1, 17),
                                        None,
                                        vec![TagValueFilter {
                                            name: token("upper", 18, 1, 19),
                                            token: token("|upper", 17, 1, 18),
                                            arg: None,
                                        }],
                                        vec![],
                                        vec![],
                                    )),
                                    ValueChild::Value(int_value(
                                        token("3|lower", 25, 1, 26),
                                        token("3", 25, 1, 26),
                                        None,
                                        vec![TagValueFilter {
                                            name: token("lower", 27, 1, 28),
                                            token: token("|lower", 26, 1, 27),
                                            arg: None,
                                        }],
                                        vec![],
                                        vec![],
                                    )),
                                ],
                                kind: ValueKind::List,
                                spread: Some("*".to_string()),
                                filters: vec![],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(TagValue {
                                token: token("*{'a': 1}|default:empty", 35, 1, 36),
                                value: token("{'a': 1}", 36, 1, 37),
                                children: vec![
                                    ValueChild::Value(plain_string_value("'a'", 37, 1, 38, None)),
                                    ValueChild::Value(plain_int_value("1", 42, 1, 43, None)),
                                ],
                                kind: ValueKind::Dict,
                                spread: Some("*".to_string()),
                                filters: vec![TagValueFilter {
                                    name: token("default", 45, 1, 46),
                                    token: token("|default:empty", 44, 1, 45),
                                    arg: Some(plain_variable_value("empty", 53, 1, 54, None)),
                                }],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(variable_value(
                                token(r#"*my_list|join:",""#, 60, 1, 61),
                                token("my_list", 61, 1, 62),
                                Some("*"),
                                vec![TagValueFilter {
                                    name: token("join", 69, 1, 70),
                                    token: token(r#"|join:",""#, 68, 1, 69),
                                    arg: Some(plain_string_value(r#"",""#, 74, 1, 75, None)),
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(string_value(
                                token("*'xyz'|upper", 79, 1, 80),
                                token("'xyz'", 80, 1, 81),
                                Some("*"),
                                vec![TagValueFilter {
                                    name: token("upper", 86, 1, 87),
                                    token: token("|upper", 85, 1, 86),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(translation_value(
                                token("*_('hello')|escape", 93, 1, 94),
                                token("_('hello')", 94, 1, 95),
                                Some("*"),
                                vec![TagValueFilter {
                                    name: token("escape", 105, 1, 106),
                                    token: token("|escape", 104, 1, 105),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(template_string_value(
                                token("*'{{ var }}'|safe", 113, 1, 114),
                                token("'{{ var }}'", 114, 1, 115),
                                Some("*"),
                                vec![TagValueFilter {
                                    name: token("safe", 126, 1, 127),
                                    token: token("|safe", 125, 1, 126),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(float_value(
                                token("*3.14|round", 132, 1, 133),
                                token("3.14", 133, 1, 134),
                                Some("*"),
                                vec![TagValueFilter {
                                    name: token("round", 138, 1, 139),
                                    token: token("|round", 137, 1, 138),
                                    arg: None,
                                }],
                                vec![],
                                vec![],
                            )),
                            ValueChild::Value(int_value(
                                token("4|default:0", 145, 1, 146),
                                token("4", 145, 1, 146),
                                None,
                                vec![TagValueFilter {
                                    name: token("default", 147, 1, 148),
                                    token: token("|default:0", 146, 1, 147),
                                    arg: Some(plain_int_value("0", 155, 1, 156, None)),
                                }],
                                vec![],
                                vec![],
                            )),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_spread_invalid() {
        // Test asterisk at top level as value-only
        let input = "{% my_tag *value %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow asterisk operator at top level"
        );

        // Test asterisk in value position of key-value pair
        let input = "{% my_tag key=*value %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow asterisk operator in value position of key-value pair"
        );

        // Test asterisk in key position
        let input = "{% my_tag *key=value %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow asterisk operator in key position"
        );

        // Test asterisk with nested list at top level
        let input = "{% my_tag *[1, 2, 3] %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow asterisk operator with list at top level"
        );

        // Test asterisk with nested list in key-value pair
        let input = "{% my_tag key=*[1, 2, 3] %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow asterisk operator with list in key-value pair"
        );

        // Test combining spread operators
        let input = "{% my_tag ...*[1, 2, 3] %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow combining spread operators"
        );

        // Test combining spread operators with variable
        let input = "{% my_tag ...*my_list %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow combining spread operators with variable"
        );

        // Test combining spread operators
        let input = "{% my_tag *...[1, 2, 3] %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow combining spread operators"
        );
    }

    #[test]
    fn test_list_spread_comments() {
        // Test comments before / after spread
        let input = "{% my_tag [{# ... #}*{# ... #}1,*{# ... #}2,{# ... #}3] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        "{% my_tag [{# ... #}*{# ... #}1,*{# ... #}2,{# ... #}3] %}",
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
                        token: token("[{# ... #}*{# ... #}1,*{# ... #}2,{# ... #}3]", 10, 1, 11),
                        value: token("[{# ... #}*{# ... #}1,*{# ... #}2,{# ... #}3]", 10, 1, 11),
                        children: vec![
                            ValueChild::Value(
                                TagValue {
                                    token: token("*{# ... #}1", 20, 1, 21),
                                    value: token("1", 30, 1, 31),
                                    children: vec![],
                                    kind: ValueKind::Int,
                                    spread: Some("*".to_string()),
                                    filters: vec![],
                                    used_variables: vec![],
                                    assigned_variables: vec![],
                                },
                            ),
                            ValueChild::Value(
                                TagValue {
                                    token: token("*{# ... #}2", 32, 1, 33),
                                    value: token("2", 42, 1, 43),
                                    children: vec![],
                                    kind: ValueKind::Int,
                                    spread: Some("*".to_string()),
                                    filters: vec![],
                                    used_variables: vec![],
                                    assigned_variables: vec![],
                                }
                            ),
                            ValueChild::Value(
                                TagValue {
                                    token: token("3", 53, 1, 54),
                                    value: token("3", 53, 1, 54),
                                    children: vec![],
                                    kind: ValueKind::Int,
                                    spread: None,
                                    filters: vec![],
                                    used_variables: vec![],
                                    assigned_variables: vec![],
                                },
                            ),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
    fn test_list_spread_nested_comments() {
        // Test comments with nested spread
        let input =
            "{% my_tag {# c0 #}[1, {# c1 #}*{# c2 #}[2, {# c3 #}*{# c4 #}[3, 4]], 5]{# c5 #} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        "{% my_tag {# c0 #}[1, {# c1 #}*{# c2 #}[2, {# c3 #}*{# c4 #}[3, 4]], 5]{# c5 #} %}",
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
                            "[1, {# c1 #}*{# c2 #}[2, {# c3 #}*{# c4 #}[3, 4]], 5]",
                            18,
                            1,
                            19
                        ),
                        value: token(
                            "[1, {# c1 #}*{# c2 #}[2, {# c3 #}*{# c4 #}[3, 4]], 5]",
                            18,
                            1,
                            19
                        ),
                        children: vec![
                            ValueChild::Value(plain_int_value("1", 19, 1, 20, None)),
                            ValueChild::Value(TagValue {
                                token: token("*{# c2 #}[2, {# c3 #}*{# c4 #}[3, 4]]", 30, 1, 31),
                                value: token("[2, {# c3 #}*{# c4 #}[3, 4]]", 39, 1, 40),
                                children: vec![
                                    ValueChild::Value(plain_int_value("2", 40, 1, 41, None)),
                                    ValueChild::Value(TagValue {
                                        token: token("*{# c4 #}[3, 4]", 51, 1, 52),
                                        value: token("[3, 4]", 60, 1, 61),
                                        children: vec![
                                            ValueChild::Value(plain_int_value("3", 61, 1, 62, None)),
                                            ValueChild::Value(plain_int_value("4", 64, 1, 65, None)),
                                        ],
                                        kind: ValueKind::List,
                                        spread: Some("*".to_string()),
                                        filters: vec![],
                                        used_variables: vec![],
                                        assigned_variables: vec![],
                                    }),
                                ],
                                kind: ValueKind::List,
                                spread: Some("*".to_string()),
                                filters: vec![],
                                used_variables: vec![],
                                assigned_variables: vec![],
                            }),
                            ValueChild::Value(plain_int_value("5", 69, 1, 70, None)),
                        ],
                        kind: ValueKind::List,
                        spread: None,
                        filters: vec![],
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
