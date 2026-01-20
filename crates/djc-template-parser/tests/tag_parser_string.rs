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
        plain_parse_tag_v1, plain_string_value, plain_variable_value, string_value, tag_attr, token,
    };

    #[test]
    fn test_string_as_arg() {
        let input = r#"{% my_tag "hello" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag "hello" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_string_value(r#""hello""#, 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_multiple_args() {
        let input = r#"{% my_tag "value1" "value2" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag "value1" "value2" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        plain_string_value(r#""value1""#, 10, 1, 11, None),
                        false
                    ),
                    tag_attr(
                        None,
                        plain_string_value(r#""value2""#, 19, 1, 20, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag "hello"|lower %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag "hello"|lower %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    string_value(
                        token(r#""hello"|lower"#, 10, 1, 11),
                        token(r#""hello""#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|lower", 17, 1, 18),
                            name: token("lower", 18, 1, 19),
                            arg: None,
                        }],
                        vec![],
                        vec![],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag "hello"|select:"world" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag "hello"|select:"world" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    string_value(
                        token(r#""hello"|select:"world""#, 10, 1, 11),
                        token(r#""hello""#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token(r#"|select:"world""#, 17, 1, 18),
                            name: token("select", 18, 1, 19),
                            arg: Some(plain_string_value(r#""world""#, 25, 1, 26, None)),
                        }],
                        vec![],
                        vec![],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_arg_with_spread() {
        let input = r#"{% my_tag ..."hello" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ..."hello" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_string_value(r#""hello""#, 10, 1, 11, Some("...")),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_kwarg() {
        let input = r#"{% my_tag key="hello" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key="hello" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    plain_string_value(r#""hello""#, 14, 1, 15, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_multiple_kwargs() {
        let input = r#"{% my_tag key1="value1" key2="value2" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key1="value1" key2="value2" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("key1", 10, 1, 11)),
                        plain_string_value(r#""value1""#, 15, 1, 16, None),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 24, 1, 25)),
                        plain_string_value(r#""value2""#, 29, 1, 30, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key="hello"|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key="hello"|upper %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    string_value(
                        token(r#""hello"|upper"#, 14, 1, 15),
                        token(r#""hello""#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|upper", 21, 1, 22),
                            name: token("upper", 22, 1, 23),
                            arg: None,
                        }],
                        vec![],
                        vec![],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_kwarg_with_filter_with_arg() {
        let input = r#"{% my_tag key="hello"|select:"world" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key="hello"|select:"world" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    string_value(
                        token(r#""hello"|select:"world""#, 14, 1, 15),
                        token(r#""hello""#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token(r#"|select:"world""#, 21, 1, 22),
                            name: token("select", 22, 1, 23),
                            arg: Some(plain_string_value(r#""world""#, 29, 1, 30, None)),
                        }],
                        vec![],
                        vec![],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag "hello"|lower key="world"|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag "hello"|lower key="world"|upper %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        string_value(
                            token(r#""hello"|lower"#, 10, 1, 11),
                            token(r#""hello""#, 10, 1, 11),
                            None,
                            vec![TagValueFilter {
                                token: token("|lower", 17, 1, 18),
                                name: token("lower", 18, 1, 19),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 24, 1, 25)),
                        string_value(
                            token(r#""world"|upper"#, 28, 1, 29),
                            token(r#""world""#, 28, 1, 29),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 35, 1, 36),
                                name: token("upper", 36, 1, 37),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ..."hello"|lower key="world"|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ..."hello"|lower key="world"|upper %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        string_value(
                            token(r#"..."hello"|lower"#, 10, 1, 11),
                            token(r#""hello""#, 13, 1, 14),
                            Some("..."),
                            vec![TagValueFilter {
                                token: token("|lower", 20, 1, 21),
                                name: token("lower", 21, 1, 22),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 27, 1, 28)),
                        string_value(
                            token(r#""world"|upper"#, 31, 1, 32),
                            token(r#""world""#, 31, 1, 32),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 38, 1, 39),
                                name: token("upper", 39, 1, 40),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_list() {
        let input = r#"{% my_tag ["hello"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"["hello"]"#, 10, 1, 11),
            value: token(r#"["hello"]"#, 10, 1, 11),
            children: vec![ValueChild::Value(plain_string_value(
                r#""hello""#,
                11,
                1,
                12,
                None,
            ))],
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
                    token: token(r#"{% my_tag ["hello"] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag ["hello"|lower] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"["hello"|lower]"#, 10, 1, 11),
            value: token(r#"["hello"|lower]"#, 10, 1, 11),
            children: vec![ValueChild::Value(string_value(
                token(r#""hello"|lower"#, 11, 1, 12),
                token(r#""hello""#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|lower", 18, 1, 19),
                    name: token("lower", 19, 1, 20),
                    arg: None,
                }],
                vec![],
                vec![],
            ))],
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
                    token: token(r#"{% my_tag ["hello"|lower] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag ["hello"|select:"world"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"["hello"|select:"world"]"#, 10, 1, 11),
            value: token(r#"["hello"|select:"world"]"#, 10, 1, 11),
            children: vec![ValueChild::Value(string_value(
                token(r#""hello"|select:"world""#, 11, 1, 12),
                token(r#""hello""#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token(r#"|select:"world""#, 18, 1, 19),
                    name: token("select", 19, 1, 20),
                    arg: Some(plain_string_value(r#""world""#, 26, 1, 27, None)),
                }],
                vec![],
                vec![],
            ))],
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
                    token: token(r#"{% my_tag ["hello"|select:"world"] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_list_with_filter_with_arg_and_spread() {
        let input = r#"{% my_tag [*"hello"|select:"world"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[*"hello"|select:"world"]"#, 10, 1, 11),
            value: token(r#"[*"hello"|select:"world"]"#, 10, 1, 11),
            children: vec![ValueChild::Value(string_value(
                token(r#"*"hello"|select:"world""#, 11, 1, 12),
                token(r#""hello""#, 12, 1, 13),
                Some("*"),
                vec![TagValueFilter {
                    token: token(r#"|select:"world""#, 19, 1, 20),
                    name: token("select", 20, 1, 21),
                    arg: Some(plain_string_value(r#""world""#, 27, 1, 28, None)),
                }],
                vec![],
                vec![],
            ))],
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
                    token: token(r#"{% my_tag [*"hello"|select:"world"] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_list_with_spread() {
        let input = r#"{% my_tag [*"hello"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[*"hello"]"#, 10, 1, 11),
            value: token(r#"[*"hello"]"#, 10, 1, 11),
            children: vec![ValueChild::Value(plain_string_value(
                r#""hello""#,
                11,
                1,
                12,
                Some("*"),
            ))],
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
                    token: token(r#"{% my_tag [*"hello"] %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_dict_as_value() {
        let input = r#"{% my_tag {key: "hello"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{key: "hello"}"#, 10, 1, 11),
            value: token(r#"{key: "hello"}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#""hello""#, 16, 1, 17, None)),
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
                    token: token(r#"{% my_tag {key: "hello"} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("key", 11, 1, 12)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_dict_as_value_with_filter_with_arg() {
        let input = r#"{% my_tag {key: "hello"|select:"world"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{key: "hello"|select:"world"}"#, 10, 1, 11),
            value: token(r#"{key: "hello"|select:"world"}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(string_value(
                    token(r#""hello"|select:"world""#, 16, 1, 17),
                    token(r#""hello""#, 16, 1, 17),
                    None,
                    vec![TagValueFilter {
                        token: token(r#"|select:"world""#, 23, 1, 24),
                        name: token("select", 24, 1, 25),
                        arg: Some(plain_string_value(r#""world""#, 31, 1, 32, None)),
                    }],
                    vec![],
                    vec![],
                )),
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
                    token: token(r#"{% my_tag {key: "hello"|select:"world"} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("key", 11, 1, 12)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_dict_as_key_and_value() {
        let input = r#"{% my_tag {"my_key": "hello"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{"my_key": "hello"}"#, 10, 1, 11),
            value: token(r#"{"my_key": "hello"}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_string_value(r#""my_key""#, 11, 1, 12, None)),
                ValueChild::Value(plain_string_value(r#""hello""#, 21, 1, 22, None)),
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
                    token: token(r#"{% my_tag {"my_key": "hello"} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_dict_as_key_and_value_with_filters_and_arg() {
        let input = r#"{% my_tag {"my_key"|lower: "hello"|select:"world"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{"my_key"|lower: "hello"|select:"world"}"#, 10, 1, 11),
            value: token(r#"{"my_key"|lower: "hello"|select:"world"}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(string_value(
                    token(r#""my_key"|lower"#, 11, 1, 12),
                    token(r#""my_key""#, 11, 1, 12),
                    None,
                    vec![TagValueFilter {
                        token: token("|lower", 19, 1, 20),
                        name: token("lower", 20, 1, 21),
                        arg: None,
                    }],
                    vec![],
                    vec![],
                )),
                ValueChild::Value(string_value(
                    token(r#""hello"|select:"world""#, 27, 1, 28),
                    token(r#""hello""#, 27, 1, 28),
                    None,
                    vec![TagValueFilter {
                        token: token(r#"|select:"world""#, 34, 1, 35),
                        name: token("select", 35, 1, 36),
                        arg: Some(plain_string_value(r#""world""#, 42, 1, 43, None)),
                    }],
                    vec![],
                    vec![],
                )),
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
                        r#"{% my_tag {"my_key"|lower: "hello"|select:"world"} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_string_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**"hello"|upper} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{**"hello"|upper}"#, 10, 1, 11),
            value: token(r#"{**"hello"|upper}"#, 10, 1, 11),
            children: vec![ValueChild::Value(string_value(
                token(r#"**"hello"|upper"#, 11, 1, 12),
                token(r#""hello""#, 13, 1, 14),
                Some("**"),
                vec![TagValueFilter {
                    token: token("|upper", 20, 1, 21),
                    name: token("upper", 21, 1, 22),
                    arg: None,
                }],
                vec![],
                vec![],
            ))],
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
                    token: token(r#"{% my_tag {**"hello"|upper} %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    // #######################################
    // STRINGS EDGE CASES
    // #######################################

    #[test]
    fn test_string_single_quoted() {
        let input = r#"{% my_tag 'hello world' %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag 'hello world' %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_string_value("'hello world'", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }
}
