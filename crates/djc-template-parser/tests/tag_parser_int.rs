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
        int_value, plain_int_value, plain_parse_tag_v1, plain_variable_value, tag_attr, token,
    };

    #[test]
    fn test_int_as_arg() {
        let input = r#"{% my_tag 42 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_int_value("42", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_int_as_multiple_args() {
        let input = r#"{% my_tag 123 456 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 123 456 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, plain_int_value("123", 10, 1, 11, None), false),
                    tag_attr(None, plain_int_value("456", 14, 1, 15, None), false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_int_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag 42|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    int_value(
                        token("42|abs", 10, 1, 11),
                        token("42", 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|abs", 12, 1, 13),
                            name: token("abs", 13, 1, 14),
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
    fn test_int_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag 42|add:5 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42|add:5 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    int_value(
                        token("42|add:5", 10, 1, 11),
                        token("42", 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|add:5", 12, 1, 13),
                            name: token("add", 13, 1, 14),
                            arg: Some(plain_int_value("5", 17, 1, 18, None)),
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
    fn test_int_as_arg_with_spread() {
        let input = r#"{% my_tag ...42 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ...42 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_int_value("42", 10, 1, 11, Some("...")),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_int_as_kwarg() {
        let input = r#"{% my_tag key=42 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=42 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    plain_int_value("42", 14, 1, 15, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_int_as_multiple_kwargs() {
        let input = r#"{% my_tag key1=123 key2=456 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key1=123 key2=456 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("key1", 10, 1, 11)),
                        plain_int_value("123", 15, 1, 16, None),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 19, 1, 20)),
                        plain_int_value("456", 24, 1, 25, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_int_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key=42|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=42|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    int_value(
                        token("42|abs", 14, 1, 15),
                        token("42", 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|abs", 16, 1, 17),
                            name: token("abs", 17, 1, 18),
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
    fn test_int_as_kwarg_with_filter_with_arg() {
        let input = r#"{% my_tag key=42|add:5 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=42|add:5 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    int_value(
                        token("42|add:5", 14, 1, 15),
                        token("42", 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|add:5", 16, 1, 17),
                            name: token("add", 17, 1, 18),
                            arg: Some(plain_int_value("5", 21, 1, 22, None)),
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
    fn test_int_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag 42|abs key=123|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42|abs key=123|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        int_value(
                            token("42|abs", 10, 1, 11),
                            token("42", 10, 1, 11),
                            None,
                            vec![TagValueFilter {
                                token: token("|abs", 12, 1, 13),
                                name: token("abs", 13, 1, 14),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 17, 1, 18)),
                        int_value(
                            token("123|abs", 21, 1, 22),
                            token("123", 21, 1, 22),
                            None,
                            vec![TagValueFilter {
                                token: token("|abs", 24, 1, 25),
                                name: token("abs", 25, 1, 26),
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
    fn test_int_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ...42|abs key=123|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ...42|abs key=123|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        int_value(
                            token("...42|abs", 10, 1, 11),
                            token("42", 13, 1, 14),
                            Some("..."),
                            vec![TagValueFilter {
                                token: token("|abs", 15, 1, 16),
                                name: token("abs", 16, 1, 17),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 20, 1, 21)),
                        int_value(
                            token("123|abs", 24, 1, 25),
                            token("123", 24, 1, 25),
                            None,
                            vec![TagValueFilter {
                                token: token("|abs", 27, 1, 28),
                                name: token("abs", 28, 1, 29),
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
    fn test_int_inside_list() {
        let input = r#"{% my_tag [42] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[42]", 10, 1, 11),
            value: token("[42]", 10, 1, 11),
            children: vec![ValueChild::Value(plain_int_value("42", 11, 1, 12, None))],
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
                    token: token(r#"{% my_tag [42] %}"#, 0, 1, 1),
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
    fn test_int_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag [42|abs] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[42|abs]", 10, 1, 11),
            value: token("[42|abs]", 10, 1, 11),
            children: vec![ValueChild::Value(int_value(
                token("42|abs", 11, 1, 12),
                token("42", 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|abs", 13, 1, 14),
                    name: token("abs", 14, 1, 15),
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
                    token: token(r#"{% my_tag [42|abs] %}"#, 0, 1, 1),
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
    fn test_int_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag [42|add:5] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[42|add:5]", 10, 1, 11),
            value: token("[42|add:5]", 10, 1, 11),
            children: vec![ValueChild::Value(int_value(
                token("42|add:5", 11, 1, 12),
                token("42", 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|add:5", 13, 1, 14),
                    name: token("add", 14, 1, 15),
                    arg: Some(plain_int_value("5", 18, 1, 19, None)),
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
                    token: token(r#"{% my_tag [42|add:5] %}"#, 0, 1, 1),
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
    fn test_int_inside_list_with_filter_with_arg_and_spread() {
        let input = r#"{% my_tag [*42|add:5] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[*42|add:5]", 10, 1, 11),
            value: token("[*42|add:5]", 10, 1, 11),
            children: vec![ValueChild::Value(int_value(
                token("*42|add:5", 11, 1, 12),
                token("42", 12, 1, 13),
                Some("*"),
                vec![TagValueFilter {
                    token: token("|add:5", 14, 1, 15),
                    name: token("add", 15, 1, 16),
                    arg: Some(plain_int_value("5", 19, 1, 20, None)),
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
                    token: token(r#"{% my_tag [*42|add:5] %}"#, 0, 1, 1),
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
    fn test_int_inside_list_with_spread() {
        let input = r#"{% my_tag [*42] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[*42]", 10, 1, 11),
            value: token("[*42]", 10, 1, 11),
            children: vec![ValueChild::Value(plain_int_value(
                "42",
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
                    token: token(r#"{% my_tag [*42] %}"#, 0, 1, 1),
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
    fn test_int_inside_dict_as_value() {
        let input = r#"{% my_tag {key: 42} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{key: 42}", 10, 1, 11),
            value: token("{key: 42}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(plain_int_value("42", 16, 1, 17, None)),
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
                    token: token(r#"{% my_tag {key: 42} %}"#, 0, 1, 1),
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
    fn test_int_inside_dict_as_value_with_filter_with_arg() {
        let input = r#"{% my_tag {key: 42|add:5} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{key: 42|add:5}", 10, 1, 11),
            value: token("{key: 42|add:5}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(int_value(
                    token("42|add:5", 16, 1, 17),
                    token("42", 16, 1, 17),
                    None,
                    vec![TagValueFilter {
                        token: token("|add:5", 18, 1, 19),
                        name: token("add", 19, 1, 20),
                        arg: Some(plain_int_value("5", 23, 1, 24, None)),
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
                    token: token(r#"{% my_tag {key: 42|add:5} %}"#, 0, 1, 1),
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
    fn test_int_inside_dict_as_key_and_value() {
        let input = r#"{% my_tag {42: 123} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{42: 123}", 10, 1, 11),
            value: token("{42: 123}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_int_value("42", 11, 1, 12, None)),
                ValueChild::Value(plain_int_value("123", 15, 1, 16, None)),
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
                    token: token(r#"{% my_tag {42: 123} %}"#, 0, 1, 1),
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
    fn test_int_inside_dict_as_key_and_value_with_filters_and_arg() {
        let input = r#"{% my_tag {42|abs: 123|add:5} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{42|abs: 123|add:5}", 10, 1, 11),
            value: token("{42|abs: 123|add:5}", 10, 1, 11),
            children: vec![
                ValueChild::Value(int_value(
                    token("42|abs", 11, 1, 12),
                    token("42", 11, 1, 12),
                    None,
                    vec![TagValueFilter {
                        token: token("|abs", 13, 1, 14),
                        name: token("abs", 14, 1, 15),
                        arg: None,
                    }],
                    vec![],
                    vec![],
                )),
                ValueChild::Value(int_value(
                    token("123|add:5", 19, 1, 20),
                    token("123", 19, 1, 20),
                    None,
                    vec![TagValueFilter {
                        token: token("|add:5", 22, 1, 23),
                        name: token("add", 23, 1, 24),
                        arg: Some(plain_int_value("5", 27, 1, 28, None)),
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
                    token: token(r#"{% my_tag {42|abs: 123|add:5} %}"#, 0, 1, 1),
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
    fn test_int_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**42|abs} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{**42|abs}", 10, 1, 11),
            value: token("{**42|abs}", 10, 1, 11),
            children: vec![ValueChild::Value(int_value(
                token("**42|abs", 11, 1, 12),
                token("42", 13, 1, 14),
                Some("**"),
                vec![TagValueFilter {
                    token: token("|abs", 15, 1, 16),
                    name: token("abs", 16, 1, 17),
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
                    token: token(r#"{% my_tag {**42|abs} %}"#, 0, 1, 1),
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
    // INTS EDGE CASES
    // #######################################

    #[test]
    fn test_int_leading_zeros() {
        let input = "{% my_tag 001 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag 001 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_int_value("001", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }
}
