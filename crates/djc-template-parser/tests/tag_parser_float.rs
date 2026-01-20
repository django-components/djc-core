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
        float_value, plain_float_value, plain_parse_tag_v1, plain_variable_value, tag_attr, token,
    };

    #[test]
    fn test_float_as_arg() {
        let input = r#"{% my_tag 42.5 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42.5 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value("42.5", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_as_multiple_args() {
        let input = r#"{% my_tag 123.45 456.78 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 123.45 456.78 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, plain_float_value("123.45", 10, 1, 11, None), false),
                    tag_attr(None, plain_float_value("456.78", 17, 1, 18, None), false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag 42.5|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42.5|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    float_value(
                        token("42.5|abs", 10, 1, 11),
                        token("42.5", 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|abs", 14, 1, 15),
                            name: token("abs", 15, 1, 16),
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
    fn test_float_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag 42.5|add:5.5 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42.5|add:5.5 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    float_value(
                        token("42.5|add:5.5", 10, 1, 11),
                        token("42.5", 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|add:5.5", 14, 1, 15),
                            name: token("add", 15, 1, 16),
                            arg: Some(plain_float_value("5.5", 19, 1, 20, None)),
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
    fn test_float_as_arg_with_spread() {
        let input = r#"{% my_tag ...42.5 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ...42.5 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value("42.5", 10, 1, 11, Some("...")),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_as_kwarg() {
        let input = r#"{% my_tag key=42.5 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=42.5 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    plain_float_value("42.5", 14, 1, 15, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_as_multiple_kwargs() {
        let input = r#"{% my_tag key1=123.45 key2=456.78 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag key1=123.45 key2=456.78 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("key1", 10, 1, 11)),
                        plain_float_value("123.45", 15, 1, 16, None),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 22, 1, 23)),
                        plain_float_value("456.78", 27, 1, 28, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key=42.5|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=42.5|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    float_value(
                        token("42.5|abs", 14, 1, 15),
                        token("42.5", 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|abs", 18, 1, 19),
                            name: token("abs", 19, 1, 20),
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
    fn test_float_as_kwarg_with_filter_with_arg() {
        let input = r#"{% my_tag key=42.5|add:5.5 %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=42.5|add:5.5 %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    float_value(
                        token("42.5|add:5.5", 14, 1, 15),
                        token("42.5", 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|add:5.5", 18, 1, 19),
                            name: token("add", 19, 1, 20),
                            arg: Some(plain_float_value("5.5", 23, 1, 24, None)),
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
    fn test_float_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag 42.5|abs key=123.45|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag 42.5|abs key=123.45|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        float_value(
                            token("42.5|abs", 10, 1, 11),
                            token("42.5", 10, 1, 11),
                            None,
                            vec![TagValueFilter {
                                token: token("|abs", 14, 1, 15),
                                name: token("abs", 15, 1, 16),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 19, 1, 20)),
                        float_value(
                            token("123.45|abs", 23, 1, 24),
                            token("123.45", 23, 1, 24),
                            None,
                            vec![TagValueFilter {
                                token: token("|abs", 29, 1, 30),
                                name: token("abs", 30, 1, 31),
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
    fn test_float_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ...42.5|abs key=123.45|abs %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ...42.5|abs key=123.45|abs %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        float_value(
                            token("...42.5|abs", 10, 1, 11),
                            token("42.5", 13, 1, 14),
                            Some("..."),
                            vec![TagValueFilter {
                                token: token("|abs", 17, 1, 18),
                                name: token("abs", 18, 1, 19),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 22, 1, 23)),
                        float_value(
                            token("123.45|abs", 26, 1, 27),
                            token("123.45", 26, 1, 27),
                            None,
                            vec![TagValueFilter {
                                token: token("|abs", 32, 1, 33),
                                name: token("abs", 33, 1, 34),
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
    fn test_float_inside_list() {
        let input = r#"{% my_tag [42.5] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[42.5]", 10, 1, 11),
            value: token("[42.5]", 10, 1, 11),
            children: vec![ValueChild::Value(plain_float_value(
                "42.5", 11, 1, 12, None,
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
                    token: token(r#"{% my_tag [42.5] %}"#, 0, 1, 1),
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
    fn test_float_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag [42.5|abs] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[42.5|abs]", 10, 1, 11),
            value: token("[42.5|abs]", 10, 1, 11),
            children: vec![ValueChild::Value(float_value(
                token("42.5|abs", 11, 1, 12),
                token("42.5", 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|abs", 15, 1, 16),
                    name: token("abs", 16, 1, 17),
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
                    token: token(r#"{% my_tag [42.5|abs] %}"#, 0, 1, 1),
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
    fn test_float_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag [42.5|add:5.5] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[42.5|add:5.5]", 10, 1, 11),
            value: token("[42.5|add:5.5]", 10, 1, 11),
            children: vec![ValueChild::Value(float_value(
                token("42.5|add:5.5", 11, 1, 12),
                token("42.5", 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|add:5.5", 15, 1, 16),
                    name: token("add", 16, 1, 17),
                    arg: Some(plain_float_value("5.5", 20, 1, 21, None)),
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
                    token: token(r#"{% my_tag [42.5|add:5.5] %}"#, 0, 1, 1),
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
    fn test_float_inside_list_with_filter_with_arg_and_spread() {
        let input = r#"{% my_tag [*42.5|add:5.5] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[*42.5|add:5.5]", 10, 1, 11),
            value: token("[*42.5|add:5.5]", 10, 1, 11),
            children: vec![ValueChild::Value(float_value(
                token("*42.5|add:5.5", 11, 1, 12),
                token("42.5", 12, 1, 13),
                Some("*"),
                vec![TagValueFilter {
                    token: token("|add:5.5", 16, 1, 17),
                    name: token("add", 17, 1, 18),
                    arg: Some(plain_float_value("5.5", 21, 1, 22, None)),
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
                    token: token(r#"{% my_tag [*42.5|add:5.5] %}"#, 0, 1, 1),
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
    fn test_float_inside_list_with_spread() {
        let input = r#"{% my_tag [*42.5] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[*42.5]", 10, 1, 11),
            value: token("[*42.5]", 10, 1, 11),
            children: vec![ValueChild::Value(plain_float_value(
                "42.5",
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
                    token: token(r#"{% my_tag [*42.5] %}"#, 0, 1, 1),
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
    fn test_float_inside_dict_as_value() {
        let input = r#"{% my_tag {key: 42.5} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{key: 42.5}", 10, 1, 11),
            value: token("{key: 42.5}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(plain_float_value("42.5", 16, 1, 17, None)),
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
                    token: token(r#"{% my_tag {key: 42.5} %}"#, 0, 1, 1),
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
    fn test_float_inside_dict_as_value_with_filter_with_arg() {
        let input = r#"{% my_tag {key: 42.5|add:5.5} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{key: 42.5|add:5.5}", 10, 1, 11),
            value: token("{key: 42.5|add:5.5}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(float_value(
                    token("42.5|add:5.5", 16, 1, 17),
                    token("42.5", 16, 1, 17),
                    None,
                    vec![TagValueFilter {
                        token: token("|add:5.5", 20, 1, 21),
                        name: token("add", 21, 1, 22),
                        arg: Some(plain_float_value("5.5", 25, 1, 26, None)),
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
                    token: token(r#"{% my_tag {key: 42.5|add:5.5} %}"#, 0, 1, 1),
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
    fn test_float_inside_dict_as_key_and_value() {
        let input = r#"{% my_tag {42.5: 123.45} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{42.5: 123.45}", 10, 1, 11),
            value: token("{42.5: 123.45}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_float_value("42.5", 11, 1, 12, None)),
                ValueChild::Value(plain_float_value("123.45", 17, 1, 18, None)),
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
                    token: token(r#"{% my_tag {42.5: 123.45} %}"#, 0, 1, 1),
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
    fn test_float_inside_dict_as_key_and_value_with_filters_and_arg() {
        let input = r#"{% my_tag {42.5|abs: 123.45|add:5.5} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{42.5|abs: 123.45|add:5.5}", 10, 1, 11),
            value: token("{42.5|abs: 123.45|add:5.5}", 10, 1, 11),
            children: vec![
                ValueChild::Value(float_value(
                    token("42.5|abs", 11, 1, 12),
                    token("42.5", 11, 1, 12),
                    None,
                    vec![TagValueFilter {
                        token: token("|abs", 15, 1, 16),
                        name: token("abs", 16, 1, 17),
                        arg: None,
                    }],
                    vec![],
                    vec![],
                )),
                ValueChild::Value(float_value(
                    token("123.45|add:5.5", 21, 1, 22),
                    token("123.45", 21, 1, 22),
                    None,
                    vec![TagValueFilter {
                        token: token("|add:5.5", 27, 1, 28),
                        name: token("add", 28, 1, 29),
                        arg: Some(plain_float_value("5.5", 32, 1, 33, None)),
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
                    token: token(r#"{% my_tag {42.5|abs: 123.45|add:5.5} %}"#, 0, 1, 1),
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
    fn test_float_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**42.5|abs} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{**42.5|abs}", 10, 1, 11),
            value: token("{**42.5|abs}", 10, 1, 11),
            children: vec![ValueChild::Value(float_value(
                token("**42.5|abs", 11, 1, 12),
                token("42.5", 13, 1, 14),
                Some("**"),
                vec![TagValueFilter {
                    token: token("|abs", 17, 1, 18),
                    name: token("abs", 18, 1, 19),
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
                    token: token(r#"{% my_tag {**42.5|abs} %}"#, 0, 1, 1),
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
    // FLOATS EDGE CASES
    // #######################################

    #[test]
    fn test_float_negative() {
        let input = "{% my_tag -1.5 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag -1.5 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value("-1.5", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_positive_with_sign() {
        let input = "{% my_tag +2. %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag +2. %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value("+2.", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_positive_without_sign() {
        let input = "{% my_tag .3 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag .3 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value(".3", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_scientific_negative_base() {
        let input = "{% my_tag -1.2e2 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag -1.2e2 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value("-1.2e2", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_scientific_negative_exponent() {
        let input = "{% my_tag .2e-02 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag .2e-02 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value(".2e-02", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_float_scientific_leading_zero_exponent() {
        let input = "{% my_tag 20.e+02 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag 20.e+02 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_float_value("20.e+02", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }
}
