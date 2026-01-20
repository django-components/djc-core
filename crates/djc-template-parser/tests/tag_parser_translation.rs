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
        plain_parse_tag_v1, plain_translation_value, plain_variable_value, tag_attr, token,
        translation_value, variable_value,
    };

    #[test]
    fn test_translation_as_arg() {
        let input = r#"{% my_tag _("hello") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag _("hello") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_translation_value(r#"_("hello")"#, 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_translation_as_multiple_args() {
        let input = r#"{% my_tag _("hello") _("world") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag _("hello") _("world") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        plain_translation_value(r#"_("hello")"#, 10, 1, 11, None),
                        false
                    ),
                    tag_attr(
                        None,
                        plain_translation_value(r#"_("world")"#, 21, 1, 22, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_translation_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag _("hello")|lower %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag _("hello")|lower %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    translation_value(
                        token(r#"_("hello")|lower"#, 10, 1, 11),
                        token(r#"_("hello")"#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|lower", 20, 1, 21),
                            name: token("lower", 21, 1, 22),
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
    fn test_translation_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag _("hello")|select:_("world") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag _("hello")|select:_("world") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    translation_value(
                        token(r#"_("hello")|select:_("world")"#, 10, 1, 11),
                        token(r#"_("hello")"#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token(r#"|select:_("world")"#, 20, 1, 21),
                            name: token("select", 21, 1, 22),
                            arg: Some(plain_translation_value(r#"_("world")"#, 28, 1, 29, None)),
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
    fn test_translation_as_arg_with_spread() {
        let input = r#"{% my_tag ..._("hello") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ..._("hello") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_translation_value(r#"_("hello")"#, 10, 1, 11, Some("...")),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_translation_as_kwarg() {
        let input = r#"{% my_tag key=_("hello") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=_("hello") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    plain_translation_value(r#"_("hello")"#, 14, 1, 15, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_translation_as_multiple_kwargs() {
        let input = r#"{% my_tag key1=_("hello") key2=_("world") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key1=_("hello") key2=_("world") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("key1", 10, 1, 11)),
                        plain_translation_value(r#"_("hello")"#, 15, 1, 16, None),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 26, 1, 27)),
                        plain_translation_value(r#"_("world")"#, 31, 1, 32, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_translation_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key=_("hello")|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=_("hello")|upper %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    translation_value(
                        token(r#"_("hello")|upper"#, 14, 1, 15),
                        token(r#"_("hello")"#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|upper", 24, 1, 25),
                            name: token("upper", 25, 1, 26),
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
    fn test_translation_as_kwarg_with_filter_with_arg() {
        let input = r#"{% my_tag key=_("hello")|select:_("world") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key=_("hello")|select:_("world") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    translation_value(
                        token(r#"_("hello")|select:_("world")"#, 14, 1, 15),
                        token(r#"_("hello")"#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token(r#"|select:_("world")"#, 24, 1, 25),
                            name: token("select", 25, 1, 26),
                            arg: Some(plain_translation_value(r#"_("world")"#, 32, 1, 33, None)),
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
    fn test_translation_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag _("hello")|lower key=_("world")|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag _("hello")|lower key=_("world")|upper %}"#,
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
                        translation_value(
                            token(r#"_("hello")|lower"#, 10, 1, 11),
                            token(r#"_("hello")"#, 10, 1, 11),
                            None,
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
                        translation_value(
                            token(r#"_("world")|upper"#, 31, 1, 32),
                            token(r#"_("world")"#, 31, 1, 32),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 41, 1, 42),
                                name: token("upper", 42, 1, 43),
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
    fn test_translation_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ..._("hello")|lower key=_("world")|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ..._("hello")|lower key=_("world")|upper %}"#,
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
                        translation_value(
                            token(r#"..._("hello")|lower"#, 10, 1, 11),
                            token(r#"_("hello")"#, 13, 1, 14),
                            Some("..."),
                            vec![TagValueFilter {
                                token: token("|lower", 23, 1, 24),
                                name: token("lower", 24, 1, 25),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 30, 1, 31)),
                        translation_value(
                            token(r#"_("world")|upper"#, 34, 1, 35),
                            token(r#"_("world")"#, 34, 1, 35),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 44, 1, 45),
                                name: token("upper", 45, 1, 46),
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
    fn test_translation_inside_list() {
        let input = r#"{% my_tag [_("hello")] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[_("hello")]"#, 10, 1, 11),
            value: token(r#"[_("hello")]"#, 10, 1, 11),
            children: vec![ValueChild::Value(plain_translation_value(
                r#"_("hello")"#,
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
                    token: token(r#"{% my_tag [_("hello")] %}"#, 0, 1, 1),
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
    fn test_translation_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag [_("hello")|lower] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[_("hello")|lower]"#, 10, 1, 11),
            value: token(r#"[_("hello")|lower]"#, 10, 1, 11),
            children: vec![ValueChild::Value(translation_value(
                token(r#"_("hello")|lower"#, 11, 1, 12),
                token(r#"_("hello")"#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|lower", 21, 1, 22),
                    name: token("lower", 22, 1, 23),
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
                    token: token(r#"{% my_tag [_("hello")|lower] %}"#, 0, 1, 1),
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
    fn test_translation_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag [_("hello")|select:_("world")] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[_("hello")|select:_("world")]"#, 10, 1, 11),
            value: token(r#"[_("hello")|select:_("world")]"#, 10, 1, 11),
            children: vec![ValueChild::Value(translation_value(
                token(r#"_("hello")|select:_("world")"#, 11, 1, 12),
                token(r#"_("hello")"#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token(r#"|select:_("world")"#, 21, 1, 22),
                    name: token("select", 22, 1, 23),
                    arg: Some(plain_translation_value(r#"_("world")"#, 29, 1, 30, None)),
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
                    token: token(r#"{% my_tag [_("hello")|select:_("world")] %}"#, 0, 1, 1),
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
    fn test_translation_inside_list_with_filter_with_arg_and_spread() {
        let input = r#"{% my_tag [*_("hello")|select:_("world")] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[*_("hello")|select:_("world")]"#, 10, 1, 11),
            value: token(r#"[*_("hello")|select:_("world")]"#, 10, 1, 11),
            children: vec![ValueChild::Value(translation_value(
                token(r#"*_("hello")|select:_("world")"#, 11, 1, 12),
                token(r#"_("hello")"#, 12, 1, 13),
                Some("*"),
                vec![TagValueFilter {
                    token: token(r#"|select:_("world")"#, 22, 1, 23),
                    name: token("select", 23, 1, 24),
                    arg: Some(plain_translation_value(r#"_("world")"#, 30, 1, 31, None)),
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
                    token: token(r#"{% my_tag [*_("hello")|select:_("world")] %}"#, 0, 1, 1),
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
    fn test_translation_inside_list_with_spread() {
        let input = r#"{% my_tag [*_("hello")] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[*_("hello")]"#, 10, 1, 11),
            value: token(r#"[*_("hello")]"#, 10, 1, 11),
            children: vec![ValueChild::Value(plain_translation_value(
                r#"_("hello")"#,
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
                    token: token(r#"{% my_tag [*_("hello")] %}"#, 0, 1, 1),
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
    fn test_translation_inside_dict_as_value() {
        let input = r#"{% my_tag {key: _("hello")} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{key: _("hello")}"#, 10, 1, 11),
            value: token(r#"{key: _("hello")}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(plain_translation_value(r#"_("hello")"#, 16, 1, 17, None)),
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
                    token: token(r#"{% my_tag {key: _("hello")} %}"#, 0, 1, 1),
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
    fn test_translation_inside_dict_as_value_with_filter_with_arg() {
        let input = r#"{% my_tag {key: _("hello")|select:_("world")} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{key: _("hello")|select:_("world")}"#, 10, 1, 11),
            value: token(r#"{key: _("hello")|select:_("world")}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(translation_value(
                    token(r#"_("hello")|select:_("world")"#, 16, 1, 17),
                    token(r#"_("hello")"#, 16, 1, 17),
                    None,
                    vec![TagValueFilter {
                        token: token(r#"|select:_("world")"#, 26, 1, 27),
                        name: token("select", 27, 1, 28),
                        arg: Some(plain_translation_value(r#"_("world")"#, 34, 1, 35, None)),
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
                        r#"{% my_tag {key: _("hello")|select:_("world")} %}"#,
                        0,
                        1,
                        1
                    ),
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
    fn test_translation_inside_dict_as_key_and_value() {
        let input = r#"{% my_tag {_("key"): _("hello")} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{_("key"): _("hello")}"#, 10, 1, 11),
            value: token(r#"{_("key"): _("hello")}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_translation_value(r#"_("key")"#, 11, 1, 12, None)),
                ValueChild::Value(plain_translation_value(r#"_("hello")"#, 21, 1, 22, None)),
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
                    token: token(r#"{% my_tag {_("key"): _("hello")} %}"#, 0, 1, 1),
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
    fn test_translation_inside_dict_as_key_and_value_with_filters_and_arg() {
        let input = r#"{% my_tag {_("key")|lower: _("hello")|select:_("world")} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(
                r#"{_("key")|lower: _("hello")|select:_("world")}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{_("key")|lower: _("hello")|select:_("world")}"#,
                10,
                1,
                11,
            ),
            children: vec![
                ValueChild::Value(translation_value(
                    token(r#"_("key")|lower"#, 11, 1, 12),
                    token(r#"_("key")"#, 11, 1, 12),
                    None,
                    vec![TagValueFilter {
                        token: token("|lower", 19, 1, 20),
                        name: token("lower", 20, 1, 21),
                        arg: None,
                    }],
                    vec![],
                    vec![],
                )),
                ValueChild::Value(translation_value(
                    token(r#"_("hello")|select:_("world")"#, 27, 1, 28),
                    token(r#"_("hello")"#, 27, 1, 28),
                    None,
                    vec![TagValueFilter {
                        token: token(r#"|select:_("world")"#, 37, 1, 38),
                        name: token("select", 38, 1, 39),
                        arg: Some(plain_translation_value(r#"_("world")"#, 45, 1, 46, None)),
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
                        r#"{% my_tag {_("key")|lower: _("hello")|select:_("world")} %}"#,
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
    fn test_translation_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**_("hello")|upper} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{**_("hello")|upper}"#, 10, 1, 11),
            value: token(r#"{**_("hello")|upper}"#, 10, 1, 11),
            children: vec![ValueChild::Value(translation_value(
                token(r#"**_("hello")|upper"#, 11, 1, 12),
                token(r#"_("hello")"#, 13, 1, 14),
                Some("**"),
                vec![TagValueFilter {
                    token: token("|upper", 23, 1, 24),
                    name: token("upper", 24, 1, 25),
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
                    token: token(r#"{% my_tag {**_("hello")|upper} %}"#, 0, 1, 1),
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
    // TRANSLATIONS EDGE CASES
    // #######################################

    #[test]
    fn test_translation_single_quoted() {
        let input = r#"{% my_tag _('hello world') %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag _('hello world') %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_translation_value("_('hello world')", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_translation_whitespace() {
        let input = "{% my_tag value|default:_( 'hello' ) %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag value|default:_( 'hello' ) %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("value", 10, 1, 11)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    variable_value(
                        token("value|default:_( 'hello' )", 10, 1, 11),
                        token("value", 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            name: token("default", 16, 1, 17),
                            token: token("|default:_( 'hello' )", 15, 1, 16),
                            arg: Some(translation_value(
                                token("_( 'hello' )", 24, 1, 25),
                                Token {
                                    content: "_('hello')".to_string(),
                                    start_index: 24,
                                    end_index: 36,
                                    line_col: (1, 25),
                                },
                                None,
                                vec![],
                                vec![],
                                vec![],
                            )),
                        }],
                        vec![],
                        vec![],
                    ),
                    false,
                )],
                is_self_closing: false,
            }),
        );
    }
}
