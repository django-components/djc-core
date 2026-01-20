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
        plain_parse_tag_v1, plain_variable_value, tag_attr, token, variable_value,
    };

    #[test]
    fn test_variable_as_arg() {
        let input = "{% my_tag my_var %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my_var %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 10, 1, 11)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_variable_value("my_var", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_as_multiple_args() {
        let input = "{% my_tag my_var1 my_var2 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my_var1 my_var2 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var1", 10, 1, 11), token("my_var2", 18, 1, 19),],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        plain_variable_value("my_var1", 10, 1, 11, None),
                        false
                    ),
                    tag_attr(
                        None,
                        plain_variable_value("my_var2", 18, 1, 19, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_as_arg_with_filter_without_arg() {
        let input = "{% my_tag my_var|lower %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my_var|lower %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 10, 1, 11)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    variable_value(
                        token("my_var|lower", 10, 1, 11),
                        token("my_var", 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|lower", 16, 1, 17),
                            name: token("lower", 17, 1, 18),
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
    fn test_variable_as_arg_with_filter_with_arg() {
        let input = "{% my_tag my_var|select:other_var %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my_var|select:other_var %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 10, 1, 11), token("other_var", 24, 1, 25),],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    variable_value(
                        token("my_var|select:other_var", 10, 1, 11),
                        token("my_var", 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|select:other_var", 16, 1, 17),
                            name: token("select", 17, 1, 18),
                            arg: Some(plain_variable_value("other_var", 24, 1, 25, None)),
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
    fn test_variable_as_arg_with_spread() {
        let input = "{% my_tag ...my_var %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag ...my_var %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 13, 1, 14)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_variable_value("my_var", 10, 1, 11, Some("...")),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_as_kwarg() {
        let input = "{% my_tag key=my_var %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag key=my_var %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 14, 1, 15)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    plain_variable_value("my_var", 14, 1, 15, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_as_multiple_kwargs() {
        let input = "{% my_tag key1=my_var1 key2=my_var2 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag key1=my_var1 key2=my_var2 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var1", 15, 1, 16), token("my_var2", 28, 1, 29),],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("key1", 10, 1, 11)),
                        plain_variable_value("my_var1", 15, 1, 16, None),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 23, 1, 24)),
                        plain_variable_value("my_var2", 28, 1, 29, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_as_kwarg_with_filter_without_arg() {
        let input = "{% my_tag key=my_var|upper %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag key=my_var|upper %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 14, 1, 15)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    variable_value(
                        token("my_var|upper", 14, 1, 15),
                        token("my_var", 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|upper", 20, 1, 21),
                            name: token("upper", 21, 1, 22),
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
    fn test_variable_as_kwarg_with_filter_with_arg() {
        let input = "{% my_tag key=my_var|select:other_var %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag key=my_var|select:other_var %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 14, 1, 15), token("other_var", 28, 1, 29),],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    variable_value(
                        token("my_var|select:other_var", 14, 1, 15),
                        token("my_var", 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|select:other_var", 20, 1, 21),
                            name: token("select", 21, 1, 22),
                            arg: Some(plain_variable_value("other_var", 28, 1, 29, None)),
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
    fn test_variable_as_both_arg_and_kwarg_with_filters() {
        let input = "{% my_tag my_var|lower key=other_var|upper %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my_var|lower key=other_var|upper %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 10, 1, 11), token("other_var", 27, 1, 28),],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        variable_value(
                            token("my_var|lower", 10, 1, 11),
                            token("my_var", 10, 1, 11),
                            None,
                            vec![TagValueFilter {
                                token: token("|lower", 16, 1, 17),
                                name: token("lower", 17, 1, 18),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 23, 1, 24)),
                        variable_value(
                            token("other_var|upper", 27, 1, 28),
                            token("other_var", 27, 1, 28),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 36, 1, 37),
                                name: token("upper", 37, 1, 38),
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
    fn test_variable_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = "{% my_tag ...my_var|lower key=other_var|upper %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag ...my_var|lower key=other_var|upper %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 13, 1, 14), token("other_var", 30, 1, 31),],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        variable_value(
                            token("...my_var|lower", 10, 1, 11),
                            token("my_var", 13, 1, 14),
                            Some("..."),
                            vec![TagValueFilter {
                                token: token("|lower", 19, 1, 20),
                                name: token("lower", 20, 1, 21),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 26, 1, 27)),
                        variable_value(
                            token("other_var|upper", 30, 1, 31),
                            token("other_var", 30, 1, 31),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 39, 1, 40),
                                name: token("upper", 40, 1, 41),
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
    fn test_variable_inside_list() {
        let input = "{% my_tag [my_var] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[my_var]", 10, 1, 11),
            value: token("[my_var]", 10, 1, 11),
            children: vec![ValueChild::Value(plain_variable_value(
                "my_var", 11, 1, 12, None,
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
                    token: token("{% my_tag [my_var] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 11, 1, 12)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_list_with_filter_without_arg() {
        let input = "{% my_tag [my_var|lower] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[my_var|lower]", 10, 1, 11),
            value: token("[my_var|lower]", 10, 1, 11),
            children: vec![ValueChild::Value(variable_value(
                token("my_var|lower", 11, 1, 12),
                token("my_var", 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|lower", 17, 1, 18),
                    name: token("lower", 18, 1, 19),
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
                    token: token("{% my_tag [my_var|lower] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 11, 1, 12)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_list_with_filter_with_arg() {
        let input = "{% my_tag [my_var|select:other_var] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[my_var|select:other_var]", 10, 1, 11),
            value: token("[my_var|select:other_var]", 10, 1, 11),
            children: vec![ValueChild::Value(variable_value(
                token("my_var|select:other_var", 11, 1, 12),
                token("my_var", 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|select:other_var", 17, 1, 18),
                    name: token("select", 18, 1, 19),
                    arg: Some(plain_variable_value("other_var", 25, 1, 26, None)),
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
                    token: token("{% my_tag [my_var|select:other_var] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 11, 1, 12), token("other_var", 25, 1, 26)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_list_with_filter_with_arg_and_spread() {
        let input = "{% my_tag [*my_var|select:other_var] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[*my_var|select:other_var]", 10, 1, 11),
            value: token("[*my_var|select:other_var]", 10, 1, 11),
            children: vec![ValueChild::Value(variable_value(
                token("*my_var|select:other_var", 11, 1, 12),
                token("my_var", 12, 1, 13),
                Some("*"),
                vec![TagValueFilter {
                    token: token("|select:other_var", 18, 1, 19),
                    name: token("select", 19, 1, 20),
                    arg: Some(plain_variable_value("other_var", 26, 1, 27, None)),
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
                    token: token("{% my_tag [*my_var|select:other_var] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 12, 1, 13), token("other_var", 26, 1, 27)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_list_with_spread() {
        let input = "{% my_tag [*my_var] %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token("[*my_var]", 10, 1, 11),
            value: token("[*my_var]", 10, 1, 11),
            children: vec![ValueChild::Value(plain_variable_value(
                "my_var",
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
                    token: token("{% my_tag [*my_var] %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 12, 1, 13)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_dict_as_value() {
        let input = "{% my_tag {key: my_var} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{key: my_var}", 10, 1, 11),
            value: token("{key: my_var}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(plain_variable_value("my_var", 16, 1, 17, None)),
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
                    token: token("{% my_tag {key: my_var} %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("key", 11, 1, 12), token("my_var", 16, 1, 17)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_dict_as_value_with_filter_with_arg() {
        let input = "{% my_tag {key: my_var|select:other_var} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{key: my_var|select:other_var}", 10, 1, 11),
            value: token("{key: my_var|select:other_var}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(variable_value(
                    token("my_var|select:other_var", 16, 1, 17),
                    token("my_var", 16, 1, 17),
                    None,
                    vec![TagValueFilter {
                        token: token("|select:other_var", 22, 1, 23),
                        name: token("select", 23, 1, 24),
                        arg: Some(plain_variable_value("other_var", 30, 1, 31, None)),
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
                    token: token("{% my_tag {key: my_var|select:other_var} %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("key", 11, 1, 12),
                        token("my_var", 16, 1, 17),
                        token("other_var", 30, 1, 31)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_dict_as_key_and_value() {
        let input = "{% my_tag {my_key: my_var} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{my_key: my_var}", 10, 1, 11),
            value: token("{my_key: my_var}", 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("my_key", 11, 1, 12, None)),
                ValueChild::Value(plain_variable_value("my_var", 19, 1, 20, None)),
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
                    token: token("{% my_tag {my_key: my_var} %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_key", 11, 1, 12), token("my_var", 19, 1, 20)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_dict_as_key_and_value_with_filters_and_arg() {
        let input = "{% my_tag {my_key|lower: my_var|select:other_var} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{my_key|lower: my_var|select:other_var}", 10, 1, 11),
            value: token("{my_key|lower: my_var|select:other_var}", 10, 1, 11),
            children: vec![
                ValueChild::Value(variable_value(
                    token("my_key|lower", 11, 1, 12),
                    token("my_key", 11, 1, 12),
                    None,
                    vec![TagValueFilter {
                        token: token("|lower", 17, 1, 18),
                        name: token("lower", 18, 1, 19),
                        arg: None,
                    }],
                    vec![],
                    vec![],
                )),
                ValueChild::Value(variable_value(
                    token("my_var|select:other_var", 25, 1, 26),
                    token("my_var", 25, 1, 26),
                    None,
                    vec![TagValueFilter {
                        token: token("|select:other_var", 31, 1, 32),
                        name: token("select", 32, 1, 33),
                        arg: Some(plain_variable_value("other_var", 39, 1, 40, None)),
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
                        "{% my_tag {my_key|lower: my_var|select:other_var} %}",
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("my_key", 11, 1, 12),
                        token("my_var", 25, 1, 26),
                        token("other_var", 39, 1, 40),
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_variable_inside_dict_with_spread_and_filter() {
        let input = "{% my_tag {**my_var|upper} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token("{**my_var|upper}", 10, 1, 11),
            value: token("{**my_var|upper}", 10, 1, 11),
            children: vec![ValueChild::Value(variable_value(
                token("**my_var|upper", 11, 1, 12),
                token("my_var", 13, 1, 14),
                Some("**"),
                vec![TagValueFilter {
                    token: token("|upper", 19, 1, 20),
                    name: token("upper", 20, 1, 21),
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
                    token: token("{% my_tag {**my_var|upper} %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 13, 1, 14)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    // #######################################
    // VARIABLES EDGE CASES
    // #######################################

    #[test]
    fn test_variable_with_dots() {
        let input = "{% my_tag my.nested.value %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my.nested.value %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my", 10, 1, 11)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_variable_value("my.nested.value", 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }
}
