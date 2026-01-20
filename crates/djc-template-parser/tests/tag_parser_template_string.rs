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
        plain_parse_tag_v1, plain_string_value, plain_template_string_value,
        plain_translation_value, plain_variable_value, tag_attr, template_string_value, token,
    };

    #[test]
    fn test_template_string_as_arg() {
        let input = r#"{% my_tag "Hello {{ name }} {% tag %}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag "Hello {{ name }} {% tag %}" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_template_string_value(r#""Hello {{ name }} {% tag %}""#, 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_template_string_as_multiple_args() {
        let input = r#"{% my_tag "Hello {{ var1 }}" "World {% tag2 %}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag "Hello {{ var1 }}" "World {% tag2 %}" %}"#,
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
                        plain_template_string_value(r#""Hello {{ var1 }}""#, 10, 1, 11, None),
                        false
                    ),
                    tag_attr(
                        None,
                        plain_template_string_value(r#""World {% tag2 %}""#, 29, 1, 30, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_template_string_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag "Hello {{ name }} {% tag %}"|lower %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag "Hello {{ name }} {% tag %}"|lower %}"#,
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
                    template_string_value(
                        token(r#""Hello {{ name }} {% tag %}"|lower"#, 10, 1, 11),
                        token(r#""Hello {{ name }} {% tag %}""#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|lower", 38, 1, 39),
                            name: token("lower", 39, 1, 40),
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
    fn test_template_string_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag "Hello {{ name }} {% tag %}"|select:"World {{ key }}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag "Hello {{ name }} {% tag %}"|select:"World {{ key }}" %}"#,
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
                    template_string_value(
                        token(
                            r#""Hello {{ name }} {% tag %}"|select:"World {{ key }}""#,
                            10,
                            1,
                            11
                        ),
                        token(r#""Hello {{ name }} {% tag %}""#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token(r#"|select:"World {{ key }}""#, 38, 1, 39),
                            name: token("select", 39, 1, 40),
                            arg: Some(plain_template_string_value(
                                r#""World {{ key }}""#,
                                46,
                                1,
                                47,
                                None
                            )),
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
    fn test_template_string_as_arg_with_spread() {
        let input = r#"{% my_tag ..."Hello {{ name }} {% tag %}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ..."Hello {{ name }} {% tag %}" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_template_string_value(
                        r#""Hello {{ name }} {% tag %}""#,
                        10,
                        1,
                        11,
                        Some("...")
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_template_string_as_kwarg() {
        let input = r#"{% my_tag key="Hello {{ name }} {% tag %}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag key="Hello {{ name }} {% tag %}" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    plain_template_string_value(r#""Hello {{ name }} {% tag %}""#, 14, 1, 15, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_template_string_as_multiple_kwargs() {
        let input = r#"{% my_tag key1="Hello {{ var1 }}" key2="World {% tag2 %}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key1="Hello {{ var1 }}" key2="World {% tag2 %}" %}"#,
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
                        Some(token("key1", 10, 1, 11)),
                        plain_template_string_value(r#""Hello {{ var1 }}""#, 15, 1, 16, None),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 34, 1, 35)),
                        plain_template_string_value(r#""World {% tag2 %}""#, 39, 1, 40, None),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_template_string_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key="Hello {{ name }} {% tag %}"|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key="Hello {{ name }} {% tag %}"|upper %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    template_string_value(
                        token(r#""Hello {{ name }} {% tag %}"|upper"#, 14, 1, 15),
                        token(r#""Hello {{ name }} {% tag %}""#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|upper", 42, 1, 43),
                            name: token("upper", 43, 1, 44),
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
    fn test_template_string_as_kwarg_with_filter_with_arg() {
        let input =
            r#"{% my_tag key="Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key="Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}" %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    template_string_value(
                        token(
                            r#""Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}""#,
                            14,
                            1,
                            15
                        ),
                        token(r#""Hello {{ name }} {% tag %}""#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token(r#"|select:"world is {{ my_var }}""#, 42, 1, 43),
                            name: token("select", 43, 1, 44),
                            arg: Some(plain_template_string_value(
                                r#""world is {{ my_var }}""#,
                                50,
                                1,
                                51,
                                None
                            )),
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
    fn test_template_string_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag "Hello {{ name }}"|lower key="World {% tag %}"|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag "Hello {{ name }}"|lower key="World {% tag %}"|upper %}"#,
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
                        template_string_value(
                            token(r#""Hello {{ name }}"|lower"#, 10, 1, 11),
                            token(r#""Hello {{ name }}""#, 10, 1, 11),
                            None,
                            vec![TagValueFilter {
                                token: token("|lower", 28, 1, 29),
                                name: token("lower", 29, 1, 30),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 35, 1, 36)),
                        template_string_value(
                            token(r#""World {% tag %}"|upper"#, 39, 1, 40),
                            token(r#""World {% tag %}""#, 39, 1, 40),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 56, 1, 57),
                                name: token("upper", 57, 1, 58),
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
    fn test_template_string_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ..."Hello {{ name }}"|lower key="World {% tag %}"|upper %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ..."Hello {{ name }}"|lower key="World {% tag %}"|upper %}"#,
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
                        template_string_value(
                            token(r#"..."Hello {{ name }}"|lower"#, 10, 1, 11),
                            token(r#""Hello {{ name }}""#, 13, 1, 14),
                            Some("..."),
                            vec![TagValueFilter {
                                token: token("|lower", 31, 1, 32),
                                name: token("lower", 32, 1, 33),
                                arg: None,
                            }],
                            vec![],
                            vec![],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 38, 1, 39)),
                        template_string_value(
                            token(r#""World {% tag %}"|upper"#, 42, 1, 43),
                            token(r#""World {% tag %}""#, 42, 1, 43),
                            None,
                            vec![TagValueFilter {
                                token: token("|upper", 59, 1, 60),
                                name: token("upper", 60, 1, 61),
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
    fn test_template_string_inside_list() {
        let input = r#"{% my_tag ["Hello {{ name }} {% tag %}"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"["Hello {{ name }} {% tag %}"]"#, 10, 1, 11),
            value: token(r#"["Hello {{ name }} {% tag %}"]"#, 10, 1, 11),
            children: vec![ValueChild::Value(plain_template_string_value(
                r#""Hello {{ name }} {% tag %}""#,
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
                    token: token(r#"{% my_tag ["Hello {{ name }} {% tag %}"] %}"#, 0, 1, 1),
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
    fn test_template_string_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag ["Hello {{ name }} {% tag %}"|lower] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"["Hello {{ name }} {% tag %}"|lower]"#, 10, 1, 11),
            value: token(r#"["Hello {{ name }} {% tag %}"|lower]"#, 10, 1, 11),
            children: vec![ValueChild::Value(template_string_value(
                token(r#""Hello {{ name }} {% tag %}"|lower"#, 11, 1, 12),
                token(r#""Hello {{ name }} {% tag %}""#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|lower", 39, 1, 40),
                    name: token("lower", 40, 1, 41),
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
                    token: token(
                        r#"{% my_tag ["Hello {{ name }} {% tag %}"|lower] %}"#,
                        0,
                        1,
                        1
                    ),
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
    fn test_template_string_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag ["Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(
                r#"["Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"]"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"["Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"]"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(template_string_value(
                token(
                    r#""Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}""#,
                    11,
                    1,
                    12,
                ),
                token(r#""Hello {{ name }} {% tag %}""#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token(r#"|select:"world is {{ my_var }}""#, 39, 1, 40),
                    name: token("select", 40, 1, 41),
                    arg: Some(plain_template_string_value(
                        r#""world is {{ my_var }}""#,
                        47,
                        1,
                        48,
                        None,
                    )),
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
                    token: token(
                        r#"{% my_tag ["Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"] %}"#,
                        0,
                        1,
                        1
                    ),
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
    fn test_template_string_inside_list_with_filter_with_arg_and_spread() {
        let input =
            r#"{% my_tag [*"Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(
                r#"[*"Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"]"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"[*"Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"]"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(template_string_value(
                token(
                    r#"*"Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}""#,
                    11,
                    1,
                    12,
                ),
                token(r#""Hello {{ name }} {% tag %}""#, 12, 1, 13),
                Some("*"),
                vec![TagValueFilter {
                    token: token(r#"|select:"world is {{ my_var }}""#, 40, 1, 41),
                    name: token("select", 41, 1, 42),
                    arg: Some(plain_template_string_value(
                        r#""world is {{ my_var }}""#,
                        48,
                        1,
                        49,
                        None,
                    )),
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
                    token: token(
                        r#"{% my_tag [*"Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"] %}"#,
                        0,
                        1,
                        1
                    ),
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
    fn test_template_string_inside_list_with_spread() {
        let input = r#"{% my_tag [*"Hello {{ name }} {% tag %}"] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[*"Hello {{ name }} {% tag %}"]"#, 10, 1, 11),
            value: token(r#"[*"Hello {{ name }} {% tag %}"]"#, 10, 1, 11),
            children: vec![ValueChild::Value(plain_template_string_value(
                r#""Hello {{ name }} {% tag %}""#,
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
                    token: token(r#"{% my_tag [*"Hello {{ name }} {% tag %}"] %}"#, 0, 1, 1),
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
    fn test_template_string_inside_dict_as_value() {
        let input = r#"{% my_tag {key: "Hello {{ name }} {% tag %}"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{key: "Hello {{ name }} {% tag %}"}"#, 10, 1, 11),
            value: token(r#"{key: "Hello {{ name }} {% tag %}"}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(plain_template_string_value(
                    r#""Hello {{ name }} {% tag %}""#,
                    16,
                    1,
                    17,
                    None,
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
                        r#"{% my_tag {key: "Hello {{ name }} {% tag %}"} %}"#,
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
    fn test_template_string_inside_dict_as_value_with_filter_with_arg() {
        let input =
            r#"{% my_tag {key: "Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(
                r#"{key: "Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{key: "Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"}"#,
                10,
                1,
                11,
            ),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(template_string_value(
                    token(
                        r#""Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}""#,
                        16,
                        1,
                        17,
                    ),
                    token(r#""Hello {{ name }} {% tag %}""#, 16, 1, 17),
                    None,
                    vec![TagValueFilter {
                        token: token(r#"|select:"world is {{ my_var }}""#, 44, 1, 45),
                        name: token("select", 45, 1, 46),
                        arg: Some(plain_template_string_value(
                            r#""world is {{ my_var }}""#,
                            52,
                            1,
                            53,
                            None,
                        )),
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
                        r#"{% my_tag {key: "Hello {{ name }} {% tag %}"|select:"world is {{ my_var }}"} %}"#,
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
    fn test_template_string_inside_dict_as_key_and_value() {
        let input = r#"{% my_tag {"Hello {{ key }}": "World {% tag %}"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{"Hello {{ key }}": "World {% tag %}"}"#, 10, 1, 11),
            value: token(r#"{"Hello {{ key }}": "World {% tag %}"}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_template_string_value(
                    r#""Hello {{ key }}""#,
                    11,
                    1,
                    12,
                    None,
                )),
                ValueChild::Value(plain_template_string_value(
                    r#""World {% tag %}""#,
                    30,
                    1,
                    31,
                    None,
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
                        r#"{% my_tag {"Hello {{ key }}": "World {% tag %}"} %}"#,
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
    fn test_template_string_inside_dict_as_key_and_value_with_filters_and_arg() {
        let input = r#"{% my_tag {"Hello {{ key }}"|lower: "World {% tag %}"|select:"world is {{ my_var }}"} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(
                r#"{"Hello {{ key }}"|lower: "World {% tag %}"|select:"world is {{ my_var }}"}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{"Hello {{ key }}"|lower: "World {% tag %}"|select:"world is {{ my_var }}"}"#,
                10,
                1,
                11,
            ),
            children: vec![
                ValueChild::Value(template_string_value(
                    token(r#""Hello {{ key }}"|lower"#, 11, 1, 12),
                    token(r#""Hello {{ key }}""#, 11, 1, 12),
                    None,
                    vec![TagValueFilter {
                        token: token("|lower", 28, 1, 29),
                        name: token("lower", 29, 1, 30),
                        arg: None,
                    }],
                    vec![],
                    vec![],
                )),
                ValueChild::Value(template_string_value(
                    token(
                        r#""World {% tag %}"|select:"world is {{ my_var }}""#,
                        36,
                        1,
                        37,
                    ),
                    token(r#""World {% tag %}""#, 36, 1, 37),
                    None,
                    vec![TagValueFilter {
                        token: token(r#"|select:"world is {{ my_var }}""#, 53, 1, 54),
                        name: token("select", 54, 1, 55),
                        arg: Some(plain_template_string_value(
                            r#""world is {{ my_var }}""#,
                            61,
                            1,
                            62,
                            None,
                        )),
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
                        r#"{% my_tag {"Hello {{ key }}"|lower: "World {% tag %}"|select:"world is {{ my_var }}"} %}"#,
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
    fn test_template_string_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**"Hello {{ name }} {% tag %}"|upper} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{**"Hello {{ name }} {% tag %}"|upper}"#, 10, 1, 11),
            value: token(r#"{**"Hello {{ name }} {% tag %}"|upper}"#, 10, 1, 11),
            children: vec![ValueChild::Value(template_string_value(
                token(r#"**"Hello {{ name }} {% tag %}"|upper"#, 11, 1, 12),
                token(r#""Hello {{ name }} {% tag %}""#, 13, 1, 14),
                Some("**"),
                vec![TagValueFilter {
                    token: token("|upper", 41, 1, 42),
                    name: token("upper", 42, 1, 43),
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
                    token: token(
                        r#"{% my_tag {**"Hello {{ name }} {% tag %}"|upper} %}"#,
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

    // #######################################
    // TEMPLATE STRING EDGE CASES
    // #######################################

    #[test]
    fn test_template_string_comment() {
        let input = r#"{% my_tag "Hello {# TODO #}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag "Hello {# TODO #}" %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    template_string_value(
                        token(r#""Hello {# TODO #}""#, 10, 1, 11),
                        token(r#""Hello {# TODO #}""#, 10, 1, 11),
                        None,
                        vec![],
                        vec![],
                        vec![],
                    ),
                    false,
                )],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_template_string_mixed() {
        // Test string with multiple template tags
        let input = r#"{% my_tag "Hello {{ first_name }} {% lorem 1 w %} {# TODO #}" %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag "Hello {{ first_name }} {% lorem 1 w %} {# TODO #}" %}"#,
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
                    template_string_value(
                        token(
                            r#""Hello {{ first_name }} {% lorem 1 w %} {# TODO #}""#,
                            10,
                            1,
                            11
                        ),
                        token(
                            r#""Hello {{ first_name }} {% lorem 1 w %} {# TODO #}""#,
                            10,
                            1,
                            11
                        ),
                        None,
                        vec![],
                        vec![],
                        vec![],
                    ),
                    false,
                )],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_template_string_invalid() {
        // Test incomplete template tags (should not be marked as template_string)
        let inputs = vec![
            r#"{% my_tag "Hello {{ first_name" %}"#,
            r#"{% my_tag "Hello {% first_name" %}"#,
            r#"{% my_tag "Hello {# first_name" %}"#,
            r#"{% my_tag "Hello {{ first_name %}" %}"#,
            r#"{% my_tag "Hello first_name }}" %}"#,
            r#"{% my_tag "Hello }} first_name {{" %}"#,
        ];
        for input in inputs {
            let (result, _context) = plain_parse_tag_v1(input).unwrap();

            // Extract the string value from the input (between quotes)
            let string_start = input.find('"').unwrap() + 1;
            let string_end = input.rfind('"').unwrap();
            let string_value = &input[string_start..string_end];

            assert_eq!(
                result,
                Tag::Generic(GenericTag {
                    meta: TagMeta {
                        token: token(input, 0, 1, 1),
                        name: token("my_tag", 3, 1, 4),
                        used_variables: vec![],
                        assigned_variables: vec![],
                    },
                    attrs: vec![tag_attr(
                        None,
                        plain_string_value(&format!(r#""{}""#, string_value), 10, 1, 11, None),
                        false,
                    )],
                    is_self_closing: false,
                }),
            );
        }
    }

    #[test]
    fn test_template_string_translation() {
        // Test that template strings are not detected in translation strings
        let input = r#"{% my_tag _("{{ var }}") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag _("{{ var }}") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_translation_value(r#"_("{{ var }}")"#, 10, 1, 11, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }
}
