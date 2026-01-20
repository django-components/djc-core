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
        plain_parse_tag_v1, plain_variable_value, python_expr_value, tag_attr, token,
    };

    #[test]
    fn test_python_expr_as_arg() {
        let input = r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 38, 1, 39)],
                    assigned_variables: vec![token("nu_var", 18, 1, 19)],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 10, 1, 11),
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 10, 1, 11),
                        None,
                        vec![],
                        vec![token("my_var", 38, 1, 39)],
                        vec![token("nu_var", 18, 1, 19)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_multiple_args() {
        let input = r#"{% my_tag ( [1, (nu_var := 'a'), var1] ) ( [2, 'b', var2] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ( [1, (nu_var := 'a'), var1] ) ( [2, 'b', var2] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("var1", 33, 1, 34), token("var2", 52, 1, 53)],
                    assigned_variables: vec![token("nu_var", 17, 1, 18)],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        python_expr_value(
                            token(r#"( [1, (nu_var := 'a'), var1] )"#, 10, 1, 11),
                            token(r#"( [1, (nu_var := 'a'), var1] )"#, 10, 1, 11),
                            None,
                            vec![],
                            vec![token("var1", 33, 1, 34)],
                            vec![token("nu_var", 17, 1, 18)],
                        ),
                        false
                    ),
                    tag_attr(
                        None,
                        python_expr_value(
                            token(r#"( [2, 'b', var2] )"#, 41, 1, 42),
                            token(r#"( [2, 'b', var2] )"#, 41, 1, 42),
                            None,
                            vec![],
                            vec![token("var2", 52, 1, 53)],
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
    fn test_python_expr_as_arg_with_filter_without_arg() {
        let input = r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] )|length %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] )|length %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 38, 1, 39)],
                    assigned_variables: vec![token("nu_var", 18, 1, 19)],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(r#"( [42, (nu_var := 'hello'), my_var] )|length"#, 10, 1, 11),
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|length", 47, 1, 48),
                            name: token("length", 48, 1, 49),
                            arg: None,
                        }],
                        vec![token("my_var", 38, 1, 39)],
                        vec![token("nu_var", 18, 1, 19)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_arg_with_filter_with_arg() {
        let input = r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 38, 1, 39), token("x_var", 73, 1, 74)],
                    assigned_variables: vec![
                        token("nu_var", 18, 1, 19),
                        token("nu2_var", 58, 1, 59)
                    ],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(
                            r#"( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )"#,
                            10,
                            1,
                            11
                        ),
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 10, 1, 11),
                        None,
                        vec![TagValueFilter {
                            token: token("|first:( [(nu2_var := 2), x_var] )", 47, 1, 48),
                            name: token("first", 48, 1, 49),
                            arg: Some(python_expr_value(
                                token(r#"( [(nu2_var := 2), x_var] )"#, 54, 1, 55),
                                token(r#"( [(nu2_var := 2), x_var] )"#, 54, 1, 55),
                                None,
                                vec![],
                                vec![token("x_var", 73, 1, 74)],
                                vec![token("nu2_var", 58, 1, 59)],
                            )),
                        }],
                        vec![token("my_var", 38, 1, 39)],
                        vec![token("nu_var", 18, 1, 19)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_arg_with_spread() {
        let input = r#"{% my_tag ...( [42, (nu_var := 'hello'), my_var] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ...( [42, (nu_var := 'hello'), my_var] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 41, 1, 42)],
                    assigned_variables: vec![token("nu_var", 21, 1, 22)],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(r#"...( [42, (nu_var := 'hello'), my_var] )"#, 10, 1, 11),
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 13, 1, 14),
                        Some("..."),
                        vec![],
                        vec![token("my_var", 41, 1, 42)],
                        vec![token("nu_var", 21, 1, 22)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_kwarg() {
        let input = r#"{% my_tag key=( [42, (nu_var := 'hello'), my_var] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key=( [42, (nu_var := 'hello'), my_var] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 42, 1, 43)],
                    assigned_variables: vec![token("nu_var", 22, 1, 23)],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    python_expr_value(
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 14, 1, 15),
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 14, 1, 15),
                        None,
                        vec![],
                        vec![token("my_var", 42, 1, 43)],
                        vec![token("nu_var", 22, 1, 23)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_multiple_kwargs() {
        let input = r#"{% my_tag key1=( [1, (nu_var := 'a'), var1] ) key2=( [2, 'b', var2] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key1=( [1, (nu_var := 'a'), var1] ) key2=( [2, 'b', var2] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("var1", 38, 1, 39), token("var2", 62, 1, 63)],
                    assigned_variables: vec![token("nu_var", 22, 1, 23)],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("key1", 10, 1, 11)),
                        python_expr_value(
                            token(r#"( [1, (nu_var := 'a'), var1] )"#, 15, 1, 16),
                            token(r#"( [1, (nu_var := 'a'), var1] )"#, 15, 1, 16),
                            None,
                            vec![],
                            vec![token("var1", 38, 1, 39)],
                            vec![token("nu_var", 22, 1, 23)],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 46, 1, 47)),
                        python_expr_value(
                            token(r#"( [2, 'b', var2] )"#, 51, 1, 52),
                            token(r#"( [2, 'b', var2] )"#, 51, 1, 52),
                            None,
                            vec![],
                            vec![token("var2", 62, 1, 63)],
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
    fn test_python_expr_as_kwarg_with_filter_without_arg() {
        let input = r#"{% my_tag key=( [42, (nu_var := 'hello'), my_var] )|length %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key=( [42, (nu_var := 'hello'), my_var] )|length %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 42, 1, 43)],
                    assigned_variables: vec![token("nu_var", 22, 1, 23)],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    python_expr_value(
                        token(r#"( [42, (nu_var := 'hello'), my_var] )|length"#, 14, 1, 15),
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|length", 51, 1, 52),
                            name: token("length", 52, 1, 53),
                            arg: None,
                        }],
                        vec![token("my_var", 42, 1, 43)],
                        vec![token("nu_var", 22, 1, 23)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_kwarg_with_filter_with_arg() {
        let input = r#"{% my_tag key=( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag key=( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 42, 1, 43), token("x_var", 77, 1, 78)],
                    assigned_variables: vec![
                        token("nu_var", 22, 1, 23),
                        token("nu2_var", 62, 1, 63)
                    ],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    python_expr_value(
                        token(
                            r#"( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )"#,
                            14,
                            1,
                            15
                        ),
                        token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 14, 1, 15),
                        None,
                        vec![TagValueFilter {
                            token: token("|first:( [(nu2_var := 2), x_var] )", 51, 1, 52),
                            name: token("first", 52, 1, 53),
                            arg: Some(python_expr_value(
                                token(r#"( [(nu2_var := 2), x_var] )"#, 58, 1, 59),
                                token(r#"( [(nu2_var := 2), x_var] )"#, 58, 1, 59),
                                None,
                                vec![],
                                vec![token("x_var", 77, 1, 78)],
                                vec![token("nu2_var", 62, 1, 63)],
                            )),
                        }],
                        vec![token("my_var", 42, 1, 43)],
                        vec![token("nu_var", 22, 1, 23)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_both_arg_and_kwarg_with_filters() {
        let input = r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] )|length key=( [1, (nu_var := 'a'), var1] )|first:( [(nu2_var := 2), x_var] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ( [42, (nu_var := 'hello'), my_var] )|length key=( [1, (nu_var := 'a'), var1] )|first:( [(nu2_var := 2), x_var] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("my_var", 38, 1, 39),
                        token("var1", 82, 1, 83),
                        token("x_var", 115, 1, 116)
                    ],
                    assigned_variables: vec![
                        token("nu_var", 18, 1, 19),
                        token("nu_var", 66, 1, 67),
                        token("nu2_var", 100, 1, 101)
                    ],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        python_expr_value(
                            token(r#"( [42, (nu_var := 'hello'), my_var] )|length"#, 10, 1, 11),
                            token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 10, 1, 11),
                            None,
                            vec![TagValueFilter {
                                token: token("|length", 47, 1, 48),
                                name: token("length", 48, 1, 49),
                                arg: None,
                            }],
                            vec![token("my_var", 38, 1, 39)],
                            vec![token("nu_var", 18, 1, 19)],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 55, 1, 56)),
                        python_expr_value(
                            token(
                                r#"( [1, (nu_var := 'a'), var1] )|first:( [(nu2_var := 2), x_var] )"#,
                                59,
                                1,
                                60
                            ),
                            token(r#"( [1, (nu_var := 'a'), var1] )"#, 59, 1, 60),
                            None,
                            vec![TagValueFilter {
                                token: token("|first:( [(nu2_var := 2), x_var] )", 89, 1, 90),
                                name: token("first", 90, 1, 91),
                                arg: Some(python_expr_value(
                                    token(r#"( [(nu2_var := 2), x_var] )"#, 96, 1, 97),
                                    token(r#"( [(nu2_var := 2), x_var] )"#, 96, 1, 97),
                                    None,
                                    vec![],
                                    vec![token("x_var", 115, 1, 116)],
                                    vec![token("nu2_var", 100, 1, 101)],
                                )),
                            }],
                            vec![token("var1", 82, 1, 83)],
                            vec![token("nu_var", 66, 1, 67)],
                        ),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_as_both_arg_and_kwarg_with_filters_and_spread() {
        let input = r#"{% my_tag ...( [42, (nu_var := 'hello'), my_var] )|length key=( [1, (nu_var := 'a'), var1] )|first:( [(nu2_var := 2), x_var] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        r#"{% my_tag ...( [42, (nu_var := 'hello'), my_var] )|length key=( [1, (nu_var := 'a'), var1] )|first:( [(nu2_var := 2), x_var] ) %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("my_var", 41, 1, 42),
                        token("var1", 85, 1, 86),
                        token("x_var", 118, 1, 119)
                    ],
                    assigned_variables: vec![
                        token("nu_var", 21, 1, 22),
                        token("nu_var", 69, 1, 70),
                        token("nu2_var", 103, 1, 104)
                    ],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        python_expr_value(
                            token(
                                r#"...( [42, (nu_var := 'hello'), my_var] )|length"#,
                                10,
                                1,
                                11
                            ),
                            token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 13, 1, 14),
                            Some("..."),
                            vec![TagValueFilter {
                                token: token("|length", 50, 1, 51),
                                name: token("length", 51, 1, 52),
                                arg: None,
                            }],
                            vec![token("my_var", 41, 1, 42)],
                            vec![token("nu_var", 21, 1, 22)],
                        ),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 58, 1, 59)),
                        python_expr_value(
                            token(
                                r#"( [1, (nu_var := 'a'), var1] )|first:( [(nu2_var := 2), x_var] )"#,
                                62,
                                1,
                                63
                            ),
                            token(r#"( [1, (nu_var := 'a'), var1] )"#, 62, 1, 63),
                            None,
                            vec![TagValueFilter {
                                token: token("|first:( [(nu2_var := 2), x_var] )", 92, 1, 93),
                                name: token("first", 93, 1, 94),
                                arg: Some(python_expr_value(
                                    token(r#"( [(nu2_var := 2), x_var] )"#, 99, 1, 100),
                                    token(r#"( [(nu2_var := 2), x_var] )"#, 99, 1, 100),
                                    None,
                                    vec![],
                                    vec![token("x_var", 118, 1, 119)],
                                    vec![token("nu2_var", 103, 1, 104)],
                                )),
                            }],
                            vec![token("var1", 85, 1, 86)],
                            vec![token("nu_var", 69, 1, 70)],
                        ),
                        false
                    ),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_list() {
        let input = r#"{% my_tag [( [42, (nu_var := 'hello'), my_var] )] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[( [42, (nu_var := 'hello'), my_var] )]"#, 10, 1, 11),
            value: token(r#"[( [42, (nu_var := 'hello'), my_var] )]"#, 10, 1, 11),
            children: vec![ValueChild::Value(python_expr_value(
                token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 11, 1, 12),
                token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 11, 1, 12),
                None,
                vec![],
                vec![token("my_var", 39, 1, 40)],
                vec![token("nu_var", 19, 1, 20)],
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
                        r#"{% my_tag [( [42, (nu_var := 'hello'), my_var] )] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 39, 1, 40)],
                    assigned_variables: vec![token("nu_var", 19, 1, 20)],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_list_with_filter_without_arg() {
        let input = r#"{% my_tag [( [42, (nu_var := 'hello'), my_var] )|length] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(
                r#"[( [42, (nu_var := 'hello'), my_var] )|length]"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"[( [42, (nu_var := 'hello'), my_var] )|length]"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(python_expr_value(
                token(r#"( [42, (nu_var := 'hello'), my_var] )|length"#, 11, 1, 12),
                token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|length", 48, 1, 49),
                    name: token("length", 49, 1, 50),
                    arg: None,
                }],
                vec![token("my_var", 39, 1, 40)],
                vec![token("nu_var", 19, 1, 20)],
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
                        r#"{% my_tag [( [42, (nu_var := 'hello'), my_var] )|length] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 39, 1, 40)],
                    assigned_variables: vec![token("nu_var", 19, 1, 20)],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_list_with_filter_with_arg() {
        let input = r#"{% my_tag [( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(
                r#"[( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )]"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"[( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )]"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(python_expr_value(
                token(
                    r#"( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )"#,
                    11,
                    1,
                    12,
                ),
                token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 11, 1, 12),
                None,
                vec![TagValueFilter {
                    token: token("|first:( [(nu2_var := 2), x_var] )", 48, 1, 49),
                    name: token("first", 49, 1, 50),

                    arg: Some(python_expr_value(
                        token(r#"( [(nu2_var := 2), x_var] )"#, 55, 1, 56),
                        token(r#"( [(nu2_var := 2), x_var] )"#, 55, 1, 56),
                        None,
                        vec![],
                        vec![token("x_var", 74, 1, 75)],
                        vec![token("nu2_var", 59, 1, 60)],
                    )),
                }],
                vec![token("my_var", 39, 1, 40)],
                vec![token("nu_var", 19, 1, 20)],
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
                        r#"{% my_tag [( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 39, 1, 40), token("x_var", 74, 1, 75)],
                    assigned_variables: vec![
                        token("nu_var", 19, 1, 20),
                        token("nu2_var", 59, 1, 60)
                    ],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_list_with_filter_with_arg_and_spread() {
        let input = r#"{% my_tag [*( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(
                r#"[*( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )]"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"[*( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )]"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(python_expr_value(
                token(
                    r#"*( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )"#,
                    11,
                    1,
                    12,
                ),
                token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 12, 1, 13),
                Some("*"),
                vec![TagValueFilter {
                    token: token("|first:( [(nu2_var := 2), x_var] )", 49, 1, 50),
                    name: token("first", 50, 1, 51),
                    arg: Some(python_expr_value(
                        token(r#"( [(nu2_var := 2), x_var] )"#, 56, 1, 57),
                        token(r#"( [(nu2_var := 2), x_var] )"#, 56, 1, 57),
                        None,
                        vec![],
                        vec![token("x_var", 75, 1, 76)],
                        vec![token("nu2_var", 60, 1, 61)],
                    )),
                }],
                vec![token("my_var", 40, 1, 41)],
                vec![token("nu_var", 20, 1, 21)],
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
                        r#"{% my_tag [*( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 40, 1, 41), token("x_var", 75, 1, 76)],
                    assigned_variables: vec![
                        token("nu_var", 20, 1, 21),
                        token("nu2_var", 60, 1, 61)
                    ],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_list_with_spread() {
        let input = r#"{% my_tag [*( [42, (nu_var := 'hello'), my_var] )] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let list_value = TagValue {
            token: token(r#"[*( [42, (nu_var := 'hello'), my_var] )]"#, 10, 1, 11),
            value: token(r#"[*( [42, (nu_var := 'hello'), my_var] )]"#, 10, 1, 11),
            children: vec![ValueChild::Value(python_expr_value(
                token(r#"*( [42, (nu_var := 'hello'), my_var] )"#, 11, 1, 12),
                token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 12, 1, 13),
                Some("*"),
                vec![],
                vec![token("my_var", 40, 1, 41)],
                vec![token("nu_var", 20, 1, 21)],
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
                        r#"{% my_tag [*( [42, (nu_var := 'hello'), my_var] )] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 40, 1, 41)],
                    assigned_variables: vec![token("nu_var", 20, 1, 21)],
                },
                attrs: vec![tag_attr(None, list_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_dict_as_value() {
        let input = r#"{% my_tag {key: ( [42, (nu_var := 'hello'), my_var] )} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(r#"{key: ( [42, (nu_var := 'hello'), my_var] )}"#, 10, 1, 11),
            value: token(r#"{key: ( [42, (nu_var := 'hello'), my_var] )}"#, 10, 1, 11),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(python_expr_value(
                    token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 16, 1, 17),
                    token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 16, 1, 17),
                    None,
                    vec![],
                    vec![token("my_var", 44, 1, 45)],
                    vec![token("nu_var", 24, 1, 25)],
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
                        r#"{% my_tag {key: ( [42, (nu_var := 'hello'), my_var] )} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("key", 11, 1, 12), token("my_var", 44, 1, 45)],
                    assigned_variables: vec![token("nu_var", 24, 1, 25)],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_dict_as_value_with_filter_with_arg() {
        let input = r#"{% my_tag {key: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(
                r#"{key: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{key: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )}"#,
                10,
                1,
                11,
            ),
            children: vec![
                ValueChild::Value(plain_variable_value("key", 11, 1, 12, None)),
                ValueChild::Value(python_expr_value(
                    token(
                        r#"( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )"#,
                        16,
                        1,
                        17,
                    ),
                    token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 16, 1, 17),
                    None,
                    vec![TagValueFilter {
                        token: token("|first:( [(nu2_var := 2), x_var] )", 53, 1, 54),
                        name: token("first", 54, 1, 55),
                        arg: Some(python_expr_value(
                            token(r#"( [(nu2_var := 2), x_var] )"#, 60, 1, 61),
                            token(r#"( [(nu2_var := 2), x_var] )"#, 60, 1, 61),
                            None,
                            vec![],
                            vec![token("x_var", 79, 1, 80)],
                            vec![token("nu2_var", 64, 1, 65)],
                        )),
                    }],
                    vec![token("my_var", 44, 1, 45)],
                    vec![token("nu_var", 24, 1, 25)],
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
                        r#"{% my_tag {key: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("key", 11, 1, 12),
                        token("my_var", 44, 1, 45),
                        token("x_var", 79, 1, 80)
                    ],
                    assigned_variables: vec![
                        token("nu_var", 24, 1, 25),
                        token("nu2_var", 64, 1, 65)
                    ],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_dict_as_key_and_value() {
        let input = r#"{% my_tag {( [1, (nu_var := 'a'), var1] ): ( [42, (nu_var := 'hello'), my_var] )} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(
                r#"{( [1, (nu_var := 'a'), var1] ): ( [42, (nu_var := 'hello'), my_var] )}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{( [1, (nu_var := 'a'), var1] ): ( [42, (nu_var := 'hello'), my_var] )}"#,
                10,
                1,
                11,
            ),
            children: vec![
                ValueChild::Value(python_expr_value(
                    token(r#"( [1, (nu_var := 'a'), var1] )"#, 11, 1, 12),
                    token(r#"( [1, (nu_var := 'a'), var1] )"#, 11, 1, 12),
                    None,
                    vec![],
                    vec![token("var1", 34, 1, 35)],
                    vec![token("nu_var", 18, 1, 19)],
                )),
                ValueChild::Value(python_expr_value(
                    token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 43, 1, 44),
                    token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 43, 1, 44),
                    None,
                    vec![],
                    vec![token("my_var", 71, 1, 72)],
                    vec![token("nu_var", 51, 1, 52)],
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
                        r#"{% my_tag {( [1, (nu_var := 'a'), var1] ): ( [42, (nu_var := 'hello'), my_var] )} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("var1", 34, 1, 35), token("my_var", 71, 1, 72)],
                    assigned_variables: vec![
                        token("nu_var", 18, 1, 19),
                        token("nu_var", 51, 1, 52)
                    ],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_dict_as_key_and_value_with_filters_and_arg() {
        let input = r#"{% my_tag {( [1, (nu_var := 'a'), var1] )|length: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(
                r#"{( [1, (nu_var := 'a'), var1] )|length: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{( [1, (nu_var := 'a'), var1] )|length: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )}"#,
                10,
                1,
                11,
            ),
            children: vec![
                ValueChild::Value(python_expr_value(
                    token(r#"( [1, (nu_var := 'a'), var1] )|length"#, 11, 1, 12),
                    token(r#"( [1, (nu_var := 'a'), var1] )"#, 11, 1, 12),
                    None,
                    vec![TagValueFilter {
                        token: token("|length", 41, 1, 42),
                        name: token("length", 42, 1, 43),
                        arg: None,
                    }],
                    vec![token("var1", 34, 1, 35)],
                    vec![token("nu_var", 18, 1, 19)],
                )),
                ValueChild::Value(python_expr_value(
                    token(
                        r#"( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )"#,
                        50,
                        1,
                        51,
                    ),
                    token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 50, 1, 51),
                    None,
                    vec![TagValueFilter {
                        token: token("|first:( [(nu2_var := 2), x_var] )", 87, 1, 88),
                        name: token("first", 88, 1, 89),
                        arg: Some(python_expr_value(
                            token(r#"( [(nu2_var := 2), x_var] )"#, 94, 1, 95),
                            token(r#"( [(nu2_var := 2), x_var] )"#, 94, 1, 95),
                            None,
                            vec![],
                            vec![token("x_var", 113, 1, 114)],
                            vec![token("nu2_var", 98, 1, 99)],
                        )),
                    }],
                    vec![token("my_var", 78, 1, 79)],
                    vec![token("nu_var", 58, 1, 59)],
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
                        r#"{% my_tag {( [1, (nu_var := 'a'), var1] )|length: ( [42, (nu_var := 'hello'), my_var] )|first:( [(nu2_var := 2), x_var] )} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("var1", 34, 1, 35),
                        token("my_var", 78, 1, 79),
                        token("x_var", 113, 1, 114)
                    ],
                    assigned_variables: vec![
                        token("nu_var", 18, 1, 19),
                        token("nu_var", 58, 1, 59),
                        token("nu2_var", 98, 1, 99)
                    ],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_inside_dict_with_spread_and_filter() {
        let input = r#"{% my_tag {**( [42, (nu_var := 'hello'), my_var] )|length} %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        let dict_value = TagValue {
            token: token(
                r#"{**( [42, (nu_var := 'hello'), my_var] )|length}"#,
                10,
                1,
                11,
            ),
            value: token(
                r#"{**( [42, (nu_var := 'hello'), my_var] )|length}"#,
                10,
                1,
                11,
            ),
            children: vec![ValueChild::Value(python_expr_value(
                token(
                    r#"**( [42, (nu_var := 'hello'), my_var] )|length"#,
                    11,
                    1,
                    12,
                ),
                token(r#"( [42, (nu_var := 'hello'), my_var] )"#, 13, 1, 14),
                Some("**"),
                vec![TagValueFilter {
                    token: token("|length", 50, 1, 51),
                    name: token("length", 51, 1, 52),
                    arg: None,
                }],
                vec![token("my_var", 41, 1, 42)],
                vec![token("nu_var", 21, 1, 22)],
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
                        r#"{% my_tag {**( [42, (nu_var := 'hello'), my_var] )|length} %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_var", 41, 1, 42)],
                    assigned_variables: vec![token("nu_var", 21, 1, 22)],
                },
                attrs: vec![tag_attr(None, dict_value, false)],
                is_self_closing: false,
            })
        );
    }

    // #######################################
    // PYTHON EXPRESSIONS EDGE CASES
    // #######################################

    #[test]
    fn test_python_expr_conditional_expression() {
        let input = r#"{% my_tag ("YES" if condition else "NO") %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ("YES" if condition else "NO") %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("condition", 20, 1, 21)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(r#"("YES" if condition else "NO")"#, 10, 1, 11),
                        token(r#"("YES" if condition else "NO")"#, 10, 1, 11),
                        None,
                        vec![],
                        vec![token("condition", 20, 1, 21)],
                        vec![],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_complex_expression() {
        let input = r#"{% my_tag (my_item[0].name.upper()[:2]) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag (my_item[0].name.upper()[:2]) %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_item", 11, 1, 12)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(r#"(my_item[0].name.upper()[:2])"#, 10, 1, 11),
                        token(r#"(my_item[0].name.upper()[:2])"#, 10, 1, 11),
                        None,
                        vec![],
                        vec![token("my_item", 11, 1, 12)],
                        vec![],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_walrus_operator_in_list_comp() {
        let input = r#"{% my_tag ( [(x := y) for y in items] ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ( [(x := y) for y in items] ) %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("items", 31, 1, 32)],
                    assigned_variables: vec![token("x", 14, 1, 15)],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(r#"( [(x := y) for y in items] )"#, 10, 1, 11),
                        token(r#"( [(x := y) for y in items] )"#, 10, 1, 11),
                        None,
                        vec![],
                        vec![token("items", 31, 1, 32)],
                        vec![token("x", 14, 1, 15)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_walrus_operator_in_lambda() {
        let input = r#"{% my_tag ( lambda y: (x := y) ) %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag ( lambda y: (x := y) ) %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![token("x", 23, 1, 24)],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token(r#"( lambda y: (x := y) )"#, 10, 1, 11),
                        token(r#"( lambda y: (x := y) )"#, 10, 1, 11),
                        None,
                        vec![],
                        vec![],
                        vec![token("x", 23, 1, 24)],
                    ),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_python_expr_multiline() {
        let input = "{% my_tag ( [1, \n\nb, \n(c := 3)] ) %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag ( [1, \n\nb, \n(c := 3)] ) %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("b", 18, 3, 1)],
                    assigned_variables: vec![token("c", 23, 4, 2)],
                },
                attrs: vec![tag_attr(
                    None,
                    python_expr_value(
                        token("( [1, \n\nb, \n(c := 3)] )", 10, 1, 11),
                        token("( [1, \n\nb, \n(c := 3)] )", 10, 1, 11),
                        None,
                        vec![],
                        vec![token("b", 18, 3, 1)],
                        vec![token("c", 23, 4, 2)],
                    ),
                    false,
                )],
                is_self_closing: false
            })
        );
    }
}
