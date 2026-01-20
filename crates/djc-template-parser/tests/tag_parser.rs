// Other test files `tag_parser_<data_type>.rs` all test the same cases, but with different data types.
// This file tests any other edge cases that don't fit those other files.

mod common;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::common::{
        plain_int_value, plain_parse_tag_v1, plain_string_value, plain_variable_value, tag_attr,
        token, variable_value,
    };
    use djc_template_parser::ast::{
        GenericTag, Tag, TagMeta, TagValue, TagValueFilter, TemplateVersion, ValueChild, ValueKind,
    };
    use djc_template_parser::parser_config::{
        ParserConfig, TagConfig, TagSectionSpec, TagSpec, TagWithBodySpec,
    };
    use djc_template_parser::tag_parser::TagParser;

    // #######################################
    // TAG
    // #######################################

    #[test]
    fn test_tag_no_spaces_between_delimiters() {
        let input = "{%my_tag%}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{%my_tag%}", 0, 1, 1),
                    name: token("my_tag", 2, 1, 3),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_tag_no_spaces_between_delimiters_with_args() {
        let input = "{%my_tag key=val%}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{%my_tag key=val%}", 0, 1, 1),
                    name: token("my_tag", 2, 1, 3),
                    used_variables: vec![token("val", 13, 1, 14)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 9, 1, 10)),
                    plain_variable_value("val", 13, 1, 14, None),
                    false
                )],
                is_self_closing: false,
            })
        );
    }

    // #######################################
    // ARGS
    // #######################################

    #[test]
    fn test_arg_invalid() {
        let inputs = vec!["{% my_tag .arg %}"];

        for input in inputs {
            assert!(
                plain_parse_tag_v1(input).is_err(),
                "Input should fail: {}",
                input
            );
        }
    }

    // #######################################
    // KWARGS
    // #######################################

    #[test]
    fn test_kwarg_special_chars() {
        let input = r#"{% my_tag @click.stop=handler attr:key=val %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(r#"{% my_tag @click.stop=handler attr:key=val %}"#, 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("handler", 22, 1, 23), token("val", 39, 1, 40)],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("@click.stop", 10, 1, 11)),
                        plain_variable_value("handler", 22, 1, 23, None),
                        false
                    ),
                    tag_attr(
                        Some(token("attr:key", 30, 1, 31)),
                        plain_variable_value("val", 39, 1, 40, None),
                        false
                    )
                ],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_kwarg_invalid() {
        let inputs = vec![
            "{% my_tag key= val %}",
            "{% my_tag key =val %}",
            "{% my_tag key = val %}",
            "{% my_tag key1= val1 key2 =val2 key3 = val3 %}",
            "{% my_tag :key=val %}",
            "{% my_tag .key=val %}",
            "{% my_tag ...key=val %}",
            "{% my_tag _('hello')=val %}",
            r#"{% my_tag "key"=val %}"#,
            "{% my_tag key[0]=val %}",
        ];

        for input in inputs {
            assert!(
                plain_parse_tag_v1(input).is_err(),
                "Input should fail: {}",
                input
            );
        }
    }

    // #######################################
    // SPREADS
    // #######################################

    #[test]
    fn test_spread_between() {
        // Test spread with other attributes
        let input = "{% my_tag key1=val1 ...myvalue key2=val2 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag key1=val1 ...myvalue key2=val2 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("val1", 15, 1, 16),
                        token("myvalue", 23, 1, 24),
                        token("val2", 36, 1, 37)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        Some(token("key1", 10, 1, 11)),
                        plain_variable_value("val1", 15, 1, 16, None),
                        false
                    ),
                    tag_attr(
                        None,
                        plain_variable_value("myvalue", 20, 1, 21, Some("...")),
                        false
                    ),
                    tag_attr(
                        Some(token("key2", 31, 1, 32)),
                        plain_variable_value("val2", 36, 1, 37, None),
                        false
                    )
                ],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_spread_multiple() {
        let input = "{% my_tag ...dict1 key=val ...dict2 %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag ...dict1 key=val ...dict2 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![
                        token("dict1", 13, 1, 14),
                        token("val", 23, 1, 24),
                        token("dict2", 30, 1, 31)
                    ],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(
                        None,
                        plain_variable_value("dict1", 10, 1, 11, Some("...")),
                        false
                    ),
                    tag_attr(
                        Some(token("key", 19, 1, 20)),
                        plain_variable_value("val", 23, 1, 24, None),
                        false
                    ),
                    tag_attr(
                        None,
                        plain_variable_value("dict2", 27, 1, 28, Some("...")),
                        false
                    )
                ],
                is_self_closing: false,
            }),
        );
    }

    // NOTE: While there cannot be whitespace between the attribute and `...`,
    //       there CAN be whitespace between `*` / `**` and the value,
    //       because we're scoped inside `{ .. }` dict or `[ .. ]` list.
    #[test]
    fn test_spread_whitespace() {
        let input = r#"{% component dict={"a": "b", ** my_attr} list=["a", * my_list] %}"#;
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        // Manually construct spread variable values to match parser output
        // The parser includes the position where ** or * starts (before whitespace)
        let my_attr_spread = TagValue {
            token: token("** my_attr", 29, 1, 30), // Starts at 29 (where ** begins), includes space
            value: token("my_attr", 32, 1, 33),    // Value token (no whitespace)
            children: vec![],
            kind: ValueKind::Variable,
            spread: Some("**".to_string()),
            filters: vec![],
            used_variables: vec![token("my_attr", 32, 1, 33)],
            assigned_variables: vec![],
        };

        let my_list_spread = TagValue {
            token: token("* my_list", 52, 1, 53), // Starts at 52 (where * begins), includes space
            value: token("my_list", 54, 1, 55),   // Value token (no whitespace)
            children: vec![],
            kind: ValueKind::Variable,
            spread: Some("*".to_string()),
            filters: vec![],
            used_variables: vec![token("my_list", 54, 1, 55)],
            assigned_variables: vec![],
        };

        let dict_value = TagValue {
            token: token(r#"{"a": "b", ** my_attr}"#, 18, 1, 19),
            value: token(r#"{"a": "b", ** my_attr}"#, 18, 1, 19),
            children: vec![
                ValueChild::Value(plain_string_value(r#""a""#, 19, 1, 20, None)),
                ValueChild::Value(plain_string_value(r#""b""#, 24, 1, 25, None)),
                ValueChild::Value(my_attr_spread),
            ],
            kind: ValueKind::Dict,
            spread: None,
            filters: vec![],
            used_variables: vec![],
            assigned_variables: vec![],
        };

        let list_value = TagValue {
            token: token(r#"["a", * my_list]"#, 46, 1, 47),
            value: token(r#"["a", * my_list]"#, 46, 1, 47),
            children: vec![
                ValueChild::Value(plain_string_value(r#""a""#, 47, 1, 48, None)),
                ValueChild::Value(my_list_spread),
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
                        r#"{% component dict={"a": "b", ** my_attr} list=["a", * my_list] %}"#,
                        0,
                        1,
                        1
                    ),
                    name: token("component", 3, 1, 4),
                    used_variables: vec![token("my_attr", 32, 1, 33), token("my_list", 54, 1, 55)],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(Some(token("dict", 13, 1, 14)), dict_value, false),
                    tag_attr(Some(token("list", 41, 1, 42)), list_value, false),
                ],
                is_self_closing: false,
            })
        );
    }

    #[test]
    fn test_spread_invalid() {
        // Test spread missing value
        let input = "{% my_tag ... %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow spread operator without a value"
        );
        // Test spread whitespace between operator and value
        let input = "{% my_tag ...  myvalue %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow spread operator with whitespace between operator and value"
        );

        // Test spread in key position
        let input = "{% my_tag ...key=val %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow spread operator in key position"
        );

        // Test spread in value position of key-value pair
        let input = "{% my_tag key=...val %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow spread operator in value position of key-value pair"
        );

        // Test spread operator inside list
        let input = "{% my_tag [1, ...my_list, 2] %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow ... spread operator inside list"
        );

        // Test spread operator inside list with filters
        let input = "{% my_tag [1, ...my_list|filter, 2] %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow ... spread operator inside list with filters"
        );

        // Test spread operator inside dict
        let input = "{% my_tag {...my_dict} %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow ... spread operator inside dict"
        );

        // Test spread operator inside dict with filters
        let input = "{% my_tag {...my_dict|filter} %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow ... spread operator inside dict with filters"
        );
    }

    // #######################################
    // SELF-CLOSING TAGS
    // #######################################

    #[test]
    fn test_self_closing_tag() {
        let input = "{% my_tag / %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag / %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![],
                is_self_closing: true,
            })
        );
    }

    #[test]
    fn test_self_closing_tag_with_args() {
        let input = "{% my_tag key=val / %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag key=val / %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("val", 14, 1, 15)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 10, 1, 11)),
                    plain_variable_value("val", 14, 1, 15, None),
                    false
                )],
                is_self_closing: true,
            })
        );
    }

    #[test]
    fn test_self_closing_tag_in_middle_errors() {
        let input = "{% my_tag / key=val %}";
        let result = plain_parse_tag_v1(input);
        assert!(
            result.is_err(),
            "Self-closing slash in the middle should be an error"
        );
    }

    #[test]
    fn test_self_closing_tag_no_spaces() {
        let input = "{%my_tag/%}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{%my_tag/%}", 0, 1, 1),
                    name: token("my_tag", 2, 1, 3),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![],
                is_self_closing: true,
            })
        );
    }

    #[test]
    fn test_self_closing_tag_no_spaces_with_args() {
        let input = "{%my_tag key=val/%}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{%my_tag key=val/%}", 0, 1, 1),
                    name: token("my_tag", 2, 1, 3),
                    used_variables: vec![token("val", 13, 1, 14)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("key", 9, 1, 10)),
                    plain_variable_value("val", 13, 1, 14, None),
                    false
                )],
                is_self_closing: true,
            })
        );
    }

    // #######################################
    // FILTERS
    // #######################################

    #[test]
    fn test_filter_multiple() {
        let input = "{% my_tag value|lower|title:arg|default:'hello' %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token(
                        "{% my_tag value|lower|title:arg|default:'hello' %}",
                        0,
                        1,
                        1
                    ),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("value", 10, 1, 11), token("arg", 28, 1, 29)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    variable_value(
                        token("value|lower|title:arg|default:'hello'", 10, 1, 11),
                        token("value", 10, 1, 11),
                        None,
                        vec![
                            TagValueFilter {
                                name: token("lower", 16, 1, 17),
                                token: token("|lower", 15, 1, 16),
                                arg: None,
                            },
                            TagValueFilter {
                                name: token("title", 22, 1, 23),
                                token: token("|title:arg", 21, 1, 22),
                                arg: Some(plain_variable_value("arg", 28, 1, 29, None)),
                            },
                            TagValueFilter {
                                name: token("default", 32, 1, 33),
                                token: token("|default:'hello'", 31, 1, 32),
                                arg: Some(plain_string_value("'hello'", 40, 1, 41, None)),
                            }
                        ],
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
    fn test_filter_invalid() {
        // Test using colon instead of pipe
        let input = "{% my_tag value:filter %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow colon instead of pipe for filter"
        );

        // Test using colon with filter argument
        let input = "{% my_tag value:filter:arg %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow colon instead of pipe for filter with argument"
        );

        // Test using colon after a valid filter
        let input = "{% my_tag value|filter:arg:filter2 %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "Should not allow colon to start a new filter after an argument"
        );
    }

    // #######################################
    // FLAGS
    // #######################################

    #[test]
    fn test_flag() {
        let input = "{% my_tag 123 my_flag key='val' %}";
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "my_tag".to_string(),
            flags: HashSet::from(["my_flag".to_string()]),
        }));
        let (result, _context) = TagParser::parse_tag(input, &config).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag 123 my_flag key='val' %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, plain_int_value("123", 10, 1, 11, None), false),
                    // This `true` is what we're testing
                    tag_attr(None, plain_variable_value("my_flag", 14, 1, 15, None), true),
                    tag_attr(
                        Some(token("key", 22, 1, 23)),
                        plain_string_value("'val'", 26, 1, 27, None),
                        false
                    ),
                ],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_flag_not_as_flag() {
        // Same as test_flag, but `my_flag` is not in the flags set
        let input = "{% my_tag 123 my_flag key='val' %}";
        let config = ParserConfig::new(TemplateVersion::V1);
        let (result, _context) = TagParser::parse_tag(input, &config).unwrap();
        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag 123 my_flag key='val' %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_flag", 14, 1, 15)],
                    assigned_variables: vec![],
                },
                attrs: vec![
                    tag_attr(None, plain_int_value("123", 10, 1, 11, None), false),
                    tag_attr(
                        None,
                        plain_variable_value("my_flag", 14, 1, 15, None),
                        // This `false` is what we're testing
                        false
                    ),
                    tag_attr(
                        Some(token("key", 22, 1, 23)),
                        plain_string_value("'val'", 26, 1, 27, None),
                        false
                    ),
                ],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_flag_as_spread() {
        let input = "{% my_tag ...my_flag %}";
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "my_tag".to_string(),
            flags: HashSet::from(["my_flag".to_string()]),
        }));
        let (result, _context) = TagParser::parse_tag(input, &config).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag ...my_flag %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_flag", 13, 1, 14)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_variable_value("my_flag", 10, 1, 11, Some("...")),
                    false, // This is what we're testing
                )],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_flag_as_kwarg() {
        let input = "{% my_tag my_flag=123 %}";
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "my_tag".to_string(),
            flags: HashSet::from(["my_flag".to_string()]),
        }));
        let (result, _context) = TagParser::parse_tag(input, &config).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my_flag=123 %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    Some(token("my_flag", 10, 1, 11)),
                    plain_int_value("123", 18, 1, 19, None),
                    false
                )],
                is_self_closing: false,
            }),
        );
    }

    #[test]
    fn test_flag_duplicate() {
        let input = "{% my_tag my_flag my_flag %}";
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "my_tag".to_string(),
            flags: HashSet::from(["my_flag".to_string()]),
        }));
        let result = TagParser::parse_tag(input, &config);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Parse error:  --> 1:19\n  |\n1 | {% my_tag my_flag my_flag %}\n  |                   ^-----^\n  |\n  = Flag 'my_flag' may be specified only once."
        );
    }

    #[test]
    fn test_flag_case_sensitive() {
        let input = "{% my_tag my_flag %}";
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "my_tag".to_string(),
            flags: HashSet::from(["MY_FLAG".to_string()]), // Different case
        }));
        let (result, _context) = TagParser::parse_tag(input, &config).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% my_tag my_flag %}", 0, 1, 1),
                    name: token("my_tag", 3, 1, 4),
                    used_variables: vec![token("my_flag", 10, 1, 11)],
                    assigned_variables: vec![],
                },
                attrs: vec![tag_attr(
                    None,
                    plain_variable_value("my_flag", 10, 1, 11, None),
                    false, // This is what we're testing
                )],
                is_self_closing: false,
            }),
        );
    }

    // #######################################
    // CONFIG
    // #######################################

    #[test]
    fn test_config_tag_sections_must_be_unique_from_tags() {
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::TagWithBody(TagWithBodySpec {
            tag: TagSpec {
                tag_name: "tag1".to_string(),
                flags: HashSet::new(),
            },
            sections: vec![TagSectionSpec {
                tag: TagSpec {
                    tag_name: "conflict".to_string(),
                    flags: HashSet::new(),
                },
                repeatable: false,
            }],
        }));
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "conflict".to_string(), // This conflicts with the section tag name
            flags: HashSet::new(),
        }));

        let result = TagParser::parse_tag("{% my_tag %}", &config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("conflicts with existing tag name"));
    }

    #[test]
    fn test_config_tag_sections_must_be_unique() {
        // Section tag name conflicts with another section tag name
        // Note: The validation only works if sections have flags, as build_flags_map
        // only tracks section names that have flags
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::TagWithBody(TagWithBodySpec {
            tag: TagSpec {
                tag_name: "tag1".to_string(),
                flags: HashSet::new(),
            },
            sections: vec![TagSectionSpec {
                tag: TagSpec {
                    tag_name: "conflict".to_string(),
                    flags: HashSet::from(["flag1".to_string()]), // Add flag so it's tracked
                },
                repeatable: false,
            }],
        }));
        config.set_tag(TagConfig::TagWithBody(TagWithBodySpec {
            tag: TagSpec {
                tag_name: "tag2".to_string(),
                flags: HashSet::new(),
            },
            sections: vec![TagSectionSpec {
                tag: TagSpec {
                    tag_name: "conflict".to_string(), // This conflicts with tag1's section
                    flags: HashSet::from(["flag2".to_string()]), // Add flag so it's tracked
                },
                repeatable: false,
            }],
        }));

        let result = config.build_flags_map();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("conflicts with another section tag"));
    }

    #[test]
    fn test_config_for_tag_not_allowed() {
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "for".to_string(), // This should fail
            flags: HashSet::new(),
        }));

        let result = config.build_flags_map();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Tag 'for' is reserved and cannot be specified in tag config"
        );
    }

    #[test]
    fn test_config_correctly_passed_to_parsing_context() {
        // Verify that config (specifically flags) are correctly passed to parsing context
        let input = "{% my_tag my_flag %}";
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "my_tag".to_string(),
            flags: HashSet::from(["my_flag".to_string()]),
        }));
        let (_result, context) = TagParser::parse_tag(input, &config).unwrap();

        // Verify the flag is recognized
        let flags = context.flags.get("my_tag").unwrap();
        assert!(flags.contains("my_flag"));
    }
}
