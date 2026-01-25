mod common;

#[cfg(test)]
mod tests {
    use super::common::plain_parse_tag_v1;
    use djc_template_parser::ast::TemplateVersion;
    use djc_template_parser::error::CompileError;
    use djc_template_parser::parser_config::{ParserConfig, TagConfig, TagSpec};
    use djc_template_parser::tag_compiler::compile_tag_attrs;
    use djc_template_parser::tag_parser::TagParser;

    fn assert_compile_tag_attrs(input: &str, expected: &str) {
        let (tag, _) = plain_parse_tag_v1(input).unwrap();
        let attrs = &tag.as_generic().unwrap().attrs;
        let result = compile_tag_attrs(attrs).unwrap();
        assert_eq!(result, expected);
    }

    fn assert_compile_tag_attrs_errors(input: &str, expected: CompileError) {
        let (tag, _) = plain_parse_tag_v1(input).unwrap();
        let attrs = &tag.as_generic().unwrap().attrs;
        let result = compile_tag_attrs(attrs);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error, expected);
    }

    fn assert_compile_tag_attrs_with_flags(input: &str, expected: &str, flags: &[&str]) {
        let mut config = ParserConfig::new(TemplateVersion::V1);
        config.set_tag(TagConfig::PlainTag(TagSpec {
            tag_name: "my_tag".to_string(),
            flags: flags.iter().map(|f| f.to_string()).collect(),
        }));
        let (tag, _) = TagParser::parse_tag(input, &config).unwrap();
        let attrs = &tag.as_generic().unwrap().attrs;
        let result = compile_tag_attrs(attrs).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compile_tag_attrs_positional_after_keyword() {
        assert_compile_tag_attrs_errors(
            "{% my_tag key=value second / %}",
            CompileError::Syntax("positional argument follows keyword argument".to_string()),
        );
    }

    #[test]
    fn test_compile_tag_attrs_no_attributes() {
        assert_compile_tag_attrs(
            "{% my_tag / %}",
            "def compiled_func(context):\n    args = []\n    kwargs = []\n    return args, kwargs",
        );
    }

    #[test]
    fn test_compile_tag_attrs_single_arg() {
        assert_compile_tag_attrs(
            "{% my_tag my_var / %}",
            "def compiled_func(context):\n    args = []\n    kwargs = []\n    args.append(variable(context, source, (10, 16), filters, tags, \"\"\"my_var\"\"\"))\n    return args, kwargs"
        );
    }

    #[test]
    fn test_multiple_args() {
        assert_compile_tag_attrs(
            "{% my_tag my_var 'hello' 123 / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append(variable(context, source, (10, 16), filters, tags, """my_var"""))
    args.append('hello')
    args.append(123)
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_single_kwarg() {
        assert_compile_tag_attrs(
            "{% my_tag key=my_var / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwargs.append(('key', variable(context, source, (14, 20), filters, tags, """my_var""")))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_multiple_kwargs() {
        assert_compile_tag_attrs(
            "{% my_tag key1=my_var key2='hello' / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwargs.append(('key1', variable(context, source, (15, 21), filters, tags, """my_var""")))
    kwargs.append(('key2', 'hello'))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_mixed_args_and_kwargs() {
        assert_compile_tag_attrs(
            "{% my_tag 42 key='value' / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append(42)
    kwargs.append(('key', 'value'))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_spread_kwargs() {
        assert_compile_tag_attrs(
            "{% my_tag ...options key='value' / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwarg_seen = False
    kwarg_seen = _handle_spread(variable(context, source, (10, 20), filters, tags, """options"""), """options""", args, kwargs, kwarg_seen)
    kwargs.append(('key', 'value'))
    kwarg_seen = True
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_spread_kwargs_order_preserved() {
        assert_compile_tag_attrs(
            "{% my_tag key1='value1' ...options key2='value2' / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwargs.append(('key1', 'value1'))
    kwarg_seen = True
    kwarg_seen = _handle_spread(variable(context, source, (24, 34), filters, tags, """options"""), """options""", args, kwargs, kwarg_seen)
    kwargs.append(('key2', 'value2'))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_template_string_arg() {
        assert_compile_tag_attrs(
            "{% my_tag \"{{ my_var }}\" / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append(template_string(context, source, (10, 24), filters, tags, """{{ my_var }}"""))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_translation_arg() {
        assert_compile_tag_attrs(
            "{% my_tag _('hello world') / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append(translation(context, source, (10, 26), filters, tags, """hello world"""))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_filter() {
        assert_compile_tag_attrs(
            "{% my_tag my_var|upper / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append(filter(context, source, (16, 22), filters, tags, 'upper', variable(context, source, (10, 22), filters, tags, """my_var"""), None))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_filter_with_arg() {
        assert_compile_tag_attrs(
            "{% my_tag my_var|default:'none' / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append(filter(context, source, (16, 31), filters, tags, 'default', variable(context, source, (10, 31), filters, tags, """my_var"""), 'none'))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_multiple_filters() {
        assert_compile_tag_attrs(
            "{% my_tag my_var|upper|default:'none' / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append(filter(context, source, (22, 37), filters, tags, 'default', filter(context, source, (16, 22), filters, tags, 'upper', variable(context, source, (10, 37), filters, tags, """my_var"""), None), 'none'))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_list_value() {
        assert_compile_tag_attrs(
            "{% my_tag [1, my_var] / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append([1, variable(context, source, (14, 20), filters, tags, """my_var""")])
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_dict_value() {
        assert_compile_tag_attrs(
            "{% my_tag {'key': my_var} / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    args.append({'key': variable(context, source, (18, 24), filters, tags, """my_var""")})
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_multiple_spreads() {
        assert_compile_tag_attrs(
            "{% my_tag key1='value1' ...options1 key2='value2' ...options2 / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwargs.append(('key1', 'value1'))
    kwarg_seen = True
    kwarg_seen = _handle_spread(variable(context, source, (24, 35), filters, tags, """options1"""), """options1""", args, kwargs, kwarg_seen)
    kwargs.append(('key2', 'value2'))
    kwarg_seen = _handle_spread(variable(context, source, (50, 61), filters, tags, """options2"""), """options2""", args, kwargs, kwarg_seen)
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_compiler_skips_flags() {
        assert_compile_tag_attrs_with_flags(
            "{% my_tag key='value' disabled / %}",
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwargs.append(('key', 'value'))
    return args, kwargs"#,
            &["disabled"],
        );
    }

    #[test]
    fn test_python_expression() {
        assert_compile_tag_attrs(
            "{% my_tag (items + 1) / %}",
            "def compiled_func(context):\n    args = []\n    kwargs = []\n    args.append(expr(context, source, (10, 21), filters, tags, \"\"\"(items + 1)\"\"\"))\n    return args, kwargs"
        );
    }

    #[test]
    fn test_multiline_template_string() {
        // Test multiline template string (contains {{ }}) - should use triple quotes
        let input = r#"{% my_tag key="{{ var1 }}
    line 2
    line 3" / %}"#;
        let (tag, _) = plain_parse_tag_v1(input).unwrap();
        let attrs = &tag.as_generic().unwrap().attrs;
        let result = compile_tag_attrs(attrs).unwrap();

        // Verify it uses triple quotes and contains the multiline content
        assert!(result.contains("template_string"));
        assert!(result.contains("\"\"\""));
        assert!(result.contains("{{ var1 }}"));
        assert!(result.contains("line 2"));
        assert!(result.contains("line 3"));
    }

    #[test]
    fn test_multiline_variable() {
        // Test multiline variable value - should use triple quotes
        let input = r#"{% my_tag key=my_var / %}"#;
        let (tag, _) = plain_parse_tag_v1(input).unwrap();
        let attrs = &tag.as_generic().unwrap().attrs;
        let result = compile_tag_attrs(attrs).unwrap();

        // Verify it uses triple quotes
        assert!(result.contains("variable"));
        assert!(result.contains("\"\"\""));
        assert!(result.contains("my_var"));
    }

    #[test]
    fn test_multiline_translation() {
        // Test multiline translation - should use triple quotes
        let input = r#"{% my_tag key=_('hello
world') / %}"#;
        let (tag, _) = plain_parse_tag_v1(input).unwrap();
        let attrs = &tag.as_generic().unwrap().attrs;
        let result = compile_tag_attrs(attrs).unwrap();

        // Verify it uses triple quotes
        assert!(result.contains("translation"));
        assert!(result.contains("\"\"\""));
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }

    // ###########################################
    // PARAMETER ORDERING TESTS
    // ###########################################

    #[test]
    fn test_arg_after_kwarg_error() {
        // The parser should allow this syntax, but the compiler should raise an error
        assert_compile_tag_attrs_errors(
            r#"{% component key="value" positional_arg %}"#,
            CompileError::Syntax("positional argument follows keyword argument".to_string()),
        );
    }

    #[test]
    fn test_arg_after_spread() {
        // Altho we can see that we're spreading a literal dict,
        // spreads are evaluated only at runtime, so this should parse and compile.
        assert_compile_tag_attrs(
            r#"{% component ...{"key": "value"} positional_arg %}"#,
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwarg_seen = False
    kwarg_seen = _handle_spread({"key": "value"}, """{\"key\": \"value\"}""", args, kwargs, kwarg_seen)
    if kwarg_seen:
        raise SyntaxError("positional argument follows keyword argument")
    args.append(variable(context, source, (33, 47), filters, tags, """positional_arg"""))
    return args, kwargs"#,
        );
    }

    #[test]
    fn test_kwarg_after_spread() {
        // This is totally fine
        assert_compile_tag_attrs(
            r#"{% component ...[1, 2, 3] key="value" %}"#,
            r#"def compiled_func(context):
    args = []
    kwargs = []
    kwarg_seen = False
    kwarg_seen = _handle_spread([1, 2, 3], """[1, 2, 3]""", args, kwargs, kwarg_seen)
    kwargs.append(('key', "value"))
    kwarg_seen = True
    return args, kwargs"#,
        );
    }
}
