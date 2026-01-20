mod common;

#[cfg(test)]
mod tests {
    use djc_template_parser::ast::{EndTag, GenericTag, Tag, TagMeta};

    use super::common::{plain_parse_tag_v1, token};

    #[test]
    fn test_endtag_basic() {
        let input = "{% endslot %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::End(EndTag {
                meta: TagMeta {
                    token: token("{% endslot %}", 0, 1, 1),
                    name: token("endslot", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                }
            })
        );
    }

    #[test]
    fn test_endtag_no_whitespace() {
        let input = "{%endslot%}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::End(EndTag {
                meta: TagMeta {
                    token: token("{%endslot%}", 0, 1, 1),
                    name: token("endslot", 2, 1, 3),
                    used_variables: vec![],
                    assigned_variables: vec![],
                }
            })
        );
    }

    #[test]
    fn test_endtag_with_comments() {
        let input = "{% {# c1 #} endslot {# c2 #} %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::End(EndTag {
                meta: TagMeta {
                    token: token("{% {# c1 #} endslot {# c2 #} %}", 0, 1, 1),
                    name: token("endslot", 12, 1, 13),
                    used_variables: vec![],
                    assigned_variables: vec![],
                }
            })
        );
    }

    #[test]
    fn test_endtag_with_comments_no_spaces() {
        let input = "{%{# c1 #}endslot{# c2 #}%}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::End(EndTag {
                meta: TagMeta {
                    token: token("{%{# c1 #}endslot{# c2 #}%}", 0, 1, 1),
                    name: token("endslot", 10, 1, 11),
                    used_variables: vec![],
                    assigned_variables: vec![],
                }
            })
        );
    }

    #[test]
    fn test_endtag_with_attribute_errors() {
        let input = "{% endslot key=val %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "End tags should not allow attributes"
        );
    }

    #[test]
    fn test_endtag_self_closing_errors() {
        let input = "{% endslot / %}";
        assert!(
            plain_parse_tag_v1(input).is_err(),
            "End tags should not be self-closing"
        );
    }

    #[test]
    fn test_end_as_generic_tag() {
        let input = "{% end %}";
        let (result, _context) = plain_parse_tag_v1(input).unwrap();

        assert_eq!(
            result,
            Tag::Generic(GenericTag {
                meta: TagMeta {
                    token: token("{% end %}", 0, 1, 1),
                    name: token("end", 3, 1, 4),
                    used_variables: vec![],
                    assigned_variables: vec![],
                },
                attrs: vec![],
                is_self_closing: false,
            })
        );
    }
}
