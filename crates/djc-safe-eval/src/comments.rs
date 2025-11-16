use ruff_source_file::LineIndex;

use crate::transformer::{Comment, Token};

/// Preprocess the source string to extract comments.
///
/// Since we use `exec()` instead of `eval()`, Python naturally handles:
/// - Comments (they're ignored by the parser)
/// - Newlines (they're part of normal Python syntax)
pub fn extract_comments(source: &str) -> Result<Vec<Comment>, String> {
    let mut comments = Vec::new();
    let line_index = LineIndex::from_source_text(source);

    // Convert to bytes for easier indexing
    let bytes = source.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut string_quote: Option<u8> = None;
    let mut string_delimiter_count = 0;

    let check_for_string_start = |ch: char, i: usize| -> (bool, Option<u8>, i32, usize) {
        if !(ch == '"' || ch == '\'') {
            // Curr char NOT a quote
            return (false, None, 0, i);
        }
        let quote_byte = ch as u8;

        // is_raw_string is already set if we saw a prefix
        let in_string = true;
        let string_quote = Some(quote_byte);
        let string_delimiter_count;
        let new_i;

        // Triple quote string
        if i + 2 < bytes.len() && bytes[i + 1] == quote_byte && bytes[i + 2] == quote_byte {
            string_delimiter_count = 3;
            new_i = i + 3;
        } else {
            // Single quote string
            string_delimiter_count = 1;
            new_i = i + 1;
        }
        (in_string, string_quote, string_delimiter_count, new_i)
    };

    let check_for_comment = |ch: char, i: usize, comments: &mut Vec<Comment>| -> (bool, usize) {
        if ch != '#' {
            return (false, i);
        }

        // Found a comment - extract it
        let comment_start = i;
        let mut comment_end = i + 1;

        // Collect comment text until newline or end of input
        while comment_end < bytes.len() {
            let next_byte = bytes[comment_end];
            if next_byte == b'\n' || next_byte == b'\r' {
                break;
            }
            comment_end += 1;
        }

        let comment_text =
            String::from_utf8_lossy(&bytes[comment_start + 1..comment_end]).to_string();

        // Create tokens for the comment
        let start_pos =
            line_index.line_column(ruff_text_size::TextSize::from(comment_start as u32), source);

        let comment_token = Token {
            content: format!("#{}", comment_text),
            start_index: comment_start,
            end_index: comment_end,
            line_col: (
                start_pos.line.to_zero_indexed() + 1,
                start_pos.column.to_zero_indexed() + 1,
            ),
        };

        // Calculate position for value token (starts one character after #)
        let value_start_pos = line_index.line_column(
            ruff_text_size::TextSize::from((comment_start + 1) as u32),
            source,
        );

        let value_token = Token {
            content: comment_text.clone(),
            start_index: comment_start + 1,
            end_index: comment_end,
            line_col: (
                value_start_pos.line.to_zero_indexed() + 1,
                value_start_pos.column.to_zero_indexed() + 1,
            ),
        };

        comments.push(Comment {
            token: comment_token,
            value: value_token,
        });

        (true, comment_end)
    };

    while i < bytes.len() {
        let ch = bytes[i] as char;

        if !in_string {
            // Check for string start quote(s)
            // If so, advance past the string start quotes
            let (new_in_string, new_string_quote, new_string_delimiter_count, new_i) =
                check_for_string_start(ch, i);
            if new_in_string {
                in_string = new_in_string;
                string_quote = new_string_quote;
                string_delimiter_count = new_string_delimiter_count;
                i = new_i;
                continue;
            }

            // Check for comment
            // If found, advance past the comment
            let (found_comment, new_i) = check_for_comment(ch, i, &mut comments);
            if found_comment {
                i = new_i;
                continue;
            }

            // Regular character outside string
            i += 1;
        } else {
            // Inside a string
            let quote_byte = string_quote.unwrap();

            // Before checking for closing quotes or anything else,
            // first handle escape sequences like `\"` or `\\`.
            //
            // Whether it's a raw string or not, Python allows nested quotes if they follow
            // a backslash. The difference is that in raw string, the backslash is included
            // in the final string too. While in regular string the backslash and character
            // after it create a new single character, e.g. `\n` for newline.
            // Compare `r"abc \" def"` vs `"abc \" def"`
            //
            // So check if we're escaping the next char, and if so push and skip both characters.
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }

            // Check for closing quote(s)
            // We already handled escape sequences above, so any quote here is a closing quote
            if bytes[i] == quote_byte {
                let mut quote_count = 1;
                let mut j = i + 1;
                while j < bytes.len()
                    && quote_count < string_delimiter_count
                    && bytes[j] == quote_byte
                {
                    quote_count += 1;
                    j += 1;
                }

                if quote_count == string_delimiter_count {
                    // Closing quote(s)
                    i = j;
                    in_string = false;
                    string_quote = None;
                    string_delimiter_count = 0;
                    continue;
                }
            }

            // Regular character inside string
            i += 1;
        }
    }

    Ok(comments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _token(content: &str, start_index: usize, line: usize, col: usize) -> Token {
        Token {
            content: content.to_string(),
            start_index,
            end_index: start_index + content.len(),
            line_col: (line, col),
        }
    }

    #[test]
    fn test_simple_comment_extraction() {
        let result = extract_comments("1 # comment").unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("# comment", 2, 1, 3),
                value: _token(" comment", 3, 1, 4),
            }],
        );
    }

    #[test]
    fn test_comment_at_end_of_input() {
        let result = extract_comments("42#end").unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("#end", 2, 1, 3),
                value: _token("end", 3, 1, 4),
            }],
        );
    }

    #[test]
    fn test_multiple_comments() {
        let result = extract_comments("x # first\n y # second").unwrap();
        assert_eq!(
            result,
            vec![
                Comment {
                    token: _token("# first", 2, 1, 3),
                    value: _token(" first", 3, 1, 4),
                },
                Comment {
                    token: _token("# second", 13, 2, 4),
                    value: _token(" second", 14, 2, 5),
                },
            ],
        );
    }

    #[test]
    fn test_comment_inside_string_not_extracted() {
        let result = extract_comments(r#""text # not a comment""#).unwrap();
        assert_eq!(result, vec![],);
    }

    #[test]
    fn test_comment_after_string_extracted() {
        let result = extract_comments(r#""t#xt" # this is a comment"#).unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("# this is a comment", 7, 1, 8),
                value: _token(" this is a comment", 8, 1, 9),
            }],
        );
    }

    #[test]
    fn test_multiline_string() {
        // Newlines in triple-quoted strings are preserved
        let result = extract_comments("1 \n 2 \"\"\"my\n#tring\"\"\" 3 \n 4").unwrap();
        assert_eq!(result, vec![]);

        let result = extract_comments("1 \n 2 '''my\n#tring''' 3 \n 4").unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_raw_string_preserves_newlines() {
        // In this case `\n` in string is a newline
        let result = extract_comments("1 \n 2 r\"\"\"my\n#tring\"\"\" 3 \n 4").unwrap();
        assert_eq!(result, vec![],);

        // In this case `\#` in raw string is two characters `\` and `#` (not an escape)
        let result = extract_comments(r#"1 \n 2 r"""my\#string""" 3 \n 4"#).unwrap();
        assert_eq!(result, vec![],);
    }

    #[test]
    fn test_fstring_newline_replacement() {
        // Newlines in triple-quoted strings are preserved
        let result = extract_comments("f\"\"\"my#\n{#name}\"\"\"").unwrap();
        assert_eq!(result, vec![],);
    }

    #[test]
    fn test_regular_string_no_newline() {
        let result = extract_comments("\"he#lo\"").unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_single_quoted_string_with_literal_newline() {
        // Single-quoted strings cannot contain literal newlines in Python
        // The preprocessing preserves the newline, but parsing will catch this as a syntax error.
        let result = extract_comments("'ab#\n'").unwrap();
        assert_eq!(result, vec![]);

        let result = extract_comments("\"ab#\n\"").unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_multiline_string_with_comment() {
        // Newlines in triple-quoted strings are preserved (will work with exec())
        let result = extract_comments("\"\"\"my\n#tring\"\"\" # comment").unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("# comment", 16, 2, 11),
                value: _token(" comment", 17, 2, 12),
            }],
        );
    }

    #[test]
    fn test_string_with_escape_sequence() {
        let result = extract_comments(r##""t#xt \"qu#te\"#" # after"##).unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("# after", 18, 1, 19),
                value: _token(" after", 19, 1, 20),
            }],
        );
    }

    #[test]
    fn test_raw_string_with_escape_sequence() {
        let result = extract_comments(r##"r"t#xt \"qu#te\"#" # after"##).unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("# after", 19, 1, 20),
                value: _token(" after", 20, 1, 21),
            }],
        );
    }

    #[test]
    fn test_string_prefixes() {
        // Test various string prefixes
        assert_eq!(extract_comments(r#"r"raw""#).unwrap(), vec![],);
        assert_eq!(extract_comments(r#"f"formatted""#).unwrap(), vec![],);
        assert_eq!(extract_comments(r#"b"bytes""#).unwrap(), vec![],);
        assert_eq!(extract_comments(r#"rf"raw formatted""#).unwrap(), vec![],);
    }

    #[test]
    fn test_comment_before_string() {
        let source = r#"# comment before"text""#;
        let result = extract_comments(source).unwrap();
        // When there's no newline, the comment extends to the end of input
        // So the comment includes " comment before"text""
        assert_eq!(
            result,
            vec![Comment {
                token: _token(source, 0, 1, 1),
                value: _token(&source[1..], 1, 1, 2),
            }],
        );
    }

    #[test]
    fn test_nested_strings() {
        // String containing quote characters
        let result = extract_comments(r#""ou#ter 'in#ner' ou#ter""#).unwrap();
        assert_eq!(result, vec![],);
    }

    #[test]
    fn test_triple_quotes_in_single_quote_string() {
        // Triple quotes inside a single-quote string should not close it
        let result = extract_comments(r#"'''te#xt \"\"\" ins#ide\"\"\te#xt2'''"#).unwrap();
        assert_eq!(result, vec![],);
    }

    #[test]
    fn test_empty_comment() {
        let result = extract_comments("x #").unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("#", 2, 1, 3),
                value: _token("", 3, 1, 4),
            }],
        );
    }

    #[test]
    fn test_comment_with_carriage_return() {
        let result = extract_comments("x # comment\r\nnext").unwrap();
        assert_eq!(
            result,
            vec![Comment {
                token: _token("# comment", 2, 1, 3),
                value: _token(" comment", 3, 1, 4),
            }],
        );
    }

    #[test]
    fn test_multiline_string_with_escaped_newline() {
        // Escaped newline in non-raw string should not be replaced
        let result = extract_comments(r#""line1\\nline2""#).unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_complex_expression_with_comments() {
        let result = extract_comments(
            "[      # comment 1\n  1,   # comment 2\n  2,   # comment 3\n]       # comment 4",
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                Comment {
                    token: _token("# comment 1", 7, 1, 8),
                    value: _token(" comment 1", 8, 1, 9),
                },
                Comment {
                    token: _token("# comment 2", 26, 2, 8),
                    value: _token(" comment 2", 27, 2, 9),
                },
                Comment {
                    token: _token("# comment 3", 45, 3, 8),
                    value: _token(" comment 3", 46, 3, 9),
                },
                Comment {
                    token: _token("# comment 4", 65, 4, 9),
                    value: _token(" comment 4", 66, 4, 10),
                },
            ],
        );
    }
}
