//! A tag that nests too deeply raises a clean error instead of crashing.
//!
//! The grammar and the AST builder call themselves once per `[`, `{` or `(`
//! level. Without the checks in `src/nesting.rs`, 500 nested lists would
//! crash a 256 KiB thread and 50,000 the main thread. A crash here ends the
//! test binary, which still fails the run.

use djc_template_parser::nesting::{MAX_BRACKETS, MAX_NESTING};
use djc_template_parser::{compile_tag_attrs, parse_tag, ParseError, Tag};

/// A 256 KiB stack, smaller than the usual default for a thread.
const SMALL_STACK: usize = 256 * 1024;

/// Ways to nest one level per `[`, `{` or `(`, each as (open, inner, close).
const SHAPES: [(&str, &str, &str); 5] = [
    ("[", "1", "]"),
    ("{'a': ", "1", "}"),
    ("[x|f:", "1", "]"),
    ("{'a': x|f:", "1", "}"),
    ("(", "1", ")"),
];

fn nested((open, inner, close): (&str, &str, &str), levels: usize) -> String {
    format!(
        "{{% component {}{}{} %}}",
        open.repeat(levels),
        inner,
        close.repeat(levels)
    )
}

fn on_stack(stack: usize, check: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(check)
        .unwrap()
        .join()
        .unwrap();
}

fn assert_too_deep(result: Result<Tag, ParseError>, tag: &str) {
    let message = result.expect_err(tag).to_string();
    assert!(
        message.contains(&format!("more than {MAX_NESTING} levels deep")),
        "{tag}: {message}"
    );
}

#[test]
fn the_deepest_accepted_tag_parses_and_compiles_on_a_small_thread() {
    on_stack(SMALL_STACK, || {
        for shape in SHAPES {
            let tag = nested(shape, MAX_NESTING);
            // 64 nested `(` are one Python expression, which safe_eval
            // refuses with its own limit; every other shape must parse.
            match parse_tag(&tag, None) {
                Ok(Tag::Generic(generic)) => {
                    compile_tag_attrs(&generic.attrs).expect(&tag);
                }
                Ok(_) => panic!("{tag}: not a generic tag"),
                Err(error) => {
                    let message = error.to_string();
                    assert_eq!(shape.0, "(", "{tag}: {message}");
                    assert!(message.contains("nested too deeply"), "{tag}: {message}");
                }
            }
        }
    });
}

#[test]
fn one_level_more_is_refused() {
    for shape in SHAPES {
        let tag = nested(shape, MAX_NESTING + 1);
        assert_too_deep(parse_tag(&tag, None), &tag);
    }
}

#[test]
fn fifty_thousand_levels_fail_cleanly_on_any_thread() {
    for stack in [8 * 1024 * 1024, SMALL_STACK] {
        on_stack(stack, || {
            for shape in SHAPES {
                let tag = nested(shape, 50_000);
                assert_too_deep(parse_tag(&tag, None), &tag);
            }
        });
    }
}

#[test]
fn brackets_inside_strings_and_comments_do_not_count() {
    on_stack(SMALL_STACK, || {
        let lists = "[".repeat(5_000);
        let parens = "(".repeat(5_000);
        for tag in [
            format!(r#"{{% component "{lists}" %}}"#),
            format!(r#"{{% component key='{lists}' %}}"#),
            format!("{{% component {{# {lists} #}} x %}}"),
            format!(r#"{{% component _("{parens}") %}}"#),
            format!(r#"{{% component ("{parens}" + '{lists}') %}}"#),
            format!(r#"{{% component ("""{parens}""") %}}"#),
            format!("{{% component [{{'a': [\"{lists}\"]}}] %}}"),
        ] {
            let parsed = parse_tag(&tag, None);
            assert!(parsed.is_ok(), "{tag}: {:?}", parsed.err());
        }
    });
}

#[test]
fn a_tag_with_too_many_brackets_is_refused() {
    // The tag's own `{%` is one of the characters counted.
    let at_limit = format!(r#"{{% component "{}" %}}"#, "[".repeat(MAX_BRACKETS - 1));
    // Parsed on a small thread: the stack grows on the heap as needed.
    on_stack(SMALL_STACK, move || {
        assert!(parse_tag(&at_limit, None).is_ok())
    });

    let over = format!(r#"{{% component "{}" %}}"#, "[".repeat(MAX_BRACKETS));
    let message = parse_tag(&over, None)
        .expect_err("over the limit")
        .to_string();
    assert!(
        message.contains(&format!("more than {MAX_BRACKETS}")),
        "{message}"
    );
}

#[test]
fn a_key_read_two_ways_still_fails_cleanly() {
    // `a|f:(b=[...` is first read as the key `a|f:(b` and a list value,
    // where `"x\\" ((((... "` is one tag string. That list never closes,
    // so the grammar reads the attribute again as `a|f:( ... )`, a Python
    // expression in which the string ends after `\\"` and every `(` after
    // it nests. The check before parsing stops at this attribute and leaves
    // it to the check on the grammar's output; the stack sized from the
    // bracket count keeps the grammar from crashing.
    on_stack(SMALL_STACK, || {
        let parens = "(".repeat(5_000);
        let tag = format!(r#"{{% component a|f:(b=["x\\" {parens} " %}}"#);
        let message = parse_tag(&tag, None).expect_err(&tag).to_string();
        // The check before parsing let it through; the grammar refused it.
        assert!(!message.contains("levels deep"), "{message}");
    });
}

#[test]
fn the_check_after_parsing_counts_parentheses_inside_an_expression() {
    // 60 lists around 6 nested `(` are 66 levels in both checks, also when
    // an attribute read two ways (`a(=1`) makes the first check stop.
    let value = format!("{}((((((1)))))){}", "[".repeat(60), "]".repeat(60));
    for tag in [
        format!("{{% component {value} %}}"),
        format!("{{% component a(=1 {value} %}}"),
        format!("{{% component a(={value} %}}"),
    ] {
        assert_too_deep(parse_tag(&tag, None), &tag);
    }
}

#[test]
fn the_deepest_accepted_value_can_be_copied_on_a_tiny_thread() {
    // Python's attribute getters copy the value on the calling thread, one
    // call per level. A 64 KiB stack is far smaller than any default.
    // 64 nested `(` are refused by safe_eval, so that shape is left out.
    for shape in SHAPES.into_iter().filter(|shape| shape.0 != "(") {
        let tag = nested(shape, MAX_NESTING);
        let Ok(Tag::Generic(generic)) = parse_tag(&tag, None) else {
            panic!("{tag}: not parsed as a generic tag");
        };
        on_stack(64 * 1024, move || {
            let copy = generic.attrs.clone();
            assert_eq!(copy, generic.attrs);
        });
    }
}
