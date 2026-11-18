//! A tag that nests too deeply raises a clean error instead of crashing.
//!
//! The grammar and the AST builder call themselves once per `[`, `{` or `(`
//! level. Without the checks in `src/nesting.rs`, 500 nested lists would
//! crash a 256 KiB thread and 50,000 the main thread. A crash here ends the
//! test binary, which still fails the run. The Python that `compile_tag`
//! writes also nests one call per filter, and CPython's compiler reads it, so
//! filters count as levels too. The Python tests check that the deepest
//! accepted tags compile in CPython on a small thread.

use djc_template_parser::nesting::{MAX_BRACKETS, MAX_NESTING};
use djc_template_parser::{compile_tag_attrs, parse_tag, ParseError, Tag};

/// A 256 KiB stack, smaller than the usual default for a thread.
const SMALL_STACK: usize = 256 * 1024;

/// Ways to nest, each as (open, inner, close, levels that one repeat adds).
const SHAPES: [(&str, &str, &str, usize); 7] = [
    ("[", "1", "]", 1),
    ("{'a': ", "1", "}", 1),
    ("(", "1", ")", 1),
    // The filter wraps its argument, which holds the next level.
    ("[x|f:", "1", "]", 2),
    ("{'a': x|f:", "1", "}", 2),
    // A filter chain with no brackets at all.
    ("", "x", "|f", 1),
    // The argument of `f` also sits inside both later filters.
    ("[x|f:", "1", "|g|g]", 4),
];

/// A tag with `shape` repeated until it is `levels` deep, or the first depth
/// past `levels` the shape can reach.
fn nested((open, inner, close, per_repeat): (&str, &str, &str, usize), levels: usize) -> String {
    let repeats = levels.div_ceil(per_repeat);
    format!(
        "{{% component {}{}{} %}}",
        open.repeat(repeats),
        inner,
        close.repeat(repeats)
    )
}

fn on_stack<T: Send + 'static>(stack: usize, check: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(check)
        .unwrap()
        .join()
        .unwrap()
}

fn assert_too_deep(result: Result<Tag, ParseError>, tag: &str) {
    let message = result.expect_err(tag).to_string();
    assert!(
        message.contains(&format!("more than {MAX_NESTING} levels deep")),
        "{tag}: {message}"
    );
}

#[test]
fn every_shape_divides_the_limit() {
    // Otherwise `nested(shape, MAX_NESTING)` would build a deeper tag.
    for shape in SHAPES {
        assert_eq!(MAX_NESTING % shape.3, 0, "{shape:?}");
    }
}

#[test]
fn the_deepest_accepted_tag_parses_and_compiles_on_a_small_thread() {
    on_stack(SMALL_STACK, || {
        for shape in SHAPES {
            let tag = nested(shape, MAX_NESTING);
            let Ok(Tag::Generic(generic)) = parse_tag(&tag, None) else {
                panic!("{tag}: not parsed as a generic tag");
            };
            compile_tag_attrs(&generic.attrs).expect(&tag);
            // Comparing and freeing a value walk it one call per level with
            // no stack check, which this thread has room for.
            let copy = generic.attrs.clone();
            assert_eq!(copy, generic.attrs, "{tag}");
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
fn only_the_filters_around_an_argument_count_for_it() {
    // `x|f:[...]|g` writes `filter(g, filter(f, x, [...]), None)`: the list
    // sits inside both filters. The argument of the last filter sits inside
    // only that one, so a list one level deeper fits there.
    let deep_list = |levels: usize| format!("{}1{}", "[".repeat(levels), "]".repeat(levels));
    let first = format!("{{% component x|f:{}|g %}}", deep_list(MAX_NESTING - 1));
    assert_too_deep(parse_tag(&first, None), &first);
    let last = format!("{{% component x|g|f:{} %}}", deep_list(MAX_NESTING - 1));
    assert!(parse_tag(&last, None).is_ok(), "{last}");
}

#[test]
fn fifty_thousand_levels_fail_cleanly_on_any_thread() {
    for stack in [8 * 1024 * 1024, SMALL_STACK] {
        on_stack(stack, || {
            for shape in SHAPES {
                let tag = nested(shape, 50_000 * shape.3);
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
    // 11 lists around 6 nested `(` are 17 levels in both checks, also when
    // an attribute read two ways (`a(=1`) makes the first check stop.
    let value = format!("{}((((((1)))))){}", "[".repeat(11), "]".repeat(11));
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
    // call per level, and the copy checks the stack at each level. A 64 KiB
    // stack is far smaller than any default. On Windows only about 33 KiB
    // of it is left when the thread starts: Rust reserves 20 KiB of each
    // thread it starts for its stack overflow handler, and `stacker` also
    // leaves out the guard pages below that.
    for shape in SHAPES {
        let tag = nested(shape, MAX_NESTING);
        let Ok(Tag::Generic(generic)) = parse_tag(&tag, None) else {
            panic!("{tag}: not parsed as a generic tag");
        };
        let original = generic.attrs;
        // Only the copy runs on the tiny thread. Comparing and freeing the
        // values have no stack check, so both happen back on this thread.
        // The 256 KiB test above checks them on a small thread.
        let (copy, original) = on_stack(64 * 1024, move || {
            let copy = original.clone();
            (copy, original)
        });
        assert_eq!(copy, original, "{tag}");
    }
}
