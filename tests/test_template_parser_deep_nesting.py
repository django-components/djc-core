"""
A tag that nests too deeply fails with a clean error, never a crash.

The tag grammar and the code after it call themselves once for each `[`, `{`
or `(` a value opens, so tens of thousands of them would crash the process.
CPython's own compiler, which reads the Python `compile_tag()` writes, calls
itself once per nested bracket or call there, and each filter adds a call.
`parse_tag()` raises `SyntaxError` for a tag whose lists, dicts, parentheses
and filters nest more than 16 levels. Brackets inside strings and comments do
not count.

The deep cases run in a separate interpreter, so a crash fails one test
instead of ending the pytest run.
"""

from __future__ import annotations

import io
import subprocess
import sys
import textwrap
import time
import tokenize

import pytest

from djc_core.rust import template_parser
from djc_core.template_parser import TagAttr, TagValue, ValueChild, compile_tag, parse_tag

LIMIT = 16
TOO_DEEP = f"more than {LIMIT} levels deep"

# Each shape repeats (open, innermost value, close), and each repeat adds the
# given number of levels.
SHAPES = {
    "lists": ("[", "1", "]", 1),
    "dicts": ("{'a': ", "1", "}", 1),
    "parentheses": ("(", "1", ")", 1),
    "filter arguments": ("[x|f:", "1", "]", 2),
    "filter arguments in dicts": ("{'a': x|f:", "1", "}", 2),
    "filter chain": ("", "x", "|f", 1),
    "argument inside later filters": ("[x|f:", "y", "|g|g]", 4),
}

# Shapes whose value is a Python expression compile to a string, not to
# nested Python, so the CPython checks below leave them out.
COMPILED_SHAPES = [shape for shape in SHAPES if shape != "parentheses"]


def _value(shape: str, levels: int) -> str:
    # Repeat until `levels` deep, or the first depth past it the shape reaches.
    open_, inner, close, per_repeat = SHAPES[shape]
    repeats = -(-levels // per_repeat)
    return open_ * repeats + inner + close * repeats


def _tag(shape: str, levels: int) -> str:
    return "{% component " + _value(shape, levels) + " %}"


def _bracket_depth(code: str) -> int:
    # The nesting of `(`, `[` and `{` as CPython's tokenizer counts it.
    depth = deepest = 0
    for token in tokenize.generate_tokens(io.StringIO(code).readline):
        if token.type == tokenize.OP and token.string in "([{":
            depth += 1
            deepest = max(deepest, depth)
        elif token.type == tokenize.OP and token.string in ")]}":
            depth -= 1
    return deepest


def _run(code: str) -> subprocess.CompletedProcess[str]:
    # The code goes in on stdin: a tag of 100 KB or more is longer than a
    # Windows command line allows. `-I` keeps the repo's `djc_core` source
    # folder off `sys.path`, so it cannot shadow the installed package.
    return subprocess.run(
        [sys.executable, "-I", "-"],
        input=textwrap.dedent(code),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def test_every_shape_divides_the_limit() -> None:
    # Otherwise `_tag(shape, LIMIT)` would build a deeper tag.
    for open_, inner, close, per_repeat in SHAPES.values():
        assert LIMIT % per_repeat == 0, (open_, inner, close)


@pytest.mark.parametrize("shape", COMPILED_SHAPES)
@pytest.mark.parametrize("form", ["positional", "keyword", "spread", "value"])
def test_the_python_written_for_the_deepest_tag_nests_at_most_four_levels_more(shape: str, form: str) -> None:
    # The limit was chosen so that this Python compiles on small threads
    # (see `MAX_NESTING` in `src/nesting.rs`), which needs this bound.
    value = _value(shape, LIMIT)
    tag = {
        "positional": "{% component " + value + " %}",
        "keyword": "{% component key=" + value + " %}",
        "spread": "{% component ..." + value + " %}",
        "value": "{% component " + value + " %}",
    }[form]
    ast = parse_tag(tag)
    if form == "value":
        code = "def compiled_func(context):\n    return " + template_parser.compile_value(ast.attrs[0].value)
    else:
        code = template_parser.compile_tag_attrs(ast.attrs)
    assert _bracket_depth(code) <= LIMIT + 4, code


@pytest.mark.parametrize("stack", [128 * 1024, 256 * 1024])
def test_the_deepest_accepted_tags_parse_and_compile_in_cpython_on_a_small_thread(stack: int) -> None:
    # 128 KiB is the default thread stack of the musl CPython builds that uv
    # installs. `compile_tag()` hands the Python it writes to CPython's
    # `compile()`, which calls itself once per nested bracket or call and,
    # before Python 3.14, has no stack check of its own: too deep, and it
    # crashes the thread; on 3.14 and later it raises `MemoryError`.
    tags = [
        "{% component " + prefix + _value(shape, LIMIT) + " %}"
        for shape in COMPILED_SHAPES
        for prefix in ["", "key="]
    ]
    result = _run(
        f"""
        import threading

        from djc_core.template_parser import compile_tag, compile_value, parse_tag

        def work():
            for tag in {tags!r}:
                ast = parse_tag(tag)
                compile_tag(
                    ast, source=tag, filters={{}}, tags={{}}, expr=None,
                    template_string=None, variable=None, translation=None, filter=None,
                )
                compile_value(
                    ast.attrs[0].value, source=tag, filters={{}}, tags={{}}, expr=None,
                    template_string=None, variable=None, translation=None, filter=None,
                )
            print("done")

        threading.stack_size({stack})
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()
        """
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "done", result.stderr[-2000:]


@pytest.mark.parametrize("shape", SHAPES)
def test_one_level_more_raises_syntax_error(shape: str) -> None:
    with pytest.raises(SyntaxError, match=TOO_DEEP):
        parse_tag(_tag(shape, LIMIT + 1))


@pytest.mark.parametrize("stack", [0, 256 * 1024])
def test_fifty_thousand_levels_fail_cleanly(stack: int) -> None:
    builders = {shape: _tag(shape, 50_000) for shape in SHAPES}
    result = _run(
        f"""
        import threading

        from djc_core.template_parser import parse_tag

        def work():
            for tag in {list(builders.values())!r}:
                try:
                    parse_tag(tag)
                except SyntaxError as error:
                    print("SyntaxError", {TOO_DEEP!r} in str(error))
                else:
                    print("no error")

        if {stack}:
            threading.stack_size({stack})
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()
        """
    )
    # Exit code 0 means no crash.
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.splitlines() == ["SyntaxError True"] * len(SHAPES)


@pytest.mark.parametrize(
    "value",
    [
        '"' + "[" * 1000 + '"',
        "key='" + "{" * 1000 + "'",
        "{# " + "[" * 1000 + " #} x",
        '_("' + "(" * 1000 + '")',
        '("' + "(" * 1000 + '" + x)',
        '("""' + "(" * 1000 + '""")',
        "[{'a': ['" + "[" * 1000 + "']}]",
    ],
    ids=["string", "kwarg string", "comment", "translation", "expression string", "triple quotes", "nested string"],
)
def test_brackets_inside_strings_and_comments_do_not_count(value: str) -> None:
    parse_tag("{% component " + value + " %}")


def test_a_tag_with_too_many_brackets_raises_syntax_error() -> None:
    # The tag's own `{%` is one of the 100,000 characters counted.
    parse_tag('{% component "' + "[" * 99_999 + '" %}')
    with pytest.raises(SyntaxError, match="more than 100000"):
        parse_tag('{% component "' + "[" * 100_000 + '" %}')


def test_a_key_read_two_ways_fails_cleanly_on_a_small_thread() -> None:
    # `a|f:(b=[...` is read first as a key and a list holding one long tag
    # string, then, when the list never closes, as a Python expression in
    # which the string ends early and 5,000 `(` nest. The depth check before
    # parsing stops at this attribute and leaves it to the check on the
    # grammar's output; the grammar still gets enough stack.
    tag = '{% component a|f:(b=["x\\\\" ' + "(" * 5000 + ' " %}'
    result = _run(
        f"""
        import threading

        from djc_core.template_parser import parse_tag

        def work():
            try:
                parse_tag({tag!r})
            except SyntaxError:
                print("SyntaxError")

        threading.stack_size(256 * 1024)
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()
        """
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "SyntaxError"


def test_compile_tag_refuses_a_hand_built_value_deeper_than_the_limit() -> None:
    # `parse_tag()` never returns such a value, but the AST classes can be
    # built by hand. Wrap a parsed list at the limit in one more list.
    attr = parse_tag(_tag("lists", LIMIT)).attrs[0]
    inner = attr.value
    value = TagValue(
        inner.token,
        inner.value,
        inner.kind,
        inner.spread,
        inner.filters,
        inner.used_variables,
        inner.assigned_variables,
        [ValueChild(inner)],
    )
    attr = TagAttr(attr.token, attr.key, value, attr.is_flag)
    with pytest.raises(SyntaxError, match=f"more than {LIMIT} levels deep"):
        compile_tag(
            [attr],
            source="",
            filters={},
            tags={},
            expr=None,
            template_string=None,
            variable=None,
            translation=None,
            filter=None,
        )


@pytest.mark.parametrize("shape", SHAPES)
def test_the_deepest_accepted_tag_can_be_read_on_a_128_kib_thread(shape: str) -> None:
    # Reading `attrs` and `value` copies the parsed value on the calling
    # thread, one call per level, and so do `repr()` and `==`. 128 KiB is the
    # default thread stack on musl.
    result = _run(
        f"""
        import threading

        from djc_core.template_parser import parse_tag

        def work():
            ast = parse_tag({_tag(shape, LIMIT)!r})
            ast.attrs[0].value.filters
            repr(ast)
            assert ast == ast
            print("done")

        threading.stack_size(128 * 1024)
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()
        """
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "done"


@pytest.mark.parametrize(
    "tag",
    [
        '{% component (x<=-y or "\\\\" + "' + "[" * 70 + '") %}',
        '{% for i in (x<=y or "\\\\" + "' + "[" * 70 + '") %}',
    ],
    ids=["expression with <=", "for loop iterable"],
)
def test_an_expression_that_looks_like_a_key_is_read_as_python(tag: str) -> None:
    # `(x<` looks like a key followed by `=`. Read that way, `"\\" + "`
    # would be one tag string and the 70 `[` would count; the grammar reads
    # a Python expression, where they are inside a string.
    parse_tag(tag)


@pytest.mark.parametrize(
    "tag",
    [
        '{% component "' + '\\"' * 300_000 + " %}",
        "{% component " + "{# } " * 50_000 + "%}",
    ],
    ids=["unclosed tag strings", "unclosed comments"],
)
def test_unclosed_strings_and_comments_do_not_slow_the_check(tag: str) -> None:
    # Each unclosed quote or `{#` once made the check search to the end of
    # the tag again, which took about 30 seconds for the first tag.
    started = time.perf_counter()
    with pytest.raises(SyntaxError):
        parse_tag(tag)
    assert time.perf_counter() - started < 3


@pytest.mark.parametrize("prefix", ["", "a(=1 "], ids=["plain", "after a two-way attribute"])
def test_parentheses_inside_an_expression_count_the_same_way_everywhere(prefix: str) -> None:
    # 11 lists around 6 nested `(` are 17 levels. `a(=1` makes the check
    # before parsing stop, and the check after parsing counts the same way.
    value = "[" * 11 + "((((((1))))))" + "]" * 11
    with pytest.raises(SyntaxError, match=TOO_DEEP):
        parse_tag("{% component " + prefix + value + " %}")
