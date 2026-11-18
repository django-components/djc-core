"""
Deep expressions fail with a clean error, never a crash.

The Rust passes over an expression's syntax tree call themselves once per
level, so an expression such as ``1+1+...+1`` or ``not not ... x`` with many
thousands of terms would overflow the stack. The parser rejects an expression
whose depth bound, counted from its tokens, is above 200 (about 97 chained
``+``) with ``SyntaxError``.

CPython's own compiler then reads the Python code written for the
expression, and it calls itself once per nested bracket or call there. So that
code may nest at most 20 levels (20 nested lists, or 18 attribute reads),
which compiles even on a thread with a 128 KiB stack.

The 10,000-level cases run in a separate interpreter, so a crash fails one test
instead of ending the pytest run.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from djc_core.safe_eval import safe_eval
from djc_core.template_parser import parse_tag

TOO_DEEP = "expression is nested too deeply"
CODE_LIMIT = 20

# Shapes that overflow the stack without the depth check, each nesting `n` levels deep.
SHAPES = {
    "lists": lambda n: "[" * n + "]" * n,
    "additions": lambda n: "1" + "+1" * n,
    "not": lambda n: "not " * n + "x",
    "minus": lambda n: "-" * n + "1",
    "attributes": lambda n: "a" + ".b" * n,
    "conditionals": lambda n: "1 if x else " * n + "2",
}


def test_an_expression_within_the_limit_still_evaluates() -> None:
    # 20 nested lists write code 20 levels deep, and Python evaluates them as usual.
    source = "[" * CODE_LIMIT + "]" * CODE_LIMIT
    assert safe_eval(source)({}) == eval(source)  # noqa: S307 - a literal built above


@pytest.mark.parametrize(
    "expression",
    ["[" * (CODE_LIMIT + 1) + "]" * (CODE_LIMIT + 1), "a" + ".b" * (CODE_LIMIT - 1)],
    ids=["lists", "attributes"],
)
def test_code_nested_one_level_too_deep_raises_syntax_error(expression: str) -> None:
    with pytest.raises(SyntaxError, match="nests calls and brackets 21 levels deep"):
        safe_eval(expression)
    with pytest.raises(SyntaxError, match=TOO_DEEP):
        parse_tag("{% comp (" + expression + ") %}")


# Constructs that nest the Python code written for an expression, each
# repeated `n` times.
CODE_SHAPES = {
    "lists": lambda n: "[" * n + "]" * n,
    "tuples": lambda n: "(" * n + "1" + ",)" * n,
    "dicts": lambda n: "{1: " * n + "1" + "}" * n,
    "sets": lambda n: "{" * n + "1" + "}" * n,
    "additions": lambda n: "1" + "+1" * n,
    "not": lambda n: "not " * n + "x",
    "attributes": lambda n: "a" + ".b" * n,
    "method calls": lambda n: "a" + ".b()" * n,
    "call chain": lambda n: "f" + "(1, 2)" * n,
    "subscripts": lambda n: "a" + "[0]" * n,
    "slices": lambda n: "a" + "[1:2]" * n,
    "nested calls": lambda n: "f(" * n + "x" + ")" * n,
    "keyword arguments": lambda n: "f(x=" * n + "1" + ")" * n,
    "star arguments": lambda n: "f(*" * n + "a" + ")" * n,
    "calls in lists": lambda n: "[f(" * n + "x" + ")]" * n,
    "conditionals": lambda n: "(x if " * n + "y" + " else z)" * n,
    "lambdas": lambda n: "lambda a=1, *b, c=2, **d: " * n + "x",
    "walrus": lambda n: "(w := " * n + "1" + ")" * n,
    "comprehensions": lambda n: "{x: x for x in " * n + "y" + "}" * n,
    "generators": lambda n: "(x for x in " * n + "y" + ")" * n,
    "f-strings": lambda n: "f'{" * n + "x" + "}'" * n,
    "f-string formats": lambda n: "f'{x:{" * n + "x" + "}}'" * n,
}


def _deepest_accepted(shape: str) -> str:
    # The checks only get stricter with `n`, so stop at the first refusal.
    build = CODE_SHAPES[shape]
    deepest = None
    for n in range(1, 300):
        try:
            safe_eval(build(n))
        except SyntaxError:
            break
        deepest = build(n)
    assert deepest is not None, shape
    return deepest


@pytest.mark.parametrize("shape", SHAPES)
def test_a_too_deep_expression_raises_syntax_error(shape: str) -> None:
    expression = SHAPES[shape](150)
    with pytest.raises(SyntaxError, match=TOO_DEEP):
        safe_eval(expression)
    with pytest.raises(SyntaxError, match=TOO_DEEP):
        parse_tag("{% comp (" + expression + ") %}")


def _run(code: str) -> subprocess.CompletedProcess[str]:
    # The code goes in on stdin rather than with `-c`: it can hold an
    # expression of 100 KB or more, longer than a Windows command line allows.
    # `-I` leaves the working directory off `sys.path`, so the repo's `djc_core` source
    # folder cannot shadow the installed package with its compiled module.
    return subprocess.run(
        [sys.executable, "-I", "-"],
        input=textwrap.dedent(code),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.mark.parametrize("shape", SHAPES)
def test_ten_thousand_levels_fail_cleanly_in_every_entry_point(shape: str) -> None:
    builder = repr(SHAPES[shape](10_000))
    result = _run(
        f"""
        from djc_core.safe_eval import safe_eval
        from djc_core.template_parser import parse_tag

        expression = {builder}
        calls = [
            lambda: safe_eval(expression),
            lambda: parse_tag("{{% comp (" + expression + ") %}}"),
        ]
        for call in calls:
            try:
                call()
            except Exception as error:
                print(type(error).__name__)
            else:
                print("no error")
        """
    )
    # Exit code 0 means no crash. Each call must have raised a clean error.
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.split() == ["SyntaxError", "SyntaxError"]


def test_the_deepest_accepted_expressions_compile_on_a_small_python_thread() -> None:
    # 128 KiB is the default thread stack of the musl CPython builds that uv
    # installs. `safe_eval()` hands the code it writes to CPython's
    # `compile()`, which, before Python 3.14, crashes the thread when the code
    # nests too deeply; 3.14 and later raise `MemoryError`.
    expressions = [_deepest_accepted(shape) for shape in CODE_SHAPES]
    result = _run(
        f"""
        import threading

        from djc_core.safe_eval import safe_eval
        from djc_core.template_parser import parse_tag

        def work():
            for expression in {expressions!r}:
                safe_eval(expression)
                # A tag also counts the `(` inside an expression toward its
                # own limit, and reads `f(x=` as a key, so it refuses some of
                # these, but with a clean error.
                try:
                    parse_tag("{{% comp (" + expression + ") %}}")
                except SyntaxError:
                    pass
            print("done")

        threading.stack_size(128 * 1024)
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()
        """
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "done", result.stderr[-2000:]
