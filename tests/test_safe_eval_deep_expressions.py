"""
Deep expressions fail with a clean error, never a crash.

The Rust passes over an expression's syntax tree call themselves once per
level, so an expression such as ``1+1+...+1`` or ``not not ... x`` with many
thousands of terms would overflow the stack. The parser rejects an expression
whose depth bound, counted from its tokens, is above 200 (about 97 chained
``+`` or 65 nested lists) with ``SyntaxError``.

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
    # 60 nested lists stay under the limit, and Python evaluates them as usual.
    source = "[" * 60 + "]" * 60
    assert safe_eval(source)({}) == eval(source)  # noqa: S307 - a literal built above


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


def test_the_limit_holds_on_a_small_python_thread() -> None:
    # A 256 KiB thread stack is smaller than the usual default. The deepest
    # list the parser accepts (65 levels) must still be parsed there.
    result = _run(
        """
        import threading

        from djc_core.safe_eval import safe_eval
        from djc_core.template_parser import parse_tag

        def work():
            expression = "[" * 65 + "]" * 65
            safe_eval(expression)
            parse_tag("{% comp (" + expression + ") %}")
            print("done")

        threading.stack_size(256 * 1024)
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()
        """
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "done"
