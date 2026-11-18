"""
A function that the expression may not call must not reach a built-in that calls it.

`list.sort(key=...)`, `sorted`, `map` and similar built-ins call the function they are given
from C, without going back through the sandbox's call check. So the sandbox refuses reading
`format` and `format_map` on every string type, and refuses passing any function it would
refuse to call as an argument of a call. Each marker below records when it runs; no test may
let one run.
"""

import collections
import functools
import weakref
from typing import Any, Callable, Dict, List

import pytest

from djc_core.safe_eval import SecurityError, safe_eval
from djc_core.safe_eval.sandbox import unsafe

HITS: List[str] = []


@pytest.fixture(autouse=True)
def clear_hits() -> None:
    HITS.clear()


class Holder:
    """A context object with a private property and two methods templates may not call."""

    rank = 2

    @property
    def _trigger(self) -> str:
        HITS.append("private property read")
        return "PRIVATE-MARKER"

    def delete(self, *args: Any) -> None:
        HITS.append("alters_data method called")

    delete.alters_data = True  # type: ignore[attr-defined]

    @unsafe
    def remove(self, *args: Any) -> None:
        HITS.append("@unsafe method called")

    def order(self, item: Any) -> int:
        return -item


class Forwarder:
    """An app object that hands out the attributes of a string it wraps."""

    def __init__(self, text: str) -> None:
        self.text = text

    def __getattr__(self, name: str) -> Any:
        return getattr(self.text, name)


def refused_by_hook(*args: Any) -> None:
    HITS.append("function refused by the hook called")


# Hooks that accept everything, so the wrapped helpers run and the built-in checks must still
# apply behind them.
ALL_HOOKS: Dict[str, Callable[..., bool]] = {
    "validate_variable": lambda name: True,
    "validate_attribute": lambda obj, name: True,
    "validate_subscript": lambda obj, key: True,
    "validate_callable": lambda func: True,
    "validate_assign": lambda name, value: True,
}


def make_context() -> Dict[str, Any]:
    obj = Holder()
    return {
        "obj": obj,
        "Holder": Holder,
        "text": collections.UserString("{0._trigger}"),
        "fwd": Forwarder("{0._trigger}"),
        "str": str,
        "map": map,
        "list": list,
        "sorted": sorted,
        "pg": functools.partial(getattr, obj),
        "fmt": str.format,
        "d": {"k": obj.delete},
        "wp": weakref.proxy(refused_by_hook),
    }


def run(source: str, **hooks: Any) -> Any:
    return safe_eval(source, **hooks)(make_context())


# Routes that need nothing but the template text.
TEXT_ONLY_ROUTES = [
    pytest.param("[obj].sort(key='{0._trigger}'.format)", id="sort-key-format"),
    pytest.param("[{'x': obj}].sort(key='{x._trigger}'.format_map)", id="sort-key-format-map"),
    pytest.param("[obj].sort(**{'key': '{0._trigger}'.format})", id="sort-key-through-mapping"),
    pytest.param("(lambda f: [obj].sort(key=f))('{0._trigger}'.format)", id="through-lambda-argument"),
    pytest.param("[obj].sort(key=f'{{0._trigger}}'.format)", id="format-text-from-f-string"),
    pytest.param("[None].sort(key=obj.delete)", id="sort-key-alters-data"),
    pytest.param("[None].sort(key=obj.remove)", id="sort-key-unsafe-mark"),
    pytest.param("[None].sort(key=(lambda: obj.delete)())", id="returned-by-lambda"),
    pytest.param("[None].sort(key=[obj.delete][0])", id="from-list-item"),
    pytest.param("[obj].sort(key=Holder.delete)", id="function-read-from-class"),
]

# Routes where the app put a helper or a refused function in the context.
CONTEXT_ROUTES = [
    pytest.param("[obj].sort(key=text.format)", id="user-string-format"),
    pytest.param("list(map(str.format, ['{0._trigger}'], [obj]))", id="str-format-from-class"),
    pytest.param("[obj].sort(key=fwd.format)", id="format-from-forwarding-object"),
    pytest.param("list(map(fmt, ['{0._trigger}'], [obj]))", id="str-format-passed-in"),
    pytest.param("['_trigger'].sort(key=pg)", id="partial-of-getattr"),
    pytest.param("sorted([None], key=obj.delete)", id="sorted-key"),
    pytest.param("list(map(obj.delete, [None]))", id="map-function"),
    pytest.param("list(map(*[obj.delete, [None]]))", id="map-through-star-args"),
    pytest.param("[None].sort(key=d['k'])", id="from-context-dict"),
    pytest.param("[None].sort(key=wp)", id="weak-proxy"),
]


class TestRefusedFunctionsDoNotReachBuiltins:
    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    @pytest.mark.parametrize("source", TEXT_ONLY_ROUTES + CONTEXT_ROUTES)
    def test_route_is_refused_before_the_marker_runs(self, source: str, hooks: Dict[str, Any]) -> None:
        with pytest.raises(SecurityError) as excinfo:
            run(source, **hooks)
        assert HITS == []
        assert "PRIVATE-MARKER" not in str(excinfo.value)

    def test_a_function_the_hook_refuses_is_not_passed_on(self) -> None:
        def validate_callable(func: Any) -> bool:
            return func is not refused_by_hook

        with pytest.raises(SecurityError, match="can't be passed to"):
            safe_eval("[None].sort(key=f)", validate_callable=validate_callable)({"f": refused_by_hook})
        assert HITS == []

    def test_the_hook_sees_only_functions_among_the_arguments(self) -> None:
        seen: List[Any] = []

        def validate_callable(func: Any) -> bool:
            seen.append(func)
            return True

        items = [3, 1, 2]
        safe_eval("items.sort(key=k, reverse=True)", validate_callable=validate_callable)({"items": items, "k": abs})
        assert items == [3, 2, 1]
        # The bound `sort` itself, then `abs`; not the list or `True`.
        assert seen[1:] == [abs]

    def test_reading_format_says_what_to_use_instead(self) -> None:
        with pytest.raises(SecurityError, match=r"attribute 'format' .* Use an f-string instead"):
            run("'{0._trigger}'.format")
        assert HITS == []

    def test_passing_a_refused_function_names_both_functions(self) -> None:
        with pytest.raises(SecurityError) as excinfo:
            run("[None].sort(key=obj.delete)")
        message = str(excinfo.value)
        assert "Holder.delete" in message
        assert "can't be passed to" in message
        assert "sort" in message

    def test_passing_a_refused_formatter_keeps_its_advice(self) -> None:
        with pytest.raises(SecurityError, match="can't be passed to .* Use an f-string instead"):
            run("list(map(fmt, ['{0._trigger}'], [obj]))")


class TestOrdinaryExpressionsStillWork:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("'a-b'.upper()", "A-B"),
            ("', '.join(['a', 'b'])", "a, b"),
            ("'a b'.split()", ["a", "b"]),
            ("'x'.replace('x', '{0}')", "{0}"),
            ("'{name}'.startswith('{')", True),
            ("f'{obj.rank:>3}|'", "  2|"),
            ("'%s and %s' % (1, 2)", "1 and 2"),
            ("sorted([obj, obj], key=lambda o: o.rank)[0].rank", 2),
            ("(items := [3, 1, 2], items.sort(key=lambda x: -x), items)[2]", [3, 2, 1]),
            ("sorted([2, -3, 1], key=abs)", [1, 2, -3]),
            ("sorted([1, 2], key=obj.order)", [2, 1]),
            ("list(map(str.upper, ['a', 'b']))", ["A", "B"]),
            ("list(map(lambda s: f'<{s}>', ['a']))", ["<a>"]),
            ("isinstance(obj, Holder)", True),
            ("''.join(str(x) for x in [1, 2])", "12"),
            ("text.upper()", "{0._TRIGGER}"),
        ],
    )
    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    def test_expression(self, source: str, expected: Any, hooks: Dict[str, Any]) -> None:
        context = make_context()
        context.update({"abs": abs, "isinstance": isinstance})
        assert safe_eval(source, **hooks)(context) == expected
        assert HITS == []
