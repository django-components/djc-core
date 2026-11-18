"""
A Django lazy object must not let an expression run `str.format` on its real value.

A lazy string from `gettext_lazy()`, `format_lazy()` or `lazy()` is not a `str`. Each of its
methods passes the call on to the real string, so `lazy_text.format(obj)` would run
`str.format` and read the private attributes that the text names. The sandbox refuses every
attribute of a lazy object, and every method or class taken from one that the app passes in,
without importing Django. It also refuses Django's own formatting functions, and Django's
`lazy()` and `keep_lazy()` wrappers around a refused function. The `_trigger` property
records each read; no test may let it run.

The tests need Django, which is a test-only dependency. Without it they are skipped, except
the one that checks the sandbox never imports Django.
"""

import functools
import importlib
import subprocess
import sys
import weakref
from typing import Any, Callable, Dict, List

import pytest

from djc_core.safe_eval import SecurityError, safe_eval

try:
    import django
    from django.conf import settings
except ImportError:
    django = None

needs_django = pytest.mark.skipif(django is None, reason="needs Django, a test-only dependency")

if django is not None:
    # `gettext_lazy()` reads the settings when its text is shown. No app needs to be loaded.
    if not settings.configured:
        settings.configure(USE_I18N=False)

    from django.utils.functional import SimpleLazyObject, keep_lazy_text, lazy
    from django.utils.html import escape, format_html, format_html_join
    from django.utils.safestring import mark_safe
    from django.utils.text import capfirst, format_lazy
    from django.utils.translation import gettext_lazy

HITS: List[str] = []

LAZY_MESSAGE = "A Django lazy object"


@pytest.fixture(autouse=True)
def clear_hits() -> None:
    HITS.clear()


class Holder:
    """A context object with a private property that no expression may read."""

    @property
    def _trigger(self) -> str:
        HITS.append("private property read")
        return "PRIVATE-MARKER"


class HtmlHolder(Holder):
    """A `Holder` that `format_html` keeps as it is, because its `__html__` returns itself."""

    def __html__(self) -> "HtmlHolder":
        return self


def run(source: str, context: Dict[str, Any], **hooks: Any) -> Any:
    return safe_eval(source, **hooks)(context)


def assert_refused(source: str, context: Dict[str, Any], match: str = LAZY_MESSAGE, **hooks: Any) -> None:
    with pytest.raises(SecurityError, match=match):
        run(source, context, **hooks)
    assert HITS == []


# A weak proxy does not keep its object alive, so the lazy objects behind the proxies are kept
# here for the whole session.
KEEP_ALIVE: List[Any] = []


def weak_proxy_of_lazy(text: str) -> Any:
    target = gettext_lazy(text)
    KEEP_ALIVE.append(target)
    return weakref.proxy(target)


# Each factory builds, from the text, a lazy object whose real value is that text.
LAZY_FACTORIES: Dict[str, Callable[[str], Any]] = {
    "gettext_lazy": lambda text: gettext_lazy(text),
    "format_lazy": lambda text: format_lazy("{}", text),
    "lazy_str": lambda text: lazy(lambda: text, str)(),
    "mark_safe_of_lazy": lambda text: mark_safe(gettext_lazy(text)),
    "simple_lazy_object": lambda text: SimpleLazyObject(lambda: gettext_lazy(text)),
    "weak_proxy": weak_proxy_of_lazy,
}


# ---------------------------------------------------------------------------
# Reading an attribute of a lazy object
# ---------------------------------------------------------------------------


@needs_django
class TestLazyObjectAttributes:
    @pytest.mark.parametrize("factory", LAZY_FACTORIES.values(), ids=LAZY_FACTORIES.keys())
    @pytest.mark.parametrize(
        "source",
        [
            "text.format(obj)",
            "text.format",
            "[obj].sort(key=text.format)",
            "sorted([obj], key=text.format)",
            "[{'x': obj}].sort(key=text.format_map)",
        ],
    )
    def test_format_is_refused(self, factory: Callable[[str], Any], source: str) -> None:
        # `format_map` looks names up in its mapping, so its text names the key `x` instead of
        # position 0.
        text = "{0._trigger}" if "format_map" not in source else "{x._trigger}"
        assert_refused(source, {"text": factory(text), "obj": Holder(), "sorted": sorted})

    @pytest.mark.parametrize("source", ["text.upper()", "text.split", "text.join(['a'])"])
    def test_every_method_is_refused(self, source: str) -> None:
        # Every method of a lazy object passes the call on, and `lazy()` can give it the
        # methods of any class, so no method name is safe.
        assert_refused(source, {"text": gettext_lazy("abc")})

    def test_message_says_what_to_do(self) -> None:
        with pytest.raises(SecurityError, match=r"f\"\{text\}\"\.upper\(\)"):
            run("text.upper()", {"text": gettext_lazy("abc")})

    def test_lazy_class_attribute_is_refused(self) -> None:
        text = gettext_lazy("{0._trigger}")
        assert_refused("cls.format(text, obj)", {"cls": type(text), "text": text, "obj": Holder()})

    def test_permissive_attribute_hook_does_not_skip_the_check(self) -> None:
        assert_refused(
            "text.format(obj)",
            {"text": gettext_lazy("{0._trigger}"), "obj": Holder()},
            validate_attribute=lambda obj, attr: True,
        )

    def test_string_key_is_refused_and_index_is_allowed(self) -> None:
        # Subscripts share the attribute check for string keys. A string key adds no way to run
        # `format`, but refusing it keeps one rule for lazy objects, and a lazy string has no
        # string keys anyway.
        # An index is not a name, so it is allowed.
        text = gettext_lazy("abc")
        assert_refused("text['upper']", {"text": text}, match="key 'upper' on object")
        assert run("text[0]", {"text": text}) == "a"


# ---------------------------------------------------------------------------
# Lazy methods and classes that the app passes in
# ---------------------------------------------------------------------------


def _app_callables() -> Dict[str, Callable[[], Any]]:
    # Built inside a function, because the values need Django.
    return {
        "bound_method": lambda: gettext_lazy("{0._trigger}").format,
        "partial_of_bound_method": lambda: functools.partial(gettext_lazy("{0._trigger}").format),
        "simple_lazy_object_method": lambda: SimpleLazyObject(lambda: gettext_lazy("{0._trigger}")).format,
    }


APP_CALLABLE_IDS = ["bound_method", "partial_of_bound_method", "simple_lazy_object_method"]


@needs_django
class TestLazyMethodsPassedIn:
    @pytest.mark.parametrize("name", APP_CALLABLE_IDS)
    def test_called(self, name: str) -> None:
        assert_refused("fn(obj)", {"fn": _app_callables()[name](), "obj": Holder()})

    @pytest.mark.parametrize("name", APP_CALLABLE_IDS)
    def test_as_sort_key(self, name: str) -> None:
        assert_refused("[obj].sort(key=fn)", {"fn": _app_callables()[name](), "obj": Holder()})

    @pytest.mark.parametrize("name", APP_CALLABLE_IDS)
    def test_with_permissive_callable_hook(self, name: str) -> None:
        assert_refused(
            "[obj].sort(key=fn)",
            {"fn": _app_callables()[name](), "obj": Holder()},
            validate_callable=lambda func: True,
        )

    def test_method_taken_from_the_class(self) -> None:
        # Not bound to any lazy object, but takes one as its first argument.
        text = gettext_lazy("{0._trigger}")
        context = {"fn": type(text).format, "text": text, "obj": Holder()}
        assert_refused("fn(text, obj)", context)
        assert_refused("[text].sort(key=fn)", context)

    def test_other_method_taken_from_the_class(self) -> None:
        text = gettext_lazy("{0._trigger}")
        assert_refused("fn(text)", {"fn": type(text).upper, "text": text})

    def test_lazy_class(self) -> None:
        # Calling the class of a `format_lazy()` result builds one with the expression's text.
        cls = type(format_lazy("{}", "x"))
        context = {"cls": cls, "str": str, "obj": Holder()}
        assert_refused("str(cls(('{0._trigger}', obj), {}))", context)
        assert_refused("[str(x) for x in map(cls, [('{0._trigger}', obj)], [{}])]", {**context, "map": map})

    def test_method_found_without_django_in_sys_modules(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The check of the function that `lazy()` puts on the class reads only its code, so it
        # holds even after the module has left `sys.modules`.
        text = gettext_lazy("{0._trigger}")
        monkeypatch.delitem(sys.modules, "django.utils.functional")
        context = {"fn": text.format, "copy": type(text).format, "text": text, "obj": Holder()}
        assert_refused("[obj].sort(key=fn)", context)
        assert_refused("copy(text, obj)", context)


# Wrappers that the app builds with Django's `lazy()` and `keep_lazy()` around a function
# that follows the paths in its text. Each takes the text and the object.
def _lazy_wrappers() -> Dict[str, Callable[[], Any]]:
    return {
        "lazy_of_str_format": lambda: lazy(str.format, str),
        "lazy_of_format_html": lambda: lazy(format_html, str),
        "keep_lazy_text_of_str_format": lambda: keep_lazy_text(str.format),
        "keep_lazy_text_of_format_html": lambda: keep_lazy_text(format_html),
        "private_format_lazy": lambda: importlib.import_module("django.utils.text")._format_lazy,
    }


LAZY_WRAPPER_IDS = [
    "lazy_of_str_format",
    "lazy_of_format_html",
    "keep_lazy_text_of_str_format",
    "keep_lazy_text_of_format_html",
    "private_format_lazy",
]


@needs_django
class TestLazyWrappersPassedIn:
    @pytest.mark.parametrize("name", LAZY_WRAPPER_IDS)
    def test_called(self, name: str) -> None:
        context = {"fn": _lazy_wrappers()[name](), "obj": HtmlHolder(), "str": str}
        assert_refused("str(fn('{0._trigger}', obj))", context, match="unsafe")

    @pytest.mark.parametrize("name", LAZY_WRAPPER_IDS)
    def test_passed_to_a_call(self, name: str) -> None:
        context = {"fn": _lazy_wrappers()[name](), "obj": HtmlHolder(), "str": str, "map": map}
        assert_refused("[str(x) for x in map(fn, ['{0._trigger}'], [obj])]", context, match="unsafe")

    def test_wrapper_around_a_plain_function_works(self) -> None:
        # `gettext_lazy` and `keep_lazy` filters such as `escape` wrap functions that are safe.
        context = {"translate": gettext_lazy, "escape": escape, "str": str}
        assert run("str(translate('abc'))", context) == "abc"
        assert run("escape(translate('<b>'))", context) == "&lt;b&gt;"


# ---------------------------------------------------------------------------
# Django's formatting functions
# ---------------------------------------------------------------------------


@needs_django
class TestDjangoFormatters:
    @pytest.mark.parametrize(
        ("name", "source"),
        [
            ("format_lazy", "str(fn('{0._trigger}', obj))"),
            ("format_html", "fn('{0._trigger}', obj)"),
            ("format_html_join", "fn('', '{0._trigger}', [[obj]])"),
        ],
    )
    def test_called(self, name: str, source: str) -> None:
        functions = {"format_lazy": format_lazy, "format_html": format_html, "format_html_join": format_html_join}
        # `format_html` keeps an object whose `__html__` returns itself, so the path in the
        # text reaches `HtmlHolder._trigger`.
        context = {"fn": functions[name], "obj": HtmlHolder(), "str": str}
        assert_refused(source, context, match="follows the attribute paths")
        assert_refused(
            source.replace("fn(", "wrapped(", 1),
            {**context, "wrapped": functools.partial(functions[name])},
            match="follows the attribute paths",
        )

    def test_passed_to_a_call(self) -> None:
        assert_refused(
            "list(map(fn, ['{0._trigger}'], [obj]))",
            {"fn": format_html, "obj": HtmlHolder(), "map": map, "list": list},
            match="follows the attribute paths",
        )


# ---------------------------------------------------------------------------
# Ordinary use keeps working
# ---------------------------------------------------------------------------


@needs_django
class TestOrdinaryUse:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("text", "abc"),
            ("f'{text}!'", "abc!"),
            ("f'{text!r}'", "'abc'"),
            ("f'{text!s:>5}'", "  abc"),
            ("f'{text}'.upper()", "ABC"),
            ("text == 'abc'", True),
            ("text + 'x'", "abcx"),
            ("'%s!' % text", "abc!"),
            ("str(text)", "abc"),
            ("len(text)", 3),
            ("'b' in text", True),
            ("[text][0]", "abc"),
            ("(lambda t: f'{t}')(text)", "abc"),
            ("sorted([text, 'aaa'])", ["aaa", "abc"]),
            ("sorted([text, 'aaa'], key=str)", ["aaa", "abc"]),
            ("escape(text)", "abc"),
            ("capfirst(text)", "Abc"),
            ("mark_safe(text)", "abc"),
        ],
    )
    def test_works(self, source: str, expected: Any) -> None:
        context = {
            "text": gettext_lazy("abc"),
            "str": str,
            "len": len,
            "sorted": sorted,
            "escape": escape,
            "capfirst": capfirst,
            "mark_safe": mark_safe,
        }
        result = run(source, context)
        # A lazy result compares equal to its text.
        assert result == expected

    def test_plain_string_methods_still_work(self) -> None:
        assert run("text.upper()", {"text": "abc"}) == "ABC"


# ---------------------------------------------------------------------------
# No Django import
# ---------------------------------------------------------------------------


def test_sandbox_does_not_import_django() -> None:
    # Run in a fresh interpreter, because this test session may have loaded Django already.
    code = (
        "import sys\n"
        "from djc_core.safe_eval import safe_eval\n"
        "assert safe_eval('text.upper()')({'text': 'abc'}) == 'ABC'\n"
        "assert safe_eval('fn(text)')({'fn': len, 'text': 'abc'}) == 3\n"
        "print(sorted(name for name in sys.modules if name.split('.')[0] == 'django'))\n"
    )
    # `-I` keeps the current directory off `sys.path`, so the installed package is the one imported.
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "[]"
