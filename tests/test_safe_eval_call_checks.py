"""
How `safe_eval()` checks a call: the called object, its keyword names, and the error it prints.

The callable check follows what Python's call machinery does with the called object: the
function inside a `functools.partial`, the function of a bound method, the function that a
`__call__` method belongs to, and the `__call__` that Python finds on an object's class. A
refused function stays refused behind any of them. Keyword names that start with `_` are
refused, because such a name reaches a parameter the function keeps for itself.
"""

import functools
import re
import types
from typing import Any, Callable, Dict

import pytest

from djc_core.safe_eval import SecurityError, safe_eval
from djc_core.safe_eval.sandbox import MAX_CALL_STEPS, is_safe_callable, unsafe

MARKER = "CALL-MARKER"


class Holder:
    """A context object whose public attribute a refused formatter could read out."""

    secret = MARKER


def run(source: str, context: Dict[str, Any], **hooks: Any) -> Any:
    return safe_eval(source, **hooks)(context)


def allow_all(*_args: Any) -> bool:
    return True


ALL_HOOKS = {
    "validate_variable": allow_all,
    "validate_attribute": allow_all,
    "validate_subscript": allow_all,
    "validate_callable": allow_all,
    "validate_assign": allow_all,
}


# ---------------------------------------------------------------------------
# Errors print once
# ---------------------------------------------------------------------------


class TestErrorPrintsOnce:
    """A hook wraps the default check, and both used to add the prefix and the excerpt."""

    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    @pytest.mark.parametrize(
        ("source", "context", "error", "expected"),
        [
            (
                "f(1)",
                {"f": lambda x: x + "s"},
                TypeError,
                "Error in call: TypeError: unsupported operand type(s) for +: 'int' and 'str'\n\n"
                "     1 | f(1)\n"
                "         ^^^^",
            ),
            (
                "1 + eval('1')",
                {"eval": eval},
                SecurityError,
                "Error in call: SecurityError: function '<built-in function eval>' is unsafe\n\n"
                "     1 | 1 + eval('1')\n"
                "             ^^^^^^^^^",
            ),
            (
                "obj.missing",
                {"obj": Holder()},
                AttributeError,
                "Error in attribute: AttributeError: 'Holder' object has no attribute 'missing'\n\n"
                "     1 | obj.missing\n"
                "         ^^^^^^^^^^^",
            ),
            (
                "data['nope']",
                {"data": {}},
                KeyError,
                "Error in subscript: KeyError: 'nope'\n\n"
                "     1 | data['nope']\n"
                "         ^^^^^^^^^^^^",
            ),
        ],
        ids=["call", "refused-call", "attribute", "subscript"],
    )
    def test_error_has_one_prefix_and_one_excerpt(
        self, hooks: Dict[str, Any], source: str, context: Dict[str, Any], error: type, expected: str
    ) -> None:
        with pytest.raises(error) as excinfo:
            run(source, context, **hooks)
        message = excinfo.value.args[0]
        assert message == expected
        assert message.count("Error in") == 1

    def test_hook_refusal_prints_once(self) -> None:
        with pytest.raises(SecurityError) as excinfo:
            run("f(1)", {"f": len}, validate_callable=lambda f: False)
        message = excinfo.value.args[0]
        assert message.count("Error in") == 1
        assert message.count("     1 | f(1)") == 1

    def test_error_inside_lambda_points_at_its_own_place(self) -> None:
        # The lambda runs inside the call that calls it. The innermost helper names the
        # exact place, so the call around it adds nothing.
        with pytest.raises(AttributeError) as excinfo:
            run("(lambda y: y.nope)(1)", {})
        assert excinfo.value.args[0] == (
            "Error in attribute: AttributeError: 'int' object has no attribute 'nope'\n\n"
            "     1 | (lambda y: y.nope)(1)\n"
            "                    ^^^^^^"
        )


# ---------------------------------------------------------------------------
# Keyword names
# ---------------------------------------------------------------------------


def forwarding_upper(text: str, *args: Any, __method_name: str = "upper", **kwargs: Any) -> Any:
    """Stands in for a Django lazy string method, whose keyword picks the method that runs."""
    return getattr(text, __method_name)(*args, **kwargs)


def record_kwargs(**kwargs: Any) -> Dict[str, Any]:
    return kwargs


class TestKeywordNames:
    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    @pytest.mark.parametrize(
        ("source", "name"),
        [
            ("up('{0.secret}', obj, __method_name='format')", "__method_name"),
            ("up('{0.secret}', obj, **choice)", "__method_name"),
            ("f(_x=1)", "_x"),
            ("f(**{'_x': 1})", "_x"),
            ("f(a=1, **{'_': 2})", "_"),
        ],
        ids=["written", "from-mapping", "single-underscore", "mapping-literal", "bare-underscore"],
    )
    def test_keyword_starting_with_underscore_is_refused(self, hooks: Dict[str, Any], source: str, name: str) -> None:
        called = []

        def f(**kwargs: Any) -> None:
            called.append(kwargs)

        context = {"up": forwarding_upper, "obj": Holder(), "choice": {"__method_name": "format"}, "f": f}
        with pytest.raises(
            SecurityError,
            match=re.escape(f"keyword argument '{name}' is unsafe. Keyword names that start with '_' are not allowed."),
        ) as excinfo:
            run(source, context, **hooks)
        assert MARKER not in excinfo.value.args[0]
        assert called == []

    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    def test_keywords_named_like_the_helper_arguments_reach_the_function(self, hooks: Dict[str, Any]) -> None:
        # The helper takes its own arguments by position only, so these names are free.
        result = run("f(func=1, context=2, source=3, token=4)", {"f": record_kwargs}, **hooks)
        assert result == {"func": 1, "context": 2, "source": 3, "token": 4}

    def test_plain_keywords_and_mappings_still_work(self) -> None:
        assert run("up('abc')", {"up": forwarding_upper}) == "ABC"
        assert run("f(a=1, **d)", {"f": record_kwargs, "d": {"b": 2}}) == {"a": 1, "b": 2}

    def test_lambda_parameter_with_underscore_still_works_by_position(self) -> None:
        assert run("(lambda _x: _x + 1)(1)", {}) == 2


# ---------------------------------------------------------------------------
# Objects that pass the call on
# ---------------------------------------------------------------------------


class StaticGetattrCall:
    __call__ = staticmethod(getattr)


class BuiltinGetattrCall:
    # A built-in function does not bind, so calling an instance calls `getattr(obj, name)`.
    __call__ = getattr


class PartialMethodCall:
    __call__ = functools.partialmethod(getattr)


class PropertyCall:
    @property
    def __call__(self) -> Callable[..., Any]:
        return getattr


class MarkedCall:
    @unsafe
    def __call__(self) -> str:
        return MARKER


class InheritedCall(StaticGetattrCall):
    pass


class HidingMeta(type):
    """Shows a harmless `__call__` to `type(obj).__call__`; Python calls the class `__dict__` one."""

    def __getattribute__(cls, name: str) -> Any:
        if name == "__call__":
            return len
        return super().__getattribute__(name)


class HiddenCall(metaclass=HidingMeta):
    __call__ = staticmethod(getattr)


class PlainCall:
    def __call__(self, value: Any) -> Any:
        return value


REFUSED_CALLABLES = {
    "str.format.__call__": str.format.__call__,
    "bound-format.__call__": "{0.secret}".format.__call__,
    "getattr.__call__": getattr.__call__,
    "eval.__call__.__call__": eval.__call__.__call__,
    "partial.__call__": functools.partial(getattr).__call__,
    "method-of-partial": types.MethodType(functools.partial(getattr), Holder()),
    "method-of-method": types.MethodType(types.MethodType(getattr, Holder()), Holder()),
    "staticmethod-call": StaticGetattrCall(),
    "builtin-call": BuiltinGetattrCall(),
    "partialmethod-call": PartialMethodCall(),
    "property-call": PropertyCall(),
    "unsafe-call": MarkedCall(),
    "inherited-call": InheritedCall(),
    "metaclass-hidden-call": HiddenCall(),
}


class TestCallTargets:
    @pytest.mark.parametrize("func", REFUSED_CALLABLES.values(), ids=REFUSED_CALLABLES.keys())
    def test_refused_behind_another_object(self, func: Any) -> None:
        assert is_safe_callable(func)[0] is False

    def test_format_through_call_is_refused_with_its_message(self) -> None:
        assert is_safe_callable(str.format.__call__) == (False, "Use f-strings instead.")
        with pytest.raises(SecurityError, match="Use f-strings instead") as excinfo:
            run("f('{0.secret}', obj)", {"f": str.format.__call__, "obj": Holder()})
        assert MARKER not in excinfo.value.args[0]

    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    def test_callable_instance_with_refused_class_call_is_refused(self, hooks: Dict[str, Any]) -> None:
        with pytest.raises(SecurityError):
            run("f(obj, 'secret')", {"f": StaticGetattrCall(), "obj": Holder()}, **hooks)

    @pytest.mark.parametrize(
        "func",
        [
            len,
            len.__call__,
            PlainCall(),
            PlainCall().__call__,
            Holder,
            "x".upper,
            functools.partial(len),
            types.MethodType(len, Holder()),
        ],
        ids=["builtin", "builtin.__call__", "instance", "bound-call", "class", "bound-builtin", "partial", "method"],
    )
    def test_ordinary_callables_pass(self, func: Any) -> None:
        assert is_safe_callable(func) == (True, None)

    def test_chain_up_to_the_limit_passes_and_longer_is_refused(self) -> None:
        def chain(length: int) -> Any:
            func: Any = len
            for _ in range(length):
                func = types.MethodType(func, Holder())
            return func

        assert is_safe_callable(chain(MAX_CALL_STEPS)) == (True, None)
        is_safe, message = is_safe_callable(chain(MAX_CALL_STEPS + 1))
        assert is_safe is False
        assert message is not None
        assert str(MAX_CALL_STEPS) in message

    def test_object_that_passes_the_call_to_itself_ends_the_check(self) -> None:
        class SelfCall:
            @property
            def __call__(self) -> Any:
                return self

        assert is_safe_callable(SelfCall()) == (True, None)


# ---------------------------------------------------------------------------
# Objects that can't be hashed
# ---------------------------------------------------------------------------


class UnhashableCall:
    __hash__ = None  # type: ignore[assignment]

    def __call__(self) -> str:
        return "called"


class UnhashableGetattrCall:
    __hash__ = None  # type: ignore[assignment]
    __call__ = staticmethod(getattr)


class TestUnhashableCallables:
    """No listed function is unhashable, so such an object is called after the other checks."""

    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    def test_unhashable_callable_is_called(self, hooks: Dict[str, Any]) -> None:
        assert is_safe_callable(UnhashableCall()) == (True, None)
        assert run("f()", {"f": UnhashableCall()}, **hooks) == "called"

    def test_bound_method_of_unhashable_callable_is_called(self) -> None:
        func = types.MethodType(UnhashableCall(), Holder())
        assert is_safe_callable(func) == (True, None)

    @pytest.mark.parametrize("hooks", [{}, ALL_HOOKS], ids=["no-hooks", "all-hooks"])
    def test_unhashable_callable_with_refused_class_call_is_refused(self, hooks: Dict[str, Any]) -> None:
        assert is_safe_callable(UnhashableGetattrCall())[0] is False
        with pytest.raises(SecurityError):
            run("f(obj, 'secret')", {"f": UnhashableGetattrCall(), "obj": Holder()}, **hooks)
