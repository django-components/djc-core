"""
A sandbox layer that refuses unsafe names and calls in a Python expression.

Based on the Jinja v3.1.6 sandbox implementation.
See https://github.com/pallets/jinja/blob/5ef70112a1ff19c05324ff889dd30405b1002044/src/jinja2/sandbox.py

What the sandbox does
---------------------
It checks every variable, attribute, item, and call that the expression text writes.
It refuses:

- Names that start with `_`: variables read from the context, attributes (so no
  `obj.__class__`), string item keys (`data["_key"]`), and keyword argument names in a
  call, written as `f(_x=1)` or passed through `f(**mapping)`. A lambda parameter or
  comprehension variable may start with `_`, because it holds only what the expression
  gave it.
- Calls to functions that are dangerous by themselves, such as `eval`, `getattr`, and `open`.
  The check compares the function, not its name, so a function passed in under another
  name is refused too. So is one of these objects when it passes the call on to one of them:
  a `functools.partial`, a `staticmethod`, a `functools.lru_cache()` wrapper, a
  `types.GenericAlias`, a bound method, a function's `__call__`, or an object whose class
  `__call__` is one of them. A weak proxy of a callable is refused, because it hides what it
  calls.
- Text formatting that follows paths written inside the string. Reading `format` or
  `format_map` on a `str`, a `str` subclass such as `markupsafe.Markup`, or a
  `collections.UserString`, or any method of a `string.Formatter`, is refused, and so is
  building an `operator.attrgetter` or `operator.methodcaller`. Use f-strings instead.
- Every attribute of a Django lazy object, such as a lazy string from `gettext_lazy()`, and
  calling a method taken from one. Each method of a lazy object passes the call on to the
  real value, so any of them can run `format`. Show the lazy string as it is, or turn it
  into plain text with an f-string first, such as `f"{text}".upper()`. Django's
  `format_lazy`, `format_html` and `format_html_join` are refused like `str.format`, and
  so is a Django `lazy()` or `keep_lazy()` wrapper around a refused function.
- Functions marked with `@unsafe` or `alters_data = True`.
- Passing a function that the expression may not call as an argument of a call, such as
  `items.sort(key=obj.delete)`. A built-in like `list.sort` or `sorted` calls the function
  it is given without these checks, so the check runs when the expression hands it over.
  Only a function given directly as an argument is checked; a function inside a list,
  tuple or dict argument is not.

What the sandbox does not promise
---------------------------------
It is a second layer of protection. It does not make a template from a stranger safe to run.

- It does not limit the objects you pass in. Every attribute and method of a context
  object whose name does not start with `_` can be read and called, so what such an
  object can reach or do is available to the expression. A secret in a public attribute
  is readable, and a public method that deletes data can be called. Mark such a method
  with `@unsafe`, or leave the object out of the context.
- It checks only the lookups and calls that the expression text writes, and the functions
  that a call receives directly as arguments. A function that you pass in and that looks up
  names from text, or calls functions it finds inside a list or another object, does so
  without these checks. Examples are `map` and `functools.reduce` (`map` can be given
  itself as the function to call, as in `map(map, [f], [[x]])`), `itertools.starmap`,
  `operator.call`, `type` with three arguments (it builds a class from a dict of
  functions), a `getattr`-style helper, `inspect`, `importlib`, and `logging.Formatter`
  with `{` style. Do not pass such helpers in.
- It hides an item key that starts with `_` only when the expression writes the lookup
  itself. `data["_key"]` is refused, but `data.get("_key")`, iterating over `data`, and
  `"%(_key)s" % data` read the same item.
- It does not limit time or memory. `9 ** 9 ** 9` and `"x" * 10**10` run until the process
  runs out of resources.
- The expression text must come from the template author. Request data belongs in the
  context, as a value.

The generated code names its own helpers and arguments with the `_sx_` prefix
(`_sx_variable`, `_sx_context`, and so on). The Rust transformer turns every name the
expression does not bind itself into an `_sx_variable()` lookup, which refuses names that
start with `_`. That includes a name in a comprehension's first iterable, which Python reads
before the loop variable exists. The transformer also raises `SyntaxError` for a lambda
parameter or comprehension variable that starts with `_sx_`, so no template name can replace
a check. On CPython, the evaluation namespace holds an empty `__builtins__`, so a plain name
never reaches a Python builtin.

We do NOT support:
- Builtins. If you need to use `len()`, `str()`, `int()`, `list()`, `dict()`, etc.,
  you'll have to pass them as variables.
- "safe" range. Jinja puts limit on the number of items a range may produce.
  We don't expose `range()` function to the sandboxed code at all.
- "Immutable" sandbox (e.g. raising when mutating a list).
- Async functions, coroutines, etc.
- The string formatting methods above. Jinja runs them through a sandboxed formatter;
  we refuse them. Use f-strings instead, which the transformer rewrites so that every
  lookup inside is checked. The rewrite builds a `str.format` template with each literal
  brace doubled, so text in an f-string or its format spec stays text and cannot add a
  field that reads an attribute.

We add these safety features not present in Jinja:
- Prevent users from calling unsafe builtins like `eval` even if they were passed as variables.

To mark custom functions as unsafe, use the `@unsafe` decorator.

Example:
```python
@unsafe
def delete(self):
    pass
```
"""

import builtins
import functools
import operator
import string
import sys
import types
import weakref
from collections import UserString
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

#: Unsafe function attributes.
UNSAFE_FUNCTION_ATTRIBUTES: Set[str] = set()

#: Unsafe method attributes. Function attributes are unsafe for methods too.
UNSAFE_METHOD_ATTRIBUTES: Set[str] = set()

#: unsafe generator attributes.
UNSAFE_GENERATOR_ATTRIBUTES = {"gi_frame", "gi_code"}

#: unsafe attributes on coroutines
UNSAFE_COROUTINE_ATTRIBUTES = {"cr_frame", "cr_code"}

#: unsafe attributes on async generators
UNSAFE_ASYNC_GENERATOR_ATTRIBUTES = {"ag_code", "ag_frame"}

# Builtin functions that users have no business calling in sandboxed code.
# We check for these as it may happen that these functons were passed as variables,
# and the user may try to call them.
# Dictionary mapping unsafe functions to replacement messages.
_UNSAFE_BUILTIN_FUNCTION_NAMES = {
    "__build_class__": None,
    "__import__": None,
    "__lazy_import__": None,
    "__loader__": None,
    "aiter": None,
    "anext": None,
    "breakpoint": None,
    "classmethod": None,
    "compile": None,
    "delattr": None,
    "eval": None,
    "exec": None,
    "exit": None,
    "getattr": None,
    "globals": None,
    "help": None,
    "input": None,
    "locals": None,
    "memoryview": None,
    "open": None,
    "property": None,
    "quit": None,
    "setattr": None,
    "staticmethod": None,
    "super": None,
    "vars": None,
}
UNSAFE_BUILTIN_FUNCTIONS: Dict[Any, Optional[str]] = {
    getattr(builtins, attr): replacement
    for attr, replacement in _UNSAFE_BUILTIN_FUNCTION_NAMES.items()
    if hasattr(builtins, attr)
}

# `format` and `format_map` read the attribute and item paths written inside the string,
# e.g. `"a{0.b.__builtins__[__import__]}b".format({"b": 42})`, and they look each field up
# with the real `getattr`, so the checks in this module never see the lookup. Every string
# type that has such methods is refused, not only `str`: `str` subclasses may define their
# own (`markupsafe.Markup` does), `collections.UserString` is not a `str` subclass and calls
# the real `str.format`, and `string.Formatter` is the object that does the lookup.
# Reading the method is refused, not only calling it, because a built-in such as `list.sort`
# calls a `key=` function without going through this module.
_FORMAT_MESSAGE = 'Use an f-string instead, such as f"{a} and {b}" in place of "{} and {}".format(a, b).'

#: The methods that format a string by following the paths written inside it.
_FORMAT_METHOD_NAMES = frozenset({"format", "format_map"})

#: The public methods of `string.Formatter`. Each one either follows a path or hands
#: out the pieces a path is built from, so all of them are refused on a formatter.
_FORMATTER_METHOD_NAMES = frozenset(
    name for name in vars(string.Formatter) if not name.startswith("_")
)

# Django's lazy objects, such as the lazy string that `gettext_lazy()` returns, are not
# `str`, so the checks above do not apply to them. Each of their methods passes the call on
# to the real value: `lazy_text.format(obj)` runs `str.format` on the translated text. On
# Django 5.0 and later, every method also takes a keyword argument that picks the real
# method to run. So the sandbox refuses every attribute of a lazy object, and every method
# taken from one.
_LAZY_OBJECT_MESSAGE = (
    "A Django lazy object, such as a lazy string from gettext_lazy(), passes each method call "
    "on to its real value, so any of its methods can run format(). To call a string method, "
    'turn it into plain text with an f-string first, such as f"{text}".upper().'
)

# The module where Django defines `Promise`, `lazy()` and `keep_lazy()`.
_DJANGO_FUNCTIONAL_MODULE = "django.utils.functional"

# Django's functions that format text by following the paths written in it, as `str.format`
# does: each module, the function's name in it, and the name to show in the message.
# `_format_lazy` is the function that `format_lazy` calls when its result is shown. The
# expression can call one of them only if the app passes it in, so they are checked only
# when called or passed to a call, by identity with the function in the loaded module.
_DJANGO_FORMATTERS = (
    ("django.utils.text", "format_lazy", "format_lazy"),
    ("django.utils.text", "_format_lazy", "format_lazy"),
    ("django.utils.html", "format_html", "format_html"),
    ("django.utils.html", "format_html_join", "format_html_join"),
)

#: The modules in `_DJANGO_FORMATTERS`, so that other functions skip the lookups.
_DJANGO_FORMATTER_MODULES = frozenset(module_name for module_name, _, _ in _DJANGO_FORMATTERS)

#: Attribute names that need the extra string-type check in `is_safe_attribute`. Checking
#: this set first keeps the extra `isinstance` calls off the path of every other name.
_FORMATTING_ATTRIBUTE_NAMES = _FORMAT_METHOD_NAMES | _FORMATTER_METHOD_NAMES

# The functions below are what a class lookup returns, such as `UserString.format`. The
# expression can't read them, but the app may pass one in, so they are refused by
# identity when called or passed to a call. A subclass's own override (`Markup.format`)
# is a different function that can't be listed ahead of time, so `is_safe_attribute`
# refuses it by the type of the object it is read from, and `_formatting_method_message`
# refuses a bound one by its owner.
UNSAFE_FUNCTIONS: Dict[Any, Optional[str]] = {
    str.format: _FORMAT_MESSAGE,
    str.format_map: _FORMAT_MESSAGE,
    UserString.format: _FORMAT_MESSAGE,
    UserString.format_map: _FORMAT_MESSAGE,
    **{
        function: _FORMAT_MESSAGE
        for function in vars(string.Formatter).values()
        if isinstance(function, types.FunctionType)
    },
    # These build a function that reads an attribute or calls a method named by a string
    # (`attrgetter("__class__")(obj)`), with the real `getattr`. They are refused when
    # called, so the template author cannot choose the path. A reader that the app built
    # with its own path is a plain callable and keeps working.
    operator.attrgetter: "Read the attribute in the expression instead.",
    operator.methodcaller: "Call the method in the expression instead.",
}


def unsafe(f: F) -> F:
    """
    Marks a function or method as unsafe.

    Example:
    ```python
    @unsafe
    def delete(self):
        pass
    ```
    """
    f.unsafe_callable = True  # type: ignore
    return f


def _is_internal_attribute(obj: Any, attr: str) -> bool:
    """
    Test if the attribute is an internal Python attribute.

    >>> _is_internal_attribute(str, "mro")
    True
    >>> _is_internal_attribute(str, "upper")
    False
    """
    if isinstance(obj, types.FunctionType):
        if attr in UNSAFE_FUNCTION_ATTRIBUTES:
            return True
    elif isinstance(obj, types.MethodType):
        if attr in UNSAFE_FUNCTION_ATTRIBUTES or attr in UNSAFE_METHOD_ATTRIBUTES:
            return True
    elif isinstance(obj, type):
        if attr == "mro":
            return True
    elif isinstance(obj, (types.CodeType, types.TracebackType, types.FrameType)):
        return True
    elif isinstance(obj, types.GeneratorType):
        if attr in UNSAFE_GENERATOR_ATTRIBUTES:
            return True
    elif hasattr(types, "CoroutineType") and isinstance(obj, types.CoroutineType):
        if attr in UNSAFE_COROUTINE_ATTRIBUTES:
            return True
    elif hasattr(types, "AsyncGeneratorType") and isinstance(
        obj, types.AsyncGeneratorType
    ):
        if attr in UNSAFE_ASYNC_GENERATOR_ATTRIBUTES:
            return True
    return attr.startswith("__")


def _is_formatting_member(obj: Any, attr: str) -> bool:
    """
    Test if reading `attr` from `obj` gives a method that formats text by following paths.

    That is `format` or `format_map` on `str`, `collections.UserString` or a subclass of
    either (the object or the class itself), and any method of `string.Formatter` on a
    formatter or a formatter class.

    >>> _is_formatting_member(string.Formatter(), "vformat")
    True
    >>> _is_formatting_member("text", "format")
    True
    >>> _is_formatting_member("text", "upper")
    False
    """
    is_class = isinstance(obj, type)

    def derives_from(kinds: type | tuple[type, ...]) -> bool:
        return issubclass(obj, kinds) if is_class else isinstance(obj, kinds)

    if derives_from(string.Formatter):
        return attr in _FORMATTER_METHOD_NAMES
    # Exact `str` counts too. The call check knows `str.format`, but a built-in that calls
    # a function it is given, such as `[obj].sort(key="{0._x}".format)`, never runs that
    # check, so the bound method must not reach the expression at all.
    return attr in _FORMAT_METHOD_NAMES and derives_from((str, UserString))


def _django_promise_class() -> Optional[type]:
    """Return Django's `Promise` class, the base class of every lazy object, if Django is loaded."""
    # djc-core does not depend on Django and must not import it. Django defines `Promise` in
    # `django.utils.functional`, so no lazy object can exist before that module is imported,
    # and while it stays imported, `sys.modules` holds it. Django itself relies on that one
    # class staying the same (`isinstance(value, Promise)` throughout its code).
    module = sys.modules.get(_DJANGO_FUNCTIONAL_MODULE)
    promise = getattr(module, "Promise", None)
    return promise if isinstance(promise, type) else None


def _is_lazy(obj: Any, promise: type) -> bool:
    """Test if `obj` is an instance of `promise`, or a subclass of it."""
    if isinstance(obj, promise):
        return True
    return isinstance(obj, type) and issubclass(obj, promise)


def _is_django_lazy(obj: Any) -> bool:
    """
    Test if `obj` is a Django lazy object, or the class of one.

    A lazy object is an instance of `django.utils.functional.Promise`: the result of
    `gettext_lazy()`, `format_lazy()`, `reverse_lazy()`, `lazy()` and `keep_lazy()`
    functions such as `mark_safe()` given a lazy string. A `SimpleLazyObject` around one
    counts too, because `isinstance` reads its `__class__`, which is that of the object
    inside. The class counts as well, because its methods take a lazy object as their first
    argument.
    """
    promise = _django_promise_class()
    return promise is not None and _is_lazy(obj, promise)


def _django_callable_refusal(obj: Any) -> Optional[str]:
    """
    Return the refusal message if calling `obj` runs Django code that can format text.

    That is a lazy object or its class, a method bound to either, the function that Django
    puts on the lazy class for each method of the real value, and the functions in
    `_DJANGO_FORMATTERS`. The expression can't read a lazy object's methods, but the app may
    pass one in, as `lazy_text.format`, inside a `functools.partial`, or taken from the
    class (`type(lazy_text).format`), which is bound to no lazy object.
    """
    # A plain function is neither a lazy object nor bound to one, so it only needs the
    # checks that read its code.
    if type(obj) is types.FunctionType:
        return _django_function_refusal(obj)
    promise = _django_promise_class()
    # Without `django.utils.functional` loaded there is no lazy object to find.
    if promise is None:
        return None
    # Calling a lazy class builds a lazy object from the arguments, such as the text and
    # values of `format_lazy()`, which formats that text when it is shown.
    if _is_lazy(obj, promise) or _is_lazy(getattr(obj, "__self__", None), promise):
        return _LAZY_OBJECT_MESSAGE
    return None


def _django_function_refusal(func: types.FunctionType) -> Optional[str]:
    """Return the refusal message if `func` is a lazy object's method or a Django formatter."""
    # The module whose globals the function runs with. Unlike `__module__`, `lazy()` and
    # `functools.wraps` do not change it.
    module_name = func.__globals__.get("__name__")
    if module_name == _DJANGO_FUNCTIONAL_MODULE:
        # The function that `lazy()` puts on the lazy class for each method of the real
        # value is called `__wrapper__` and takes the lazy object as its first argument, in
        # Django 4.2 to 6.1. The function that `lazy()` returns, such as `gettext_lazy`, is
        # also called `__wrapper__` and takes only `*args` and `**kw`; `_call_targets` follows
        # it to the function it wraps. This check reads only the code, so it holds even if
        # `django.utils.functional` has left `sys.modules`.
        code = func.__code__
        if code.co_name == "__wrapper__" and code.co_argcount >= 1:
            return _LAZY_OBJECT_MESSAGE
        return None
    if module_name in _DJANGO_FORMATTER_MODULES:
        for formatter_module, name, shown_name in _DJANGO_FORMATTERS:
            module = sys.modules.get(formatter_module)
            if module is not None and getattr(module, name, None) is func:
                return (
                    f"{shown_name}() follows the attribute paths written in its text. Call "
                    f"{shown_name}() in Python and pass the result in instead."
                )
    return None


def is_safe_attribute(obj: Any, attr: str) -> bool:
    """
    Check if the attribute of an object is safe to access.

    Unsafe attributes are:
    - Starting with an underscore `_`
    - Internal attributes as set by `_is_internal_attribute`.
    - The methods that format text by following paths inside it: `format` and
      `format_map` on `str`, `UserString` and their subclasses, and the methods of a
      `string.Formatter` (see `_is_formatting_member`).
    - Every attribute of a Django lazy object or its class, such as a lazy string from
      `gettext_lazy()` (see `_is_django_lazy`). Every method of a lazy object can run
      `format` on the real value.
    """
    # Non-string subscripts should be fine, as they should be found only
    # as list slices.
    if not isinstance(attr, str):
        return True
    if attr.startswith("_"):
        return False
    # The whole lazy object is refused, not only `format` and `format_map`, because the
    # object hides the type of its real value: `lazy()` gives it the methods of any class,
    # so the sandbox can't tell from a name which method formats text.
    if _is_django_lazy(obj):
        return False
    # The name test comes first so that no other attribute pays for the `isinstance` calls.
    if attr in _FORMATTING_ATTRIBUTE_NAMES and _is_formatting_member(obj, attr):
        return False
    return not _is_internal_attribute(obj, attr)


def unsafe_attribute_hint(obj: Any, attr: str) -> Optional[str]:
    """Return advice to show with a refused attribute of `obj`, or None when there is none."""
    # A name that starts with `_` is refused for its name alone, whatever the object.
    if attr.startswith("_"):
        return None
    if _is_django_lazy(obj):
        return _LAZY_OBJECT_MESSAGE
    return _FORMAT_MESSAGE if attr in _FORMATTING_ATTRIBUTE_NAMES else None


def _formatting_method_message(obj: Any) -> Optional[str]:
    """
    Return the refusal message if `obj` is a bound method that formats text by following paths.

    This looks at the object the method is bound to, not at the function, because a `str`
    subclass defines its own `format` function and each one is a different function.
    """
    owner = getattr(obj, "__self__", None)
    if owner is None:
        return None
    # Every method of a formatter is refused: `vformat`, `get_field` and the rest take
    # part in the same path lookup as `format`.
    if isinstance(owner, string.Formatter):
        return _FORMAT_MESSAGE
    if (
        isinstance(owner, (str, UserString))
        and getattr(obj, "__name__", None) in _FORMAT_METHOD_NAMES
    ):
        return _FORMAT_MESSAGE
    return None


#: How many objects behind the called one `is_safe_callable` follows before it refuses the
#: call. An ordinary callable adds one or two steps: a bound method and its function, a
#: partial and the function inside it, an object and its class `__call__`.
MAX_CALL_STEPS = 32

_CALL_STEPS_MESSAGE = (
    f"It passes the call on through more than {MAX_CALL_STEPS} other objects, too many to check. "
    "Pass the function itself instead."
)

# A weak proxy forwards the call, and every attribute read, to an object that it does not
# expose, so the check can't see what it would call. It can't be hashed but compares equal to
# the object it stands for, so the table lookup would miss a listed function behind it.
_WEAK_PROXY_MESSAGE = "A weak proxy hides the function it calls. Pass the function itself instead."

# `functools.lru_cache()` and `functools.cache()` return this C-level type. It calls the
# function in `__wrapped__` with no code of its own, so the check follows it like a partial.
_LRU_CACHE_WRAPPER_TYPE = type(functools.lru_cache(maxsize=None)(len))

# The slot that holds what a `types.GenericAlias` such as `list[int]` calls.
_GENERIC_ALIAS_ORIGIN = types.GenericAlias.__dict__["__origin__"]


def is_safe_callable(obj: Any) -> Tuple[bool, Optional[str]]:
    """
    Check if an object is safely callable.

    Returns:
        Tuple of (is_safe, replacement_message)
        - is_safe: True if safe to call, False otherwise
        - replacement_message: Optional string suggesting a replacement, None if not applicable

    Unsafe callables are:
    - Decorated with `@unsafe`
    - Marked with `obj.alters_data = True` (Django convention)
    - Unsafe builtins (e.g. `eval`)
    - `format` or `format_map` of any `str` instance, subclasses included, and of
      `collections.UserString` (use f-strings instead)
    - Every method of a `string.Formatter` instance
    - `operator.attrgetter` and `operator.methodcaller`, which would let the template name
      the attribute to read
    - A Django lazy object, its class, and every method taken from one, such as
      `lazy_text.format` (see `_django_callable_refusal`)
    - Django's `format_lazy`, `format_html` and `format_html_join`, which follow the paths
      written in their text as `str.format` does, and a Django `lazy()` or `keep_lazy()`
      wrapper around any refused function
    - One of these objects when it passes the call on to one of the above: a
      `functools.partial` or `functools.partialmethod`, a `staticmethod`, a
      `functools.lru_cache()` wrapper, a `types.GenericAlias` such as `list[int]`, a bound
      method, the `__call__` of a refused function, or an object whose class `__call__` is
      refused
    - A weak proxy (`weakref.proxy()`) of a callable, which hides what it calls
    - Anything that passes the call on through more than `MAX_CALL_STEPS` objects

    The check does not look inside the code of a function you pass in. A function that calls
    a refused function in its own body, such as a `functools.wraps` wrapper, is not refused.
    """
    # Each object is checked, then the objects that calling it would call in turn. `seen` is
    # keyed by `id()` and holds each object, so an object made during the check (a bound
    # `__call__`) can't free its id for another one and be skipped.
    seen: Dict[int, Any] = {}
    pending = [obj]
    while pending:
        step = pending.pop()
        # An object that passes the call back to itself adds nothing new to check.
        if id(step) in seen:
            continue
        seen[id(step)] = step
        # Refuse rather than stop looking, so a long chain can't hide a refused function at
        # its end. `seen` holds `obj` itself as well as the objects behind it.
        if len(seen) > MAX_CALL_STEPS + 1:
            return (False, _CALL_STEPS_MESSAGE)

        refusal = _check_one_callable(step)
        if refusal is not None:
            return refusal
        pending.extend(_call_targets(step))

    return (True, None)


def _check_one_callable(obj: Any) -> Optional[Tuple[bool, Optional[str]]]:
    """Return the refusal for `obj` by itself, or None when nothing about it is refused."""
    # Marks set with `@unsafe` or Django's `alters_data`. A bound method shows the marks of
    # its function, and the function is checked as its own step too.
    if getattr(obj, "unsafe_callable", False) or getattr(obj, "alters_data", False):
        return (False, None)

    if isinstance(obj, weakref.CallableProxyType):
        return (False, _WEAK_PROXY_MESSAGE)

    # Django's lazy objects and formatting functions, found without importing Django.
    django_refusal = _django_callable_refusal(obj)
    if django_refusal is not None:
        return (False, django_refusal)

    # Identity of the listed functions, such as `eval` or `str.format`.
    listed = _listed_refusal(obj)
    if listed is not None:
        return listed

    # Check the type the method is bound to. The identity checks above know `str.format`
    # but not the `format` that a subclass such as `Markup` defines for itself.
    message = _formatting_method_message(obj)
    if message is not None:
        return (False, message)
    return None


def _listed_refusal(obj: Any) -> Optional[Tuple[bool, Optional[str]]]:
    """Return the refusal if `obj` is in `UNSAFE_FUNCTIONS` or `UNSAFE_BUILTIN_FUNCTIONS`."""
    # The tables are dictionaries, so a lookup hashes `obj`, and that raises `TypeError` for
    # an object that can't be hashed, such as an instance of a class that sets `__eq__` but
    # not `__hash__`. Every key in the tables is an object that can be hashed, so such an
    # object is not one of them. It may still pass the call on to one: the check refuses a
    # weak proxy before this lookup, and follows an object's class `__call__` as its own step.
    try:
        hash(obj)
    except TypeError:
        return None
    if obj in UNSAFE_FUNCTIONS:
        return (False, UNSAFE_FUNCTIONS[obj])
    if obj in UNSAFE_BUILTIN_FUNCTIONS:
        return (False, UNSAFE_BUILTIN_FUNCTIONS[obj])
    return None


def _call_targets(obj: Any) -> List[Any]:
    """
    Return the objects that calling `obj` passes the call on to, without code of its own.

    Python's own call machinery does this for a partial, a bound method and an object with a
    class `__call__`. A function's body is not followed.
    """
    targets: List[Any] = []

    # A partial calls its wrapped function with some arguments filled in, so it is as safe
    # as that function. Without this, `partial(getattr, obj)` would be a way to call a
    # refused function under another name.
    if isinstance(obj, functools.partial):
        targets.append(obj.func)
    # A `partialmethod` in a class does the same once bound. For a function that does not
    # bind, such as `getattr`, binding gives a helper whose body calls the function, and
    # the check does not read function bodies, so the wrapped function is checked here.
    if isinstance(obj, functools.partialmethod):
        targets.append(obj.func)
    # Since Python 3.10 a `staticmethod` can be called by itself, and it calls its function.
    if isinstance(obj, staticmethod):
        targets.append(obj.__func__)
    if isinstance(obj, _LRU_CACHE_WRAPPER_TYPE):
        targets.append(obj.__wrapped__)
    # Django's `lazy()` and `keep_lazy()` return a function whose code calls the function it
    # wraps with the same arguments, at once or when the lazy result is shown, and
    # `functools.wraps` stores that function in `__wrapped__`. The check reads no other
    # function's code, but these two are known to only pass the call on, as in
    # `lazy(str.format, str)`.
    if (
        type(obj) is types.FunctionType
        and obj.__code__.co_name in ("__wrapper__", "wrapper")
        and obj.__globals__.get("__name__") == _DJANGO_FUNCTIONAL_MODULE
    ):
        wrapped = getattr(obj, "__wrapped__", None)
        if wrapped is not None:
            targets.append(wrapped)
    # Calling `list[int]` calls `list`. The origin is read through the type's own slot,
    # because a generic alias forwards most attribute reads to its origin.
    if type(obj) is types.GenericAlias:
        targets.append(_GENERIC_ALIAS_ORIGIN.__get__(obj))

    # A bound method calls its function with the object first. A Python method keeps the
    # function in `__func__`.
    if isinstance(obj, types.MethodType):
        targets.append(obj.__func__)
    elif hasattr(obj, "__self__") and hasattr(obj, "__name__") and not hasattr(obj, "__func__"):
        # A built-in bound method, such as `"text".format`, has no `__func__`, but the
        # function it runs is the one its class has under the same name (`str.format`).
        # A built-in function such as `len` is bound to its module, whose class has
        # nothing to find, so it skips the lookup.
        if not isinstance(obj.__self__, types.ModuleType):
            try:
                targets.append(getattr(type(obj.__self__), obj.__name__))
            except (AttributeError, TypeError):
                pass

    # `function.__call__` belongs to `function` and calls it. It is neither of the above:
    # for a built-in function it is a `method-wrapper`, and its class lookup above finds
    # only the generic `__call__` of the function type.
    if getattr(obj, "__name__", None) == "__call__":
        owner = getattr(obj, "__self__", None)
        if owner is not None:
            targets.append(owner)

    # Calling an object runs the `__call__` that Python finds on its class and binds to the
    # object, which may be a refused function, such as `__call__ = staticmethod(getattr)`.
    # A built-in type's own `__call__` is a C-level wrapper (`WrapperDescriptorType`) that
    # runs the type's own call code. The built-in types this check knows to call another
    # object (a partial, a staticmethod, an `lru_cache()` wrapper, a generic alias, a bound
    # method) are followed above. Others, such as a `ctypes` callback, are not.
    class_call = None if type(obj) in _BUILTIN_CALL_TYPES else _find_on_type(obj, "__call__")
    if class_call is not None and not isinstance(class_call, types.WrapperDescriptorType):
        targets.append(class_call)
        # Binding can give another object, as with `staticmethod`, `functools.partialmethod`
        # or a property. A plain function only becomes a bound method of itself, so it is
        # not bound here.
        if not isinstance(class_call, types.FunctionType):
            bind = _find_on_type(class_call, "__get__")
            if bind is not None:
                targets.append(bind(class_call, obj, type(obj)))
    return targets


# Built-in types whose `__call__` is always the C-level one. Their attributes can't be
# changed, so `_call_targets` skips the class lookup for them, which is most calls.
_BUILTIN_CALL_TYPES = frozenset(
    {
        types.FunctionType,
        types.BuiltinFunctionType,
        types.MethodType,
        types.MethodWrapperType,
        types.MethodDescriptorType,
        types.WrapperDescriptorType,
        type,
        functools.partial,
    }
)

# The descriptors that `type` itself uses for `__mro__` and `__dict__`, so that a metaclass
# can't change what `_find_on_type` reads.
_TYPE_MRO = type.__dict__["__mro__"]
_TYPE_DICT = type.__dict__["__dict__"]


def _find_on_type(obj: Any, name: str) -> Any:
    """
    Look `name` up the way Python does when it runs a special method such as `__call__`.

    Python reads the `__dict__` of each class in the method resolution order of `type(obj)`.
    Reading `type(obj).__call__` instead would go through the metaclass and the descriptor,
    which can return a different object.
    """
    for klass in _TYPE_MRO.__get__(type(obj)):
        namespace = _TYPE_DICT.__get__(klass)
        if name in namespace:
            return namespace[name]
    return None


def is_safe_variable(var_name: str) -> bool:
    """
    Check if a variable is safe to access.

    Unsafe variables are:
    - Starting with an underscore `_`
    """
    return not var_name.startswith("_")
