import builtins
from itertools import chain
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Tuple

from djc_core.rust import safe_eval as safe_eval_module
from djc_core.safe_eval.error import error_context, _format_error_with_context
from djc_core.safe_eval.sandbox import (
    is_safe_attribute,
    is_safe_callable,
    is_safe_variable,
    unsafe_attribute_hint,
)


class SecurityError(Exception):
    """An error raised when a security violation occurs."""

    pass


def safe_eval(
    source: str,
    *,
    validate_variable: Optional[Callable[[str], bool]] = None,
    validate_attribute: Optional[Callable[[Any, str], bool]] = None,
    validate_subscript: Optional[Callable[[Any, Any], bool]] = None,
    validate_callable: Optional[Callable[[Callable], bool]] = None,
    validate_assign: Optional[Callable[[str, Any], bool]] = None,
) -> Callable[[Mapping[str, Any]], Any]:
    """
    Compile a Python expression string into a safe evaluation function.

    This function takes a Python expression string and transforms it into safe code
    by wrapping potentially unsafe operations (like variable access, function calls,
    attribute access, etc.) with sandboxed function calls.

    This is the re-implementation of Jinja's sandboxed evaluation logic.

    The expression text must come from the template author. Pass request data in the
    context, as a value.

    Args:
        source: The Python expression string to transform.
        validate_variable: Optional extra validation for variable lookups.
        validate_attribute: Optional extra validation for attribute access.
        validate_subscript: Optional extra validation for subscript access.
        validate_callable: Optional extra validation for function calls.
        validate_assign: Optional extra validation for variable assignments.

    Returns:
        A compiled function that takes a context mapping and evaluates the expression.
        The function signature is: `func(context: Mapping[str, Any]) -> Any`

        The returned function may raise SecurityError if the expression is unsafe.

    Raises:
        SyntaxError: If the input is not valid Python syntax, contains forbidden constructs,
            or nests too deeply (more than about 97 chained operators, or more than 20
            nested calls and brackets in the code it writes, such as 21 nested lists).

    Example:
        >>> compiled = safe_eval("my_var + 1")
        >>> result = compiled({"my_var": 5})
        >>> print(result)
        6

        >>> compiled = safe_eval("lambda x: x + my_var")
        >>> func = compiled({"my_var": 10})
        >>> print(func(5))
        15

        >>> compiled = safe_eval("unsafe_var + 1", validate_variable=lambda name: name != "unsafe_var")
        >>> result = compiled({"unsafe_var": 5})
        SecurityError: variable 'unsafe_var' is unsafe
    """
    # If user specified extra validation functions, wrap the original functions with them
    if validate_variable is not None:

        @error_context("variable")
        def variable_fn(
            __context: Mapping[str, Any],
            __source: str,
            __token: Tuple[int, int],
            var_name: str,
        ) -> Any:
            if not validate_variable(var_name):
                raise SecurityError(f"variable '{var_name}' is unsafe")
            return variable(__context, __source, __token, var_name)
    else:
        variable_fn = variable

    if validate_attribute is not None:

        @error_context("attribute")
        def attribute_fn(
            __context: Mapping[str, Any],
            __source: str,
            __token: Tuple[int, int],
            obj: Any,
            attr_name: str,
        ) -> Any:
            if not validate_attribute(obj, attr_name):
                raise SecurityError(
                    f"attribute '{attr_name}' on object '{type(obj)}' is unsafe"
                )
            return attribute(__context, __source, __token, obj, attr_name)
    else:
        attribute_fn = attribute

    if validate_subscript is not None:

        @error_context("subscript")
        def subscript_fn(
            __context: Mapping[str, Any],
            __source: str,
            __token: Tuple[int, int],
            obj: Any,
            key: Any,
        ) -> Any:
            if not validate_subscript(obj, key):
                raise SecurityError(f"key '{key}' on object '{type(obj)}' is unsafe")
            return subscript(__context, __source, __token, obj, key)
    else:
        subscript_fn = subscript

    if validate_callable is not None:

        @error_context("call")
        def call_fn(
            __context: Mapping[str, Any],
            __source: str,
            __token: Tuple[int, int],
            func: Callable,
            /,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if not validate_callable(func):
                raise SecurityError(f"function '{func!r}' is unsafe")
            # The hook also checks each function passed as an argument, for the same reason
            # `call` does: `items.sort(key=fn)` runs `fn` without asking the hook.
            for value in chain(args, kwargs.values()):
                if callable(value) and not validate_callable(value):
                    raise SecurityError(_passed_function_message(value, func, None))
            return call(__context, __source, __token, func, *args, **kwargs)
    else:
        call_fn = call

    if validate_assign is not None:

        @error_context("assign")
        def assign_fn(
            __context: Mapping[str, Any],
            __source: str,
            __token: Tuple[int, int],
            var_name: str,
            value: Any,
        ) -> Any:
            if not validate_assign(var_name, value):
                raise SecurityError(f"assignment to variable '{var_name}' is unsafe")
            return assign(__context, __source, __token, var_name, value)
    else:
        assign_fn = assign

    # Create evaluation namespace with wrapped functions
    # These are captured in the closure of the function we'll create
    # The names start with `_sx_`, as the Rust transformer writes them (`GENERATED_NAMES` in
    # `djc_safe_eval`). A template can neither read a `_` name nor bind one with this
    # prefix, so no template name can replace a helper.
    eval_namespace = {
        "_sx_variable": variable_fn,
        "_sx_attribute": attribute_fn,
        "_sx_subscript": subscript_fn,
        "_sx_call": call_fn,
        "_sx_assign": assign_fn,
        "_sx_slice": slice,
        "_sx_interpolation": interpolation,
        "_sx_template": template,
        "_sx_format": format,
        # Pass through the source string. This way we won't have to re-define
        # the functions on each evaluation.
        "_sx_source": source,
        # Without this entry, `exec()` adds the real builtins to the namespace, and a plain
        # name the transformer let through would reach them. The generated code needs no
        # builtin, so an empty mapping is a second layer behind the Rust check. PyPy
        # ignores it.
        "__builtins__": _NO_BUILTINS,
    }

    # Get transformed code from Rust
    transformed_code = safe_eval_module.safe_eval(source)

    # Wrap the transformed code in a function that captures the helper functions
    # This avoids the overhead of calling eval() and creating a dict on each evaluation
    # NOTE: The function is defined with `exec()` instead of `eval()`
    #       to support triple-quoted multi-line strings (which `eval()` doesn't handle).
    #       We wrap with parentheses and newlines to allow multi-line expressions and trailing comments:
    #       the newlines ensure that trailing comments don't swallow the closing parenthesis.
    # Callers pass the mapping as `context`, by position or by keyword. The generated code reads
    # it as `_sx_context`, so the public parameter is moved there and deleted: a template name
    # `context` then never refers to the real mapping.
    lambda_code = f"def _eval_expr(context):\n    _sx_context = context\n    del context\n    return (\n{transformed_code}\n)"

    return _exec_func_with_error_handling(lambda_code, "_eval_expr", source, "expression", eval_namespace)


# A read-only empty mapping used as `__builtins__` while the generated code runs. On CPython
# it hides every builtin; PyPy ignores it. Because it is read-only, an expression cannot
# change it for the next one, and it can be shared without a per-call copy.
_NO_BUILTINS: Mapping[str, Any] = MappingProxyType({})


# NOTE: This is used also in djc_template_parser.
def _exec_func_with_error_handling(func_string: str, func_name: str, source: str, kind: str, global_scope: Mapping[str, Any]) -> Callable[..., Any]:
    local_scope = {}

    # The `func_string` code should create a function and assign it to the local_scope[func_name] variable.
    # We do so to avoid the overhead of calling `exec()` on each evaluation.
    try:
        exec(func_string, global_scope, local_scope)
    except Exception as e:
        # If the error hasn't been processed by `error_context` decorator,
        # include the whole expression in the error message (without the "Error in..." prefix)
        if not getattr(e, "_error_processed", False):
            _format_error_with_context(
                e, source, 0, len(source), kind, add_prefix=False
            )
            # Mark it as processed to avoid double-formatting if re-raised
            e._error_processed = True  # type: ignore[attr-defined]
        raise
    else:
        # Get the function from the local scope
        compiled_func = local_scope[func_name]

    # Return a function that calls the compiled function
    # We return this wrapper function so that we can intercept errors and add context to the error message.
    def evaluate(*args, **kwargs) -> Any:
        """Evaluate the compiled function with the given arguments."""
        try:
            return compiled_func(*args, **kwargs)
        except Exception as e:
            # If the error hasn't been processed by `error_context` decorator,
            # include the whole source code in the error message (without the "Error in..." prefix)
            if not getattr(e, "_error_processed", False):
                _format_error_with_context(
                    e, source, 0, len(source), kind, add_prefix=False
                )
                # Mark it as processed to avoid double-formatting if re-raised
                e._error_processed = True  # type: ignore[attr-defined]
            raise

    evaluate._source_code = func_string
    return evaluate


# Following are the operations that we intercept. These functions are called by the transformed code.
#
# E.g.
# ```python
# my_var
# obj := {"attr": 2}
# ```
#
# is transformed into:
# ```python
# _sx_variable(_sx_context, _sx_source, (0, 6), "my_var")
# _sx_assign(_sx_context, _sx_source, (0, 18), "obj", {"attr": 2})
# ```
#
# Each interceptor function receives the same 3 first positional arguments:
# - __context: Mapping[str, Any] - The evaluation context
# - __source: str - The source code
# - __token: Tuple[int, int] - The token tuple (start_index, end_index)
#
# The __source and __token arguments are used by `@error_context` decorator to add the position
# where the error occurred to the error message.
# E.g.
# ```
# obj := eval("unsafe code")
#        ^^^^^^^^^^^^^^^^^^^
# SecurityError: <built-in function eval> is unsafe
# ```


@error_context("variable")
def variable(
    __context: Mapping[str, Any], __source: str, __token: Tuple[int, int], var_name: str
) -> Any:
    """Look up a variable in the evaluation context, e.g. `my_var`"""
    if not is_safe_variable(var_name):
        raise SecurityError(f"variable '{var_name}' is unsafe")
    return __context[var_name]


@error_context("attribute")
def attribute(
    __context: Mapping[str, Any],
    __source: str,
    __token: Tuple[int, int],
    obj: Any,
    attr_name: str,
) -> Any:
    """Access an attribute of an object, e.g. `obj.attr`"""
    if not is_safe_attribute(obj, attr_name):
        error_msg = f"attribute '{attr_name}' on object '{type(obj)}' is unsafe"
        # Name the replacement for the formatting methods and lazy objects, as a refused
        # call does.
        hint = unsafe_attribute_hint(obj, attr_name)
        if hint:
            error_msg += f". {hint}"
        raise SecurityError(error_msg)
    return getattr(obj, attr_name)


@error_context("subscript")
def subscript(
    __context: Mapping[str, Any],
    __source: str,
    __token: Tuple[int, int],
    obj: Any,
    key: Any,
) -> Any:
    """Access a key of an object, e.g. `obj[key]`"""
    # NOTE: Right now subscript uses the same logic as attribute
    if not is_safe_attribute(obj, key):
        raise SecurityError(f"key '{key}' on object '{type(obj)}' is unsafe")
    return obj[key]


# NOTE: The helper's own arguments are positional-only (`/`), so that a keyword such as
#       `func=` never fills one of the helper's own arguments.
@error_context("call")
def call(
    __context: Mapping[str, Any],
    __source: str,
    __token: Tuple[int, int],
    func: Callable,
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Call a function, e.g. `func(arg1, arg2, ...)`"""
    is_safe, replacement_message = is_safe_callable(func)
    if not is_safe:
        error_msg = f"function '{func!r}' is unsafe"
        if replacement_message:
            error_msg += f". {replacement_message}"
        raise SecurityError(error_msg)
    # A keyword that starts with `_` reaches a parameter the function keeps for itself. On
    # Django 5.0 and later, each method of a lazy string takes `__method_name`, which picks
    # the method that runs, so `text.upper(__method_name="format")` would run the refused
    # `format`. `name=` and `**mapping` both arrive here, so one check covers both.
    if kwargs:
        # A key from a `**mapping` can be a `str` subclass whose own `startswith` or `__eq__`
        # lies about its text, and Python may bind it to a parameter by `__eq__`. Plain copies
        # of the keys are checked and passed on, so the check and the call see the same names.
        if any(type(name) is not str for name in kwargs):
            plain_kwargs = {str.__str__(name): value for name, value in kwargs.items()}
            # Two keys with the same text would collapse into one. Python refuses that.
            if len(plain_kwargs) != len(kwargs):
                raise TypeError("got multiple values for the same keyword argument")
            kwargs = plain_kwargs
        for name in kwargs:
            if name.startswith("_"):
                raise SecurityError(
                    f"keyword argument {name!r} is unsafe. Keyword names that start with '_' are not "
                    "allowed; pass the value under another name."
                )
    # A function given to the call may be called by it, and a built-in such as `list.sort`,
    # `sorted` or `map` does that without coming back through this helper. So a function
    # that the expression may not call is refused here, when the expression hands it over.
    # The arguments are the final ones, after `*args` and `**mapping` are unpacked. A
    # function inside a list, tuple or dict argument is not looked for: that would cost
    # time in proportion to the container on every call, and the docs tell apps not to
    # pass the helpers, such as `map`, that call functions found that way (for example
    # `map(map, ...)`).
    for value in chain(args, kwargs.values()):
        # `callable()` reads only the type, so a value that can't be called adds only this
        # one cheap test.
        if callable(value):
            is_safe, replacement_message = is_safe_callable(value)
            if not is_safe:
                raise SecurityError(_passed_function_message(value, func, replacement_message))
    return func(*args, **kwargs)


def _passed_function_message(value: Any, func: Any, replacement_message: Optional[str]) -> str:
    """Return the refusal message for a refused function passed as an argument of `func`."""
    message = (
        f"function '{value!r}' is unsafe, so it can't be passed to '{func!r}', "
        "which could call it"
    )
    return f"{message}. {replacement_message}" if replacement_message else message


@error_context("assign")
def assign(
    __context: Mapping[str, Any],
    __source: str,
    __token: Tuple[int, int],
    var_name: str,
    value: Any,
) -> Any:
    """Assign a value to a variable in the evaluation context, e.g. `(x := 5)`"""
    if not is_safe_variable(var_name):
        raise SecurityError(f"variable '{var_name}' is unsafe")
    __context[var_name] = value
    return value


# NOTE: We don't need to validate the slice arguments as they are always safe.
#       Slice had to be redefined from bracket syntax `obj[lower:upper:step]` to function call syntax
#       `slice(lower, upper, step)` because we convert brackets to function calls `subscript(obj, key)`.
#       But since we had to intercept it, this function ensures we show the correct position in the error message.
@error_context("slice")
def slice(
    __context: Mapping[str, Any],
    __source: str,
    __token: Tuple[int, int],
    lower: Any = None,
    upper: Any = None,
    step: Any = None,
) -> builtins.slice:
    """Create a slice object, e.g. `obj[lower:upper:step]`"""
    return builtins.slice(lower, upper, step)


# For compatiblity with Python 3.14+:
# - on 3.14+, t-strings are created as normal
# - on >=3.13, using t-strings raises an error
# See: https://docs.python.org/3.14/library/string.templatelib.html#template-strings
@error_context("interpolation")
def interpolation(
    __context: Mapping[str, Any],
    __source: str,
    __token: Tuple[int, int],
    value: Any,
    expression: str,
    conversion: Optional[str],
    format_spec: str,
) -> Any:
    """Process t-string interpolation."""
    try:
        from string.templatelib import Interpolation  # type: ignore[import-untyped]
    except ImportError:
        raise NotImplementedError("t-string interpolation is not supported")
    return Interpolation(value, expression, conversion, format_spec)


@error_context("template")
def template(
    __context: Mapping[str, Any], __source: str, __token: Tuple[int, int], *parts: Any
) -> Any:
    """Construct a template from parts."""
    try:
        from string.templatelib import Template  # type: ignore[import-untyped]
    except ImportError:
        raise NotImplementedError("t-string template construction is not supported")
    return Template(*parts)


@error_context("format")
def format(
    __context: Mapping[str, Any],
    __source: str,
    __token: Tuple[int, int],
    template_string: str,
    *args: Any,
) -> str:
    """
    Format a template string with arguments.

    Each argument is a tuple (value, conversion_flag, format_spec) where:
    - value: The expression value to format
    - conversion_flag: "r", "s", "a", or None
    - format_spec: A string for static specs, or a tuple (template, *args) for dynamic specs

    This wraps the built-in str.format() method so that errors inside f-strings get nice
    error reporting with underlining via the `@error_context` decorator.

    `template_string` and a dynamic spec's template come from the Rust transformer, which
    doubles every literal brace, so their only fields are bare `{}` placeholders. No field
    can follow an attribute path, which would run outside the sandbox's checks.
    """
    processed_args = []
    for value, conversion_flag, format_spec in args:
        # Apply conversion flag if present
        if conversion_flag == "r":
            value = repr(value)
        elif conversion_flag == "s":
            value = str(value)
        elif conversion_flag == "a":
            value = ascii(value)
        # If None, keep value as-is

        # Apply format spec if present (non-empty string or tuple)
        if format_spec:
            if isinstance(format_spec, tuple):
                # Dynamic format spec: (template, *args)
                spec_template, *spec_args = format_spec
                # Format the spec template with its args
                format_spec_str = spec_template.format(*spec_args)
            else:
                # Static format spec: already a string
                format_spec_str = format_spec

            # Only apply format spec if it's non-empty
            if format_spec_str:
                value = builtins.format(value, format_spec_str)

        processed_args.append(value)

    return template_string.format(*processed_args)
