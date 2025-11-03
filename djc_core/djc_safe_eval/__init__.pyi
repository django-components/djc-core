# ruff: noqa
from typing import Any, Callable, Dict, Optional, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

class SecurityError(Exception):
    """An error raised when a security violation occurs."""


def safe_eval(
    source: str,
    *,
    validate_variable: Optional[Callable[[str], bool]] = None,
    validate_attribute: Optional[Callable[[Any, str], bool]] = None,
    validate_subscript: Optional[Callable[[Any, Any], bool]] = None,
    validate_callable: Optional[Callable[[Callable], bool]] = None,
    validate_assign: Optional[Callable[[str, Any], bool]] = None,
) -> Callable[[Dict[str, Any]], Any]:
    """
    Compile a Python expression string into a safe evaluation function.

    This function takes a Python expression string and transforms it into safe code
    by wrapping potentially unsafe operations (like variable access, function calls,
    attribute access, etc.) with sandboxed function calls.

    This is the re-implementation of Jinja's sandboxed evaluation logic.

    Args:
        source: The Python expression string to transform.
        validate_variable: Optional extra validation for variable lookups.
        validate_attribute: Optional extra validation for attribute access.
        validate_subscript: Optional extra validation for subscript access.
        validate_callable: Optional extra validation for function calls.
        validate_assign: Optional extra validation for variable assignments.

    Returns:
        A compiled function that takes a context dictionary and evaluates the expression.
        The function signature is: `func(context: Dict[str, Any]) -> Any`

        The returned function may raise SecurityError if the expression is unsafe.

    Raises:
        SyntaxError: If the input is not valid Python syntax or contains forbidden constructs.

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


__all__ = [
    "safe_eval",
    "SecurityError",
    "unsafe",
]
