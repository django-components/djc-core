# DJC safe Python eval

This is a re-implementation of Jinja2's sandboxed evaluation logic, built in Rust using the Ruff Python parser.

It works by:

1. Parsing the Python expression into an AST using `ruff_python_parser`
2. Validating the AST against a set of allowed nodes -> Unsupported syntax raises error.
3. Transforming specific nodes so we can intercept them:
   - Variables → `variable("name")`
   - Function calls → `call(func, *args, **kwargs)`
   - Attributes → `attribute(obj, "attr")`
   - Subscripts → `subscript(obj, key)`
   - Walrus operator → `assign("var", value)`
   - F-strings → `format("...")` calls with transformed arguments
   - T-strings → `template(...)` calls with interpolation objects
4. Re-generating Python code from the modified AST using `ruff_python_codegen`
5. On the Python side we define `call()`, `variable()`, etc.
   - This is the logic that runs when the target expression uses e.g. function calls.
     Here we implement similar safety measures as Jinja.
6. User receives back a function to evaluate the compiled code.


5. **Runtime**: The generated code is evaluated with sandboxed interceptors that enforce security policies


This package is split in 2 parts:

- The Rust code defined here
- Python code defined in [`djc_core/djc_safe_eval`](../../djc_core/djc_safe_eval/)

The expression parsing is done in Rust so that this module can be used directly
by the djc template parser and linter. This module not only sandboxes the Python
expression, but also collects metadata for the linter about:

1. What variables were used in the expression
2. What variables were introduced in the expression using walrus operator `x := 1`

## Usage

### Basic usage

```python
from djc_core import safe_eval

# Compile an expression
compiled = safe_eval("my_var + 1")

# Evaluate with a context
result = compiled({"my_var": 5})
print(result)  # 6
```

### More examples

```python
from djc_core import safe_eval

# Conditionals
compiled = safe_eval(
    "'Login' if not user.authenticated else 'Logout'"
)
result = compiled({"user": anon_user})
print(result)  # "Login"

# Comprehension
compiled = safe_eval(
    "[x * 2 for x in items if x > 0]"
)
result = compiled({"items": [1, 2, -3, 4, 5]})
print(result)  # [2, 4, 8, 10]

# Lambda
compiled = safe_eval(
    "max(users, key=lambda u: u.last_login)"
)
result = compiled({
    "users": [User(), ...],
    "max": max,
})
print(result)  # 2025-11-02T15:54:36Z
```

### Assignments

You can use the walrus operator `x := val` to assign a value to the context object. Assigned variable is then accessible to the rest of the expression:

```py
compiled = safe_eval("(y := x * 2)")
context = {"x": 4}
result = compiled(context)
print(result)  # 8
print(context)  # {"x": 4, "y": 8}
```

### Unsafe operations

Unsafe operations raise `SecurityError`. See all unsafe scenarios in [What is unsafe?](#what-is-unsafe)

```python
# Unsafe functions
compiled = safe_eval("eval('1+1')")
result = compiled({"eval": eval})
# SecurityError: unsafe builtin 'eval'
#
#     1 | eval('1+1')
#         ^^^^^^^^^^^

# Private attributes
compiled = safe_eval("obj._private")
result = compiled({"obj": MyObject()})
# SecurityError: unsafe attribute '_private'
#
#     1 | obj._private
#         ^^^^^^^^^^^^
```

### Mark functions as unsafe

Use the `@unsafe` decorator to mark functions as unsafe in expressions.

This is compatible with Jinja's `@unsafe` decorator.

```py
from djc_core import safe_eval, unsafe

@unsafe
def dump_all_passwords():
    return UserPasswords.objects.all()

compiled = safe_eval("evil()")
result = compiled({"evil": dump_all_passwords})
# SecurityError: unsafe function 'dump_all_passwords'
#
#     1 | evil()
#         ^^^^^^
```

### Custom validators

`safe_eval` can accept extra validators. These are run **in addition to** the rules defined in [What is unsafe?](#what-is-unsafe)

Return `False` to indicate that the value is NOT safe.

| Function             | Signature                             |
| -------------------- | ------------------------------------- |
| `validate_variable`  | `(var_name: str) -> bool`             |
| `validate_attribute` | `(obj: Any, attr: str) -> bool`       |
| `validate_subscript` | `(obj: Any, key: str) -> bool`        |
| `validate_callable`  | `(obj: Any) -> bool`                  |
| `validate_assign`    | `(var_name: str, value: Any) -> bool` |

```python
from djc_core import safe_eval, SecurityError

# Example 1: Custom variable validator
def validate_var(name: str) -> bool:
    return not name.startswith("secret")

compiled = safe_eval(
    "public_var + secret_var",
    validate_variable=validate_var,
)
result = compiled({
    "public_var": 1,
    "secret_var": 42,
})
# SecurityError: unsafe variable 'secret_var'
#
#     1 | public_var + secret_var
#                      ^^^^^^^^^^

# Example 2: Custom attribute validator
allowed = {"name", "value", "items"}
def validate_attr(obj: Any, attr: str) -> bool:
    return attr in allowed

compiled = safe_eval(
    "f'Owner: {obj.owner}'",
    validate_attribute=validate_attr
)
result = compiled({"obj": MyObject()})
# SecurityError: unsafe attribute 'owner'
#
#     1 | f'Owner: {obj.owner}'
#                   ^^^^^^^^^
```

### Error reporting

When an expression raises an error, the error message includes the position in the expression where the error happened:

```python
from djc_core import safe_eval

compiled = safe_eval("my_var + undefined_var")
result = compiled({"my_var": 5})
# NameError: name 'undefined_var' is not defined
#
#     1 | my_var + undefined_var
#                  ^^^^^^^^^^^^^
```

### What is unsafe?

Here's a list of all unsafe scenarios that will trigger `SecurityError`:

- **Unsafe builtins**: `eval`, `exec`, `compile`, `open`, `input`, etc., even if passed under different names.
- **Private attributes**: Starting with `_`
- **Dunder attributes**: Internal Python attributes like `__class__`, `__dict__`, `mro`, etc.
- **Unsafe methods**:
  - Functions decorated with `@unsafe`
  - Django methods marked with `alters_data = True`
  - `str.format` and `str.format_map` (use f-strings instead)
- **Internal attributes**: Prevents access to frame, code, and other internal Python object attributes

## Syntax features

_This section describes the features enforced on the compiler (Rust) level._

[Statements](https://docs.python.org/3/library/ast.html#statements) are NOT supported (AKA anything that spans multiple lines and uses identation, like `for`, `match`, `with`, etc).

The entire python code must be a SINGLE [expression](https://docs.python.org/3/library/ast.html#expressions). As a rule of thumb, anything that can be assigned to a variable is an expression. So even, `a and b` or `c + d` are both still just a single expression.

For simplicity we don't allow async features like async comprehensions.

### Supported syntax

Almost anything that is a valid Python expression is allowed:

- **Literals**: strings, numbers (integers, floats, scientific notation), bytes, booleans, `None`, `Ellipsis`
- **Data structures**: lists, tuples, sets, dictionaries
- **String formatting**: f-strings (`f"Hello {name}"`), t-strings (template strings), `%` formatting
- **Operators**:
  - Unary: `+`, `-`, `not`, `~`
  - Binary: `+`, `-`, `*`, `/`, `%`, `**`, `//`, `<<`, `>>`, `&`, `^`, `|`
  - Comparison: `<`, `<=`, `>`, `>=`, `==`, `!=`, `in`, `not in`, `is`, `is not`
  - Boolean: `and`, `or`
- **Comprehensions**: list (`[...]`), set (`{...}`), dict (`{k: v ...}`), generator (`(...)`)
  - Note: Async comprehensions are **not** allowed
- **Conditional expressions**: ternary operator (`x if condition else y`)
- **Variables**: `obj` with security checks
- **Function calls**: with positional, keyword, `*args`, and `**kwargs` arguments
- **Spread operators**: `*args`, `**kwargs` in function calls
- **Attribute access**: `obj.attr` with security checks
- **Subscript access**: `obj[key]` and slice notation `obj[start:end:step]`
- **Lambda functions**: anonymous functions with proper parameter scoping
- **Walrus operator**: `(x := value)` for inline assignments

### Unsupported syntax

- **Statements**: assignments (`=`), augmented assignments (`+=`, `-=`), `del`, `import`, class/function definitions, `return`, `yield`, etc.
- **Async/Await**: async comprehensions, `await` expressions
- **Control Flow**: `if`/`elif`/`else` statements, `for`, `while`, `break`, `continue`, `try`/`except`/`finally`, `with`
- **Builtins**: No built-in functions are available by default (pass them as variables if needed)
- **Type annotations:** `x: int`
- **Class and functions:** `def fn()` or `class Cls`
- **Function-only keywords:** return, yield, global, nonlocal

### Variable scoping

The transformer correctly handles Python's scoping rules:

- **Comprehensions**: Variables introduced in comprehensions are local to the comprehension (e.g., `x` in `[x for x in items]`)
- **Lambda parameters**: Lambda parameters are local to the lambda and not transformed
- **Walrus operator**:
  - In comprehensions: Walrus assignments remain available OUTSIDE of comprehensions
  - In lambdas: Walrus assignments are NOT available outside

## Performance

Python expressions with `safe_eval` are 5-8x slower than if the expression was called outside of the template:

```py
fn = safe_eval("a + b * c")
fn({"a": 1, "b": 2, "c": 3})

# vs

fn = lambda ctx: ctx["a"] + ctx["b"] * ctx["c"]
fn({"a": 1, "b": 2, "c": 3})
```

This is the tradeoff for all the security checks that we do, as we have to check safety of each attribute or variable access, or function call.

I tried to see what would happen if I cached the results, and got about 30-50% improvement. LLM estimated that at 10,000 entries, the cache could take up ~3-5 MB. This would be relevant only to large projects, say with 500 templates, each having total of 20 tags or expressions (`{% ...%}`, `{{ }}`).

- For comparison, my last work project had about ~100 templates, and that was a mid-sized app that I worked on for ~1.5 years.

However, I removed this caching from this final PR. In django-components I think that it will be more meaningful to cache on the level of entire tags and expressions (`{% ...%}`, `{{ }}`), which will make the caching in `safe_eval` less relevant.

Once the Python expressions are fully integrated in django-components, and we find that these Python expressions take up non-neglibible time, we could introduce the caching.

## Development

### Dependencies

This crate depends on several internal crates from the `ruff` project, included as a git submodule:

- [`ruff_python_parser`](https://github.com/astral-sh/ruff/crates/ruff_python_parser) - Python parser
- [`ruff_python_ast`](https://github.com/astral-sh/ruff/crates/ruff_python_ast) - AST types
- [`ruff_python_codegen`](https://github.com/astral-sh/ruff/crates/ruff_python_codegen) - Code generation
- [`ruff_source_file`](https://github.com/astral-sh/ruff/crates/ruff_source_file) - Source file handling
- [`ruff_text_size`](https://github.com/astral-sh/ruff/crates/ruff_text_size) - Text size utilities

These crates are essential for parsing Python code into an AST and manipulating it.

However, there's an issue with using these as upstream dependencies:

1. These crates are not available on [crates.io](https://crates.io/). Their `Cargo.toml` files are marked with `publish = false`.

2. `cargo` allows to specify dependencies as git links ([see docs](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories)). However, I (Juro) wasn't able to get it working.

   - It seems that `cargo` may be ignoring nested crates if there is `Cargo.toml` at the root. And `ruff`'s codebase does have a root `Cargo.toml`. So we're unable to target the internal crates like `ruff_python_ast`.

So as a workaround solution, we use a **Git submodule** to have access to the `ruff` source code directly in our project.

The `ruff` repository is included as a submodule in `crates/djc-safe-eval/submodules/ruff`. Our `Cargo.toml` uses `path` dependencies to refer to the crates within this submodule.

### Initial setup

When you first clone this repository, the submodule directory will be empty. You must initialize it:

```bash
git submodule update --init --recursive
```

### Updating the Ruff dependency

The version of `ruff` is locked to a specific commit or tag, documented in `.gitmodules`. To update:

1. Navigate into the submodule directory:

   ```bash
   cd crates/djc-safe-eval/submodules/ruff
   ```

2. Fetch the latest tags:

   ```bash
   git fetch origin --tags
   ```

3. Check out the new tag (e.g., `0.15.0`):

   ```bash
   git checkout 0.15.0
   ```

4. Navigate back and commit the change:
   ```bash
   cd ../../..
   git add .gitmodules crates/djc-safe-eval/submodules/ruff
   git commit -m "Update Ruff submodule to 0.15.0"
   ```

5. To keep track of the current version, update the comment in the `.gitmodules` file.
