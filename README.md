# djc-core

[![PyPI - Version](https://img.shields.io/pypi/v/djc-core)](https://pypi.org/project/djc-core/) [![PyPI - Python Version](https://img.shields.io/pypi/pyversions/djc-core)](https://pypi.org/project/djc-core/) [![PyPI - License](https://img.shields.io/pypi/l/djc-core)](https://github.com/django-components/djc-core/blob/master/LICENSE/) [![PyPI - Downloads](https://img.shields.io/pypi/dm/djc-core)](https://pypistats.org/packages/djc-core) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/django-components/djc-core/tests.yml)](https://github.com/django-components/djc-core/actions/workflows/tests.yml)

Rust-based parsers and toolings used by [django-components](https://github.com/django-components/django-components). Exposed as a Python package with [maturin](https://www.maturin.rs/).

## Installation

```sh
pip install djc-core
```

## Packages

### Safe eval

Re-implementation of Jinja2's sandboxed evaluation logic, built in Rust using the Ruff Python parser.

**Usage**

```python
from djc_core.safe_eval import safe_eval

# Compile an expression
compiled = safe_eval("my_var + 1")

# Evaluate with a context
result = compiled({"my_var": 5})
print(result)  # 6
```

**Key Features**

- **Security**: Blocks unsafe operations like `eval()`, `exec()`, accessing private attributes (`_private`), and dangerous builtins
- **Variable tracking**: Reports which variables are used and which are assigned via walrus operator (`:=`)
- **Error reporting**: Provides detailed error messages with underlined source code indicating where errors occurred
- **Performance**: Implemented in Rust for fast parsing and transformation

**Supported Syntax**

Almost all Python expression features are supported:

- Literals, data structures, operators
- Comprehensions, lambdas, conditionals
- F-strings and t-strings
- Function calls, attribute/subscript access
- Walrus operator for assignments

**Security**

By default, `safe_eval` blocks:

- Unsafe builtins (`eval`, `exec`, `open`, etc.)
- Private attributes (starting with `_`)
- Dunder attributes (`__class__`, `__dict__`, etc.)
- Functions decorated with `@unsafe`
- Django methods marked with `alters_data = True`

For more details, examples, and advanced usage, see [`crates/djc-safe-eval/README.md`](crates/djc-safe-eval/README.md).

> **WARNING!** Just like Jinja2 and Django's templating, none of these are 100% bulletproof solutions!
>
> Because they work by blocking known unsafe scenarios. There can always be a new unknown scenario.
>
> If you expose a dangerous function to the template/expression, this can be potentially exploited.
>
> Safer approach would be to allow to call only those functions that have been explicitly tagged as safe.
>
> If you really need to render templates submitted from your users you should instead define the UI blocks yourself, and let your users pick and choose through JSON or similar:
>
> ```json
> {
>   "template": "my_template",
>   "user_id": 123,
>   "blocks": [
>     {"type": "header", "title": "Hello!"},
>     {"type": "paragraph", "text": "This is my blog"},
>     {"type": "table", "data": [[1, 2, 3], [3, 4, 5]]},
>   ]
> }
> ```

### HTML transfomer

Transform HTML in a single pass. This is a simple implementation.

This implementation was found to be 40-50x faster than our Python implementation, taking ~90ms to parse 5 MB of HTML.

**Usage**

```python
from djc_core.html_transformer import set_html_attributes

html = '<div><p>Hello</p></div>'
result, _ = set_html_attributes(
  html,
  # Add attributes to the root elements
  root_attributes=['data-root-id'],
  # Add attributes to all elements
  all_attributes=['data-v-123'],
)
```

To save ourselves from re-parsing the HTML, `set_html_attributes` returns not just the transformed HTML, but also a dictionary as the second item.

This dictionary contains a record of which HTML attributes were written to which elemenents.

To populate this dictionary, you need set `watch_on_attribute` to an attribute name.

Then, during the HTML transformation, we check each element for this attribute. And if the element HAS this attribute, we:

1. Get the value of said attribute
2. Record the attributes that were added to the element, using the value of the watched attribute as the key.

```python
from djc_core.html_transformer import set_html_attributes

html = """
  <div data-watch-id="123">
    <p data-watch-id="456">
      Hello
    </p>
  </div>
"""

result, captured = set_html_attributes(
  html,
  # Add attributes to the root elements
  root_attributes=['data-root-id'],
  # Add attributes to all elements
  all_attributes=['data-djc-tag'],
  # Watch for this attribute on elements
  watch_on_attribute='data-watch-id',
)

print(captured)
# {
#   '123': ['data-root-id', 'data-djc-tag'],
#   '456': ['data-djc-tag'],
# }
```

## Architecture

This project uses a multi-crate Rust workspace structure to maintain clean separation of concerns:

### Crate structure

- **`djc-html-transformer`**: Pure Rust library for HTML transformation
- **`djc-template-parser`**: Pure Rust library for Django template parsing
- **`djc-core`**: Python bindings that combines all other libraries

### Design philosophy

To make sense of the code, the Python API and Rust logic are defined separately:

1. Each crate (AKA Rust package) has `lib.rs` (which is like Python's `__init__.py`). These files do not define the main logic, but only the public API of the crate. So the API that's to be used by other crates.
2. The `djc-core` crate imports other crates
3. And it is only this `djc-core` where we define the Python API using PyO3.

## Development

1. Setup python env

   ```sh
   python -m venv .venv
   ```

2. Install dependencies

   ```sh
   uv sync --group dev
   ```

   The dev requirements also include `maturin` which is used packaging a Rust project
   as Python package.

3. Install Rust

   See https://www.rust-lang.org/tools/install

4. Run Rust tests

   ```sh
   cargo test
   ```

5. Build the Python package

   ```sh
   maturin develop
   ```

   To build the production-optimized package, use `maturin develop --release`.

6. Run Python tests

   ```sh
   pytest
   ```

   > NOTE: When running Python tests, you need to run `maturin develop` first.

## Deployment

Deployment is done automatically via GitHub Actions.

To publish a new version of the package, you need to:

1. Bump the version in `pyproject.toml` and `Cargo.toml`
2. Open a PR and merge it to `main`.
3. Create a new tag on the `main` branch with the new version number (e.g. `1.0.0`), or create a new release in the GitHub UI.

## Creating new crates

### 1. Create Rust-side code

Each new package should be a Rust crate, meaning that other Rust crates should be
able to import from it. Thus, we start by defing a regular Rust package:

1. Define new crate inside `crates`, e.g. `djc-new-package`, and give it `Cargo.toml` (`crates/djc-new-package/Cargo.toml`)
2. Add the new crate to top-level [`Cargo.toml`](./Cargo.toml).
3. If the new crate needs new 3rd party dependencies, add them to the top-level [`Cargo.toml`](./Cargo.toml).

   Then, inside the `djc-new-package/Cargo.toml`, link to those dependencies as `pyo3 = { workspace = true }`.
4. Define the Rust-side public API for this new crate in `lib.rs` (`crates/djc-new-package/src/lib.rs`)
5. Write Rust test for the Rust-side API in `djc-new-package/tests/` directory.
6. Lastly, write package-level README in `djc-new-package/README,md`

### 2. Expose Rust code to Python

Once we know that the code works, expose the Rust code to Python. All Rust crates
are exposed through a single Rust crate, `djc-core`.

Bringing all the crates together minimizes the overhead. A single Rust-to-Python binary
can have ~100 MB, because it contains the Rust binary, and other things. Thus, instead of
having 5x 100 MB binaries, we put them all together to end up with only a single 100 MB binary.

1. Create `py_new_package.rs` file in `crates/djc-core/src`. Put here any code needed to help with
   converting Rust API to Python API (e.g. Rust exceptions to Python exceptions).
2. Define the actual Python API of the new package in `crates/djc-core/src/lib.rs`.

   Create its own Python module for this new crate to avoid name conflicts, e.g.<br/>
   `let new_package = PyModule::new(m.py(), "new_package")?;`

   Then add the symbols (methods, classes, variables) that the module should expose.

When you then run `maturin dev`, a `djc_core` binary file will be created inside
the `djc_core/` Python project.

Your new Rust API will be available in Python as:

```py
from djc_core.djc_core.new_package import some_func

some_func(...)
```

### 3. Define Python-side code

By default, when you create Python bindings for Rust using `maturin` and you don't
define any Python code, `maturin` will generate it for you. What this auto-generated Python code
does is that it re-exports the API that was exposed from Rust to Python, but this time it's re-exported
as Python *package* API.

However, sometimes we need to modify the Python public API from what maturin/PyO3 generated:
- For some functionalities we need the Python runtime, like when calling `exec()` on generated code.
- If a Rust function returns a union, you will want to wrap that function in Python function,
  and unwrap the union.

Because of the cases like these, we take ownership of the Python API, and define/update it manually.

So it's important to remember that the binary that `maturin` creates is NOT a python package itself.
It's only a Python *module*, that you can then re-export as a Python *package*:

```txt
,-----------,
| Rust code |
|___________|
     ||
     \/
,----------------------,
| Compiled Rust binary |
|  (as Python module)  |
|______________________|
     ||
     \/
,----------------,
| Python package |
|________________|
```

The implication is that the final Python package can contain also OTHER code, than just
what was exposed from Rust.

Here is how we handle that for new packages:

1. Extract the virtual module that scopes the Rust-to-Python API of the new package.

   Head over to [`djc_core/rust.py`](./djc_core/rust.py) and add entry for the new package:

   ```py
   from djc_core import djc_core

   template_parser = djc_core.template_parser
   new_package = djc_core.new_package
   ```

   We do this to resolve issue with pytest and how it handles virtual modules.

   We need to do this because `djc_core.new_package` is a virtual module that exists only
   inside the Rust-to-Python binary. It doesn't exist as an actual file called `new_package.py`.

   See [`djc_core/rust.py`](./djc_core/rust.py) for more details.

2. Add typing for the new Rust-to-Python package and all its members in [`djc_core/rust.pyi`](./djc_core/rust.pyi):

   There create a new class with the same name as the submodule of thenew package.

   Inside it, add signatures and docstrings for all the functions/variables that were
   exposed from Rust to Python.

   See [`djc_core/rust.pyi`](./djc_core/rust.pyi) for more details.

   ```py
   class new_package:
      class Comment:
          """Represents a Django template comment `{# ... #}` or `{% comment %}...{% endcomment %}`"""
          def __init__(self, token: template_parser.Token, value: template_parser.Token) -> None: ...
          token: template_parser.Token  # Entire comment span including delimiters
          value: template_parser.Token  # Comment text without delimiters
   ```

3. Define Python-side code for the new package under `djc_core/new_package`.

   If your code needs to call the code exposed from Rust, you can import it from [`djc_core/rust.py`](./djc_core/rust.py).
   
   Imports from `rust.pyi` will be properly typed thanks to `rust.pyi` that we've defined.

   ```py
   from djc_core.rust import new_package

   new_package.some_func(123)
   ```

4. Define the new Python-side API. Add `__init__.py` to `djc_core/new_package`,
   and re-export everything that should be public. See [`template_parser/__init__.py`](./djc_core/template_parser/__init__.py)

   When the `djc_core` package is published, we will use the package-specific API by importing
   from this submodule directly, like so:

   ```py
   from djc_core.new_package import some_func

   some_func(123)
   ```

5. Add Python-side tests for the new Python-side API in `tests/test_new_package.py`.

6. Lastly, update the top-level `README.md`, describing what the new package does.
