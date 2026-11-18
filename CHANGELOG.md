# Release notes

## v1.4.0

### Feat

- Add support for Python 3.15, with wheels for the same platforms as 3.14.
  Free-threaded wheels are for Linux and macOS. On free-threaded Python, importing
  `djc_core` turns the GIL on and Python prints a `RuntimeWarning`.

### Fix

- Tighten the checks `safe_eval()` applies to comprehensions, lambda parameters,
  and string formatting.
- F-string text in `safe_eval()` now reads as in Python: `f'{{a}}'` gives `{a}`,
  `'x' f'{y}'` keeps its `'x'`, and `f'{x=}'` shows `x=` before the value. A lone
  surrogate escape such as `'\ud800'` now means that character, and a t-string
  interpolation's `expression` holds its source text.
- A `safe_eval()` expression nested too deeply now raises `SyntaxError` instead
  of crashing the process.
- `safe_eval()` now raises `SecurityError` for a keyword argument name that
  starts with `_` in a call, written as `f(_x=1)` or passed through
  `f(**mapping)`. Such calls used to run; pass the value under another name.
- `safe_eval()` now also raises `SecurityError` when you call a refused function
  such as `str.format` through another object: its `__call__`, a bound method, a
  `staticmethod`, a `functools.partialmethod`, an `lru_cache()` or `cache()`
  wrapper, a generic alias, or the `__call__` of an object's class. A weak proxy
  of a callable is refused too.
- `safe_eval()` can now call an object that can't be hashed, other than a weak
  proxy. It used to raise `TypeError`.
- A `safe_eval()` error now shows its message and source excerpt once, even when
  you pass a `validate_*` hook or the error happens inside a lambda.
- A keyword argument named `func` in a `safe_eval()` call now reaches the called
  function instead of raising `TypeError`.
- `safe_eval()` now raises `SecurityError` when an expression reads `format` or
  `format_map` on a `str`, a `str` subclass or a `UserString`, even without calling
  it. Use an f-string instead.
- `safe_eval()` now raises `SecurityError` when an expression passes a function it
  may not call, such as a Django model's `delete`, to another function, as in
  `items.sort(key=obj.delete)`. Built-ins such as `list.sort` used to run it. A
  `validate_callable` hook now also receives each function passed as an argument,
  including classes and lambdas.
- `parse_tag()` now raises `SyntaxError` for a tag that nests lists, dicts and
  parentheses more than 64 levels deep, instead of crashing the process at a few
  thousand levels. Brackets inside strings and comments do not count. Tags nested
  65 to between about 1,300 and 3,600 levels, depending on what they nest, used to
  parse and are now refused. A tag with more than 100,000 `(`, `[` and `{`
  characters, counting those inside strings, is refused too.
- A plain tag string can now hold its own quote as `\"` or `\'`, and a tag key can
  end in a backslash.

### Refactor

- Upgrade the Rust dependencies, including PyO3 to 0.30.1 and quick-xml to
  0.42.0. `set_html_attributes()` returns the same HTML as before for ordinary
  pages. A DOCTYPE with an unmatched quote or `[` now raises `ValueError`, and
  a `>` inside a quoted DOCTYPE string no longer ends the DOCTYPE. Some error
  messages are worded differently, including `TypeError` messages for wrong
  argument types.
- Wheels no longer include debug info, so Linux wheels are much smaller.

## v1.3.1

### Fix

- Fix `SyntaxError` when a tag value was a multiline plain string (a quoted
  string that spans multiple lines and contains no `{{ }}` template
  expressions), e.g. an Alpine.js or hyperscript handler:

    ```django
    {% component "small_button"
        _="on click
            set replyForm to closest <form />"
    %}{% endcomponent %}
    ```

    Literal newlines are now escaped when the string is compiled to a Python
    literal, so the value stays a valid single-line literal. Regression from
    v1.3.0. ([#37](https://github.com/django-components/djc-core/pull/37))

## v1.3.0

Drop support for Python 3.8 and 3.9.

### Feat

- Allow multiline quoted strings:

    ```django
    {% component "ListItem"
        attrs:class="
            {{ module_classes }}
            project-nav--item
            w-full mt-0 shadow
        "
    / %}
    ```

## v1.2.2

- Add `get_tag()` method to `ParserConfig` to retrieve tag configurations
- Remove `ParserConfig.tags` attribute (use `get_tag()` instead)

## v1.2.1

- Allow to get allowed flags from `TagConfig`

## v1.2.0

- Added template parsing and compiling with `parse_tag()` and `compile_tag()`

## v1.1.1

- Add pre-built wheels for:
  - Windows - Python 3.8
  - MacOS - Python 3.8, 3.9, 3.10

## v1.1.0

- Renamed package from `djc-core-html-parser` to `djc-core`
- Refactored project into a monorepo

## v1.0.3

- Update to Python 3.14

## v1.0.2

- Add build for Python 3.13 for Windows.

## v1.0.1

- Fix module typing.

## v1.0.0

Initial release.

#### Feat

- Parser can be configured to add attributes to the HTML elements.
- Parser optionally captures what attributes were set on HTML elements
  identified by a specific attribute.
