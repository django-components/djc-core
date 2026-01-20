# Release notes

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
