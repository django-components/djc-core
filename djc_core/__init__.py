# NOTE:
# By default, maturin auto-generates this file.
#
# However, due to the complexity of the project:
# - having multiple crates
# - Python-side code for some crates (like template parser or safe eval)
# - And splitting the Python API into submodules (html_transformer, template_parser, safe_eval)
#
# Instead, we manually manage the Python-side API for each crate.
#
# ---
#
# The compiled Rust code is accessible as Python module `djc_core.djc_core`.
#
# But for the Python-side public API, each crate has its own directory with `__init__.py`` file.
#
# Thus, to import from any crate, you do e.g.
# ```python
# from djc_core.html_transformer import set_html_attributes
# ```
#
