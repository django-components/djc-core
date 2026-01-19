pub mod py_html_transformer;
pub mod py_safe_eval;
pub mod py_template_parser;

use pyo3::prelude::*;

use djc_template_parser::{
    Comment, EndTag, ForLoopTag, GenericTag, ParserConfig, Tag, TagAttr, TagConfig, TagMeta,
    TagSectionSpec, TagSpec, TagValue, TagValueFilter, TagWithBodySpec, TemplateVersion, Token,
    ValueChild, ValueKind,
};

use crate::py_html_transformer::set_html_attributes;
use crate::py_safe_eval::safe_eval;
use crate::py_template_parser::{compile_tag_attrs, compile_value, parse_tag};

/// Singular Python API that brings togther all the other Rust crates.
/// Each crate is exposed as a submodule.
#[pymodule]
fn djc_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // HTML transformer
    let html_transformer = PyModule::new(m.py(), "html_transformer")?;
    m.add_submodule(&html_transformer)?;
    html_transformer.add_function(wrap_pyfunction!(set_html_attributes, &html_transformer)?)?;

    // Safe eval
    let safe_eval_module = PyModule::new(m.py(), "safe_eval")?;
    m.add_submodule(&safe_eval_module)?;
    safe_eval_module.add_function(wrap_pyfunction!(safe_eval, &safe_eval_module)?)?;

    // Template parser
    let template_parser = PyModule::new(m.py(), "template_parser")?;
    m.add_submodule(&template_parser)?;
    // Template parser - functions
    template_parser.add_function(wrap_pyfunction!(compile_tag_attrs, &template_parser)?)?;
    template_parser.add_function(wrap_pyfunction!(compile_value, &template_parser)?)?;
    template_parser.add_function(wrap_pyfunction!(parse_tag, &template_parser)?)?;
    // Template parser - AST API
    template_parser.add_class::<Comment>()?;
    template_parser.add_class::<EndTag>()?;
    template_parser.add_class::<ForLoopTag>()?;
    template_parser.add_class::<GenericTag>()?;
    template_parser.add_class::<Tag>()?;
    template_parser.add_class::<TagAttr>()?;
    template_parser.add_class::<TagMeta>()?;
    template_parser.add_class::<TagValue>()?;
    template_parser.add_class::<TagValueFilter>()?;
    template_parser.add_class::<TemplateVersion>()?;
    template_parser.add_class::<Token>()?;
    template_parser.add_class::<ValueChild>()?;
    template_parser.add_class::<ValueKind>()?;
    // Template parser - Config API
    template_parser.add_class::<ParserConfig>()?;
    template_parser.add_class::<TagConfig>()?;
    template_parser.add_class::<TagSectionSpec>()?;
    template_parser.add_class::<TagSpec>()?;
    template_parser.add_class::<TagWithBodySpec>()?;

    Ok(())
}
