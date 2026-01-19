use crate::tag_parser::TagParser;

pub mod ast;
pub mod error;
pub mod grammar;
pub mod parser_config;
pub mod parser_context;
pub mod tag_compiler;
pub mod tag_parser;
pub mod utils {
    pub mod pest;
    pub mod text;
}

// Re-export the types that users need
pub use crate::ast::{
    Comment, EndTag, ForLoopTag, GenericTag, Tag, TagAttr, TagMeta, TagValue, TagValueFilter,
    TemplateVersion, Token, ValueChild, ValueKind,
};
pub use crate::error::{CompileError, ParseError};
pub use crate::parser_config::{ParserConfig, TagConfig, TagSectionSpec, TagSpec, TagWithBodySpec};
pub use crate::parser_context::ParserContext;
pub use crate::tag_compiler::{compile_tag_attrs, compile_value};

/// Parse a template tag string into a Tag AST
pub fn parse_tag(
    input: &str,
    // Parser config containing information about tags (flags, sections, etc.)
    // If None, a default config is used (no flags, no sections)
    config: Option<&ParserConfig>,
) -> Result<Tag, ParseError> {
    let (tag, _context) = match config {
        Some(c) => TagParser::parse_tag(input, c)?,
        None => {
            let default_config = ParserConfig::new(TemplateVersion::V1);
            TagParser::parse_tag(input, &default_config)?
        }
    };
    Ok(tag)
}
