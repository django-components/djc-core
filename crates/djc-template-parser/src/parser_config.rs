//! Parser config for template / tag parsing

use std::collections::{HashMap, HashSet};

use crate::ast::TemplateVersion;
use pyo3::prelude::*;

/// Basic metadata for a tag, e.g. `{% if %}`
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct TagSpec {
    /// The tag name
    #[pyo3(get, set)]
    pub tag_name: String,
    /// Flags that this tag can accept
    #[pyo3(get, set)]
    pub flags: HashSet<String>,
}

#[pymethods]
impl TagSpec {
    #[new]
    fn new(tag_name: String, flags: HashSet<String>) -> Self {
        Self { tag_name, flags }
    }
}

/// Metadata for a tag section
///
/// Represents a sub-tag that splits the parent's tag body into multiple sections.
/// For example, `{% elif %}` and `{% else %}` are sections for the `{% if %}` tag.
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct TagSectionSpec {
    /// The tag specification (name and flags)
    #[pyo3(get, set)]
    pub tag: TagSpec,
    /// Whether this tag can appear multiple times (true) or only once (false)
    ///
    /// For example, `{% elif %}` is repeatable (can appear multiple times),
    /// while `{% else %}` is not repeatable (can appear only once).
    #[pyo3(get, set)]
    pub repeatable: bool,
}

#[pymethods]
impl TagSectionSpec {
    #[new]
    fn new(tag: TagSpec, repeatable: bool) -> Self {
        Self { tag, repeatable }
    }
}

/// Metadata for a tag with body (and optionally extra sections).
///
/// For example, `{% if %}` can contain `{% elif %}` and `{% else %}` sections.
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub struct TagWithBodySpec {
    /// The parent tag specification (name and flags)
    ///
    /// For example, for `{% if %}`, this would be the "if" tag with its flags.
    #[pyo3(get, set)]
    pub tag: TagSpec,
    /// Sections of related tags that can appear within this tag's body
    ///
    /// For example, for `{% if %}`, the section might contain:
    /// - `{% elif %}` (0..many)
    /// - `{% else %}` (0..1)
    ///
    /// Tag names in sections must be globally unique across all tags and sections.
    #[pyo3(get, set)]
    pub sections: Vec<TagSectionSpec>,
}

#[pymethods]
impl TagWithBodySpec {
    #[new]
    fn new(tag: TagSpec, sections: Vec<TagSectionSpec>) -> Self {
        Self { tag, sections }
    }
}

/// Config for a tag - This sets how the parser will parse the tag.
///
/// This is a union type that differentiates between:
/// - Tags without bodies (just a single tag, e.g., `{% lorem %}`)
/// - Tags with bodies that can contain sections (e.g., `{% if %}` with `{% elif %}` and `{% else %}`)
///
/// Tags with bodies must either:
/// - Have a self-closing mark `/` in their start tag (e.g., `{% component "table" / %}`)
/// - Wait for their closing end tag (e.g., `{% endif %}`)
///
/// End tags always follow the pattern `{% end<tag> %}`
#[pyclass]
#[derive(Debug, Clone, PartialEq)]
pub enum TagConfig {
    /// Tag without a body (just a single tag)
    PlainTag(TagSpec),
    /// Tag with a body that can contain sections
    TagWithBody(TagWithBodySpec),
}

impl TagConfig {
    pub fn tag_name(&self) -> &str {
        match self {
            TagConfig::PlainTag(tag_spec) => &tag_spec.tag_name,
            TagConfig::TagWithBody(tag_with_body_spec) => &tag_with_body_spec.tag.tag_name,
        }
    }
}

#[pymethods]
impl TagConfig {
    #[new]
    fn new(tag: TagSpec, sections: Option<Vec<TagSectionSpec>>) -> Self {
        match sections {
            Some(sections) => Self::TagWithBody(TagWithBodySpec { tag, sections }),
            None => Self::PlainTag(tag),
        }
    }

    pub fn get_flags(&self) -> &HashSet<String> {
        match self {
            TagConfig::PlainTag(tag) => &tag.flags,
            TagConfig::TagWithBody(tag_with_body) => &tag_with_body.tag.flags,
        }
    }
}

/// Parser config
///
/// This struct holds info on how the parser will parse the template / tags.
/// It can be constructed from Python or Rust.
#[pyclass]
#[derive(Debug, Clone)]
pub struct ParserConfig {
    pub tags: HashMap<String, TagConfig>,
    pub version: TemplateVersion,
}

#[pymethods]
impl ParserConfig {
    /// Create a new ParserConfig
    #[new]
    pub fn new(version: TemplateVersion) -> Self {
        Self {
            tags: HashMap::new(),
            version,
        }
    }

    /// Set config for a tag
    pub fn set_tag(&mut self, tag_config: TagConfig) {
        let tag_name = tag_config.tag_name().to_string();
        self.tags.insert(tag_name, tag_config);
    }

    /// Get config for a tag
    pub fn get_tag(&self, tag_name: &str) -> Option<TagConfig> {
        self.tags.get(tag_name).cloned()
    }
}

impl ParserConfig {
    /// Build a flags map from parser config
    ///
    /// For easier lookup, internally we construct a map of tag_name -> flags.
    ///
    /// It includes:
    /// - Flags for the main tags
    /// - Flags for all sections (tag names in sections must be globally unique)
    ///
    /// Returns an error if any tag name in a section conflicts with an existing tag name
    /// or with another section's tag name.
    pub fn build_flags_map(&self) -> Result<HashMap<String, HashSet<String>>, String> {
        let mut flags_map = HashMap::new();

        // Add flags for all tags and section items
        for (parent_tag_name, tag_config) in &self.tags {
            match tag_config {
                TagConfig::PlainTag(tag_spec) => {
                    // Add flags for the tag itself
                    if !tag_spec.flags.is_empty() {
                        flags_map.insert(tag_spec.tag_name.clone(), tag_spec.flags.clone());
                    }
                }
                TagConfig::TagWithBody(tag_with_sections) => {
                    // Add flags for the parent tag
                    if !tag_with_sections.tag.flags.is_empty() {
                        flags_map.insert(
                            tag_with_sections.tag.tag_name.clone(),
                            tag_with_sections.tag.flags.clone(),
                        );
                    }
                    // Add flags for all section items
                    for section_spec in &tag_with_sections.sections {
                        // Check for conflicts with existing tags
                        if self.tags.contains_key(&section_spec.tag.tag_name) {
                            return Err(format!(
                                "Section tag '{}' in tag '{}' conflicts with existing tag name",
                                section_spec.tag.tag_name, parent_tag_name
                            ));
                        }

                        // Check for conflicts with existing section items
                        if flags_map.contains_key(&section_spec.tag.tag_name) {
                            return Err(format!(
                                "Section tag '{}' in tag '{}' conflicts with another section tag",
                                section_spec.tag.tag_name, parent_tag_name
                            ));
                        }

                        // Add flags for this section item
                        if !section_spec.tag.flags.is_empty() {
                            flags_map.insert(
                                section_spec.tag.tag_name.clone(),
                                section_spec.tag.flags.clone(),
                            );
                        }
                    }
                }
            }
        }

        // Check that "for" is not specified, as it's a reserved special tag
        if self.tags.contains_key("for") {
            return Err("Tag 'for' is reserved and cannot be specified in tag config".to_string());
        }

        Ok(flags_map)
    }
}
