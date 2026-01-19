use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::ast::{Comment, Token};
use crate::error::ParseError;
use crate::grammar::Rule;
use crate::parser_config::ParserConfig;

/// Global context for parsing templates and tags
#[derive(Debug, Clone)]
pub struct ParserContext {
    /// Parser configuration (shared via Rc to avoid cloning in nested contexts)
    pub config: Rc<ParserConfig>,
    /// Map from tag name to a set of valid flags for that tag
    ///
    /// This is built internally from config for efficient flag checking.
    /// Shared via Rc to avoid cloning in nested contexts.
    /// For each template tag name (e.g. `component`, `slot`, etc.),
    /// we can specify a set of valid flags.
    /// For example: `{"component": {"only"}, "slot": {"default"}}`
    /// If a tag is not in the map, it's assumed to have no flags.
    pub flags: Rc<HashMap<String, HashSet<String>>>,
    /// Line offset to add to all line numbers (0-based internally, but reported as 1-based)
    pub line_offset: usize,
    /// Column offset to add to column numbers on the first line only
    pub col_offset: usize,
    /// Index offset to add to start_index and end_index
    pub index_offset: usize,
    /// Comments collected during parsing (mutable interior)
    /// Comments are collected for syntax highlighting / LSP.
    comments: RefCell<Vec<Comment>>,
    /// Variables used by the current tag being parsed (temporary storage)
    current_tag_used_vars: RefCell<Vec<Token>>,
    /// Variables assigned by the current tag being parsed (temporary storage)
    current_tag_assigned_vars: RefCell<Vec<Token>>,
}

impl ParserContext {
    /// Create a new context with no offsets from parser config
    pub fn new(config: &ParserConfig) -> Result<Self, String> {
        let flags = config.build_flags_map()?;
        Ok(Self {
            // TODO - Do not clone config and instead use a reference + lifetime?
            config: Rc::new(config.clone()),
            flags: Rc::new(flags),
            line_offset: 0,
            col_offset: 0,
            index_offset: 0,
            comments: RefCell::new(Vec::new()),
            current_tag_used_vars: RefCell::new(Vec::new()),
            current_tag_assigned_vars: RefCell::new(Vec::new()),
        })
    }

    /// Create a child context with specified offsets, sharing the parent's config
    ///
    /// This is used when creating nested contexts (e.g., for template strings).
    /// The config is shared via Rc, so no cloning occurs.
    pub fn create_child_context(
        parent: &Self,
        line_offset: usize,
        col_offset: usize,
        index_offset: usize,
    ) -> Self {
        Self {
            config: Rc::clone(&parent.config),
            flags: Rc::clone(&parent.flags),
            line_offset,
            col_offset,
            index_offset,
            comments: RefCell::new(Vec::new()),
            current_tag_used_vars: RefCell::new(Vec::new()),
            current_tag_assigned_vars: RefCell::new(Vec::new()),
        }
    }

    /// Add a comment to this context
    fn add_comment(&self, comment: Comment) {
        self.comments.borrow_mut().push(comment);
    }

    /// Append comments from a child context to this context
    pub fn append_comments(&self, child_comments: Vec<Comment>) {
        self.comments.borrow_mut().extend(child_comments);
    }

    /// Take all comments from this context, leaving it empty
    pub fn take_comments(&self) -> Vec<Comment> {
        self.comments.borrow_mut().drain(..).collect()
    }

    /// Helper to create a Comment from a COMMENT rule pair
    fn create_comment(&self, pair: &pest::iterators::Pair<Rule>) -> Result<Comment, ParseError> {
        let token = self.create_token(pair);

        // A comment must be at least 4 characters: {# #}
        if token.content.len() < 4 {
            return Err(ParseError::from_span(
                pair.as_span(),
                format!("Invalid comment: too short ({})", token.content.clone()),
            ));
        }

        // Create value token with offsets to skip {# at start and #} at end
        // The content will be automatically sliced and trimmed
        let value_token = Token::from_pair(pair).crop_cols(2, -2);
        let value_token = self.offset_token(value_token);

        Ok(Comment {
            token,
            value: value_token,
        })
    }

    /// Filter wrapper pairs whose single child might be a COMMENT
    ///
    /// This helper is used for cases like `template_element` which wraps a single child
    /// that could be `django_tag | expression | COMMENT | text`.
    ///
    /// For each parent pair:
    /// 1. Peeks at the single child
    /// 2. If child is a COMMENT, extracts it and adds to context
    /// 3. If child is not a COMMENT, keeps the parent pair
    /// 4. Returns a Vec of parent pairs (excluding those with COMMENT children)
    pub fn extract_comments_from_pairs<'i>(
        &self,
        pairs: impl IntoIterator<Item = pest::iterators::Pair<'i, Rule>>,
    ) -> Result<impl Iterator<Item = pest::iterators::Pair<'i, Rule>>, ParseError> {
        let mut filtered_pairs = Vec::new();

        for pair in pairs {
            let pair_rule = pair.as_rule();

            // Handle spacing and spacing_with_whitespace by recursively extracting comments
            if pair_rule == Rule::spacing || pair_rule == Rule::spacing_with_whitespace {
                // Recursively process spacing to extract nested comments
                self._extract_comments_from_pairs(pair.into_inner())?
                    .for_each(|_| {});
                // Don't add spacing pairs to filtered_pairs
                continue;
            }

            // Keep the parent pair if child is not a comment
            filtered_pairs.push(pair);
        }

        Ok(filtered_pairs.into_iter())
    }

    /// Filter pairs, extracting and collecting comments and spacing, returning only meaningful pairs
    ///
    /// This helper processes an iterator of pairs and:
    /// 1. Extracts COMMENT pairs and adds them to the context
    /// 2. Recursively processes spacing pairs to extract nested comments
    /// 3. Returns a Vec of non-comment, non-spacing pairs
    fn _extract_comments_from_pairs<'i>(
        &self,
        pairs: impl IntoIterator<Item = pest::iterators::Pair<'i, Rule>>,
    ) -> Result<impl Iterator<Item = pest::iterators::Pair<'i, Rule>>, ParseError> {
        let mut filtered_pairs = Vec::new();

        for pair in pairs {
            match pair.as_rule() {
                Rule::COMMENT => {
                    // Collect the comment
                    let comment = self.create_comment(&pair)?;
                    self.add_comment(comment);
                }
                Rule::spacing => {
                    // Recursively process spacing to extract nested comments
                    self._extract_comments_from_pairs(pair.into_inner())?
                        .for_each(|_| {});
                    // Note: we don't add spacing pairs to filtered_pairs
                }
                _ => {
                    // Keep all other pairs
                    filtered_pairs.push(pair);
                }
            }
        }

        Ok(filtered_pairs.into_iter())
    }

    /// Apply context offsets (line, column, index) to an existing Token
    ///
    /// This modifies the token's positions to account for the context's offsets.
    /// This is useful when you have a token created in a different context (e.g., from safe_eval)
    /// and need to adjust it to match the current context's position.
    pub fn offset_token(&self, token: Token) -> Token {
        token.offset(self.index_offset, self.line_offset, self.col_offset)
    }

    /// Create a Token from a pest Pair, applying line, column, and index offsets
    pub fn create_token(&self, pair: &pest::iterators::Pair<Rule>) -> Token {
        let token = Token::from_pair(pair);
        self.offset_token(token)
    }

    /// Start collecting variables for a new tag
    /// Raises an error if current tag variables are non-empty (indicating a previous tag wasn't finished)
    pub fn start_tag(&self) -> Result<(), String> {
        if !self.current_tag_used_vars.borrow().is_empty() {
            return Err(format!(
                "start_tag called but current_tag_used_vars is not empty ({} items)",
                self.current_tag_used_vars.borrow().len()
            ));
        }
        if !self.current_tag_assigned_vars.borrow().is_empty() {
            return Err(format!(
                "start_tag called but current_tag_assigned_vars is not empty ({} items)",
                self.current_tag_assigned_vars.borrow().len()
            ));
        }
        Ok(())
    }

    /// Collect variables from a TagValue into the current tag's variables
    pub fn collect_variables(&self, used_vars: &[Token], assigned_vars: &[Token]) {
        self.current_tag_used_vars
            .borrow_mut()
            .extend_from_slice(used_vars);
        self.current_tag_assigned_vars
            .borrow_mut()
            .extend_from_slice(assigned_vars);
    }

    /// Finish parsing a tag and return the collected variables
    /// Also extends the template-level variables
    /// Clears the current tag variables after extracting them
    pub fn finish_tag(&self) -> (Vec<Token>, Vec<Token>) {
        let used_vars: Vec<Token> = self.current_tag_used_vars.borrow_mut().drain(..).collect();
        let assigned_vars: Vec<Token> = self
            .current_tag_assigned_vars
            .borrow_mut()
            .drain(..)
            .collect();

        (used_vars, assigned_vars)
    }
}
