//! Refuse a tag that nests too deeply, and give the grammar enough stack for
//! the rest.
//!
//! The grammar in `grammar.pest` calls itself once for every `[` (rule
//! `list`), `{` (`dict`) and `(` (`python_expr`, and `python_nested_paren`
//! inside an expression) that it opens, and the code that turns its output
//! into an AST calls itself once per list or dict. A tag value with tens of
//! thousands of these would overflow the stack and crash the process. So
//! `TagParser::parse_tag` runs three checks:
//!
//! 1. `check_before_parse` counts every `(`, `[` and `{` byte in the tag,
//!    strings included, and refuses more than `MAX_BRACKETS`. Each recursive
//!    rule consumes one of these characters before it calls itself, so the
//!    grammar can never open more levels than this count. The cap only keeps
//!    the stack that step 3 asks for within a size limit.
//! 2. It then reads the tag the way the grammar does and refuses one whose
//!    lists, dicts and parentheses nest more than `MAX_NESTING` levels.
//!    Brackets inside strings and `{# #}` comments do not count. This is the
//!    limit users see.
//! 3. `with_enough_stack` runs the grammar and the AST builder on a stack
//!    sized from the step 1 count, and `check_parsed_depth` reads the real
//!    depth from the grammar's output before the AST is built.
//!
//! The step 2 reading follows the grammar closely but not every attempt the
//! grammar makes. `attribute` tries `key=value` first, and a key may contain
//! `(`: when that attempt fails, the same text is read again as a Python
//! expression, whose strings end in other places. Counting either way could
//! then report more or less than the depth the grammar reaches, so step 2
//! stops at such an attribute and leaves the decision to step 3. Steps 1 and
//! 3 also make sure any other input step 2 reads differently still ends in a
//! clean error.
//!
//! After the AST is built, `check_tag_depth` counts the levels once more, now
//! with filters: the Python that `tag_compiler.rs` writes wraps a value in one
//! `filter(...)` call per filter, so each filter adds a level around the
//! value it applies to and around the arguments of the filters before it.
//! CPython's own compiler then reads that Python, and it too calls itself
//! once per level (see `MAX_NESTING`).
//!
//! Two more passes call themselves once per level. The compiler in
//! `tag_compiler.rs` checks a value's depth with `check_value_depth` and runs
//! under `with_stack_for_tree`. Copying a value, which Python's attribute
//! getters do on the calling thread, checks the stack at each level through
//! `with_stack_for_one_level` (see `Clone for TagValue` in `ast.rs`).

use pest::iterators::Pairs;
use pest::Span;

use crate::ast::{Tag, TagValue, ValueChild, ValueKind};
use crate::error::{CompileError, ParseError};
use crate::grammar::Rule;

/// The most levels of lists, dicts, parentheses and filters a tag value may
/// nest.
///
/// Real tags nest a few levels. The limit comes from CPython, not from this
/// crate: `compile_tag` and `compile_value` hand the Python they write to
/// CPython's `compile()`, which calls itself once per nested bracket or call
/// and has no stack check of its own before 3.14. On a thread with a 128 KiB
/// stack (the default thread size of the musl CPython builds that uv
/// installs), CPython 3.10 to 3.13 crash from about 54 levels of that Python,
/// and so do 3.14 and later on musl. On glibc and macOS, 3.14 and later raise
/// `MemoryError` from about 38 levels. Measured at the top of a new thread on
/// Linux (x86-64 and arm64, glibc and musl) and macOS arm64. Python threads
/// on Windows got about 2 MB whatever size was asked for.
///
/// A tag value `MAX_NESTING` levels deep becomes Python at most 4 levels
/// deeper (`kwargs.append((key, ...))` around it, and a `variable(..., (start,
/// end), ...)` call inside it), so 20 levels: about half of what fits, which
/// leaves the rest for the frames of the code that calls `compile_tag`.
/// `safe_eval()` limits the Python it writes to the same depth (see
/// `djc_safe_eval::nesting::MAX_CODE_NESTING`).
pub const MAX_NESTING: usize = 16;

/// The most `(`, `[` and `{` characters a tag may hold, inside strings or not.
///
/// It bounds the stack `with_enough_stack` reserves: about 400 MiB of address
/// space at the limit in a release build and 3 GiB in a debug build, of
/// which only the pages the grammar actually reaches are used. On Windows,
/// `stacker` creates that stack as a fiber (a second stack on the same
/// thread), and Windows counts its whole size against the system's commit
/// limit (memory plus page file) until the parse ends. When Windows cannot
/// give that much, `stacker` panics, which Python sees as `PanicException`.
pub const MAX_BRACKETS: usize = 100_000;

/// Stack for a tag with no brackets, with room for the error path.
const STACK_BASE: usize = 256 * 1024;

/// Stack the grammar needs for each level it opens. Measured on macOS arm64,
/// Linux x86-64 and Windows x86-64 at up to 1.6 KB per level in a release
/// build and 15 KB in a debug build (lists or dicts whose items have filter
/// arguments, on Windows), then rounded up to at least twice that. The Rust
/// tests run debug builds.
#[cfg(not(debug_assertions))]
const GRAMMAR_STACK_PER_BRACKET: usize = 4 * 1024;
#[cfg(debug_assertions)]
const GRAMMAR_STACK_PER_BRACKET: usize = 32 * 1024;

/// Stack the grammar, the AST builder and the compiler need for each level
/// of the finished tree. Measured on macOS arm64, Linux x86-64 and Windows
/// x86-64 with a dict value that has a filter argument, parsing a tag 64
/// levels deep needed up to 9.4 KB per level in a release build (Windows)
/// and 64 KB in a debug build (macOS). Compiling it needed no more. Rounded
/// up to at least twice that.
#[cfg(not(debug_assertions))]
const AST_STACK_PER_LEVEL: usize = 24 * 1024;
#[cfg(debug_assertions)]
const AST_STACK_PER_LEVEL: usize = 128 * 1024;

/// The bytes the grammar treats as whitespace (rule `WHITESPACE`).
const WHITESPACE: [u8; 4] = [b' ', b'\t', b'\n', b'\r'];

/// A bracket that is still open while the tag is read.
#[derive(Clone, Copy, PartialEq)]
enum Open {
    List,
    Dict,
    /// The `(` of a Python expression, or a `(` nested inside one.
    Paren,
}

/// Check the tag before the grammar reads it (steps 1 and 2 above).
///
/// Returns the number of `(`, `[` and `{` characters, which sizes the stack
/// for `with_enough_stack`.
pub(crate) fn check_before_parse(input: &str) -> Result<usize, ParseError> {
    let bytes = input.as_bytes();

    let mut brackets = 0;
    for (offset, byte) in bytes.iter().enumerate() {
        if matches!(byte, b'(' | b'[' | b'{') {
            brackets += 1;
            if brackets > MAX_BRACKETS {
                return Err(error_at(
                    input,
                    offset,
                    format!(
                        "This tag holds more than {MAX_BRACKETS} `(`, `[` and `{{` characters, \
                         counting those inside strings and comments, the most djc-core \
                         can parse in one tag. Pass long text in a variable instead."
                    ),
                ));
            }
        }
    }

    if let Some(offset) = first_bracket_too_deep(bytes) {
        return Err(too_deep(input, offset));
    }
    Ok(brackets)
}

/// Run `work`, which parses one tag and builds its AST, with enough stack for
/// a tag holding `brackets` `(`, `[` and `{` characters.
///
/// The grammar's depth can reach the bracket count, and after
/// `check_parsed_depth` the AST's depth is at most `MAX_NESTING`. When less
/// stack than that is left, `stacker` runs the work on a new segment mapped
/// from the heap; only the pages the work touches are used. On a large
/// thread with a typical tag nothing is allocated.
///
/// The work must not call into Python: CPython 3.14 and later check the stack
/// pointer against the thread's own stack, and a heap segment is outside it.
pub(crate) fn with_enough_stack<T>(brackets: usize, work: impl FnOnce() -> T) -> T {
    let grammar = brackets * GRAMMAR_STACK_PER_BRACKET;
    let tree = brackets.min(MAX_NESTING + 1) * AST_STACK_PER_LEVEL;
    let needed = STACK_BASE + grammar.max(tree);
    stacker::maybe_grow(needed, needed, work)
}

/// Refuse grammar output whose lists, dicts and Python expressions nest more
/// than `MAX_NESTING` levels (step 3 above).
///
/// Pest keeps its output as one flat list of start and end markers, so this
/// reads the real depth without recursion, before the AST builder walks it.
/// The `(` nested inside an expression leave no markers, so each expression
/// is read again for them, which keeps the rule the same as in step 2.
pub(crate) fn check_parsed_depth(input: &str, pairs: &Pairs<Rule>) -> Result<(), ParseError> {
    let bytes = input.as_bytes();
    let mut failed = FailedSearches::default();
    let mut depth = 0;
    for token in pairs.clone().tokens() {
        match token {
            pest::Token::Start { rule, pos } if nests(rule) => {
                if rule == Rule::python_expr {
                    if let Some(offset) = first_paren_too_deep(bytes, pos.pos(), depth, &mut failed)
                    {
                        return Err(too_deep(input, offset));
                    }
                }
                depth += 1;
                if depth > MAX_NESTING {
                    return Err(too_deep(input, pos.pos()));
                }
            }
            pest::Token::End { rule, .. } if nests(rule) => depth -= 1,
            _ => {}
        }
    }
    Ok(())
}

/// The offset of the first `(` that opens level `MAX_NESTING + 1` in the
/// Python expression whose `(` is at `start`, with `levels_above` levels
/// already open around it, read as rule `python_inner` does.
fn first_paren_too_deep(
    bytes: &[u8],
    start: usize,
    levels_above: usize,
    failed: &mut FailedSearches,
) -> Option<usize> {
    let mut open = levels_above;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => i = python_string_end(bytes, i, failed).unwrap_or(i + 1),
            b'(' => {
                if open == MAX_NESTING {
                    return Some(i);
                }
                open += 1;
                i += 1;
            }
            b')' => {
                open -= 1;
                if open == levels_above {
                    return None;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// The rules that add a level to the AST.
fn nests(rule: Rule) -> bool {
    matches!(rule, Rule::list | Rule::dict | Rule::python_expr)
}

/// Refuse a tag value that nests more than `MAX_NESTING` levels once filters
/// are counted, before the compiler walks it.
///
/// `parse_tag` never returns a deeper value (see `check_tag_depth`), but
/// Python code can build one by hand.
///
/// Returns the deepest number of levels found, which sizes the stack for
/// `with_stack_for_tree`.
pub(crate) fn check_value_depth(value: &TagValue) -> Result<usize, CompileError> {
    deepest_levels(value).map_err(|_| {
        CompileError::Syntax(format!(
            "This tag value nests lists, dicts, parentheses and filters more than \
             {MAX_NESTING} levels deep, the most djc-core can compile. Build the deeper \
             part in Python and pass it in as a variable."
        ))
    })
}

/// Refuse a parsed tag with a value that nests more than `MAX_NESTING` levels
/// once filters are counted (see the module notes).
pub(crate) fn check_tag_depth(input: &str, tag: &Tag) -> Result<(), ParseError> {
    let values: Vec<&TagValue> = match tag {
        Tag::Generic(generic) => generic.attrs.iter().map(|attr| &attr.value).collect(),
        Tag::ForLoop(for_loop) => vec![&for_loop.iterable],
        Tag::End(_) => Vec::new(),
    };
    for value in values {
        if let Err(too_deep_value) = deepest_levels(value) {
            // Point at the value that opens the level past the limit. Its
            // offsets come from the grammar, so they are character
            // boundaries; the fallback only guards against a future caller.
            let token = &too_deep_value.value;
            let span = Span::new(input, token.start_index, token.end_index)
                .or_else(|| Span::new(input, 0, 0))
                .expect("an empty span at 0 is always valid");
            return Err(ParseError::from_span(span, too_deep_message()));
        }
    }
    Ok(())
}

/// The deepest number of levels in `value`, counting each list, dict and
/// Python expression, and each filter around everything it wraps in the
/// Python that `tag_compiler.rs` writes. Returns the first value deeper than
/// `MAX_NESTING` as the error.
///
/// The compiler writes `x|f:a|g:b` as `filter(g, filter(f, x, a), b)`: the
/// value sits inside every filter, and the argument of a filter inside that
/// filter and every filter after it. The tree is read with a list of values
/// still to visit, without recursion.
fn deepest_levels(value: &TagValue) -> Result<usize, &TagValue> {
    let mut deepest = 0;
    let mut to_visit = vec![(value, 0)];
    while let Some((value, levels_above)) = to_visit.pop() {
        let filters = value.filters.len();
        let opens_level = matches!(
            value.kind,
            ValueKind::List | ValueKind::Dict | ValueKind::PythonExpr
        );
        let levels = levels_above + filters + usize::from(opens_level);
        if levels > MAX_NESTING {
            return Err(value);
        }
        deepest = deepest.max(levels);
        to_visit.extend(
            value
                .children
                .iter()
                .filter_map(ValueChild::as_value)
                .map(|child| (child, levels)),
        );
        // The argument of filter `index` sits inside it and the filters
        // after it, plus one level when the argument is a list or dict.
        to_visit.extend(
            value
                .filters
                .iter()
                .enumerate()
                .filter_map(|(index, filter)| {
                    filter
                        .arg
                        .as_ref()
                        .map(|arg| (arg, levels_above + filters - index))
                }),
        );
    }
    Ok(deepest)
}

/// Stack one level of copying a tag value may use, with a wide margin. One
/// level needed up to 2.8 KB in a release build (Windows) and 5.8 KB in a
/// debug build (macOS), measured on macOS arm64, Linux x86-64 and Windows
/// x86-64.
const ONE_LEVEL_RED_ZONE: usize = 64 * 1024;

/// The size of each new segment for copying, which holds many levels.
const ONE_LEVEL_SEGMENT: usize = 1024 * 1024;

/// Run `work`, one level of a recursive pass over a tag value, on a new stack
/// segment when less than `ONE_LEVEL_RED_ZONE` is left. Like
/// `with_enough_stack`, the work must not call into Python.
pub(crate) fn with_stack_for_one_level<T>(work: impl FnOnce() -> T) -> T {
    stacker::maybe_grow(ONE_LEVEL_RED_ZONE, ONE_LEVEL_SEGMENT, work)
}

/// Run `work`, which walks tag values at most `levels` deep (as returned by
/// `check_value_depth`), with enough stack. Like `with_enough_stack`, the
/// work must not call into Python.
pub(crate) fn with_stack_for_tree<T>(levels: usize, work: impl FnOnce() -> T) -> T {
    let needed = STACK_BASE + (levels + 1) * AST_STACK_PER_LEVEL;
    stacker::maybe_grow(needed, needed, work)
}

fn too_deep(input: &str, offset: usize) -> ParseError {
    error_at(input, offset, too_deep_message())
}

/// The message for a tag that nests too deeply. The checks before and right
/// after parsing count brackets only, and a tag they refuse nests too deeply
/// by the rule this message states.
fn too_deep_message() -> String {
    format!(
        "This tag nests lists, dicts, parentheses and filters more than {MAX_NESTING} \
         levels deep, the most djc-core can compile. Each filter adds a level around the \
         value before it. Brackets inside strings and comments do not count. Build the \
         deeper part in Python and pass it in as a variable."
    )
}

/// An error pointing at the one ASCII character at `offset`.
fn error_at(input: &str, offset: usize, message: String) -> ParseError {
    // Every offset passed here is a bracket, one ASCII byte, so both ends are
    // character boundaries. The fallback only guards against a future caller.
    let span = Span::new(input, offset, offset + 1)
        .or_else(|| Span::new(input, 0, 0))
        .expect("an empty span at 0 is always valid");
    ParseError::from_span(span, message)
}

/// The offset of the first bracket that opens level `MAX_NESTING + 1`, as the
/// grammar reads the tag, or `None` when the tag stays within the limit or
/// the reading stops being certain.
///
/// The reading works on bytes: every character the grammar treats specially
/// is ASCII, and in UTF-8 no byte of a longer character is ASCII.
fn first_bracket_too_deep(bytes: &[u8]) -> Option<usize> {
    let mut failed = FailedSearches::default();
    let mut open: Vec<Open> = Vec::new();
    let mut i = 0;
    // An attribute starts after whitespace or a comment. The scanner also
    // reads the tag name as an attribute, which is harmless because a tag
    // name never holds `(`.
    let mut after_spacing = true;

    while i < bytes.len() {
        let byte = bytes[i];
        let next = bytes.get(i + 1).copied();

        // Inside `( ... )` the grammar reads Python (rule `python_inner`):
        // Python strings, and only `(` and `)` nest.
        if open.last() == Some(&Open::Paren) {
            match byte {
                b'"' | b'\'' => i = python_string_end(bytes, i, &mut failed).unwrap_or(i + 1),
                b'(' => {
                    if open.len() == MAX_NESTING {
                        return Some(i);
                    }
                    open.push(Open::Paren);
                    i += 1;
                }
                b')' => {
                    open.pop();
                    after_spacing = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }

        // Outside an expression: tag strings, comments and keys.
        if WHITESPACE.contains(&byte) {
            after_spacing = true;
            i += 1;
            continue;
        }
        if byte == b'{' && next == Some(b'#') {
            // A comment the grammar would skip as spacing. An unclosed `{#`
            // is not a comment, so it falls through and its `{` counts.
            if let Some(end) = comment_end(bytes, i, &mut failed) {
                after_spacing = true;
                i = end;
                continue;
            }
        }
        if open.is_empty() && after_spacing && can_be_read_two_ways(bytes, i) {
            // From here on the grammar may read the tag with tag strings or
            // with Python strings, which end in different places. Counting
            // either way could refuse a valid tag, so leave the decision to
            // `check_parsed_depth`, which reads the grammar's real output.
            return None;
        }
        after_spacing = false;

        match byte {
            // The tag's own delimiters. Read anywhere else, `{%` opens a dict
            // that fails at once.
            b'{' if next == Some(b'%') => i += 2,
            b'%' if next == Some(b'}') => i += 2,
            // A string the grammar cannot close is a syntax error; until the
            // grammar gets there, its quote is read as a plain character, so
            // the brackets after it still count.
            b'"' | b'\'' => i = tag_string_end(bytes, i, &mut failed).unwrap_or(i + 1),
            // `_("...")` is a translation. Even when it is not one, the `(`
            // after `_` cannot start an expression: a value never starts in
            // the middle of a name.
            b'_' if next == Some(b'(') => {
                i = translation_end(bytes, i, &mut failed).unwrap_or(i + 2)
            }
            b'[' | b'{' | b'(' => {
                if open.len() == MAX_NESTING {
                    return Some(i);
                }
                open.push(match byte {
                    b'[' => Open::List,
                    b'{' => Open::Dict,
                    _ => Open::Paren,
                });
                i += 1;
            }
            // A closer that does not match the innermost bracket makes the
            // grammar fail there, so it closes nothing.
            b']' => {
                if open.last() == Some(&Open::List) {
                    open.pop();
                }
                i += 1;
            }
            b'}' => {
                if open.last() == Some(&Open::Dict) {
                    open.pop();
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// The earliest start from which each kind of search below found no end.
///
/// A search that fails from one start also fails from every later start of
/// the same kind, so remembering the first failure keeps the reading linear:
/// without it, thousands of unclosed `{#` or quotes would each search to the
/// end of the tag.
///
/// - A comment or a triple quote searches for a fixed end in the rest of the
///   tag, and a later start leaves less to search.
/// - A tag string that does not close has a `\` before every later quote of
///   its kind, so a string that starts at any of those quotes does not close
///   either.
/// - A Python string opened by one quote mark (`"` or `'`, not three) that
///   does not close has every later quote of its kind escaped, and a string
///   that starts at one of them reads the rest of the tag in the same steps
///   of one or two bytes.
struct FailedSearches {
    comment: usize,
    /// Indexed by `quote_index`.
    tag_string: [usize; 2],
    python_string: [usize; 2],
    triple_quote: [usize; 2],
}

impl Default for FailedSearches {
    fn default() -> Self {
        FailedSearches {
            comment: usize::MAX,
            tag_string: [usize::MAX; 2],
            python_string: [usize::MAX; 2],
            triple_quote: [usize::MAX; 2],
        }
    }
}

/// Run `search` unless one of its kind already failed from an earlier start,
/// and remember `start` when it fails.
fn search_once(
    failed_from: &mut usize,
    start: usize,
    search: impl FnOnce() -> Option<usize>,
) -> Option<usize> {
    if start >= *failed_from {
        return None;
    }
    let end = search();
    if end.is_none() {
        *failed_from = start;
    }
    end
}

fn quote_index(quote: u8) -> usize {
    usize::from(quote == b'\'')
}

/// The end of the `{# ... #}` comment starting at `start` (rule `COMMENT`).
fn comment_end(bytes: &[u8], start: usize, failed: &mut FailedSearches) -> Option<usize> {
    search_once(&mut failed.comment, start, || {
        find(bytes, start + 2, b"#}").map(|at| at + 2)
    })
}

/// The end of the tag string starting with the quote at `start` (rules
/// `double_quoted_string` and `single_quoted_string`): the string ends at its
/// quote unless the quote follows a `\`.
fn tag_string_end(bytes: &[u8], start: usize, failed: &mut FailedSearches) -> Option<usize> {
    let quote = bytes[start];
    search_once(&mut failed.tag_string[quote_index(quote)], start, || {
        let mut i = start + 1;
        while i < bytes.len() {
            if bytes[i] == quote {
                return Some(i + 1);
            }
            if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                i += 1;
            }
        }
        None
    })
}

/// The end of the Python string starting with the quote at `start` (rules
/// `python_str_*`): triple quotes have no escapes, and in a string opened by
/// one quote mark `\` escapes the next character.
fn python_string_end(bytes: &[u8], start: usize, failed: &mut FailedSearches) -> Option<usize> {
    let quote = bytes[start];
    let index = quote_index(quote);
    if bytes.get(start + 1) == Some(&quote) && bytes.get(start + 2) == Some(&quote) {
        let triple = search_once(&mut failed.triple_quote[index], start, || {
            find(bytes, start + 3, &[quote, quote, quote]).map(|at| at + 3)
        });
        if triple.is_some() {
            return triple;
        }
        // An unclosed triple quote falls through, as in the grammar, which
        // then reads its first two quotes as an empty string.
    }
    search_once(&mut failed.python_string[index], start, || {
        let mut i = start + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                byte if byte == quote => return Some(i + 1),
                _ => i += 1,
            }
        }
        None
    })
}

/// The end of the translation `_( "..." )` starting at `start` (rule
/// `translation`).
fn translation_end(bytes: &[u8], start: usize, failed: &mut FailedSearches) -> Option<usize> {
    let mut i = skip_spacing(bytes, start + 2, failed);
    if !matches!(bytes.get(i), Some(b'"' | b'\'')) {
        return None;
    }
    let string_end = tag_string_end(bytes, i, failed)?;
    i = skip_spacing(bytes, string_end, failed);
    (bytes.get(i) == Some(&b')')).then_some(i + 1)
}

/// The first offset at or after `i` that is not whitespace or a comment
/// (rule `spacing`).
fn skip_spacing(bytes: &[u8], mut i: usize, failed: &mut FailedSearches) -> usize {
    loop {
        if bytes.get(i).is_some_and(|byte| WHITESPACE.contains(byte)) {
            i += 1;
        } else if bytes.get(i) == Some(&b'{') && bytes.get(i + 1) == Some(&b'#') {
            match comment_end(bytes, i, failed) {
                Some(end) => i = end,
                None => return i,
            }
        } else {
            return i;
        }
    }
}

/// Whether the grammar may read the attribute starting at `start` in two
/// ways (rules `attribute`, `key`, `key_start` and `key_char`).
///
/// `attribute` tries `key=value` first. A key may hold `(`, so in `(x<=-y)`
/// the grammar first reads the key `(x<`; the value `-y` fails, so it reads
/// `(x<=-y)` as a Python expression. When the value parses, the key reading
/// stands. A `for` tag reads the same text as its iterable, with no key.
/// Without a `(` in the key both readings see the same brackets and quotes,
/// and when no value can start after the `=` the key reading fails at once.
fn can_be_read_two_ways(bytes: &[u8], start: usize) -> bool {
    let Some(&first) = bytes.get(start) else {
        return false;
    };
    let starts_translation = first == b'_' && bytes.get(start + 1) == Some(&b'(');
    if matches!(first, b':' | b'.' | b'=') || starts_translation || stops_key(first) {
        return false;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|&byte| byte != b'=' && !stops_key(byte))
    {
        end += 1;
    }
    let Some(&value_start) = bytes.get(end + 1) else {
        return false;
    };
    let can_start_value = value_start.is_ascii_alphanumeric()
        || matches!(
            value_start,
            b'{' | b'[' | b'(' | b'_' | b'-' | b'+' | b'.' | b'"' | b'\''
        );
    bytes[end] == b'=' && can_start_value && bytes[start..end].contains(&b'(')
}

/// Bytes that end a key (rule `key_char`). `_(` and `...` do not end one,
/// because `key_char` accepts `_` and `.` before it checks for them.
fn stops_key(byte: u8) -> bool {
    matches!(byte, b'\'' | b'"' | b'[' | b'{' | b'*') || WHITESPACE.contains(&byte)
}

fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|at| from + at)
}

#[cfg(test)]
mod tests {
    use pest::Parser;

    use super::*;
    use crate::grammar::GrammarParser;

    fn depth_ok(tag: &str) -> bool {
        first_bracket_too_deep(tag.as_bytes()).is_none()
    }

    fn nest(open: &str, inner: &str, close: &str, levels: usize) -> String {
        format!("{}{}{}", open.repeat(levels), inner, close.repeat(levels))
    }

    #[test]
    fn counts_each_kind_of_bracket() {
        for (open, close) in [("[", "]"), ("{'a': ", "}"), ("(", ")"), ("[x|f:", "]")] {
            let at_limit = format!("{{% c {} %}}", nest(open, "1", close, MAX_NESTING));
            let over = format!("{{% c {} %}}", nest(open, "1", close, MAX_NESTING + 1));
            assert!(depth_ok(&at_limit), "{open}");
            assert!(!depth_ok(&over), "{open}");
        }
    }

    #[test]
    fn siblings_do_not_add_up() {
        let siblings = "[1] ".repeat(1000);
        assert!(depth_ok(&format!("{{% c {siblings}%}}")));
        let items = vec!["{'a': [1, (2)]}"; 1000].join(", ");
        assert!(depth_ok(&format!("{{% c [{items}] %}}")));
    }

    #[test]
    fn skips_strings_comments_translations_and_keys() {
        let deep = "[".repeat(500);
        let parens = "(".repeat(500);
        for tag in [
            format!(r#"{{% c "{deep}" %}}"#),
            format!(r#"{{% c '{deep}' %}}"#),
            format!(r#"{{% c "a\"{deep}" %}}"#),
            format!("{{% c {{# {deep} #}} x %}}"),
            format!(r#"{{% c _("{parens}") %}}"#),
            format!(r#"{{% c _( {{# c #}} '{parens}' ) %}}"#),
            format!(r#"{{% c ("{parens}") %}}"#),
            format!(r#"{{% c ('{parens}\'{parens}') %}}"#),
            format!(r#"{{% c ("""{parens}"{parens}""") %}}"#),
            format!("{{% c ('''{parens}''') %}}"),
            format!("{{% c {parens}{}=1 %}}", ")".repeat(500)),
            format!("{{% c a|f:{parens}=1 %}}"),
        ] {
            assert!(depth_ok(&tag), "{tag}");
        }
    }

    #[test]
    fn reads_strings_as_the_grammar_does() {
        let deep = "[".repeat(MAX_NESTING + 1);
        // In a tag string only `\"` is an escape, so the string below runs
        // on past `\\"` to the last quote and hides the brackets.
        assert!(depth_ok(&format!(r#"{{% c "a\\" {deep} " %}}"#)));
        // Inside an expression, `[` does not nest but `(` does, and a Python
        // string ends at the quote after `\\`.
        assert!(depth_ok(&format!("{{% c ({deep}) %}}")));
        let parens = "(".repeat(MAX_NESTING);
        assert!(!depth_ok(&format!(r#"{{% c ("a\\" {parens}) %}}"#)));
        // An unclosed string or comment does not hide what follows.
        assert!(!depth_ok(&format!(r#"{{% c "a {deep} %}}"#)));
        assert!(!depth_ok(&format!("{{% c {{# {deep} %}}")));
        assert!(!depth_ok(&format!(r#"{{% c ("""a {parens}) %}}"#)));
        // Comments exist only outside expressions.
        assert!(!depth_ok(&format!("{{% c ({{# {parens} #}}) %}}")));
        // `_(` without a string after it is not a translation, and its `(`
        // opens nothing, but what follows still counts.
        assert!(!depth_ok(&format!("{{% c _(x {deep} %}}")));
        // A key with `=` and no value after it is read as a value instead.
        assert!(!depth_ok(&format!("{{% c ({parens}==1 %}}")));
    }

    #[test]
    fn gives_up_where_an_attribute_can_be_read_two_ways() {
        let deep = "[".repeat(MAX_NESTING + 1);
        // Read as a key, `"\\" + "` would be one tag string and the brackets
        // would count; the grammar reads a Python expression, where they sit
        // inside a string. `check_parsed_depth` decides instead.
        for tag in [
            format!(r#"{{% c (x<=-y or "\\" + "{deep}") %}}"#),
            format!(r#"{{% for i in (x<=y or "\\" + "{deep}") %}}"#),
            format!(r#"{{% c a|f:(b=[1] {deep} %}}"#),
        ] {
            assert!(depth_ok(&tag), "{tag}");
        }
        // Without a `(` in the key, both readings agree and the check stays.
        assert!(!depth_ok(&format!("{{% c a|f:b=[1] {deep} %}}")));
    }

    #[test]
    fn unclosed_strings_and_comments_are_searched_once() {
        // Each of these would search to the end of the tag once per quote or
        // `{#` if failed searches were not remembered.
        let n = 200_000;
        for tag in [
            format!(r#"{{% c "{}%}}"#, r#"\""#.repeat(n)),
            format!("{{% c {}%}}", "{# } ".repeat(n)),
            format!(r#"{{% c ("{}) %}}"#, r#"\""#.repeat(n)),
            format!(r#"{{% c ("""{}) %}}"#, r#"""\""#.repeat(n)),
        ] {
            let started = std::time::Instant::now();
            first_bracket_too_deep(tag.as_bytes());
            assert!(started.elapsed().as_secs() < 2, "{}", &tag[..20]);
        }
    }

    #[test]
    fn parsed_depth_counts_lists_dicts_and_expressions() {
        for (open, close, levels) in [
            ("[", "]", MAX_NESTING),
            ("{'a': ", "}", MAX_NESTING - 1),
            ("[", "]", MAX_NESTING + 1),
        ] {
            let tag = format!(
                "{{% c {}(1){} %}}",
                open.repeat(levels),
                close.repeat(levels)
            );
            let pairs = GrammarParser::parse(Rule::tag_wrapper, &tag).unwrap();
            let result = check_parsed_depth(&tag, &pairs);
            assert_eq!(result.is_ok(), levels < MAX_NESTING, "{open} {levels}");
        }
    }
}
