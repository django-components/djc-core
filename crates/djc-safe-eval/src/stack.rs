//! Make sure djc-safe-eval's own passes over one expression have enough
//! stack, whatever thread runs them.
//!
//! The passes over an expression's tree (parsing, the sandbox transformer, and
//! code generation) call themselves once per tree level. `nesting::MAX_NESTING`
//! bounds the depth, but at that depth the passes still need more stack than a
//! small thread has. citry-core, which this module comes from, measured about
//! 9 KB per level in a debug build and about 1.2 KB in a release build on
//! macOS arm64, with one more pass than this crate runs. `tests/nesting.rs`
//! checks this crate on a 256 KiB thread.
//!
//! So each public entry point runs its work through `with_enough_stack`. When
//! less than `RED_ZONE` is left, `stacker` runs the work on a new stack
//! segment taken from the heap. On a large thread, such as the usual 8 MB
//! main thread on Linux and macOS, nothing is allocated and the check is
//! cheap.

/// The stack one expression can need: 200 levels at about 9 KB each is about
/// 1.8 MB in a debug build, rounded up for a margin.
const RED_ZONE: usize = 2 * 1024 * 1024;

/// The size of a new segment, twice the red zone, so one segment holds the
/// passes over a whole expression.
const SEGMENT: usize = 4 * 1024 * 1024;

/// Run `work` with at least `RED_ZONE` bytes of stack available.
///
/// The work must not call into Python: CPython 3.14 and later check the stack
/// pointer against the thread's own stack, and a heap segment is outside it.
pub(crate) fn with_enough_stack<T>(work: impl FnOnce() -> T) -> T {
    stacker::maybe_grow(RED_ZONE, SEGMENT, work)
}
