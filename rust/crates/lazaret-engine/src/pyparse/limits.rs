//! The nesting limits: what Python 3.13 refuses for nesting, refused here
//! too (and the parser's own recursion bounded by it).
//!
//! Python refuses deep nesting in three places:
//!
//! - its tokenizer: more than 200 open brackets ("too many nested
//!   parentheses"), 100 indentation levels, 150 nested f-strings, a format
//!   specifier in two others (`lexer.rs` refuses the same, at the same
//!   token);
//! - its parser, a PEG parser whose rules call each other: past 6000 calls
//!   deep it gives up ("Parser stack overflowed - Python source too complex
//!   to parse", a MemoryError). The parser here keeps `level`, an estimate
//!   of that depth: each construct that nests adds what it costs there (the
//!   costs below), and past `MAX_LEVEL` the input is refused. They were
//!   measured on Python 3.13, where the depth depends on the order the
//!   parser tries its alternatives in, as it keeps what a rule read at a
//!   token (memoizes) for the alternatives after: the deepest it goes is
//!   where it first reads a bracket's inside, at the full depth of an
//!   expression's rules, except for a bracket that starts a statement or an
//!   assignment's value, which it first reads as a possible assignment
//!   target, a shorter way (`CHEAP_*`); an f-string likewise (`FSTRING`);
//!   and a line that starts with `match` and what can start a subject, which
//!   it first reads as a match statement (`MATCH_LIKE`). The estimate is
//!   Python's depth for the chains that nest alone (unary operators, `**`,
//!   lambdas, conditional expressions, `elif`, brackets: the tests hold each
//!   to Python's limit), and close to it, never under it, elsewhere;
//! - converting its tree to Python objects, which recurses on the tree: a
//!   tree deeper than `MAX_DEPTH` nodes (the Module at depth 1; chains of
//!   binary operators, attributes, calls and subscripts nest without
//!   brackets) is refused (a RecursionError). The depth is counted when the
//!   tree is compacted (`Tree::compact`).

/// Python's parser stack (MAXSTACK).
pub const MAX_LEVEL: u32 = 6000;

/// The deepest tree Python 3.13 converts (its C recursion limit, 10000,
/// less the 3 levels `ast.parse` is called at).
pub const MAX_DEPTH: u32 = 9997;

// ---- statements ----
pub const MODULE: u32 = 1;
/// a simple statement's expressions (an expression statement's: with
/// MODULE and ATOM, 31)
pub const STMT: u32 = 20;
/// a simple statement after a `;`
pub const SEMI_STMT: u32 = 2;
/// an assignment's (and an augmented assignment's) value
pub const ASSIGN_VALUE: u32 = 3;
/// an annotated assignment's value
pub const ANN_VALUE: u32 = 4;
/// `return`'s value
pub const RETURN: u32 = 2;
/// a `yield` statement (its value adds YIELD)
pub const YIELD_STMT: u32 = 2;
/// `yield`'s value
pub const YIELD: u32 = 1;
/// `raise … from`'s cause, `assert`'s message
pub const SECOND_PART: u32 = 1;
/// an `except` clause's expression
pub const EXCEPT: u32 = 1;
/// `del`'s targets
pub const DEL: u32 = 1;
/// a decorator
pub const DECORATOR: u32 = 3;
/// a type parameter's bound or default
pub const TYPE_PARAM: u32 = 25;
/// a parameter's default, annotation, a function's return annotation
pub const DEFAULT: u32 = 6;
pub const ANNOTATION: u32 = 7;
pub const RETURNS: u32 = 1;
/// `for`'s target and iterable; `with`'s first item, later items
pub const FOR: u32 = 1;
pub const WITH_ITEM: u32 = 1;
pub const WITH_LATER_ITEM: u32 = 2;
/// `match`'s subject
pub const SUBJECT: u32 = 2;
/// a line that starts with `match` and what can start a subject but is not
/// a match statement (`match(x)`): Python reads it as one first, what
/// follows `match` as its subject, deeper than a statement's expression
/// (and no bracket there is cheap)
pub const MATCH_LIKE: u32 = 6;
/// a case (its body adds nothing), its patterns, its guard
pub const CASE: u32 = 9;
pub const PATTERNS: u32 = 15;
pub const GUARD: u32 = 14;
/// blocks: of `if`, `for`, `while`, `with`, `try`; of `def`, `class`,
/// `else`, `finally`; of `except`, `case`
pub const BLOCK: u32 = 6;
pub const DEF_BLOCK: u32 = 8;
pub const EXCEPT_BLOCK: u32 = 9;
/// each `elif` (an If nested in the one before), an `elif`'s test
pub const ELIF: u32 = 1;
pub const ELIF_TEST: u32 = 4;

// ---- expressions ----
/// `not`, `-`, `+`, `~`
pub const UNARY: u32 = 1;
/// a binary operator's right operand
pub const BINARY_RIGHT: u32 = 1;
/// a comparison's operands after the first
pub const COMPARE_RIGHT: u32 = 4;
/// `and`'s and `or`'s operands after the first
pub const BOOL_RIGHT: u32 = 3;
/// an assignment expression's value (`y := …`)
pub const WALRUS: u32 = 1;
/// `a if b else …`: each, and once for an `else` part that starts with a
/// unary operator
pub const IFEXP: u32 = 1;
pub const IFEXP_LAST: u32 = 1;
/// `lambda: …`: each, and once for the body
pub const LAMBDA: u32 = 2;
pub const LAMBDA_BODY: u32 = 1;
/// `a ** …`: each, and once for the right side
pub const POWER: u32 = 2;
pub const POWER_RIGHT: u32 = 1;
pub const AWAIT: u32 = 0;
/// brackets: `(…)`, `[…]`, `{…}`, a call's and a subscript's
pub const PAREN: u32 = 28;
pub const LIST: u32 = 29;
pub const BRACE: u32 = 29;
pub const CALL: u32 = 24;
pub const SUBSCRIPT: u32 = 24;
/// … where a statement or an assignment's value starts with them
pub const CHEAP_PAREN: u32 = 10;
/// … the second of two a statement starts with (`((`)
pub const SECOND_PAREN: u32 = 1;
pub const CHEAP_LIST: u32 = 11;
pub const CHEAP_BRACE: u32 = 11;
pub const CHEAP_CALL: u32 = 6;
pub const CHEAP_SUBSCRIPT: u32 = 6;
/// the items of a tuple, a list or a match statement's subject after the
/// first, of a call after the first, of a subscript's tuple after the first
pub const LATER_ITEM: u32 = 2;
pub const LATER_ARG: u32 = 4;
pub const LATER_SLICE: u32 = 3;
/// a slice's step
pub const STEP: u32 = 1;
/// a keyword argument's value, a starred argument
pub const KEYWORD_ARG: u32 = 3;
pub const COMPREHENSION: u32 = 1;
pub const STRINGS: u32 = 0;
/// an f-string's replacement field, a format specifier's field
pub const FIELD: u32 = 15;
pub const SPEC_FIELD: u32 = 4;
/// an f-string, except where a statement or an assignment's value starts
/// with it (or a statement with `(` and it): there Python reads it first as
/// a possible assignment target, a shorter way, and keeps what it read
pub const FSTRING: u32 = 18;
/// a pattern's brackets: `[…]` and `{…}`, `(…)`, a class pattern's; an
/// or-pattern's alternatives after the first, a sequence's items after the
/// first
pub const PATTERN: u32 = 9;
pub const PATTERN_PAREN: u32 = 6;
pub const PATTERN_CLASS: u32 = 8;
pub const PATTERN_OR: u32 = 1;
pub const PATTERN_LATER: u32 = 2;
/// what an atom takes, at the bottom of it all
pub const ATOM: u32 = 10;
