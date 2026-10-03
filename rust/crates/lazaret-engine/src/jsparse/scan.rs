//! The scanner's pieces: the literals the grammar compares token values
//! with, character classes, and jsparse.py's token patterns matched by hand.
//!
//! Each matcher below replaces one of jsparse.py's regular expressions and
//! gives that pattern's own match: every one of them has a single way to
//! match at each position (an alternative is chosen by the next character,
//! and nothing after a greedy run can make it give back), as each
//! function's note argues. Positions are code-point offsets.

// ---- the literals ----

macro_rules! literals {
    ($($name:ident = $s:literal),* $(,)?) => {
        #[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
        #[repr(u32)]
        enum Lit { $($name),* }
        $(pub const $name: u32 = Lit::$name as u32;)*
        /// Every string the grammar compares a token's value with: the
        /// first ids of every tree's string table (tree::Strings).
        pub const LITERALS: &[&str] = &[$($s),*];
    };
}

literals! {
    EMPTY = "",
    // punctuators: every token _PUNCT_RE and _GT_RE give (the operators first: Node::op holds them)
    P_ELLIPSIS = "...", P_SEQ = "===", P_SNE = "!==", P_POW_ASSIGN = "**=", P_SHL_ASSIGN = "<<=", P_AND_ASSIGN = "&&=",
    P_OR_ASSIGN = "||=", P_NULLISH_ASSIGN = "??=", P_ARROW = "=>", P_EQ = "==", P_NE = "!=", P_LE = "<=",
    P_AND = "&&", P_OR = "||", P_NULLISH = "??", P_OPTIONAL = "?.", P_INC = "++", P_DEC = "--",
    P_ADD_ASSIGN = "+=", P_SUB_ASSIGN = "-=", P_MUL_ASSIGN = "*=", P_DIV_ASSIGN = "/=", P_MOD_ASSIGN = "%=",
    P_BITAND_ASSIGN = "&=", P_BITOR_ASSIGN = "|=", P_XOR_ASSIGN = "^=", P_POW = "**", P_SHL = "<<",
    P_LBRACE = "{", P_RBRACE = "}", P_LPAREN = "(", P_RPAREN = ")", P_LBRACK = "[", P_RBRACK = "]",
    P_SEMI = ";", P_COMMA = ",", P_LT = "<", P_GT = ">", P_PLUS = "+", P_MINUS = "-", P_STAR = "*",
    P_SLASH = "/", P_PERCENT = "%", P_BITAND = "&", P_BITOR = "|", P_CARET = "^", P_BANG = "!", P_TILDE = "~",
    P_QUESTION = "?", P_COLON = ":", P_ASSIGN = "=", P_DOT = ".", P_AT = "@", P_HASH = "#",
    P_USHR_ASSIGN = ">>>=", P_SHR_ASSIGN = ">>=", P_USHR = ">>>", P_SHR = ">>", P_GE = ">=",
    // the operator words
    W_TYPEOF = "typeof", W_VOID = "void", W_DELETE = "delete", W_INSTANCEOF = "instanceof", W_IN = "in",
    // (ids from here on are never an operator)
    W_AS = "as", W_SATISFIES = "satisfies",
    // reserved words
    W_BREAK = "break", W_CASE = "case", W_CATCH = "catch", W_CLASS = "class", W_CONST = "const",
    W_CONTINUE = "continue", W_DEBUGGER = "debugger", W_DEFAULT = "default", W_DO = "do", W_ELSE = "else",
    W_EXPORT = "export", W_EXTENDS = "extends", W_FINALLY = "finally", W_FOR = "for", W_FUNCTION = "function",
    W_IF = "if", W_IMPORT = "import", W_NEW = "new", W_RETURN = "return", W_SUPER = "super", W_SWITCH = "switch",
    W_THIS = "this", W_THROW = "throw", W_TRY = "try", W_VAR = "var", W_WHILE = "while", W_WITH = "with",
    W_NULL = "null", W_TRUE = "true", W_FALSE = "false", W_ENUM = "enum",
    // contextual words
    W_LET = "let", W_USING = "using", W_AWAIT = "await", W_ASYNC = "async", W_YIELD = "yield", W_OF = "of",
    W_FROM = "from", W_TYPE = "type", W_GET = "get", W_SET = "set", W_STATIC = "static",
    W_CONSTRUCTOR = "constructor", W_PUBLIC = "public", W_PRIVATE = "private", W_PROTECTED = "protected",
    W_READONLY = "readonly", W_ABSTRACT = "abstract", W_OVERRIDE = "override", W_DECLARE = "declare",
    W_ACCESSOR = "accessor", W_INTERFACE = "interface", W_NAMESPACE = "namespace", W_MODULE = "module",
    W_GLOBAL = "global", W_IMPLEMENTS = "implements", W_ASSERT = "assert", W_ASSERTS = "asserts", W_IS = "is",
    W_KEYOF = "keyof", W_UNIQUE = "unique", W_INFER = "infer", W_OUT = "out", W_REQUIRE = "require",
}

/// Literal ids below this are the operators (they fit `Node::op`).
pub const OPERATOR_LITERALS: usize = W_AS as usize;
const _: () = assert!(OPERATOR_LITERALS <= 256 && W_IN < W_AS);

/// _RESERVED: never an identifier reference, a binding or a label.
#[inline]
pub fn reserved(v: u32) -> bool {
    matches!(
        v,
        W_BREAK
            | W_CASE
            | W_CATCH
            | W_CLASS
            | W_CONST
            | W_CONTINUE
            | W_DEBUGGER
            | W_DEFAULT
            | W_DELETE
            | W_DO
            | W_ELSE
            | W_EXPORT
            | W_EXTENDS
            | W_FINALLY
            | W_FOR
            | W_FUNCTION
            | W_IF
            | W_IMPORT
            | W_IN
            | W_INSTANCEOF
            | W_NEW
            | W_RETURN
            | W_SUPER
            | W_SWITCH
            | W_THIS
            | W_THROW
            | W_TRY
            | W_TYPEOF
            | W_VAR
            | W_VOID
            | W_WHILE
            | W_WITH
            | W_NULL
            | W_TRUE
            | W_FALSE
            | W_ENUM
    )
}

/// _BINARY_PREC for a punctuator (`>` and its family come through gt_op).
#[inline]
pub fn binary_prec(v: u32) -> u8 {
    match v {
        P_NULLISH | P_OR => 1,
        P_AND => 2,
        P_BITOR => 3,
        P_CARET => 4,
        P_BITAND => 5,
        P_EQ | P_NE | P_SEQ | P_SNE => 6,
        P_LT | P_GT | P_LE | P_GE | W_INSTANCEOF | W_IN => 7,
        P_SHL | P_SHR | P_USHR => 8,
        P_PLUS | P_MINUS => 9,
        P_STAR | P_SLASH | P_PERCENT => 10,
        P_POW => 11,
        _ => 0,
    }
}

/// _ASSIGN_OPS
#[inline]
pub fn assign_op(v: u32) -> bool {
    matches!(
        v,
        P_ASSIGN
            | P_ADD_ASSIGN
            | P_SUB_ASSIGN
            | P_MUL_ASSIGN
            | P_DIV_ASSIGN
            | P_MOD_ASSIGN
            | P_POW_ASSIGN
            | P_SHL_ASSIGN
            | P_SHR_ASSIGN
            | P_USHR_ASSIGN
            | P_BITAND_ASSIGN
            | P_BITOR_ASSIGN
            | P_XOR_ASSIGN
            | P_AND_ASSIGN
            | P_OR_ASSIGN
            | P_NULLISH_ASSIGN
    )
}

// ---- character classes ----

const C_ID_START: u8 = 1;
const C_ID_PART: u8 = 2;
const C_DIGIT: u8 = 4;
const C_HEX: u8 = 8;
const C_BLANK: u8 = 16;

static ASCII: [u8; 128] = ascii_table();

const fn ascii_table() -> [u8; 128] {
    let mut t = [0u8; 128];
    let mut c = 0;
    while c < 128 {
        let ch = c as u8;
        let mut v = 0;
        if ch.is_ascii_alphabetic() || ch == b'_' || ch == b'$' {
            v |= C_ID_START | C_ID_PART;
        }
        if ch.is_ascii_digit() {
            v |= C_DIGIT | C_ID_PART | C_HEX;
        }
        if matches!(ch, b'a'..=b'f' | b'A'..=b'F') {
            v |= C_HEX;
        }
        if matches!(ch, b'\t' | 0x0b | 0x0c | b' ' | b'\n' | b'\r') {
            v |= C_BLANK;
        }
        t[c] = v;
        c += 1;
    }
    t
}

/// A line terminator: LF, CR, U+2028, U+2029.
#[inline]
pub fn is_lt(c: u32) -> bool {
    c == 0x0A || c == 0x0D || c == 0x2028 || c == 0x2029
}

/// _BLANKS_RE's class: _WS_CHARS and the line terminators.
#[inline]
pub fn is_blank(c: u32) -> bool {
    if c < 128 {
        ASCII[c as usize] & C_BLANK != 0
    } else {
        matches!(c, 0xA0 | 0xFEFF | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000 | 0x2028 | 0x2029)
    }
}

/// _ID_OTHER: every code point past ASCII but the blanks.
#[inline]
pub fn is_id_other(c: u32) -> bool {
    (0x80..=0x10FFFF).contains(&c)
        && !matches!(c, 0xA0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000 | 0xFEFF)
}

#[inline]
pub fn is_id_start(c: u32) -> bool {
    if c < 128 {
        ASCII[c as usize] & C_ID_START != 0
    } else {
        is_id_other(c)
    }
}

#[inline]
pub fn is_id_part(c: u32) -> bool {
    if c < 128 {
        ASCII[c as usize] & C_ID_PART != 0
    } else {
        is_id_other(c)
    }
}

#[inline]
pub fn is_digit(c: u32) -> bool {
    (0x30..=0x39).contains(&c)
}

#[inline]
pub fn is_hex(c: u32) -> bool {
    c < 128 && ASCII[c as usize] & C_HEX != 0
}

#[inline]
fn hex_val(c: u32) -> u32 {
    match c {
        0x30..=0x39 => c - 0x30,
        0x61..=0x66 => c - 0x61 + 10,
        _ => c - 0x41 + 10,
    }
}

#[inline]
fn at(s: &[u32], i: usize) -> u32 {
    s.get(i).copied().unwrap_or(NO_CHAR)
}

/// What `at` gives past the end: no character matches it.
const NO_CHAR: u32 = u32::MAX;

const fn c(ch: char) -> u32 {
    ch as u32
}

// ---- the token patterns ----

/// _ESC at `i` (a backslash): `\uXXXX` or `\u{X…}`; its end.
/// (The alternatives: four hex digits, else a brace; `\u{` without hex
/// digits and a closing brace is no escape.)
pub fn esc_end(s: &[u32], i: usize) -> Option<usize> {
    if at(s, i + 1) != c('u') {
        return None;
    }
    let j = i + 2;
    if j + 4 <= s.len() && s[j..j + 4].iter().all(|&x| is_hex(x)) {
        return Some(j + 4);
    }
    if at(s, j) == c('{') {
        let mut k = j + 1;
        while k < s.len() && is_hex(s[k]) {
            k += 1;
        }
        if k > j + 1 && at(s, k) == c('}') {
            return Some(k + 1);
        }
    }
    None
}

/// _IDENT_RE.match(s, b): its end and whether it holds an escape.
/// (`(?:[ID_START]|ESC)[ID_PART]*(?:ESC[ID_PART]*)*`: the parts run as far
/// as they go; at a backslash an escape continues the name, and one that
/// does not match ends it before the backslash.)
pub fn ident_end(s: &[u32], b: usize) -> Option<(usize, bool)> {
    let n = s.len();
    let mut i = b;
    let mut esc = false;
    let first = at(s, i);
    if is_id_start(first) {
        i += 1;
    } else if first == c('\\') {
        i = esc_end(s, i)?;
        esc = true;
    } else {
        return None;
    }
    loop {
        while i < n && is_id_part(s[i]) {
            i += 1;
        }
        if i < n && s[i] == c('\\') {
            if let Some(j) = esc_end(s, i) {
                i = j;
                esc = true;
                continue;
            }
        }
        return Some((i, esc));
    }
}

/// The value of a code point's hex digits, U+FFFD past U+10FFFF
/// (`chr(cp) if cp <= 0x10FFFF else "�"`).
fn hex_code_point(digits: &[u32]) -> u32 {
    let mut v: u32 = 0;
    for &d in digits {
        v = v.saturating_mul(16).saturating_add(hex_val(d));
        if v > 0x10FFFF {
            v = 0x110000; // (stays past the range: more digits only add to it)
        }
    }
    if v <= 0x10FFFF {
        v
    } else {
        0xFFFD
    }
}

/// `_ESC_RE.sub(_unescape_ident_one, text)` then `_utf16`, into `out`.
pub fn unescape_ident(text: &[u32], out: &mut Vec<u32>) {
    out.clear();
    let mut i = 0;
    while i < text.len() {
        if text[i] == c('\\') {
            if let Some(j) = esc_end(text, i) {
                let digits = if text[i + 2] == c('{') { &text[i + 3..j - 1] } else { &text[i + 2..j] };
                out.push(hex_code_point(digits));
                i = j;
                continue;
            }
        }
        out.push(text[i]);
        i += 1;
    }
    pair_surrogates(out);
}

/// _utf16: the text as a JavaScript string holds it (a high surrogate
/// followed by a low one is the one character they encode).
pub fn pair_surrogates(s: &mut Vec<u32>) {
    if !s.iter().any(|&x| (0xD800..0xE000).contains(&x)) {
        return;
    }
    let mut w = 0;
    let mut r = 0;
    while r < s.len() {
        let x = s[r];
        if (0xD800..0xDC00).contains(&x) && r + 1 < s.len() && (0xDC00..0xE000).contains(&s[r + 1]) {
            s[w] = 0x10000 + ((x - 0xD800) << 10) + (s[r + 1] - 0xDC00);
            r += 2;
        } else {
            s[w] = x;
            r += 1;
        }
        w += 1;
    }
    s.truncate(w);
}

/// _NUM_RE.match(s, b) where s[b] is a digit, or a dot and a digit: its end.
/// (`0[xX]…`, `0[oO]…` and `0[bB]…` are taken by the two characters that
/// start them; otherwise digits, an optional fraction, an optional
/// exponent — which needs a digit or `_` after its sign, else it is not
/// taken — and an optional `n`.)
pub fn number_end(s: &[u32], b: usize) -> usize {
    let n = s.len();
    let c0 = s[b];
    let c1 = at(s, b + 1);
    let run = |mut i: usize, ok: &dyn Fn(u32) -> bool| {
        while i < n && ok(s[i]) {
            i += 1;
        }
        i
    };
    let opt_n = |i: usize| if at(s, i) == c('n') { i + 1 } else { i };
    if c0 == c('0') {
        if c1 == c('x') || c1 == c('X') {
            return opt_n(run(b + 2, &|x| is_hex(x) || x == c('_')));
        }
        if c1 == c('o') || c1 == c('O') {
            return opt_n(run(b + 2, &|x| (0x30..=0x37).contains(&x) || x == c('_')));
        }
        if c1 == c('b') || c1 == c('B') {
            return opt_n(run(b + 2, &|x| x == c('0') || x == c('1') || x == c('_')));
        }
    }
    let digit_ = |x: u32| is_digit(x) || x == c('_');
    let mut i;
    if is_digit(c0) {
        i = run(b + 1, &digit_);
        if at(s, i) == c('.') {
            i = run(i + 1, &digit_);
        }
    } else {
        // `.` and a digit
        i = run(b + 2, &digit_);
    }
    let e = at(s, i);
    if e == c('e') || e == c('E') {
        let mut j = i + 1;
        let sign = at(s, j);
        if sign == c('+') || sign == c('-') {
            j += 1;
        }
        if digit_(at(s, j)) {
            i = run(j + 1, &digit_);
        }
    }
    opt_n(i)
}

/// _STR_RE[q].match(s, b) where s[b] is the quote: the end, past the
/// closing quote; None when the string is not closed on its line.
/// (`q[^q\\\n\r]*(?:\\(?:\r\n|[\s\S])[^q\\\n\r]*)*q`: a backslash takes the
/// next character, CRLF as one; a bare CR or LF, or the end, has no match.)
pub fn string_end(s: &[u32], b: usize) -> Option<usize> {
    let q = s[b];
    let n = s.len();
    let mut i = b + 1;
    while i < n {
        let x = s[i];
        if x == q {
            return Some(i + 1);
        }
        if x == c('\\') {
            if i + 1 >= n {
                return None;
            }
            if s[i + 1] == c('\r') && at(s, i + 2) == c('\n') {
                i += 3;
            } else {
                i += 2;
            }
            continue;
        }
        if x == 0x0A || x == 0x0D {
            return None;
        }
        i += 1;
    }
    None
}

/// _COOK_RE.sub(_cook_one, raw) and _utf16, into `out` (the caller checks
/// that `raw` holds a backslash: without one jsparse.py keeps it as it is).
/// (At each backslash the alternatives in order: `u{X+}`, `uXXXX`, `xXX`,
/// one to three octal digits, CRLF, any one character.)
pub fn cook(raw: &[u32], out: &mut Vec<u32>) {
    out.clear();
    let n = raw.len();
    let mut i = 0;
    while i < n {
        let x = raw[i];
        if x != c('\\') || i + 1 >= n {
            out.push(x);
            i += 1;
            continue;
        }
        let j = i + 1;
        let d = raw[j];
        if d == c('u') {
            if at(raw, j + 1) == c('{') {
                let mut k = j + 2;
                while k < n && is_hex(raw[k]) {
                    k += 1;
                }
                if k > j + 2 && at(raw, k) == c('}') {
                    out.push(hex_code_point(&raw[j + 2..k]));
                    i = k + 1;
                    continue;
                }
            }
            if j + 5 <= n && raw[j + 1..j + 5].iter().all(|&h| is_hex(h)) {
                out.push(raw[j + 1..j + 5].iter().fold(0, |v, &h| v * 16 + hex_val(h)));
                i = j + 5;
                continue;
            }
        } else if d == c('x') {
            if j + 3 <= n && is_hex(raw[j + 1]) && is_hex(raw[j + 2]) {
                out.push(hex_val(raw[j + 1]) * 16 + hex_val(raw[j + 2]));
                i = j + 3;
                continue;
            }
        } else if (0x30..=0x37).contains(&d) {
            let mut k = j;
            while k < n && k < j + 3 && (0x30..=0x37).contains(&raw[k]) {
                k += 1;
            }
            let digits = &raw[j..k];
            let v = digits.iter().fold(0, |v, &o| v * 8 + (o - 0x30));
            if v > 255 {
                // \400 is \40, then "0"
                out.push((digits[0] - 0x30) * 8 + (digits[1] - 0x30));
                out.extend_from_slice(&digits[2..]);
            } else {
                out.push(v);
            }
            i = k;
            continue;
        }
        // (\r\n|[\s\S])
        if d == c('\r') && at(raw, j + 1) == c('\n') {
            i = j + 2; // a line continuation
            continue;
        }
        i = j + 1;
        if is_lt(d) {
            continue; // a line continuation
        }
        out.push(match d {
            0x6E => 0x0A, // n
            0x72 => 0x0D, // r
            0x74 => 0x09, // t
            0x62 => 0x08, // b
            0x66 => 0x0C, // f
            0x76 => 0x0B, // v
            _ => d,
        });
    }
    pair_surrogates(out);
}

/// _TMPL_RE.match(s, pos): the end of a template chunk's text.
/// (`[^`\\$]*(?:(?:\\[\s\S]|\$(?!\{))[^`\\$]*)*`: a backslash takes the
/// next character — at the end it is left out —, a `$` not before `{` is
/// text; it stops at a backtick or `${`.)
pub fn template_end(s: &[u32], pos: usize) -> usize {
    let n = s.len();
    let mut i = pos;
    while i < n {
        let x = s[i];
        if x == c('`') {
            break;
        }
        if x == c('\\') {
            if i + 1 >= n {
                break;
            }
            i += 2;
            continue;
        }
        if x == c('$') && at(s, i + 1) == c('{') {
            break;
        }
        i += 1;
    }
    i
}

/// _REGEX_RE.match(s, b) where s[b] is `/`: (the closing slash, the end
/// past the flags); None when it is not closed on its line.
/// (Body: characters but `/ \ [` and line terminators; a backslash takes
/// any character but a line terminator; a class `[…]` takes anything to
/// its `]` but a line terminator, a backslash in it taking the next
/// character. Each is chosen by its first character, and a failed escape
/// or class cannot be read any other way. Flags: [ID_PART]*.)
pub fn regex_end(s: &[u32], b: usize) -> Option<(usize, usize)> {
    let n = s.len();
    let mut i = b + 1;
    loop {
        if i >= n {
            return None;
        }
        let x = s[i];
        if x == c('/') {
            break;
        }
        if is_lt(x) {
            return None;
        }
        if x == c('\\') {
            if i + 1 >= n || is_lt(s[i + 1]) {
                return None;
            }
            i += 2;
            continue;
        }
        if x == c('[') {
            i += 1;
            loop {
                if i >= n {
                    return None;
                }
                let y = s[i];
                if y == c(']') {
                    i += 1;
                    break;
                }
                if is_lt(y) {
                    return None;
                }
                if y == c('\\') {
                    if i + 1 >= n || is_lt(s[i + 1]) {
                        return None;
                    }
                    i += 2;
                    continue;
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    let close = i;
    let mut e = close + 1;
    while e < n && is_id_part(s[e]) {
        e += 1;
    }
    Some((close, e))
}

/// _PUNCT_RE.match(s, b): (the punctuator's literal id, its length).
/// (Its alternatives are ordered longest first within each first character.)
pub fn punct(s: &[u32], b: usize) -> Option<(u32, usize)> {
    let c1 = at(s, b + 1);
    let c2 = at(s, b + 2);
    let x = s[b];
    let r = match char::from_u32(x).unwrap_or('\0') {
        '.' => {
            if c1 == c('.') && c2 == c('.') {
                (P_ELLIPSIS, 3)
            } else {
                (P_DOT, 1)
            }
        }
        '=' => {
            if c1 == c('=') && c2 == c('=') {
                (P_SEQ, 3)
            } else if c1 == c('>') {
                (P_ARROW, 2)
            } else if c1 == c('=') {
                (P_EQ, 2)
            } else {
                (P_ASSIGN, 1)
            }
        }
        '!' => {
            if c1 == c('=') && c2 == c('=') {
                (P_SNE, 3)
            } else if c1 == c('=') {
                (P_NE, 2)
            } else {
                (P_BANG, 1)
            }
        }
        '*' => {
            if c1 == c('*') && c2 == c('=') {
                (P_POW_ASSIGN, 3)
            } else if c1 == c('=') {
                (P_MUL_ASSIGN, 2)
            } else if c1 == c('*') {
                (P_POW, 2)
            } else {
                (P_STAR, 1)
            }
        }
        '<' => {
            if c1 == c('<') && c2 == c('=') {
                (P_SHL_ASSIGN, 3)
            } else if c1 == c('=') {
                (P_LE, 2)
            } else if c1 == c('<') {
                (P_SHL, 2)
            } else {
                (P_LT, 1)
            }
        }
        '&' => {
            if c1 == c('&') && c2 == c('=') {
                (P_AND_ASSIGN, 3)
            } else if c1 == c('&') {
                (P_AND, 2)
            } else if c1 == c('=') {
                (P_BITAND_ASSIGN, 2)
            } else {
                (P_BITAND, 1)
            }
        }
        '|' => {
            if c1 == c('|') && c2 == c('=') {
                (P_OR_ASSIGN, 3)
            } else if c1 == c('|') {
                (P_OR, 2)
            } else if c1 == c('=') {
                (P_BITOR_ASSIGN, 2)
            } else {
                (P_BITOR, 1)
            }
        }
        '?' => {
            if c1 == c('?') && c2 == c('=') {
                (P_NULLISH_ASSIGN, 3)
            } else if c1 == c('?') {
                (P_NULLISH, 2)
            } else if c1 == c('.') && !is_digit(c2) {
                (P_OPTIONAL, 2)
            } else {
                (P_QUESTION, 1)
            }
        }
        '+' => {
            if c1 == c('+') {
                (P_INC, 2)
            } else if c1 == c('=') {
                (P_ADD_ASSIGN, 2)
            } else {
                (P_PLUS, 1)
            }
        }
        '-' => {
            if c1 == c('-') {
                (P_DEC, 2)
            } else if c1 == c('=') {
                (P_SUB_ASSIGN, 2)
            } else {
                (P_MINUS, 1)
            }
        }
        '/' => {
            if c1 == c('=') {
                (P_DIV_ASSIGN, 2)
            } else {
                (P_SLASH, 1)
            }
        }
        '%' => {
            if c1 == c('=') {
                (P_MOD_ASSIGN, 2)
            } else {
                (P_PERCENT, 1)
            }
        }
        '^' => {
            if c1 == c('=') {
                (P_XOR_ASSIGN, 2)
            } else {
                (P_CARET, 1)
            }
        }
        '>' => (P_GT, 1),
        '{' => (P_LBRACE, 1),
        '}' => (P_RBRACE, 1),
        '(' => (P_LPAREN, 1),
        ')' => (P_RPAREN, 1),
        '[' => (P_LBRACK, 1),
        ']' => (P_RBRACK, 1),
        ';' => (P_SEMI, 1),
        ',' => (P_COMMA, 1),
        '~' => (P_TILDE, 1),
        ':' => (P_COLON, 1),
        '@' => (P_AT, 1),
        '#' => (P_HASH, 1),
        _ => return None,
    };
    Some(r)
}

/// _GT_RE.match(s, s0) at a `>`: the operator it starts and its length.
pub fn gt_op(s: &[u32], s0: usize) -> (u32, usize) {
    let c1 = at(s, s0 + 1);
    let c2 = at(s, s0 + 2);
    let c3 = at(s, s0 + 3);
    if c1 == c('>') {
        if c2 == c('>') {
            if c3 == c('=') {
                (P_USHR_ASSIGN, 4)
            } else {
                (P_USHR, 3)
            }
        } else if c2 == c('=') {
            (P_SHR_ASSIGN, 3)
        } else {
            (P_SHR, 2)
        }
    } else if c1 == c('=') {
        (P_GE, 2)
    } else {
        (P_GT, 1)
    }
}

/// _JSX_NAME_RE.match(s, b): `[ID_START][ID_PART\-]*`; its end.
pub fn jsx_name_end(s: &[u32], b: usize) -> Option<usize> {
    if !is_id_start(at(s, b)) {
        return None;
    }
    let mut i = b + 1;
    while i < s.len() && (is_id_part(s[i]) || s[i] == c('-')) {
        i += 1;
    }
    Some(i)
}

/// `'text'` as jsparse.py's _quote writes it.
pub fn quote(text: &[u32], out: &mut Vec<u32>) {
    out.push(c('\''));
    for &x in text {
        if x == c('\\') {
            out.push(x);
            out.push(x);
        } else if x == c('\'') {
            out.push(c('\\'));
            out.push(x);
        } else {
            out.push(x);
        }
    }
    out.push(c('\''));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    #[test]
    fn literal_ids() {
        assert_eq!(LITERALS[P_GT as usize], ">");
        assert_eq!(LITERALS[W_IN as usize], "in");
        assert_eq!(LITERALS[W_REQUIRE as usize], "require");
        let mut seen = std::collections::HashSet::new();
        for l in LITERALS {
            assert!(seen.insert(*l), "duplicate literal {}", l);
        }
    }

    #[test]
    fn numbers() {
        let end = |s: &str| number_end(&cp(s), 0);
        assert_eq!(end("0x1Fn;"), 5);
        assert_eq!(end("0b12"), 3);
        assert_eq!(end("1e+x"), 1);
        assert_eq!(end("1e_"), 3);
        assert_eq!(end("1.e5n"), 5);
        assert_eq!(end(".5e-3"), 5);
        assert_eq!(end("5..3"), 2);
        assert_eq!(end("0_1"), 3);
    }

    #[test]
    fn cooking() {
        let mut out = Vec::new();
        cook(&cp("a\\n\\x41\\u0042\\u{1F600}\\101\\\ncont\\q"), &mut out);
        assert_eq!(out, cp("a\nAB\u{1F600}Acontq"));
        cook(&cp("\\uD83D\\uDE00"), &mut out);
        assert_eq!(out, vec![0x1F600]);
        cook(&cp("\\400\\08\\u{110000}\\u{zz}\\x4"), &mut out);
        assert_eq!(out, cp(" 0\u{0}8\u{FFFD}u{zz}x4"));
    }
}
