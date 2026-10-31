//! An .npy header read as numpy reads it (H1, the external review of Oct 21): `ast.literal_eval` of its text (string
//! escapes, implicit concatenation, comments, a duplicate key's last value, Python 2's `3L`), and its `descr` read by
//! numpy's dtype grammar (`numpy.lib.format.descr_to_dtype`: a dtype string, a (dtype, shape) tuple, a structured
//! list at any depth; a string's type codes and names, byte order, sizes, a subarray's shape, comma-separated
//! fields). What holds an object is Object (its array is a pickle); what is numeric for certain is Plain; anything
//! the reader cannot place for certain is Unknown, never Plain.

/// A Python literal of an .npy header.
#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    /// a str's code points
    Str(Vec<u32>),
    Bytes(Vec<u8>),
    Int,
    /// a float, a complex, True, False, None
    Other,
    Tuple(Vec<Lit>),
    List(Vec<Lit>),
    Set(Vec<Lit>),
    Dict(Vec<(Lit, Lit)>),
}

/// What a dtype holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DClass {
    Plain,
    Object,
    Unknown,
}

fn worst(a: DClass, b: DClass) -> DClass {
    match (a, b) {
        (DClass::Object, _) | (_, DClass::Object) => DClass::Object,
        (DClass::Unknown, _) | (_, DClass::Unknown) => DClass::Unknown,
        _ => DClass::Plain,
    }
}

const MAX_DEPTH: usize = 64;

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    /// White space, comments and a backslash at a line's end (inside brackets lines join anyway).
    fn ws(&mut self) {
        loop {
            match self.s.get(self.i) {
                Some(b' ' | b'\t' | b'\x0c' | b'\n' | b'\r') => self.i += 1,
                Some(b'#') => {
                    while self.i < self.s.len() && !matches!(self.s[self.i], b'\n' | b'\r') {
                        self.i += 1;
                    }
                }
                Some(b'\\') if matches!(self.s.get(self.i + 1), Some(b'\n' | b'\r')) => self.i += 2,
                _ => return,
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<Lit> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        let c = *self.s.get(self.i)?;
        match c {
            b'(' | b'[' | b'{' => self.container(c, depth),
            b'+' | b'-' => {
                self.i += 1;
                match self.value(depth + 1)? {
                    v @ (Lit::Int | Lit::Other) => Some(v),
                    _ => None,
                }
            }
            b'0'..=b'9' | b'.' => self.number(),
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                // a string's prefix, or a name
                let start = self.i;
                while self.i < self.s.len() && (self.s[self.i].is_ascii_alphanumeric() || self.s[self.i] == b'_') {
                    self.i += 1;
                }
                let word = &self.s[start..self.i];
                if matches!(self.s.get(self.i), Some(b'\'' | b'"')) {
                    self.i = start;
                    return self.strings();
                }
                match word {
                    b"True" | b"False" | b"None" => Some(Lit::Other),
                    _ => None,
                }
            }
            b'\'' | b'"' => self.strings(),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<Lit> {
        let start = self.i;
        let mut float = false;
        while let Some(&c) = self.s.get(self.i) {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
                if c == b'.' || ((c == b'e' || c == b'E') && !self.s[start..self.i].starts_with(b"0x")) {
                    float = true;
                }
                if (c == b'e' || c == b'E') && matches!(self.s.get(self.i + 1), Some(b'+' | b'-')) && float {
                    self.i += 1;
                }
                self.i += 1;
            } else {
                break;
            }
        }
        let t = &self.s[start..self.i];
        let t = t.strip_suffix(b"L").or(t.strip_suffix(b"l")).unwrap_or(t);   // (an old header's 3L: _filter_header)
        if t.is_empty() {
            return None;
        }
        if t.ends_with(b"j") || t.ends_with(b"J") || float {
            return Some(Lit::Other);
        }
        let digits = |b: &[u8], radix: u32| !b.is_empty() && b.iter().all(|&c| c == b'_' || (c as char).is_digit(radix));
        let ok = match t {
            [b'0', b'x' | b'X', rest @ ..] => digits(rest, 16),
            [b'0', b'o' | b'O', rest @ ..] => digits(rest, 8),
            [b'0', b'b' | b'B', rest @ ..] => digits(rest, 2),
            _ => digits(t, 10),
        };
        ok.then_some(Lit::Int)
    }

    fn container(&mut self, open: u8, depth: usize) -> Option<Lit> {
        let close = match open {
            b'(' => b')',
            b'[' => b']',
            _ => b'}',
        };
        self.i += 1;
        let mut items = Vec::new();
        let mut pairs = Vec::new();
        let mut commas = 0;
        let mut set = false;
        loop {
            self.ws();
            if self.s.get(self.i) == Some(&close) {
                self.i += 1;
                break;
            }
            let v = self.value(depth + 1)?;
            self.ws();
            if open == b'{' {
                if self.s.get(self.i) == Some(&b':') && !set {
                    self.i += 1;
                    let w = self.value(depth + 1)?;
                    pairs.push((v, w));
                } else if pairs.is_empty() {
                    set = true;
                    items.push(v);
                } else {
                    return None;
                }
            } else {
                items.push(v);
            }
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                    commas += 1;
                }
                Some(&d) if d == close => {}
                _ => return None,
            }
        }
        Some(match open {
            // (a parenthesized value, or a tuple: a comma makes one)
            b'(' if items.len() == 1 && commas == 0 => items.pop()?,
            b'(' => Lit::Tuple(items),
            b'[' => Lit::List(items),
            _ if set => Lit::Set(items),
            _ => Lit::Dict(pairs),
        })
    }

    /// One or more string literals, side by side (Python joins them; a str and a bytes cannot be).
    fn strings(&mut self) -> Option<Lit> {
        let mut text: Option<Vec<u32>> = None;
        let mut bytes: Option<Vec<u8>> = None;
        loop {
            self.ws();
            let start = self.i;
            while self.i < self.s.len() && self.s[self.i].is_ascii_alphabetic() {
                self.i += 1;
            }
            let prefix: Vec<u8> = self.s[start..self.i].to_ascii_lowercase();
            if !matches!(self.s.get(self.i), Some(b'\'' | b'"')) {
                self.i = start;
                break;
            }
            let (raw, is_bytes) = match prefix.as_slice() {
                b"" | b"u" => (false, false),
                b"r" => (true, false),
                b"b" => (false, true),
                b"br" | b"rb" => (true, true),
                _ => return None,                                  // (an f-string is no literal)
            };
            let q = self.s[self.i];
            let triple = self.s.get(self.i..self.i + 3) == Some(&[q, q, q][..]);
            self.i += if triple { 3 } else { 1 };
            let mut out: Vec<u32> = Vec::new();
            loop {
                let c = *self.s.get(self.i)?;
                if c == q && (!triple || self.s.get(self.i..self.i + 3) == Some(&[q, q, q][..])) {
                    self.i += if triple { 3 } else { 1 };
                    break;
                }
                if !triple && (c == b'\n' || c == b'\r') {
                    return None;
                }
                if is_bytes && c >= 0x80 {
                    return None;                                   // (bytes literals hold ASCII only)
                }
                self.i += 1;
                if c != b'\\' {
                    out.push(c as u32);
                    continue;
                }
                let e = *self.s.get(self.i)?;
                if raw {
                    // a raw string keeps the backslash; it only keeps a quote from ending the string
                    out.push(b'\\' as u32);
                    out.push(e as u32);
                    self.i += 1;
                    continue;
                }
                self.i += 1;
                match e {
                    b'\n' => {}
                    b'\r' => {
                        if self.s.get(self.i) == Some(&b'\n') {
                            self.i += 1;
                        }
                    }
                    b'\\' | b'\'' | b'"' => out.push(e as u32),
                    b'a' => out.push(7),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'n' => out.push(10),
                    b'r' => out.push(13),
                    b't' => out.push(9),
                    b'v' => out.push(11),
                    b'0'..=b'7' => {
                        let mut v = (e - b'0') as u32;
                        for _ in 0..2 {
                            match self.s.get(self.i) {
                                Some(&d @ b'0'..=b'7') => {
                                    v = v * 8 + (d - b'0') as u32;
                                    self.i += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push(if is_bytes { v & 0xff } else { v });
                    }
                    b'x' => out.push(self.hex(2)?),
                    b'u' if !is_bytes => out.push(self.hex(4)?),
                    b'U' if !is_bytes => {
                        let v = self.hex(8)?;
                        char::from_u32(v)?;
                        out.push(v);
                    }
                    // \N{NAME}: a character by its Unicode name, which the reader does not hold
                    b'N' if !is_bytes => return None,
                    other => {
                        out.push(b'\\' as u32);
                        out.push(other as u32);
                    }
                }
            }
            if is_bytes {
                if text.is_some() {
                    return None;
                }
                bytes.get_or_insert_with(Vec::new).extend(out.iter().map(|&c| c as u8));
            } else {
                if bytes.is_some() {
                    return None;
                }
                text.get_or_insert_with(Vec::new).extend(out);
            }
        }
        match (text, bytes) {
            (Some(t), None) => Some(Lit::Str(t)),
            (None, Some(b)) => Some(Lit::Bytes(b)),
            _ => None,
        }
    }

    fn hex(&mut self, n: usize) -> Option<u32> {
        let h = self.s.get(self.i..self.i + n)?;
        let v = u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
        self.i += n;
        Some(v)
    }
}

/// `ast.literal_eval` of an .npy header (latin-1 text), or None when it is not a literal the reader reads.
pub fn parse(header: &[u8]) -> Option<Lit> {
    let mut p = P { s: header, i: 0 };
    let v = p.value(0)?;
    p.ws();
    (p.i == header.len() || header[p.i..].iter().all(|&c| c == 0)).then_some(v)
}

fn key_is(k: &Lit, name: &str) -> bool {
    matches!(k, Lit::Str(s) if s.iter().copied().eq(name.chars().map(|c| c as u32)))
}

/// What an .npy header's dtype holds: Ok(true) objects (its array is a pickle), Ok(false) none for certain, Err(why)
/// the reader cannot tell. The header must be a dict of exactly numpy's three keys (a key's last value counts).
pub fn header_has_object(header: &[u8]) -> Result<bool, String> {
    let Some(Lit::Dict(pairs)) = parse(header) else {
        return Err("an .npy header that is not a literal dict the reader reads".into());
    };
    let mut descr = None;
    for (k, v) in &pairs {
        if key_is(k, "descr") {
            descr = Some(v);                                       // (Python's dict keeps a key's last value)
        } else if !key_is(k, "fortran_order") && !key_is(k, "shape") {
            return Err("an .npy header with a key numpy does not write".into());
        }
    }
    match descr.map(|d| descr_class(d, 0)) {
        Some(DClass::Object) => Ok(true),
        Some(DClass::Plain) => Ok(false),
        Some(DClass::Unknown) => Err("an .npy header whose dtype the reader cannot place".into()),
        None => Err("an .npy header without a dtype".into()),
    }
}

fn is_shape(v: &Lit) -> bool {
    match v {
        Lit::Int => true,
        Lit::Tuple(items) => items.iter().all(|x| *x == Lit::Int),
        _ => false,
    }
}

/// numpy's descr_to_dtype: a dtype string; (dtype, shape); a list of fields, each (name, dtype) or (name, dtype,
/// shape), a name a string or a (title, name) pair.
pub fn descr_class(d: &Lit, depth: usize) -> DClass {
    if depth > MAX_DEPTH {
        return DClass::Unknown;
    }
    match d {
        Lit::Str(s) => {
            let t: String = s.iter().map(|&c| char::from_u32(c).unwrap_or('\u{fffd}')).collect();
            dtype_str_class(&t)
        }
        Lit::Bytes(b) => dtype_str_class(&b.iter().map(|&c| c as char).collect::<String>()),
        Lit::Tuple(items) if items.len() == 2 => {
            if !is_shape(&items[1]) {
                return worst(descr_class(&items[0], depth + 1), DClass::Unknown);
            }
            descr_class(&items[0], depth + 1)
        }
        Lit::List(fields) => {
            let mut out = DClass::Plain;
            for f in fields {
                let parts = match f {
                    Lit::Tuple(p) | Lit::List(p) => p,
                    _ => return worst(out, DClass::Unknown),
                };
                let name_ok = match parts.first() {
                    Some(Lit::Str(_) | Lit::Bytes(_)) => true,
                    Some(Lit::Tuple(tn)) => tn.len() == 2,
                    _ => false,
                };
                let c = match parts.len() {
                    2 => descr_class(&parts[1], depth + 1),
                    3 if is_shape(&parts[2]) => descr_class(&parts[1], depth + 1),
                    3 => worst(descr_class(&parts[1], depth + 1), DClass::Unknown),
                    _ => DClass::Unknown,
                };
                out = worst(out, if name_ok { c } else { worst(c, DClass::Unknown) });
            }
            out
        }
        _ => DClass::Unknown,
    }
}

/// The names numpy's dtype() takes for types that hold no object (its type codes aside).
const PLAIN_NAMES: &[&str] = &[
    "bool", "bool_", "bool8", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64", "float16",
    "float32", "float64", "float96", "float128", "complex64", "complex128", "complex192", "complex256", "half",
    "single", "double", "longdouble", "longfloat", "csingle", "cdouble", "clongdouble", "clongfloat", "singlecomplex",
    "complex_", "cfloat", "longcomplex", "byte", "ubyte", "short", "ushort", "intc", "uintc", "int", "int_", "uint",
    "long", "ulong", "longlong", "ulonglong", "intp", "uintp", "int0", "uint0", "float", "float_", "complex", "str",
    "str_", "unicode", "unicode_", "bytes", "bytes_", "string_", "void", "void0", "datetime64", "timedelta64", "a",
];

/// A dtype string as numpy's dtype() reads it: comma-separated fields, each an optional subarray shape (`(2,3)` or a
/// count), an optional byte order, and a type code with its size (and a datetime's unit) or a type's name.
pub fn dtype_str_class(s: &str) -> DClass {
    // fields: commas outside a subarray's parentheses
    let mut fields = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    for (k, c) in s.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                fields.push(&s[start..k]);
                start = k + 1;
            }
            _ => {}
        }
    }
    fields.push(&s[start..]);
    let many = fields.len() > 1;
    let mut out = DClass::Plain;
    let mut any = false;
    for f in fields {
        let f = f.trim();
        if f.is_empty() && many {
            continue;                                              // ('f8,': one field)
        }
        any = true;
        out = worst(out, one_dtype(f));
    }
    if any { out } else { DClass::Unknown }
}

fn one_dtype(f: &str) -> DClass {
    let mut t = f.trim();
    // a subarray: "(2,3)" or a count before the type
    if let Some(rest) = t.strip_prefix('(') {
        let Some(k) = rest.find(')') else { return DClass::Unknown };
        if !rest[..k].chars().all(|c| c.is_ascii_digit() || c == ',' || c == ' ') {
            return DClass::Unknown;
        }
        t = rest[k + 1..].trim_start();
    } else {
        let n = t.chars().take_while(|c| c.is_ascii_digit()).count();
        if n > 0 && n < t.len() {
            t = &t[n..];
        }
    }
    let t = t.strip_prefix(['<', '>', '|', '=', '!']).unwrap_or(t).trim();
    if t.is_empty() {
        return DClass::Unknown;
    }
    // an object: O, O4, O8, and its names
    if t.starts_with('O') && t[1..].chars().all(|c| c.is_ascii_digit()) {
        return DClass::Object;
    }
    if matches!(t, "object" | "object_" | "object0") {
        return DClass::Object;
    }
    // a datetime's or a timedelta's unit
    let (base, unit) = match t.find('[') {
        Some(k) if t.ends_with(']') => (&t[..k], Some(&t[k + 1..t.len() - 1])),
        Some(_) => return DClass::Unknown,
        None => (t, None),
    };
    if unit.is_some_and(|u| !u.chars().all(|c| c.is_ascii_alphanumeric())) {
        return DClass::Unknown;
    }
    let mut cs = base.chars();
    let code = cs.next().unwrap_or(' ');
    let size = cs.as_str();
    if "?bBhHiIlLqQpPnNefdgFDGSaUVcmMu".contains(code) && size.chars().all(|c| c.is_ascii_digit())
        && (unit.is_none() || matches!(code, 'm' | 'M'))
    {
        return DClass::Plain;
    }
    if PLAIN_NAMES.contains(&base) && (unit.is_none() || matches!(base, "datetime64" | "timedelta64")) {
        return DClass::Plain;
    }
    DClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Result<bool, String> {
        header_has_object(s.as_bytes())
    }

    #[test]
    fn the_headers_numpy_writes() {
        assert_eq!(h("{'descr': '<f8', 'fortran_order': False, 'shape': (3,), }"), Ok(false));
        assert_eq!(h("{'descr': '|O', 'fortran_order': False, 'shape': (3,), }      \n"), Ok(true));
        assert_eq!(h("{'descr': '<M8[ns]', 'fortran_order': False, 'shape': (2, 2), }"), Ok(false));
        assert_eq!(h("{'descr': [('a', '<f8'), ('b', [('c', '<i4')]), ('d', '<f4', (2, 3))], 'fortran_order': False, 'shape': (1,), }"), Ok(false));
        assert_eq!(h("{'descr': [('a', '<f8'), ('o', '|O')], 'fortran_order': False, 'shape': (1,), }"), Ok(true));
        // Python 2's: 3L, u'' and a trailing NUL padding
        assert_eq!(h("{'descr': u'<f8', 'fortran_order': False, 'shape': (3L, 4L), }"), Ok(false));
        assert_eq!(h("{'descr': '<U5', 'fortran_order': True, 'shape': (), }\x00\x00"), Ok(false));
    }

    #[test]
    fn every_way_to_write_an_object_is_an_object() {
        for d in ["'object'", "'(1,)O'", "'3O'", r"'\x4f'", r"'\117'", r"'O'", r"'\U0000004f'", "'O8'", "'=O'",
                  "'i8,O'", "'(2,3)i8, O'", "('O', (2,))", "[('x', 'object')]", r"[('x', '\x4f')]", "[(('t', 'x'), 'O')]",
                  "[('x', [('y', [('z', 'O')])])]", "'O' ''", "b'|O'", "'o' 'bject'", "[('x', 'O', (2,))]", "'object_'"] {
            assert_eq!(h(&format!("{{'descr': {d}, 'fortran_order': False, 'shape': (1,)}}")), Ok(true), "{d}");
        }
        // a duplicate key: Python's dict keeps the last
        assert_eq!(h("{'descr':'<i8', 'descr':'|O', 'fortran_order':False, 'shape':(1,)}"), Ok(true));
        assert_eq!(h("{'descr':'|O', 'descr':'<i8', 'fortran_order':False, 'shape':(1,)}"), Ok(false));
        // a key written with escapes is the key; a comment, a line joined
        assert_eq!(h("{'\\x64escr': 'O', 'fortran_order': False, 'shape': (1,)}"), Ok(true));
        assert_eq!(h("{'descr': # a comment\n 'O', 'fortran_order': False, 'shape': (1,)}"), Ok(true));
    }

    #[test]
    fn what_cannot_be_placed_is_not_plain() {
        for d in ["'T'", "'Object'", "'f8[ns]'", "'xyz'", "{'names': ['a'], 'formats': ['O']}", "'(a)f8'", "('f8', 'x')",
                  r"'\N{LATIN CAPITAL LETTER O}'", "1", "[('x',)]"] {
            assert!(h(&format!("{{'descr': {d}, 'fortran_order': False, 'shape': (1,)}}")).is_err(), "{d}");
        }
        assert!(h("{'descr': '<f8', 'fortran_order': False, 'shape': (1,), 'extra': 1}").is_err());
        assert!(h("{'descr': f'<f8', 'fortran_order': False, 'shape': (1,)}").is_err());
        assert!(h("{'fortran_order': False, 'shape': (1,)}").is_err());
        assert!(h("not a dict").is_err());
    }
}
