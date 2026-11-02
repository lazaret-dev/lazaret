//! The parser: `go/parser`'s grammar (Go 1.24's `parser.go`, function for function) over [`Scanner`]'s tokens,
//! building a [`Tree`] in `go/ast`'s shapes.
//!
//! `go/parser` goes on after an error and returns a tree with `BadExpr`s in it together with the list of errors; this
//! one stops at the first (every `p.error` of `go/parser` is a failure here, so a file is accepted exactly when
//! `go/parser` accepts it, and the tree of an accepted file has no `Bad*` node). Nothing recovers, so there is no
//! `advance`, no `safePos`, and the position of the error is the token it was found at.
//!
//! Recursion is bounded by [`MAX_DEPTH`]: statements, expressions (a unary operand), types and composite literals
//! count one each (`go/parser`'s `incNestLev` counts the same places, with a limit of 100,000). The postfix
//! operations of a primary expression, the operands of a binary expression and the `else if`s of a chain are loops,
//! not recursion, so a chain of any length costs no depth, as it costs none in the stack.
//!
//! Positions are code-point offsets and each node holds the `Pos()` and `End()` that `go/ast` computes for it.

use super::scan::{Scanner, Tok};
use super::tree::*;

/// Nested statements, expressions, types and composite literals.
pub const MAX_DEPTH: u32 = 256;
/// The longest text read (offsets and ids are u32).
pub const MAX_LEN: usize = (u32::MAX - 16) as usize;

/// A file `go/parser` refuses: where (a code-point offset), and what it was reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub pos: u32,
    pub msg: &'static str,
    /// The token that was wanted (`Tok::Illegal` when the message says it).
    pub want: Tok,
    /// The token that was found.
    pub found: Tok,
}

impl Error {
    /// `expected ';', found '}'`, or the message alone.
    pub fn message(&self) -> String {
        if self.want == Tok::Illegal {
            format!("{} (at '{}')", self.msg, self.found.name())
        } else {
            format!("expected '{}', found '{}'", self.want.name(), self.found.name())
        }
    }
}

type R<T> = Result<T, Error>;

const NIL: [u32; 4] = [NONE; 4];

struct P<'a> {
    sc: Scanner<'a>,
    tok: Tok,
    pos: u32,
    end: u32,
    /// the semicolon is a line break's, not a written one
    implicit: bool,
    tree: Tree,
    /// < 0: in a control clause (a `{` is the block's), >= 0: in an expression
    expr_lev: i32,
    /// parsing a right-hand side: `=` is read as `==`
    in_rhs: bool,
    depth: u32,
}

/// The tree of a Go file, or the first thing `go/parser` would refuse it for.
pub fn parse(src: &[u32]) -> Result<Tree, Error> {
    if src.len() >= MAX_LEN {
        return Err(Error { pos: 0, msg: "text too long", want: Tok::Illegal, found: Tok::Eof });
    }
    let mut p = P {
        sc: Scanner::new(src),
        tok: Tok::Illegal,
        pos: 0,
        end: 0,
        implicit: false,
        tree: Tree::new(),
        expr_lev: 0,
        in_rhs: false,
        depth: 0,
    };
    p.tree.nodes.reserve((src.len() / 6).min(1 << 22) + 16);
    p.next()?;
    let root = p.file()?;
    p.tree.root = root;
    Ok(p.tree)
}

fn is_assign(t: Tok) -> bool {
    matches!(
        t,
        Tok::Define | Tok::Assign | Tok::AddAssign | Tok::SubAssign | Tok::MulAssign | Tok::QuoAssign | Tok::RemAssign
            | Tok::AndAssign | Tok::OrAssign | Tok::XorAssign | Tok::ShlAssign | Tok::ShrAssign | Tok::AndNotAssign
    )
}

/// What `parse_simple_stmt` found: a statement, or the assignment of a range clause (`k, v := range x`) whose parts
/// the `for` takes apart.
enum Simple {
    Stmt(u32),
    Range { lhs: Vec<u32>, op: Tok, x: u32 },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Basic,
    LabelOk,
    RangeOk,
}

impl<'a> P<'a> {
    // ---- tokens ----

    fn next(&mut self) -> R<()> {
        let t = self.sc.scan();
        if let Some((at, msg)) = self.sc.error {
            return Err(Error { pos: at as u32, msg, want: Tok::Illegal, found: t.tok });
        }
        self.tok = t.tok;
        self.pos = t.start;
        self.end = t.end;
        self.implicit = t.implicit;
        Ok(())
    }

    fn fail<T>(&self, msg: &'static str) -> R<T> {
        Err(Error { pos: self.pos, msg, want: Tok::Illegal, found: self.tok })
    }

    fn expected<T>(&self, want: Tok) -> R<T> {
        Err(Error { pos: self.pos, msg: "unexpected token", want, found: self.tok })
    }

    /// Consume `tok`: its (start, end).
    fn expect(&mut self, tok: Tok) -> R<(u32, u32)> {
        if self.tok != tok {
            return self.expected(tok);
        }
        let r = (self.pos, self.end);
        self.next()?;
        Ok(r)
    }

    /// A semicolon is optional before a closing `)` or `}`.
    fn expect_semi(&mut self) -> R<()> {
        if self.tok == Tok::Rparen || self.tok == Tok::Rbrace {
            return Ok(());
        }
        if self.tok == Tok::Semicolon {
            return self.next();
        }
        self.expected(Tok::Semicolon)
    }

    /// Is the next token the comma of a list closed by `follow`? Anything else than the end is an error (a comma
    /// missing at a line break, as `go/parser` reports it).
    fn at_comma(&mut self, follow: Tok) -> R<bool> {
        if self.tok == Tok::Comma {
            return Ok(true);
        }
        if self.tok != follow {
            return self.fail("missing ','");
        }
        Ok(false)
    }

    fn enter(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.fail("exceeded max nesting depth");
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    // ---- nodes ----

    fn add(&mut self, kind: Kind, op: u8, flags: u8, start: u32, end: u32, f: [u32; 4]) -> u32 {
        self.tree.add(kind, op, flags, start, end, f)
    }

    fn st(&self, id: u32) -> u32 {
        self.tree.nodes[id as usize].start
    }

    fn en(&self, id: u32) -> u32 {
        self.tree.nodes[id as usize].end
    }

    fn kd(&self, id: u32) -> Kind {
        self.tree.nodes[id as usize].kind
    }

    fn slot(&self, id: u32, k: usize) -> u32 {
        self.tree.nodes[id as usize].f[k]
    }

    fn list(&mut self, v: &[u32]) -> u32 {
        self.tree.list(v)
    }

    /// `ast.Unparen`.
    fn unparen(&self, mut x: u32) -> u32 {
        while self.kd(x) == Kind::ParenExpr {
            x = self.slot(x, 0);
        }
        x
    }

    /// A `FieldList`: with its delimiters (their start and end) or without.
    fn field_list(&mut self, delims: Option<(u32, u32)>, fields: &[u32]) -> u32 {
        let l = self.list(fields);
        match delims {
            Some((s, e)) => self.add(Kind::FieldList, 0, DELIMITED, s, e, [l, NONE, NONE, NONE]),
            None => {
                let (s, e) = (self.st(fields[0]), self.en(*fields.last().unwrap_or(&fields[0])));
                self.add(Kind::FieldList, 0, 0, s, e, [l, NONE, NONE, NONE])
            }
        }
    }

    /// A `Field`: `go/ast`'s Pos is the first name's or the type's, its End the tag's, the type's or the last name's.
    fn field(&mut self, names: &[u32], typ: u32, tag: u32) -> u32 {
        let start = match names.first() {
            Some(&n) => self.st(n),
            None => self.st(typ),
        };
        let end = if tag != NONE {
            self.en(tag)
        } else if typ != NONE {
            self.en(typ)
        } else {
            self.en(names[names.len() - 1])
        };
        let l = self.list(names);
        self.add(Kind::Field, 0, 0, start, end, [l, typ, tag, NONE])
    }

    fn pack_index(&mut self, x: u32, args: &[u32], end: u32) -> u32 {
        let s = self.st(x);
        if args.len() == 1 {
            self.add(Kind::IndexExpr, 0, 0, s, end, [x, args[0], NONE, NONE])
        } else {
            let l = self.list(args);
            self.add(Kind::IndexListExpr, 0, 0, s, end, [x, l, NONE, NONE])
        }
    }

    // ---- identifiers and lists ----

    fn ident(&mut self) -> R<u32> {
        if self.tok != Tok::Ident {
            return self.expected(Tok::Ident);
        }
        let (s, e) = (self.pos, self.end);
        self.next()?;
        Ok(self.add(Kind::Ident, 0, 0, s, e, NIL))
    }

    fn ident_list(&mut self) -> R<Vec<u32>> {
        let mut v = vec![self.ident()?];
        while self.tok == Tok::Comma {
            self.next()?;
            v.push(self.ident()?);
        }
        Ok(v)
    }

    fn expr_list(&mut self) -> R<Vec<u32>> {
        let mut v = vec![self.expr()?];
        while self.tok == Tok::Comma {
            self.next()?;
            v.push(self.expr()?);
        }
        Ok(v)
    }

    fn exprs(&mut self, in_rhs: bool) -> R<Vec<u32>> {
        let old = self.in_rhs;
        self.in_rhs = in_rhs;
        let r = self.expr_list();
        self.in_rhs = old;
        r
    }

    // ---- types ----

    fn parse_type(&mut self) -> R<u32> {
        match self.try_ident_or_type()? {
            Some(t) => Ok(t),
            None => self.fail("expected type"),
        }
    }

    fn qualified_ident(&mut self, ident: Option<u32>) -> R<u32> {
        let mut t = self.type_name(ident)?;
        if self.tok == Tok::Lbrack {
            t = self.type_instance(t)?;
        }
        Ok(t)
    }

    fn type_name(&mut self, ident: Option<u32>) -> R<u32> {
        let ident = match ident {
            Some(i) => i,
            None => self.ident()?,
        };
        if self.tok == Tok::Period {
            self.next()?;
            let sel = self.ident()?;
            let (s, e) = (self.st(ident), self.en(sel));
            return Ok(self.add(Kind::SelectorExpr, 0, 0, s, e, [ident, sel, NONE, NONE]));
        }
        Ok(ident)
    }

    /// `[` has been consumed (`lbrack` is where it began); `len` is the length if it has been read too.
    fn array_type(&mut self, lbrack: u32, len: Option<u32>) -> R<u32> {
        let mut len = len;
        if len.is_none() {
            self.expr_lev += 1;
            if self.tok == Tok::Ellipsis {
                let (s, e) = (self.pos, self.end);
                self.next()?;
                len = Some(self.add(Kind::Ellipsis, 0, 0, s, e, NIL));
            } else if self.tok != Tok::Rbrack {
                len = Some(self.rhs()?);
            }
            self.expr_lev -= 1;
        }
        if self.tok == Tok::Comma {
            return self.fail("unexpected comma; expecting ]");
        }
        self.expect(Tok::Rbrack)?;
        let elt = self.parse_type()?;
        let e = self.en(elt);
        Ok(self.add(Kind::ArrayType, 0, 0, lbrack, e, [len.unwrap_or(NONE), elt, NONE, NONE]))
    }

    /// `name [`: an array field (`x [N]E`, `x []E`) or an embedded instantiated type (`T[P]`). The name is None for
    /// the second.
    fn array_field_or_type_instance(&mut self, x: u32) -> R<(Option<u32>, u32)> {
        let (lbrack, _) = self.expect(Tok::Lbrack)?;
        let mut trailing_comma = false;
        let mut args: Vec<u32> = Vec::new();
        if self.tok != Tok::Rbrack {
            self.expr_lev += 1;
            args.push(self.rhs()?);
            while self.tok == Tok::Comma {
                self.next()?;
                if self.tok == Tok::Rbrack {
                    trailing_comma = true;
                    break;
                }
                args.push(self.rhs()?);
            }
            self.expr_lev -= 1;
        }
        let (_, rbrack_end) = self.expect(Tok::Rbrack)?;
        if args.is_empty() {
            let elt = self.parse_type()?;
            let e = self.en(elt);
            let a = self.add(Kind::ArrayType, 0, 0, lbrack, e, [NONE, elt, NONE, NONE]);
            return Ok((Some(x), a));
        }
        if args.len() == 1 {
            if let Some(elt) = self.try_ident_or_type()? {
                if trailing_comma {
                    return self.fail("unexpected comma; expecting ]");
                }
                let e = self.en(elt);
                let a = self.add(Kind::ArrayType, 0, 0, lbrack, e, [args[0], elt, NONE, NONE]);
                return Ok((Some(x), a));
            }
        }
        Ok((None, self.pack_index(x, &args, rbrack_end)))
    }

    fn field_decl(&mut self) -> R<u32> {
        let mut names: Vec<u32> = Vec::new();
        let typ;
        match self.tok {
            Tok::Ident => {
                let name = self.ident()?;
                if matches!(self.tok, Tok::Period | Tok::Str | Tok::Semicolon | Tok::Rbrace) {
                    // an embedded type
                    typ = if self.tok == Tok::Period { self.qualified_ident(Some(name))? } else { name };
                } else {
                    names.push(name);
                    while self.tok == Tok::Comma {
                        self.next()?;
                        names.push(self.ident()?);
                    }
                    // `T[P1, P2]` (an embedded instantiated type), `x []E` and `x [P]E` (an array field) all start
                    // `name [`
                    if names.len() == 1 && self.tok == Tok::Lbrack {
                        let (nm, t) = self.array_field_or_type_instance(name)?;
                        if nm.is_none() {
                            names.clear();
                        }
                        typ = t;
                    } else {
                        typ = self.parse_type()?;
                    }
                }
            }
            Tok::Mul => {
                let star = self.pos;
                self.next()?;
                if self.tok == Tok::Lparen {
                    return self.fail("cannot parenthesize embedded type");
                }
                let t = self.qualified_ident(None)?;
                let e = self.en(t);
                typ = self.add(Kind::StarExpr, 0, 0, star, e, [t, NONE, NONE, NONE]);
            }
            Tok::Lparen => return self.fail("cannot parenthesize embedded type"),
            _ => return self.fail("expected field name or embedded type"),
        }
        let mut tag = NONE;
        if self.tok == Tok::Str {
            let (s, e) = (self.pos, self.end);
            self.next()?;
            tag = self.add(Kind::BasicLit, Tok::Str as u8, 0, s, e, NIL);
        }
        self.expect_semi()?;
        Ok(self.field(&names, typ, tag))
    }

    fn struct_type(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Struct)?;
        let (lbrace, _) = self.expect(Tok::Lbrace)?;
        let mut fields: Vec<u32> = Vec::new();
        while matches!(self.tok, Tok::Ident | Tok::Mul | Tok::Lparen) {
            fields.push(self.field_decl()?);
        }
        let (_, rbrace_end) = self.expect(Tok::Rbrace)?;
        let fl = self.field_list(Some((lbrace, rbrace_end)), &fields);
        Ok(self.add(Kind::StructType, 0, 0, pos, rbrace_end, [fl, NONE, NONE, NONE]))
    }

    fn pointer_type(&mut self) -> R<u32> {
        let (star, _) = self.expect(Tok::Mul)?;
        let base = self.parse_type()?;
        let e = self.en(base);
        Ok(self.add(Kind::StarExpr, 0, 0, star, e, [base, NONE, NONE, NONE]))
    }

    fn dots_type(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Ellipsis)?;
        let elt = self.parse_type()?;
        let e = self.en(elt);
        Ok(self.add(Kind::Ellipsis, 0, 0, pos, e, [elt, NONE, NONE, NONE]))
    }

    /// One parameter as written: (name, type), either of them absent. `name` is a name already read.
    fn param_decl(&mut self, name: Option<u32>, type_sets_ok: bool) -> R<(Option<u32>, Option<u32>)> {
        let mut f_name: Option<u32> = None;
        let mut f_typ: Option<u32> = None;
        // with a name read, the token that follows it is read as the one after a name
        let first = if name.is_some() { Tok::Ident } else { self.tok };
        if name.is_none() && type_sets_ok && self.tok == Tok::Tilde {
            return Ok((None, Some(self.embedded_elem(None)?)));
        }
        match first {
            Tok::Ident => {
                let n = match name {
                    Some(n) => n,
                    None => self.ident()?,
                };
                f_name = Some(n);
                match self.tok {
                    Tok::Ident | Tok::Mul | Tok::Arrow | Tok::Func | Tok::Chan | Tok::Map | Tok::Struct
                    | Tok::Interface | Tok::Lparen => {
                        f_typ = Some(self.parse_type()?);
                    }
                    Tok::Lbrack => {
                        let (nm, t) = self.array_field_or_type_instance(n)?;
                        f_name = nm;
                        f_typ = Some(t);
                    }
                    Tok::Ellipsis => {
                        f_typ = Some(self.dots_type()?);
                        return Ok((f_name, f_typ));
                    }
                    Tok::Period => {
                        f_typ = Some(self.qualified_ident(Some(n))?);
                        f_name = None;
                    }
                    Tok::Tilde if type_sets_ok => return Ok((f_name, Some(self.embedded_elem(None)?))),
                    Tok::Or if type_sets_ok => return Ok((None, Some(self.embedded_elem(Some(n))?))),
                    _ => {}
                }
            }
            Tok::Mul | Tok::Arrow | Tok::Func | Tok::Lbrack | Tok::Chan | Tok::Map | Tok::Struct | Tok::Interface
            | Tok::Lparen => {
                f_typ = Some(self.parse_type()?);
            }
            Tok::Ellipsis => {
                f_typ = Some(self.dots_type()?);
                return Ok((None, f_typ));
            }
            _ => return self.fail("expected ')'"),
        }
        if type_sets_ok && self.tok == Tok::Or {
            if let Some(t) = f_typ {
                f_typ = Some(self.embedded_elem(Some(t))?);
            }
        }
        Ok((f_name, f_typ))
    }

    /// The fields of a parameter list (`name0` and `typ0` are the first parameter's parts when they have been read).
    fn parameter_list(&mut self, name0: Option<u32>, typ0: Option<u32>, closing: Tok) -> R<Vec<u32>> {
        let tparams = closing == Tok::Rbrack;
        let (mut name0, mut typ0) = (name0, typ0);
        let mut list: Vec<(Option<u32>, Option<u32>)> = Vec::new();
        let mut named = 0usize; // parameters with a name and a type
        while name0.is_some() || (self.tok != closing && self.tok != Tok::Eof) {
            let par = if let Some(t0) = typ0 {
                let t = if tparams { self.embedded_elem(Some(t0))? } else { t0 };
                (name0, Some(t))
            } else {
                self.param_decl(name0, tparams)?
            };
            name0 = None;
            typ0 = None;
            if par.0.is_some() || par.1.is_some() {
                list.push(par);
                if par.0.is_some() && par.1.is_some() {
                    named += 1;
                }
            }
            if !self.at_comma(closing)? {
                break;
            }
            self.next()?;
        }
        if list.is_empty() {
            return Ok(Vec::new());
        }
        // distribute the types: (a, b int) is two names of one type
        if named == 0 {
            // all unnamed: what was read as names are type names
            for par in list.iter_mut() {
                if let Some(n) = par.0.take() {
                    par.1 = Some(n);
                }
            }
            if tparams {
                return self.fail("missing type constraint");
            }
        } else if named != list.len() {
            let mut bad = false;
            let mut typ: Option<u32> = None;
            for par in list.iter_mut().rev() {
                if par.1.is_some() {
                    typ = par.1;
                    if par.0.is_none() {
                        bad = true;
                    }
                } else if typ.is_some() {
                    par.1 = typ;
                } else {
                    bad = true;
                }
            }
            if bad {
                return self.fail("missing parameter name or type");
            }
        }
        let mut fields: Vec<u32> = Vec::new();
        if named == 0 {
            for par in &list {
                let Some(t) = par.1 else { return self.fail("missing parameter type") };
                fields.push(self.field(&[], t, NONE));
            }
            return Ok(fields);
        }
        let mut names: Vec<u32> = Vec::new();
        let mut typ: Option<u32> = None;
        for par in &list {
            let (Some(n), Some(t)) = *par else { return self.fail("missing parameter name or type") };
            if Some(t) != typ {
                if !names.is_empty() {
                    let Some(ty) = typ else { return self.fail("missing parameter type") };
                    fields.push(self.field(&names, ty, NONE));
                    names.clear();
                }
                typ = Some(t);
            }
            names.push(n);
        }
        if !names.is_empty() {
            let Some(ty) = typ else { return self.fail("missing parameter type") };
            fields.push(self.field(&names, ty, NONE));
        }
        Ok(fields)
    }

    /// `[T any](params)` (when `accept_tparams`) and `(params)`: (the type parameters, the parameters).
    fn parameters(&mut self, accept_tparams: bool) -> R<(Option<u32>, u32)> {
        let mut tparams = None;
        if accept_tparams && self.tok == Tok::Lbrack {
            let opening = self.pos;
            self.next()?;
            let list = self.parameter_list(None, None, Tok::Rbrack)?;
            let (_, rbrack_end) = self.expect(Tok::Rbrack)?;
            if list.is_empty() {
                return self.fail("empty type parameter list");
            }
            tparams = Some(self.field_list(Some((opening, rbrack_end)), &list));
        }
        let (opening, _) = self.expect(Tok::Lparen)?;
        let fields = if self.tok != Tok::Rparen { self.parameter_list(None, None, Tok::Rparen)? } else { Vec::new() };
        let (_, rparen_end) = self.expect(Tok::Rparen)?;
        let params = self.field_list(Some((opening, rparen_end)), &fields);
        Ok((tparams, params))
    }

    fn result(&mut self) -> R<Option<u32>> {
        if self.tok == Tok::Lparen {
            let (_, results) = self.parameters(false)?;
            return Ok(Some(results));
        }
        if let Some(typ) = self.try_ident_or_type()? {
            let f = self.field(&[], typ, NONE);
            return Ok(Some(self.field_list(None, &[f])));
        }
        Ok(None)
    }

    /// A function type from its parts: it starts at `func` when there is one, else (an interface's method) at the
    /// parameters.
    fn func_type_node(&mut self, func: Option<u32>, tparams: Option<u32>, params: u32, results: Option<u32>) -> u32 {
        let start = func.unwrap_or_else(|| self.st(params));
        let end = match results {
            Some(r) => self.en(r),
            None => self.en(params),
        };
        self.add(Kind::FuncType, 0, 0, start, end, [tparams.unwrap_or(NONE), params, results.unwrap_or(NONE), NONE])
    }

    fn func_type(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Func)?;
        let (tparams, params) = self.parameters(true)?;
        if tparams.is_some() {
            return self.fail("function type must have no type parameters");
        }
        let results = self.result()?;
        Ok(self.func_type_node(Some(pos), None, params, results))
    }

    /// One element of an interface: (the method's name or none, its type or the embedded element's).
    fn method_spec(&mut self) -> R<(Vec<u32>, u32)> {
        let x = self.type_name(None)?;
        if self.kd(x) != Kind::Ident {
            // an embedded, possibly instantiated, type
            let mut typ = x;
            if self.tok == Tok::Lbrack {
                typ = self.type_instance(typ)?;
            }
            return Ok((Vec::new(), typ));
        }
        match self.tok {
            Tok::Lbrack => {
                // a generic method (an error) or an embedded instantiated type
                self.next()?;
                self.expr_lev += 1;
                let x2 = self.expr()?;
                self.expr_lev -= 1;
                if self.kd(x2) == Kind::Ident && self.tok != Tok::Comma && self.tok != Tok::Rbrack {
                    return self.fail("interface method must have no type parameters");
                }
                let mut list = vec![x2];
                if self.at_comma(Tok::Rbrack)? {
                    self.expr_lev += 1;
                    self.next()?;
                    while self.tok != Tok::Rbrack && self.tok != Tok::Eof {
                        list.push(self.parse_type()?);
                        if !self.at_comma(Tok::Rbrack)? {
                            break;
                        }
                        self.next()?;
                    }
                    self.expr_lev -= 1;
                }
                let (_, rbrack_end) = self.expect(Tok::Rbrack)?;
                Ok((Vec::new(), self.pack_index(x, &list, rbrack_end)))
            }
            Tok::Lparen => {
                // an ordinary method
                let (_, params) = self.parameters(false)?;
                let results = self.result()?;
                let typ = self.func_type_node(None, None, params, results);
                Ok((vec![x], typ))
            }
            _ => Ok((Vec::new(), x)),
        }
    }

    fn embedded_elem(&mut self, x: Option<u32>) -> R<u32> {
        let mut x = match x {
            Some(x) => x,
            None => self.embedded_term()?,
        };
        while self.tok == Tok::Or {
            let op_pos = self.pos;
            self.next()?;
            let y = self.embedded_term()?;
            let (s, e) = (self.st(x), self.en(y));
            x = self.add(Kind::BinaryExpr, Tok::Or as u8, 0, s, e, [x, y, op_pos, NONE]);
        }
        Ok(x)
    }

    fn embedded_term(&mut self) -> R<u32> {
        if self.tok == Tok::Tilde {
            let op_pos = self.pos;
            self.next()?;
            let t = self.parse_type()?;
            let e = self.en(t);
            return Ok(self.add(Kind::UnaryExpr, Tok::Tilde as u8, 0, op_pos, e, [t, NONE, NONE, NONE]));
        }
        match self.try_ident_or_type()? {
            Some(t) => Ok(t),
            None => self.fail("expected ~ term or type"),
        }
    }

    fn interface_type(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Interface)?;
        let (lbrace, _) = self.expect(Tok::Lbrace)?;
        let mut list: Vec<u32> = Vec::new();
        loop {
            if self.tok == Tok::Ident {
                let (names, mut typ) = self.method_spec()?;
                if names.is_empty() {
                    typ = self.embedded_elem(Some(typ))?;
                }
                self.expect_semi()?;
                list.push(self.field(&names, typ, NONE));
            } else if self.tok == Tok::Tilde {
                let typ = self.embedded_elem(None)?;
                self.expect_semi()?;
                list.push(self.field(&[], typ, NONE));
            } else if let Some(t) = self.try_ident_or_type()? {
                let typ = self.embedded_elem(Some(t))?;
                self.expect_semi()?;
                list.push(self.field(&[], typ, NONE));
            } else {
                break;
            }
        }
        let (_, rbrace_end) = self.expect(Tok::Rbrace)?;
        let fl = self.field_list(Some((lbrace, rbrace_end)), &list);
        Ok(self.add(Kind::InterfaceType, 0, 0, pos, rbrace_end, [fl, NONE, NONE, NONE]))
    }

    fn map_type(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Map)?;
        self.expect(Tok::Lbrack)?;
        let key = self.parse_type()?;
        self.expect(Tok::Rbrack)?;
        let value = self.parse_type()?;
        let e = self.en(value);
        Ok(self.add(Kind::MapType, 0, 0, pos, e, [key, value, NONE, NONE]))
    }

    fn chan_type(&mut self) -> R<u32> {
        let pos = self.pos;
        let mut arrow = NONE;
        let dir;
        if self.tok == Tok::Chan {
            self.next()?;
            if self.tok == Tok::Arrow {
                arrow = self.pos;
                self.next()?;
                dir = CHAN_SEND;
            } else {
                dir = CHAN_BOTH;
            }
        } else {
            arrow = self.expect(Tok::Arrow)?.0;
            self.expect(Tok::Chan)?;
            dir = CHAN_RECV;
        }
        let value = self.parse_type()?;
        let e = self.en(value);
        Ok(self.add(Kind::ChanType, dir, 0, pos, e, [value, arrow, NONE, NONE]))
    }

    fn type_instance(&mut self, typ: u32) -> R<u32> {
        self.expect(Tok::Lbrack)?;
        self.expr_lev += 1;
        let mut list: Vec<u32> = Vec::new();
        while self.tok != Tok::Rbrack && self.tok != Tok::Eof {
            list.push(self.parse_type()?);
            if !self.at_comma(Tok::Rbrack)? {
                break;
            }
            self.next()?;
        }
        self.expr_lev -= 1;
        let (_, closing_end) = self.expect(Tok::Rbrack)?;
        if list.is_empty() {
            return self.fail("expected type argument list");
        }
        Ok(self.pack_index(typ, &list, closing_end))
    }

    fn try_ident_or_type(&mut self) -> R<Option<u32>> {
        self.enter()?;
        let r = match self.tok {
            Tok::Ident => {
                let mut typ = self.type_name(None)?;
                if self.tok == Tok::Lbrack {
                    typ = self.type_instance(typ)?;
                }
                Some(typ)
            }
            Tok::Lbrack => {
                let (lbrack, _) = self.expect(Tok::Lbrack)?;
                Some(self.array_type(lbrack, None)?)
            }
            Tok::Struct => Some(self.struct_type()?),
            Tok::Mul => Some(self.pointer_type()?),
            Tok::Func => Some(self.func_type()?),
            Tok::Interface => Some(self.interface_type()?),
            Tok::Map => Some(self.map_type()?),
            Tok::Chan | Tok::Arrow => Some(self.chan_type()?),
            Tok::Lparen => {
                let lparen = self.pos;
                self.next()?;
                let typ = self.parse_type()?;
                let (_, rparen_end) = self.expect(Tok::Rparen)?;
                Some(self.add(Kind::ParenExpr, 0, 0, lparen, rparen_end, [typ, NONE, NONE, NONE]))
            }
            _ => None,
        };
        self.leave();
        Ok(r)
    }

    // ---- blocks ----

    fn stmt_list(&mut self) -> R<Vec<u32>> {
        let mut v = Vec::new();
        while !matches!(self.tok, Tok::Case | Tok::Default | Tok::Rbrace | Tok::Eof) {
            v.push(self.stmt()?);
        }
        Ok(v)
    }

    /// `{ statements }`: a function's body and a block are the same here.
    fn block(&mut self) -> R<u32> {
        let (lbrace, _) = self.expect(Tok::Lbrace)?;
        let list = self.stmt_list()?;
        let (_, rbrace_end) = self.expect(Tok::Rbrace)?;
        let l = self.list(&list);
        Ok(self.add(Kind::BlockStmt, 0, 0, lbrace, rbrace_end, [l, NONE, NONE, NONE]))
    }

    // ---- expressions ----

    fn func_type_or_lit(&mut self) -> R<u32> {
        let typ = self.func_type()?;
        if self.tok != Tok::Lbrace {
            return Ok(typ);
        }
        self.expr_lev += 1;
        let body = self.block()?;
        self.expr_lev -= 1;
        let (s, e) = (self.st(typ), self.en(body));
        Ok(self.add(Kind::FuncLit, 0, 0, s, e, [typ, body, NONE, NONE]))
    }

    /// An operand: an expression, or a type (including `[...]T`) the caller checks.
    fn operand(&mut self) -> R<u32> {
        match self.tok {
            Tok::Ident => self.ident(),
            Tok::Int | Tok::Float | Tok::Imag | Tok::Char | Tok::Str => {
                let (s, e, op) = (self.pos, self.end, self.tok as u8);
                self.next()?;
                Ok(self.add(Kind::BasicLit, op, 0, s, e, NIL))
            }
            Tok::Lparen => {
                let lparen = self.pos;
                self.next()?;
                self.expr_lev += 1;
                let x = self.rhs()?;
                self.expr_lev -= 1;
                let (_, rparen_end) = self.expect(Tok::Rparen)?;
                Ok(self.add(Kind::ParenExpr, 0, 0, lparen, rparen_end, [x, NONE, NONE, NONE]))
            }
            Tok::Func => self.func_type_or_lit(),
            _ => match self.try_ident_or_type()? {
                Some(t) => Ok(t),
                None => self.fail("expected operand"),
            },
        }
    }

    fn selector(&mut self, x: u32) -> R<u32> {
        let sel = self.ident()?;
        let (s, e) = (self.st(x), self.en(sel));
        Ok(self.add(Kind::SelectorExpr, 0, 0, s, e, [x, sel, NONE, NONE]))
    }

    fn type_assertion(&mut self, x: u32) -> R<u32> {
        self.expect(Tok::Lparen)?;
        let typ = if self.tok == Tok::Type {
            self.next()?;
            NONE // x.(type)
        } else {
            self.parse_type()?
        };
        let (_, rparen_end) = self.expect(Tok::Rparen)?;
        let s = self.st(x);
        Ok(self.add(Kind::TypeAssertExpr, 0, 0, s, rparen_end, [x, typ, NONE, NONE]))
    }

    fn index_or_slice_or_instance(&mut self, x: u32) -> R<u32> {
        self.expect(Tok::Lbrack)?;
        if self.tok == Tok::Rbrack {
            return self.fail("expected operand");
        }
        self.expr_lev += 1;
        let mut args: Vec<u32> = Vec::new();
        let mut index = [NONE; 3];
        let mut ncolons = 0usize;
        if self.tok != Tok::Colon {
            // an index expression or a type instantiation: even a named type is not read as a type here
            index[0] = self.rhs()?;
        }
        match self.tok {
            Tok::Colon => {
                while self.tok == Tok::Colon && ncolons < 2 {
                    ncolons += 1;
                    self.next()?;
                    if self.tok != Tok::Colon && self.tok != Tok::Rbrack && self.tok != Tok::Eof {
                        index[ncolons] = self.rhs()?;
                    }
                }
            }
            Tok::Comma => {
                args.push(index[0]);
                while self.tok == Tok::Comma {
                    self.next()?;
                    if self.tok != Tok::Rbrack && self.tok != Tok::Eof {
                        args.push(self.parse_type()?);
                    }
                }
            }
            _ => {}
        }
        self.expr_lev -= 1;
        let (_, rbrack_end) = self.expect(Tok::Rbrack)?;
        let s = self.st(x);
        if ncolons > 0 {
            let mut flags = 0;
            if ncolons == 2 {
                flags = SLICE3;
                if index[1] == NONE {
                    return self.fail("middle index required in 3-index slice");
                }
                if index[2] == NONE {
                    return self.fail("final index required in 3-index slice");
                }
            }
            return Ok(self.add(Kind::SliceExpr, 0, flags, s, rbrack_end, [x, index[0], index[1], index[2]]));
        }
        if args.is_empty() {
            return Ok(self.add(Kind::IndexExpr, 0, 0, s, rbrack_end, [x, index[0], NONE, NONE]));
        }
        Ok(self.pack_index(x, &args, rbrack_end))
    }

    fn call_or_conversion(&mut self, fun: u32) -> R<u32> {
        let (lparen, _) = self.expect(Tok::Lparen)?;
        self.expr_lev += 1;
        let mut list: Vec<u32> = Vec::new();
        let mut ellipsis = false;
        while self.tok != Tok::Rparen && self.tok != Tok::Eof && !ellipsis {
            list.push(self.rhs()?); // builtins may expect a type: make(some type, ...)
            if self.tok == Tok::Ellipsis {
                ellipsis = true;
                self.next()?;
            }
            if !self.at_comma(Tok::Rparen)? {
                break;
            }
            self.next()?;
        }
        self.expr_lev -= 1;
        let (_, rparen_end) = self.expect(Tok::Rparen)?;
        let l = self.list(&list);
        let s = self.st(fun);
        Ok(self.add(Kind::CallExpr, 0, if ellipsis { ELLIPSIS } else { 0 }, s, rparen_end, [fun, l, lparen, NONE]))
    }

    fn value(&mut self) -> R<u32> {
        if self.tok == Tok::Lbrace {
            return self.literal_value(None);
        }
        self.expr()
    }

    fn element(&mut self) -> R<u32> {
        let x = self.value()?;
        if self.tok == Tok::Colon {
            self.next()?;
            let v = self.value()?;
            let (s, e) = (self.st(x), self.en(v));
            return Ok(self.add(Kind::KeyValueExpr, 0, 0, s, e, [x, v, NONE, NONE]));
        }
        Ok(x)
    }

    fn literal_value(&mut self, typ: Option<u32>) -> R<u32> {
        self.enter()?;
        let (lbrace, _) = self.expect(Tok::Lbrace)?;
        let mut elts: Vec<u32> = Vec::new();
        self.expr_lev += 1;
        if self.tok != Tok::Rbrace {
            while self.tok != Tok::Rbrace && self.tok != Tok::Eof {
                elts.push(self.element()?);
                if !self.at_comma(Tok::Rbrace)? {
                    break;
                }
                self.next()?;
            }
        }
        self.expr_lev -= 1;
        let (_, rbrace_end) = self.expect(Tok::Rbrace)?;
        let l = self.list(&elts);
        let s = match typ {
            Some(t) => self.st(t),
            None => lbrace,
        };
        self.leave();
        Ok(self.add(Kind::CompositeLit, 0, 0, s, rbrace_end, [typ.unwrap_or(NONE), l, NONE, NONE]))
    }

    /// Selectors, type assertions, indexes, slices, instantiations, calls and composite literals after an operand: a
    /// loop, so a chain of any length is as deep as one.
    fn primary_expr(&mut self, x: Option<u32>) -> R<u32> {
        let mut x = match x {
            Some(x) => x,
            None => self.operand()?,
        };
        loop {
            match self.tok {
                Tok::Period => {
                    self.next()?;
                    match self.tok {
                        Tok::Ident => x = self.selector(x)?,
                        Tok::Lparen => x = self.type_assertion(x)?,
                        _ => return self.fail("expected selector or type assertion"),
                    }
                }
                Tok::Lbrack => x = self.index_or_slice_or_instance(x)?,
                Tok::Lparen => x = self.call_or_conversion(x)?,
                Tok::Lbrace => {
                    // a parenthesized composite literal's type is accepted but an error; is the `{` a composite
                    // literal's or a block statement's?
                    let t = self.unparen(x);
                    match self.kd(t) {
                        Kind::Ident | Kind::SelectorExpr | Kind::IndexExpr | Kind::IndexListExpr => {
                            if self.expr_lev < 0 {
                                return Ok(x);
                            }
                        }
                        Kind::ArrayType | Kind::StructType | Kind::MapType => {}
                        _ => return Ok(x),
                    }
                    if t != x {
                        return self.fail("cannot parenthesize type in composite literal");
                    }
                    x = self.literal_value(Some(x))?;
                }
                _ => return Ok(x),
            }
        }
    }

    fn unary_expr(&mut self) -> R<u32> {
        self.enter()?;
        let r = match self.tok {
            Tok::Add | Tok::Sub | Tok::Not | Tok::Xor | Tok::And | Tok::Tilde => {
                let (pos, op) = (self.pos, self.tok);
                self.next()?;
                let x = self.unary_expr()?;
                let e = self.en(x);
                self.add(Kind::UnaryExpr, op as u8, 0, pos, e, [x, NONE, NONE, NONE])
            }
            Tok::Arrow => {
                // a channel type or a receive: `<-chan T` is told from `<-(chan T)` by what follows
                let mut arrow = self.pos;
                self.next()?;
                let x = self.unary_expr()?;
                if self.kd(x) == Kind::ChanType {
                    // re-associate the arrow with the channel type parsed already
                    let mut dir: u8;
                    let mut typ = x;
                    loop {
                        let n = self.tree.nodes[typ as usize];
                        if n.op == CHAN_RECV {
                            return self.fail("expected 'chan'"); // (<-type) is (<-(<-chan T))
                        }
                        let old_arrow = n.f[1];
                        let node = &mut self.tree.nodes[typ as usize];
                        node.start = arrow;
                        node.f[1] = arrow;
                        dir = node.op;
                        node.op = CHAN_RECV;
                        arrow = old_arrow;
                        let value = self.slot(typ, 0);
                        if dir == CHAN_SEND && self.kd(value) == Kind::ChanType {
                            typ = value;
                        } else {
                            break;
                        }
                    }
                    if dir == CHAN_SEND {
                        return self.fail("expected channel type");
                    }
                    x
                } else {
                    // <-(expr)
                    let e = self.en(x);
                    self.add(Kind::UnaryExpr, Tok::Arrow as u8, 0, arrow, e, [x, NONE, NONE, NONE])
                }
            }
            Tok::Mul => {
                // a pointer type or a unary `*`
                let pos = self.pos;
                self.next()?;
                let x = self.unary_expr()?;
                let e = self.en(x);
                self.add(Kind::StarExpr, 0, 0, pos, e, [x, NONE, NONE, NONE])
            }
            _ => self.primary_expr(None)?,
        };
        self.leave();
        Ok(r)
    }

    /// The operator the parser reads at the current token and its precedence (`=` is read as `==` on a right-hand
    /// side, to say what was meant).
    fn tok_prec(&self) -> (Tok, u8) {
        let mut tok = self.tok;
        if self.in_rhs && tok == Tok::Assign {
            tok = Tok::Eql;
        }
        (tok, tok.precedence())
    }

    /// A binary expression; `x` is the left operand when it has been read. A loop over the operators of one
    /// precedence, a call for each higher one.
    fn binary_expr(&mut self, x: Option<u32>, prec1: u8) -> R<u32> {
        let mut x = match x {
            Some(x) => x,
            None => self.unary_expr()?,
        };
        loop {
            let (op, oprec) = self.tok_prec();
            if oprec < prec1 {
                return Ok(x);
            }
            let (op_pos, _) = self.expect(op)?;
            let y = self.binary_expr(None, oprec + 1)?;
            let (s, e) = (self.st(x), self.en(y));
            x = self.add(Kind::BinaryExpr, op as u8, 0, s, e, [x, y, op_pos, NONE]);
        }
    }

    fn expr(&mut self) -> R<u32> {
        self.binary_expr(None, 1)
    }

    fn rhs(&mut self) -> R<u32> {
        let old = self.in_rhs;
        self.in_rhs = true;
        let x = self.expr();
        self.in_rhs = old;
        x
    }

    // ---- statements ----

    fn simple_stmt(&mut self, mode: Mode) -> R<Simple> {
        let x = self.exprs(false)?;
        if is_assign(self.tok) {
            // an assignment, possibly part of a range clause
            let tok = self.tok;
            self.next()?;
            if mode == Mode::RangeOk && self.tok == Tok::Range && (tok == Tok::Define || tok == Tok::Assign) {
                let pos = self.pos;
                self.next()?;
                let r = self.rhs()?;
                let e = self.en(r);
                let u = self.add(Kind::UnaryExpr, Tok::Range as u8, 0, pos, e, [r, NONE, NONE, NONE]);
                return Ok(Simple::Range { lhs: x, op: tok, x: u });
            }
            let y = self.exprs(true)?;
            let (s, e) = (self.st(x[0]), self.en(y[y.len() - 1]));
            let (lhs, rhs) = (self.list(&x), self.list(&y));
            return Ok(Simple::Stmt(self.add(Kind::AssignStmt, tok as u8, 0, s, e, [lhs, rhs, NONE, NONE])));
        }
        if x.len() > 1 {
            return self.fail("expected 1 expression");
        }
        let x0 = x[0];
        let (s, e) = (self.st(x0), self.en(x0));
        match self.tok {
            Tok::Colon => {
                // a labeled statement
                self.next()?;
                if mode == Mode::LabelOk && self.kd(x0) == Kind::Ident {
                    let stmt = self.stmt()?;
                    let e = self.en(stmt);
                    return Ok(Simple::Stmt(self.add(Kind::LabeledStmt, 0, 0, s, e, [x0, stmt, NONE, NONE])));
                }
                self.fail("illegal label declaration")
            }
            Tok::Arrow => {
                // a send statement
                self.next()?;
                let y = self.rhs()?;
                let e = self.en(y);
                Ok(Simple::Stmt(self.add(Kind::SendStmt, 0, 0, s, e, [x0, y, NONE, NONE])))
            }
            Tok::Inc | Tok::Dec => {
                let (op, end) = (self.tok, self.end);
                self.next()?;
                Ok(Simple::Stmt(self.add(Kind::IncDecStmt, op as u8, 0, s, end, [x0, NONE, NONE, NONE])))
            }
            _ => Ok(Simple::Stmt(self.add(Kind::ExprStmt, 0, 0, s, e, [x0, NONE, NONE, NONE]))),
        }
    }

    /// A simple statement that is no range clause.
    fn simple_stmt_only(&mut self, mode: Mode) -> R<u32> {
        match self.simple_stmt(mode)? {
            Simple::Stmt(s) => Ok(s),
            Simple::Range { .. } => self.fail("unexpected range clause"),
        }
    }

    /// The call of a `go` or `defer` statement.
    fn call_expr(&mut self) -> R<u32> {
        let x = self.rhs()?; // could be a conversion: (some type)(x)
        if self.unparen(x) != x {
            return self.fail("expression in go/defer must not be parenthesized");
        }
        if self.kd(x) == Kind::CallExpr {
            return Ok(x);
        }
        self.fail("expression in go/defer must be function call")
    }

    fn go_or_defer(&mut self, tok: Tok, kind: Kind) -> R<u32> {
        let (pos, _) = self.expect(tok)?;
        let call = self.call_expr()?;
        self.expect_semi()?;
        let e = self.en(call);
        Ok(self.add(kind, 0, 0, pos, e, [call, NONE, NONE, NONE]))
    }

    fn return_stmt(&mut self) -> R<u32> {
        let (pos, pos_end) = self.expect(Tok::Return)?;
        let mut list: Vec<u32> = Vec::new();
        if self.tok != Tok::Semicolon && self.tok != Tok::Rbrace {
            list = self.exprs(true)?;
        }
        self.expect_semi()?;
        let end = match list.last() {
            Some(&x) => self.en(x),
            None => pos_end,
        };
        let l = self.list(&list);
        Ok(self.add(Kind::ReturnStmt, 0, 0, pos, end, [l, NONE, NONE, NONE]))
    }

    fn branch_stmt(&mut self, tok: Tok) -> R<u32> {
        let (pos, pos_end) = self.expect(tok)?;
        let mut label = NONE;
        if tok != Tok::Fallthrough && self.tok == Tok::Ident {
            label = self.ident()?;
        }
        self.expect_semi()?;
        let end = if label != NONE { self.en(label) } else { pos_end };
        Ok(self.add(Kind::BranchStmt, tok as u8, 0, pos, end, [label, NONE, NONE, NONE]))
    }

    /// An expression statement's expression (a statement that is anything else is an error), or nothing for no
    /// statement.
    fn make_expr(&mut self, s: Option<u32>) -> R<Option<u32>> {
        match s {
            None => Ok(None),
            Some(s) => {
                if self.kd(s) == Kind::ExprStmt {
                    Ok(Some(self.slot(s, 0)))
                } else {
                    self.fail("expected expression, found statement")
                }
            }
        }
    }

    /// `if` before its block: (init, condition).
    fn if_header(&mut self) -> R<(Option<u32>, u32)> {
        if self.tok == Tok::Lbrace {
            return self.fail("missing condition in if statement");
        }
        let prev = self.expr_lev;
        self.expr_lev = -1;
        let mut init: Option<u32> = None;
        if self.tok != Tok::Semicolon {
            if self.tok == Tok::Var {
                return self.fail("var declaration not allowed in if initializer");
            }
            init = Some(self.simple_stmt_only(Mode::Basic)?);
        }
        let cond_stmt: Option<u32>;
        let mut semi = false;
        if self.tok != Tok::Lbrace {
            if self.tok == Tok::Semicolon {
                semi = true;
                self.next()?;
            } else {
                return self.expected(Tok::Semicolon);
            }
            cond_stmt = if self.tok != Tok::Lbrace { Some(self.simple_stmt_only(Mode::Basic)?) } else { None };
        } else {
            cond_stmt = init;
            init = None;
        }
        let cond = match cond_stmt {
            Some(s) => self.make_expr(Some(s))?,
            None => None,
        };
        let cond = match cond {
            Some(c) => c,
            None => {
                return if semi { self.fail("missing condition in if statement") } else { self.fail("missing condition") }
            }
        };
        self.expr_lev = prev;
        Ok((init, cond))
    }

    /// `if header block`: the IfStmt (its else is not read).
    fn if_clause(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::If)?;
        let (init, cond) = self.if_header()?;
        let body = self.block()?;
        let e = self.en(body);
        Ok(self.add(Kind::IfStmt, 0, 0, pos, e, [init.unwrap_or(NONE), cond, body, NONE]))
    }

    /// An `if` with its `else if`s: a loop, not a recursion, so a chain of any length is as deep as one.
    fn if_stmt(&mut self) -> R<u32> {
        self.enter()?;
        let first = self.if_clause()?;
        let mut chain = vec![first];
        loop {
            let last = chain[chain.len() - 1];
            if self.tok == Tok::Else {
                self.next()?;
                match self.tok {
                    Tok::If => {
                        let n = self.if_clause()?;
                        self.tree.nodes[last as usize].f[3] = n;
                        chain.push(n);
                    }
                    Tok::Lbrace => {
                        let b = self.block()?;
                        self.expect_semi()?;
                        self.tree.nodes[last as usize].f[3] = b;
                        break;
                    }
                    _ => return self.fail("expected if statement or block"),
                }
            } else {
                self.expect_semi()?;
                break;
            }
        }
        // every IfStmt of the chain ends where the last one's else, or body, does
        let last = chain[chain.len() - 1];
        let ln = self.tree.nodes[last as usize];
        let end = if ln.f[3] != NONE { self.en(ln.f[3]) } else { self.en(ln.f[2]) };
        for &n in &chain {
            self.tree.nodes[n as usize].end = end;
        }
        self.leave();
        Ok(first)
    }

    fn case_clause(&mut self) -> R<u32> {
        let pos = self.pos;
        let mut list: Vec<u32> = Vec::new();
        if self.tok == Tok::Case {
            self.next()?;
            list = self.exprs(true)?;
        } else {
            self.expect(Tok::Default)?;
        }
        let (_, colon_end) = self.expect(Tok::Colon)?;
        let body = self.stmt_list()?;
        let end = match body.last() {
            Some(&s) => self.en(s),
            None => colon_end,
        };
        let (l, b) = (self.list(&list), self.list(&body));
        Ok(self.add(Kind::CaseClause, 0, 0, pos, end, [l, b, NONE, NONE]))
    }

    fn is_type_switch_assert(&self, x: u32) -> bool {
        self.kd(x) == Kind::TypeAssertExpr && self.slot(x, 1) == NONE
    }

    /// Is `s` a type switch guard (`x.(type)` or `v := x.(type)`)? `v = x.(type)` is an error.
    fn is_type_switch_guard(&self, s: Option<u32>) -> R<bool> {
        let Some(s) = s else { return Ok(false) };
        match self.kd(s) {
            Kind::ExprStmt => Ok(self.is_type_switch_assert(self.slot(s, 0))),
            Kind::AssignStmt => {
                let n = self.tree.nodes[s as usize];
                let (lhs, rhs) = (self.tree.items(n.f[0]), self.tree.items(n.f[1]));
                if lhs.len() == 1 && rhs.len() == 1 && self.is_type_switch_assert(rhs[0]) {
                    if n.op == Tok::Assign as u8 {
                        return self.fail("expected ':=', found '='");
                    }
                    if n.op == Tok::Define as u8 {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn switch_stmt(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Switch)?;
        let mut s1: Option<u32> = None;
        let mut s2: Option<u32> = None;
        if self.tok != Tok::Lbrace {
            let prev = self.expr_lev;
            self.expr_lev = -1;
            if self.tok != Tok::Semicolon {
                s2 = Some(self.simple_stmt_only(Mode::Basic)?);
            }
            if self.tok == Tok::Semicolon {
                self.next()?;
                s1 = s2;
                s2 = None;
                if self.tok != Tok::Lbrace {
                    // (a type switch guard may declare a variable besides the one the initializer does)
                    s2 = Some(self.simple_stmt_only(Mode::Basic)?);
                }
            }
            self.expr_lev = prev;
        }
        let type_switch = self.is_type_switch_guard(s2)?;
        let (lbrace, _) = self.expect(Tok::Lbrace)?;
        let mut list: Vec<u32> = Vec::new();
        while self.tok == Tok::Case || self.tok == Tok::Default {
            list.push(self.case_clause()?);
        }
        let (_, rbrace_end) = self.expect(Tok::Rbrace)?;
        self.expect_semi()?;
        let l = self.list(&list);
        let body = self.add(Kind::BlockStmt, 0, 0, lbrace, rbrace_end, [l, NONE, NONE, NONE]);
        if type_switch {
            return Ok(self.add(
                Kind::TypeSwitchStmt,
                0,
                0,
                pos,
                rbrace_end,
                [s1.unwrap_or(NONE), s2.unwrap_or(NONE), body, NONE],
            ));
        }
        let tag = self.make_expr(s2)?;
        Ok(self.add(Kind::SwitchStmt, 0, 0, pos, rbrace_end, [s1.unwrap_or(NONE), tag.unwrap_or(NONE), body, NONE]))
    }

    fn comm_clause(&mut self) -> R<u32> {
        let pos = self.pos;
        let mut comm = NONE;
        if self.tok == Tok::Case {
            self.next()?;
            let lhs = self.exprs(false)?;
            let (s, l0) = (self.st(lhs[0]), lhs[0]);
            if self.tok == Tok::Arrow {
                // a send statement
                if lhs.len() > 1 {
                    return self.fail("expected 1 expression");
                }
                self.next()?;
                let rhs = self.rhs()?;
                let e = self.en(rhs);
                comm = self.add(Kind::SendStmt, 0, 0, s, e, [l0, rhs, NONE, NONE]);
            } else if self.tok == Tok::Assign || self.tok == Tok::Define {
                // a receive with an assignment
                if lhs.len() > 2 {
                    return self.fail("expected 1 or 2 expressions");
                }
                let tok = self.tok;
                self.next()?;
                let rhs = self.rhs()?;
                let e = self.en(rhs);
                let (l, r) = (self.list(&lhs), self.list(&[rhs]));
                comm = self.add(Kind::AssignStmt, tok as u8, 0, s, e, [l, r, NONE, NONE]);
            } else {
                // a receive operation
                if lhs.len() > 1 {
                    return self.fail("expected 1 expression");
                }
                let e = self.en(l0);
                comm = self.add(Kind::ExprStmt, 0, 0, s, e, [l0, NONE, NONE, NONE]);
            }
        } else {
            self.expect(Tok::Default)?;
        }
        let (_, colon_end) = self.expect(Tok::Colon)?;
        let body = self.stmt_list()?;
        let end = match body.last() {
            Some(&s) => self.en(s),
            None => colon_end,
        };
        let b = self.list(&body);
        Ok(self.add(Kind::CommClause, 0, 0, pos, end, [comm, b, NONE, NONE]))
    }

    fn select_stmt(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Select)?;
        let (lbrace, _) = self.expect(Tok::Lbrace)?;
        let mut list: Vec<u32> = Vec::new();
        while self.tok == Tok::Case || self.tok == Tok::Default {
            list.push(self.comm_clause()?);
        }
        let (_, rbrace_end) = self.expect(Tok::Rbrace)?;
        self.expect_semi()?;
        let l = self.list(&list);
        let body = self.add(Kind::BlockStmt, 0, 0, lbrace, rbrace_end, [l, NONE, NONE, NONE]);
        Ok(self.add(Kind::SelectStmt, 0, 0, pos, rbrace_end, [body, NONE, NONE, NONE]))
    }

    fn for_stmt(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::For)?;
        let mut s1: Option<u32> = None;
        let mut s2: Option<u32> = None;
        let mut s3: Option<u32> = None;
        // the parts of a range clause: (the left-hand side, `:=` or `=` or Illegal, `range x`)
        let mut range: Option<(Vec<u32>, Tok, u32)> = None;
        if self.tok != Tok::Lbrace {
            let prev = self.expr_lev;
            self.expr_lev = -1;
            if self.tok != Tok::Semicolon {
                if self.tok == Tok::Range {
                    // for range x
                    let rpos = self.pos;
                    self.next()?;
                    let r = self.rhs()?;
                    let e = self.en(r);
                    let u = self.add(Kind::UnaryExpr, Tok::Range as u8, 0, rpos, e, [r, NONE, NONE, NONE]);
                    range = Some((Vec::new(), Tok::Illegal, u));
                } else {
                    match self.simple_stmt(Mode::RangeOk)? {
                        Simple::Stmt(s) => s2 = Some(s),
                        Simple::Range { lhs, op, x } => range = Some((lhs, op, x)),
                    }
                }
            }
            if range.is_none() && self.tok == Tok::Semicolon {
                self.next()?;
                s1 = s2;
                s2 = None;
                if self.tok != Tok::Semicolon {
                    s2 = Some(self.simple_stmt_only(Mode::Basic)?);
                }
                self.expect_semi()?;
                if self.tok != Tok::Lbrace {
                    s3 = Some(self.simple_stmt_only(Mode::Basic)?);
                }
            }
            self.expr_lev = prev;
        }
        let body = self.block()?;
        self.expect_semi()?;
        let end = self.en(body);
        if let Some((lhs, op, u)) = range {
            let (key, value) = match lhs.len() {
                0 => (NONE, NONE),
                1 => (lhs[0], NONE),
                2 => (lhs[0], lhs[1]),
                _ => return self.fail("expected at most 2 expressions"),
            };
            let x = self.slot(u, 0);
            return Ok(self.add(Kind::RangeStmt, op as u8, 0, pos, end, [key, value, x, body]));
        }
        let cond = self.make_expr(s2)?;
        Ok(self.add(
            Kind::ForStmt,
            0,
            0,
            pos,
            end,
            [s1.unwrap_or(NONE), cond.unwrap_or(NONE), s3.unwrap_or(NONE), body],
        ))
    }

    fn stmt(&mut self) -> R<u32> {
        self.enter()?;
        let s = match self.tok {
            Tok::Const | Tok::Type | Tok::Var => {
                let d = self.decl()?;
                let (s, e) = (self.st(d), self.en(d));
                self.add(Kind::DeclStmt, 0, 0, s, e, [d, NONE, NONE, NONE])
            }
            Tok::Ident | Tok::Int | Tok::Float | Tok::Imag | Tok::Char | Tok::Str | Tok::Func | Tok::Lparen
            | Tok::Lbrack | Tok::Struct | Tok::Map | Tok::Chan | Tok::Interface | Tok::Add | Tok::Sub | Tok::Mul
            | Tok::And | Tok::Xor | Tok::Arrow | Tok::Not => {
                let s = self.simple_stmt_only(Mode::LabelOk)?;
                // (a labeled statement has read its own semicolon)
                if self.kd(s) != Kind::LabeledStmt {
                    self.expect_semi()?;
                }
                s
            }
            Tok::Go => self.go_or_defer(Tok::Go, Kind::GoStmt)?,
            Tok::Defer => self.go_or_defer(Tok::Defer, Kind::DeferStmt)?,
            Tok::Return => self.return_stmt()?,
            Tok::Break | Tok::Continue | Tok::Goto | Tok::Fallthrough => {
                let t = self.tok;
                self.branch_stmt(t)?
            }
            Tok::Lbrace => {
                let b = self.block()?;
                self.expect_semi()?;
                b
            }
            Tok::If => self.if_stmt()?,
            Tok::Switch => self.switch_stmt()?,
            Tok::Select => self.select_stmt()?,
            Tok::For => self.for_stmt()?,
            Tok::Semicolon => {
                let (pos, implicit) = (self.pos, self.implicit);
                let end = if implicit { pos } else { self.end };
                self.next()?;
                self.add(Kind::EmptyStmt, 0, if implicit { IMPLICIT } else { 0 }, pos, end, NIL)
            }
            // a semicolon may be left out before a closing `}`
            Tok::Rbrace => self.add(Kind::EmptyStmt, 0, IMPLICIT, self.pos, self.pos, NIL),
            _ => return self.fail("expected statement"),
        };
        self.leave();
        Ok(s)
    }

    // ---- declarations ----

    fn import_spec(&mut self) -> R<u32> {
        let mut name = NONE;
        match self.tok {
            Tok::Ident => name = self.ident()?,
            Tok::Period => {
                let (s, e) = (self.pos, self.end);
                self.next()?;
                name = self.add(Kind::Ident, 0, 0, s, e, NIL);
            }
            _ => {}
        }
        if self.tok != Tok::Str {
            return self.fail(if self.tok == Tok::Int || self.tok == Tok::Float || self.tok == Tok::Imag || self.tok == Tok::Char {
                "import path must be a string"
            } else {
                "missing import path"
            });
        }
        let (ps, pe) = (self.pos, self.end);
        self.next()?;
        let path = self.add(Kind::BasicLit, Tok::Str as u8, 0, ps, pe, NIL);
        self.expect_semi()?;
        let start = if name != NONE { self.st(name) } else { ps };
        Ok(self.add(Kind::ImportSpec, 0, 0, start, pe, [name, path, NONE, NONE]))
    }

    fn value_spec(&mut self, keyword: Tok) -> R<u32> {
        let names = self.ident_list()?;
        let mut typ = NONE;
        let mut values: Vec<u32> = Vec::new();
        if keyword == Tok::Const {
            // an optional type and initialization, always accepted
            if self.tok != Tok::Eof && self.tok != Tok::Semicolon && self.tok != Tok::Rparen {
                if let Some(t) = self.try_ident_or_type()? {
                    typ = t;
                }
                if self.tok == Tok::Assign {
                    self.next()?;
                    values = self.exprs(true)?;
                }
            }
        } else {
            if self.tok != Tok::Assign {
                typ = self.parse_type()?;
            }
            if self.tok == Tok::Assign {
                self.next()?;
                values = self.exprs(true)?;
            }
        }
        self.expect_semi()?;
        let start = self.st(names[0]);
        let end = match values.last() {
            Some(&v) => self.en(v),
            None if typ != NONE => self.en(typ),
            None => self.en(names[names.len() - 1]),
        };
        let (n, v) = (self.list(&names), self.list(&values));
        Ok(self.add(Kind::ValueSpec, 0, 0, start, end, [n, typ, v, NONE]))
    }

    /// `isTypeElem`: is `x` a type element (a type that is no expression, or `~T`, or a union of them)? Not
    /// recursive: a union can be as long as the text.
    fn is_type_elem(&self, x: u32) -> bool {
        let mut stack = vec![x];
        while let Some(x) = stack.pop() {
            match self.kd(x) {
                Kind::ArrayType | Kind::StructType | Kind::FuncType | Kind::InterfaceType | Kind::MapType
                | Kind::ChanType => return true,
                Kind::BinaryExpr => {
                    stack.push(self.slot(x, 0));
                    stack.push(self.slot(x, 1));
                }
                Kind::UnaryExpr => {
                    if self.tree.nodes[x as usize].op == Tok::Tilde as u8 {
                        return true;
                    }
                }
                Kind::ParenExpr => stack.push(self.slot(x, 0)),
                _ => {}
            }
        }
        false
    }

    /// `extractName`: split `x` into a type parameter's name and the type that follows it, when `x` can be written as
    /// `name type`. The nodes of `x` that become the type are changed where they are (`P *E` was read as a product,
    /// `P(E)` as a call), so no node is left unreachable. (name, type) when it splits; None otherwise.
    fn extract_name(&mut self, x: u32, force: bool) -> Option<(u32, Option<u32>)> {
        match self.kd(x) {
            Kind::Ident => return Some((x, None)),
            Kind::BinaryExpr | Kind::CallExpr => {}
            _ => return None,
        }
        // the spine of `a | b | c`: x, x.X, ... while an OR; the force of the base is the caller's or any Y's
        let mut spine: Vec<u32> = Vec::new();
        let mut base = x;
        let mut force = force;
        while self.kd(base) == Kind::BinaryExpr && self.tree.nodes[base as usize].op == Tok::Or as u8 {
            spine.push(base);
            force = force || self.is_type_elem(self.slot(base, 1));
            base = self.slot(base, 0);
        }
        let n = self.tree.nodes[base as usize];
        let name;
        match n.kind {
            Kind::Ident => {
                // `a | b` where `a` is a name: the name alone is no split (`name != nil && lhs != nil` fails)
                return if spine.is_empty() { Some((base, None)) } else { None };
            }
            Kind::BinaryExpr if n.op == Tok::Mul as u8 => {
                let (lhs, rhs) = (n.f[0], n.f[1]);
                if self.kd(lhs) != Kind::Ident || !(force || self.is_type_elem(rhs)) {
                    return None;
                }
                // P * E: the name P and the type *E
                name = lhs;
                let node = &mut self.tree.nodes[base as usize];
                node.kind = Kind::StarExpr;
                node.start = n.f[2];
                node.f = [rhs, NONE, NONE, NONE];
            }
            Kind::CallExpr => {
                let fun = n.f[0];
                let args = self.tree.items(n.f[1]);
                if self.kd(fun) != Kind::Ident || args.len() != 1 || n.flags & ELLIPSIS != 0 {
                    return None;
                }
                let arg = args[0];
                if !(force || self.is_type_elem(arg)) {
                    return None;
                }
                // P(E): the name P and the type (E)
                name = fun;
                let node = &mut self.tree.nodes[base as usize];
                node.kind = Kind::ParenExpr;
                node.start = n.f[2];
                node.f = [arg, NONE, NONE, NONE];
            }
            _ => return None,
        }
        // the unions above the base now start where the base does
        let start = self.st(base);
        for &s in &spine {
            self.tree.nodes[s as usize].start = start;
        }
        Some((name, Some(x)))
    }

    /// After `name [` of a type declaration: the type parameters (`type T[P any] ...`) or an array type.
    fn type_spec(&mut self) -> R<u32> {
        let name = self.ident()?;
        let mut tparams = NONE;
        let mut flags = 0;
        let typ;
        if self.tok == Tok::Lbrack {
            // an array or slice type, or a type parameter list
            let lbrack = self.pos;
            self.next()?;
            if self.tok == Tok::Ident {
                // an expression `x` (a name, or more) to look at: a type parameter list starts with a name
                let mut x = self.ident()?;
                if self.tok != Tok::Lbrack {
                    // (a type bound may start with `[`, as in `P []E`: then the name stands alone)
                    self.expr_lev += 1;
                    let lhs = self.primary_expr(Some(x))?;
                    x = self.binary_expr(Some(lhs), 1)?;
                    self.expr_lev -= 1;
                }
                let force = self.tok == Tok::Comma;
                let split = self.extract_name(x, force);
                match split {
                    Some((pname, ptype)) if ptype.is_some() || self.tok != Tok::Rbrack => {
                        // name [ pname ptype? ...
                        let list = self.parameter_list(Some(pname), ptype, Tok::Rbrack)?;
                        let (_, closing_end) = self.expect(Tok::Rbrack)?;
                        tparams = self.field_list(Some((lbrack, closing_end)), &list);
                        if self.tok == Tok::Assign {
                            flags |= ALIAS;
                            self.next()?;
                        }
                        typ = self.parse_type()?;
                    }
                    _ => typ = self.array_type(lbrack, Some(x))?,
                }
            } else {
                typ = self.array_type(lbrack, None)?;
            }
        } else {
            if self.tok == Tok::Assign {
                flags |= ALIAS;
                self.next()?;
            }
            typ = self.parse_type()?;
        }
        self.expect_semi()?;
        let (s, e) = (self.st(name), self.en(typ));
        Ok(self.add(Kind::TypeSpec, 0, flags, s, e, [name, tparams, typ, NONE]))
    }

    fn gen_decl(&mut self, keyword: Tok) -> R<u32> {
        let (pos, _) = self.expect(keyword)?;
        let mut specs: Vec<u32> = Vec::new();
        let mut paren = false;
        let end;
        if self.tok == Tok::Lparen {
            paren = true;
            self.next()?;
            while self.tok != Tok::Rparen && self.tok != Tok::Eof {
                specs.push(self.spec(keyword)?);
            }
            end = self.expect(Tok::Rparen)?.1;
            self.expect_semi()?;
        } else {
            specs.push(self.spec(keyword)?);
            end = self.en(specs[0]);
        }
        let l = self.list(&specs);
        Ok(self.add(Kind::GenDecl, keyword as u8, if paren { PAREN } else { 0 }, pos, end, [l, NONE, NONE, NONE]))
    }

    fn spec(&mut self, keyword: Tok) -> R<u32> {
        match keyword {
            Tok::Import => self.import_spec(),
            Tok::Type => self.type_spec(),
            _ => self.value_spec(keyword),
        }
    }

    fn func_decl(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Func)?;
        let mut recv = None;
        if self.tok == Tok::Lparen {
            recv = Some(self.parameters(false)?.1);
        }
        let ident = self.ident()?;
        let (tparams, params) = self.parameters(true)?;
        if recv.is_some() && tparams.is_some() {
            return self.fail("method must have no type parameters");
        }
        let results = self.result()?;
        let mut body = None;
        match self.tok {
            Tok::Lbrace => {
                body = Some(self.block()?);
                self.expect_semi()?;
            }
            Tok::Semicolon => {
                self.next()?;
                if self.tok == Tok::Lbrace {
                    return self.fail("unexpected semicolon or newline before {");
                }
            }
            _ => self.expect_semi()?,
        }
        let typ = self.func_type_node(Some(pos), tparams, params, results);
        let end = match body {
            Some(b) => self.en(b),
            None => self.en(typ),
        };
        Ok(self.add(Kind::FuncDecl, 0, 0, pos, end, [recv.unwrap_or(NONE), ident, typ, body.unwrap_or(NONE)]))
    }

    fn decl(&mut self) -> R<u32> {
        match self.tok {
            Tok::Import | Tok::Const | Tok::Var | Tok::Type => {
                let k = self.tok;
                self.gen_decl(k)
            }
            Tok::Func => self.func_decl(),
            _ => self.fail("expected declaration"),
        }
    }

    // ---- the file ----

    fn file(&mut self) -> R<u32> {
        let (pos, _) = self.expect(Tok::Package)?;
        let name = self.ident()?;
        self.expect_semi()?;
        let mut decls: Vec<u32> = Vec::new();
        while self.tok == Tok::Import {
            decls.push(self.gen_decl(Tok::Import)?);
        }
        let mut prev = Tok::Import;
        while self.tok != Tok::Eof {
            // (imports after other declarations are accepted for error tolerance but complained about)
            if self.tok == Tok::Import && prev != Tok::Import {
                return self.fail("imports must appear before other declarations");
            }
            prev = self.tok;
            decls.push(self.decl()?);
        }
        let end = match decls.last() {
            Some(&d) => self.en(d),
            None => self.en(name),
        };
        let l = self.list(&decls);
        Ok(self.add(Kind::File, 0, 0, pos, end, [name, l, NONE, NONE]))
    }
}
