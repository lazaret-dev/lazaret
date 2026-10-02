//! Expressions, assignment targets, call arguments, parameters,
//! comprehensions, strings and f-strings.

use super::lexer::*;
use super::limits as L;
use super::literal::{self, Num};
use super::parser::{Ex, Fail, Parser, Pending, Piece, R};
use super::tree::*;

impl<'a> Parser<'a> {
    /// Can the token start an expression?
    pub fn starts_expression(&self) -> bool {
        Self::starts_expr(self.tok())
    }

    /// Can `t` start an expression?
    pub fn starts_expr(t: Tok) -> bool {
        match t.t {
            T::Name | T::Number | T::Str | T::FStart => true,
            T::Kw => matches!(t.k, KW_NONE | KW_TRUE | KW_FALSE | KW_NOT | KW_LAMBDA | KW_AWAIT),
            T::Op => matches!(t.k, LPAR | LSQB | LBRACE | MINUS | PLUS | TILDE | ELLIPSIS | STAR),
            _ => false,
        }
    }

    /// Can the token start an atom (and so a target)?
    fn starts_target(&self) -> bool {
        let t = self.tok();
        match t.t {
            T::Name | T::Number | T::Str | T::FStart => true,
            T::Kw => matches!(t.k, KW_NONE | KW_TRUE | KW_FALSE),
            T::Op => matches!(t.k, LPAR | LSQB | LBRACE | ELLIPSIS | STAR),
            _ => false,
        }
    }

    /// `star_expressions`: a tuple without parentheses when there is a comma.
    pub fn star_expressions(&mut self) -> R<Ex> {
        let first = self.star_expression()?;
        if !self.at_op(COMMA) {
            return Ok(first);
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        let mut e = first.e;
        self.enter(L::LATER_ITEM)?;
        while let Some(c) = self.eat_op(COMMA) {
            e = c.e;
            if !self.starts_expression() {
                break;
            }
            let x = self.star_expression()?;
            self.stack.push(x.n);
            e = x.e;
        }
        self.leave(L::LATER_ITEM);
        let elts = self.list_from(mark);
        let n = self.add(Kind::Tuple, LOAD, first.s, e, [elts, NONE, NONE, NONE]);
        Ok(Ex { n, s: first.s, e })
    }

    /// `'*' bitwise_or | expression`
    pub fn star_expression(&mut self) -> R<Ex> {
        if let Some(star) = self.eat_op(STAR) {
            let x = self.bitor()?;
            let n = self.add(Kind::Starred, LOAD, star.s, x.e, [x.n, NONE, NONE, NONE]);
            return Ok(Ex { n, s: star.s, e: x.e });
        }
        self.expression()
    }

    /// `'*' bitwise_or | named_expression`
    pub fn star_named_expression(&mut self) -> R<Ex> {
        let k = self.p;
        if let Some(star) = self.eat_op(STAR) {
            let x = self.bitor()?;
            // (first in a display, Python's error pass reads it as `'*'
            // expression`, with that rule's checks)
            let first = k > 0 && matches!(self.toks[k - 1], Tok { t: T::Op, k: LPAR | LSQB | LBRACE, .. });
            if first && self.adjacent() && self.ahead == 0 {
                self.adjacent_expression(x)?;
            }
            let n = self.add(Kind::Starred, LOAD, star.s, x.e, [x.n, NONE, NONE, NONE]);
            return Ok(Ex { n, s: star.s, e: x.e });
        }
        self.named_expression()
    }

    /// `NAME ':=' expression | expression`
    pub fn named_expression(&mut self) -> R<Ex> {
        let t = self.tok();
        if t.t == T::Name {
            let next = self.peek(1);
            if next.t == T::Op && next.k == COLONEQUAL {
                self.advance();
                self.advance();
                self.enter(L::WALRUS)?;
                let value = self.expression()?;
                self.leave(L::WALRUS);
                let target = self.add(Kind::Name, STORE, t.s, t.e, [t.v, NONE, NONE, NONE]);
                let n = self.add(Kind::NamedExpr, 0, t.s, value.e, [target, value.n, NONE, NONE]);
                return Ok(Ex { n, s: t.s, e: value.e });
            }
        }
        let x = self.expression()?;
        if self.at_op(COLONEQUAL) {
            // (at the target if what follows reads, as Python's error pass has it)
            if self.ahead == 0 {
                let at = self.p;
                self.advance();
                let value = self.read_ahead(Self::expression, false)?;
                self.p = at;
                if value.is_some() {
                    let s = self.tree.nodes[x.n as usize].start;
                    return self.fatal_at(s, "cannot use assignment expressions with this target");
                }
            }
            return self.fail("cannot use assignment expressions with this target");
        }
        if self.at_op(EQUAL) && self.ahead == 0 {
            self.equal_after(x)?;
        }
        Ok(x)
    }

    /// Is `x` a bitwise_or that does not start with a list, a tuple, a
    /// generator expression, True, None or False (what Python's error pass
    /// takes for a mistaken `=`)?
    pub fn assignable_bitor(&self, x: Ex) -> bool {
        let node = self.tree.nodes[x.n as usize];
        let paren = x.s != node.start;
        let low = match node.kind {
            Kind::Compare | Kind::BoolOp | Kind::IfExp | Kind::Lambda | Kind::NamedExpr => true,
            Kind::UnaryOp => node.op == NOT,
            _ => false,
        };
        if low && !paren {
            return false;
        }
        let first = self.toks.partition_point(|t| t.s < x.s);
        let excluded = match self.toks.get(first) {
            Some(t) if t.t == T::Kw => matches!(t.k, KW_NONE | KW_TRUE | KW_FALSE),
            Some(t) if t.t == T::Op && t.k == LSQB => true,
            Some(t) if t.t == T::Op && t.k == LPAR => paren && matches!(node.kind, Kind::Tuple | Kind::GeneratorExp),
            _ => false,
        };
        !excluded
    }

    /// Can an expression read from token `k` on, at least in part (one
    /// token at least: an atom of one token after any prefix operators)?
    pub fn prefix_reads_at(&self, mut k: usize) -> bool {
        while let Some(t) = self.toks.get(k) {
            match t.t {
                T::Name | T::Number | T::Str => return true,
                T::Kw if matches!(t.k, KW_NONE | KW_TRUE | KW_FALSE | KW_YIELD) => return true,
                T::Kw if matches!(t.k, KW_NOT | KW_AWAIT) => k += 1,
                T::Op if t.k == ELLIPSIS => return true,
                T::Op if matches!(t.k, MINUS | PLUS | TILDE | STAR) => k += 1,
                _ => return false,
            }
        }
        false
    }

    /// `x =` where only an expression may be: an error, which Python's
    /// error pass reports at `x` when `x` is a bitwise_or that is not a list,
    /// a tuple, a generator expression, True, None or False, and one follows
    /// the `=` (at least in part) with no `=` or `:=` after it.
    fn equal_after(&mut self, x: Ex) -> R<()> {
        if !self.assignable_bitor(x) {
            return Ok(());
        }
        let node = self.tree.nodes[x.n as usize];
        let paren = x.s != node.start;
        let at = self.p;
        self.advance();
        let end = self.read_prefix(Self::bitor, false, false)?;
        self.p = at;
        if let Some(end) = end {
            let next = self.toks.get(end).copied().unwrap_or(self.tok());
            if !(next.t == T::Op && (next.k == EQUAL || next.k == COLONEQUAL)) {
                let why = if node.kind == Kind::Name && !paren {
                    "invalid syntax. Maybe you meant '==' or ':=' instead of '='?"
                } else {
                    "cannot assign to this expression here. Maybe you meant '==' instead of '='?"
                };
                return self.fatal_at(node.start, why);
            }
        }
        Ok(())
    }

    /// Is `x` a walrus not in parentheses?
    fn bare_walrus(&self, x: Ex) -> bool {
        self.kind(x.n) == Kind::NamedExpr && x.s == self.tree.nodes[x.n as usize].start
    }

    /// `expression`: a disjunction, a conditional expression or a lambda
    /// (their chains — `a if b else c if d else …`, `lambda: lambda: …` —
    /// read in a loop).
    pub fn expression(&mut self) -> R<Ex> {
        let base = self.pending.len();
        let mut entered = 0;
        let mut last_charged = false;
        let mut result;
        // (the error pass's checks of this level, but at `unchecked_at`)
        let checked = self.p != self.unchecked_at;
        loop {
            if self.at_kw(KW_LAMBDA) {
                let s = self.advance().s;
                let at = self.tok().s;
                let args = self.parameters(false, at)?;
                self.expect_op(COLON)?;
                let cost = if self.pending.len() == base { L::LAMBDA + L::LAMBDA_BODY } else { L::LAMBDA };
                self.enter(cost)?;
                entered += cost;
                self.pending.push(Pending::Lambda { args, s });
                continue;
            }
            let d = self.disjunction()?;
            if self.adjacent() && self.ahead == 0 && checked {
                self.adjacent_expression(d)?;
            }
            if self.at_kw(KW_IF) {
                self.advance();
                let test = self.disjunction()?;
                if !self.at_kw(KW_ELSE) && self.ahead == 0 && !self.at_op(COLON) && checked {
                    // (where Python's error pass puts it)
                    let at = self.tree.nodes[d.n as usize].start;
                    return self.fatal_at(at, "expected 'else' after 'if' expression");
                }
                self.expect_kw(KW_ELSE)?;
                let mut cost = L::IFEXP;
                // (an `else` part that starts with a unary operator costs more, once)
                let t = self.tok();
                let unary = (t.t == T::Op && matches!(t.k, MINUS | PLUS | TILDE)) || (t.t == T::Kw && t.k == KW_NOT);
                if unary && !last_charged {
                    cost += L::IFEXP_LAST;
                    last_charged = true;
                }
                self.enter(cost)?;
                entered += cost;
                self.pending.push(Pending::IfExp { body: d, test });
                continue;
            }
            result = d;
            break;
        }
        while self.pending.len() > base {
            let p = match self.pending.pop() {
                Some(p) => p,
                None => break,
            };
            result = match p {
                Pending::Lambda { args, s } => {
                    let n = self.add(Kind::Lambda, 0, s, result.e, [args, result.n, NONE, NONE]);
                    Ex { n, s, e: result.e }
                }
                Pending::IfExp { body, test } => {
                    let n = self.add(Kind::IfExp, 0, body.s, result.e, [test.n, body.n, result.n, NONE]);
                    Ex { n, s: body.s, e: result.e }
                }
            };
        }
        self.leave(entered);
        Ok(result)
    }

    /// Can the token start an expression though no expression goes on with
    /// it (so that right after one, it is an error)?
    #[inline]
    fn adjacent(&self) -> bool {
        let t = self.tok();
        match t.t {
            T::Name | T::Number | T::Str | T::FStart => true,
            T::Kw => matches!(t.k, KW_NONE | KW_TRUE | KW_FALSE | KW_NOT | KW_LAMBDA | KW_AWAIT),
            T::Op => matches!(t.k, LBRACE | ELLIPSIS),
            _ => false,
        }
    }

    /// An expression right after the disjunction `a`: an error, which
    /// Python's error pass reports where it reads on from `a` (the
    /// expression must read, at least in part):
    ///
    /// - inside brackets (and not after a name and a string, nor a soft
    ///   keyword, nor `print` or `exec`), "Perhaps you forgot a comma?" at
    ///   `a`;
    /// - after a name alone, it reads the expressions after it, its own
    ///   checks on (an error they find is the error): after `print` or
    ///   `exec`, "Missing parentheses in call to …".
    fn adjacent_expression(&mut self, a: Ex) -> R<()> {
        let node = self.tree.nodes[a.n as usize];
        let bare = node.kind == Kind::Name && a.s == node.start;
        let legacy = if bare {
            let id = self.tree.str(node.f[A as usize]);
            ["print", "exec"].iter().copied().find(|w| w.len() == id.len() && w.bytes().zip(id).all(|(b, &c)| b as u32 == c))
        } else {
            None
        };
        let first = self.toks.partition_point(|t| t.s < a.s);
        let excluded = match self.toks.get(first) {
            Some(&ft) => {
                (ft.t == T::Name && self.toks.get(first + 1).map_or(false, |t| t.t == T::Str))
                    || (ft.t == T::Name && ft.k == 0 && matches!(ft.v, S_MATCH | S_CASE | S_TYPE | S_UNDERSCORE))
            }
            None => false,
        };
        let mut silent = None;
        if !excluded {
            // (the expression after `a` — Python's `expression_without_invalid`
            // — is read with the error pass's checks off; where none of it
            // reads, an error inside its brackets is the one Python reports:
            // read again with the checks on there)
            silent = self.read_prefix(Self::expression, false, true)?;
            match silent {
                Some(end) => {
                    if legacy.is_none() && self.brackets_open(end) > 0 {
                        return self.fatal_at(node.start, "invalid syntax. Perhaps you forgot a comma?");
                    }
                }
                None => {
                    if !bare && self.ahead_checked == 0 {
                        let unchecked_at = std::mem::replace(&mut self.unchecked_at, self.p);
                        let r = self.read_ahead(Self::expression, true);
                        self.unchecked_at = unchecked_at;
                        r?;
                    }
                }
            }
        }
        if bare && self.ahead_checked == 0 {
            // (Python's `NAME !'(' star_expressions`, its checks on — but
            // where the read above took a part, Python takes it as read)
            let read = match silent {
                Some(_) => silent,
                None => self.read_prefix(Self::star_expressions, true, true)?,
            };
            if let (Some(w), Some(_)) = (legacy, read) {
                let why = format!("Missing parentheses in call to '{}'. Did you mean {}(...)?", w, w);
                return self.fatal_at(node.start, &why);
            }
        }
        Ok(())
    }

    /// Where an expression read ahead from here ends, if one reads — at
    /// least in part: an atom of one token, after any unary operators (and
    /// `not`, where the read is of a whole expression: `logic`) — Python's
    /// ordered choices settle for the longest part that reads.
    pub fn read_prefix(&mut self, read: fn(&mut Self) -> R<Ex>, checked: bool, logic: bool) -> R<Option<usize>> {
        if let Some(end) = self.read_ahead(read, checked)? {
            return Ok(Some(end));
        }
        let mut k = self.p;
        while let Some(t) = self.toks.get(k) {
            match (t.t, t.k) {
                (T::Op, MINUS | PLUS | TILDE) | (T::Kw, KW_AWAIT) => k += 1,
                (T::Kw, KW_NOT) if logic => k += 1,
                (T::Name | T::Number | T::Str, _) | (T::Kw, KW_NONE | KW_TRUE | KW_FALSE) | (T::Op, ELLIPSIS) => {
                    return Ok(Some(k + 1));
                }
                _ => break,
            }
        }
        Ok(None)
    }

    pub fn disjunction(&mut self) -> R<Ex> {
        let first = self.conjunction()?;
        if !self.at_kw(KW_OR) {
            return Ok(first);
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        let mut e = first.e;
        self.enter(L::BOOL_RIGHT)?;
        while self.at_kw(KW_OR) {
            self.advance();
            let x = self.conjunction()?;
            self.stack.push(x.n);
            e = x.e;
        }
        self.leave(L::BOOL_RIGHT);
        let values = self.list_from(mark);
        let n = self.add(Kind::BoolOp, OR, first.s, e, [values, NONE, NONE, NONE]);
        Ok(Ex { n, s: first.s, e })
    }

    fn conjunction(&mut self) -> R<Ex> {
        let first = self.inversion()?;
        if !self.at_kw(KW_AND) {
            return Ok(first);
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        let mut e = first.e;
        self.enter(L::BOOL_RIGHT)?;
        while self.at_kw(KW_AND) {
            self.advance();
            let x = self.inversion()?;
            self.stack.push(x.n);
            e = x.e;
        }
        self.leave(L::BOOL_RIGHT);
        let values = self.list_from(mark);
        let n = self.add(Kind::BoolOp, AND, first.s, e, [values, NONE, NONE, NONE]);
        Ok(Ex { n, s: first.s, e })
    }

    /// `'not'* comparison`
    fn inversion(&mut self) -> R<Ex> {
        let mark = self.stack.len();
        while self.at_kw(KW_NOT) {
            let s = self.advance().s;
            self.stack.push(s);
            self.enter(L::UNARY)?;
        }
        let nots = (self.stack.len() - mark) as u32;
        let mut x = self.comparison()?;
        while self.stack.len() > mark {
            let s = self.stack.pop().unwrap_or(0);
            let n = self.add(Kind::UnaryOp, NOT, s, x.e, [x.n, NONE, NONE, NONE]);
            x = Ex { n, s, e: x.e };
        }
        self.leave(nots * L::UNARY);
        Ok(x)
    }

    fn compare_op(&self) -> Option<(u8, usize)> {
        let t = self.tok();
        match t.t {
            T::Op => Some((
                match t.k {
                    EQEQUAL => EQ,
                    // (`from __future__ import barry_as_FLUFL` swaps `!=` for `<>`)
                    NOTEQUAL if !self.barry => NOTEQ,
                    OLDNOTEQUAL if self.barry => NOTEQ,
                    LESS => LT,
                    LESSEQUAL => LTE,
                    GREATER => GT,
                    GREATEREQUAL => GTE,
                    _ => return None,
                },
                1,
            )),
            T::Kw => match t.k {
                KW_IN => Some((IN, 1)),
                KW_IS => {
                    let n = self.peek(1);
                    if n.t == T::Kw && n.k == KW_NOT {
                        Some((ISNOT, 2))
                    } else {
                        Some((IS, 1))
                    }
                }
                KW_NOT => {
                    let n = self.peek(1);
                    if n.t == T::Kw && n.k == KW_IN {
                        Some((NOTIN, 2))
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn comparison(&mut self) -> R<Ex> {
        let first = self.bitor()?;
        if self.barry && self.at_op(NOTEQUAL) {
            return self.fatal_at(self.tok().s, "with Barry as BDFL, use '<>' instead of '!='");
        }
        if self.compare_op().is_none() {
            return Ok(first);
        }
        let mark = self.stack.len();
        let mut e = first.e;
        self.enter(L::COMPARE_RIGHT)?;
        while let Some((op, ntok)) = self.compare_op() {
            for _ in 0..ntok {
                self.advance();
            }
            let x = self.bitor()?;
            self.stack.push(op as u32);
            self.stack.push(x.n);
            e = x.e;
            if self.barry && self.at_op(NOTEQUAL) {
                return self.fatal_at(self.tok().s, "with Barry as BDFL, use '<>' instead of '!='");
            }
        }
        self.leave(L::COMPARE_RIGHT);
        let pairs: Vec<u32> = self.stack.split_off(mark);
        let ops: Vec<u32> = pairs.iter().step_by(2).copied().collect();
        let comparators: Vec<u32> = pairs.iter().skip(1).step_by(2).copied().collect();
        let ops = self.tree.push_list(&ops);
        let comparators = self.tree.push_list(&comparators);
        let n = self.add(Kind::Compare, 0, first.s, e, [first.n, ops, comparators, NONE]);
        Ok(Ex { n, s: first.s, e })
    }

    /// `bitwise_or`
    pub fn bitor(&mut self) -> R<Ex> {
        self.binary(1)
    }

    /// The binary operators from `|` (1) to `*` `/` `//` `%` `@` (6), left
    /// to right, by precedence climbing (at most six calls deep).
    fn binary(&mut self, min: u8) -> R<Ex> {
        let mut left = self.factor()?;
        loop {
            let t = self.tok();
            if t.t != T::Op {
                break;
            }
            let (op, prec) = match t.k {
                VBAR => (BITOR, 1),
                CIRCUMFLEX => (BITXOR, 2),
                AMPER => (BITAND, 3),
                LEFTSHIFT => (LSHIFT, 4),
                RIGHTSHIFT => (RSHIFT, 4),
                PLUS => (ADD, 5),
                MINUS => (SUB, 5),
                STAR => (MULT, 6),
                SLASH => (DIV, 6),
                DOUBLESLASH => (FLOORDIV, 6),
                PERCENT => (MOD, 6),
                AT => (MATMULT, 6),
                _ => break,
            };
            if prec < min {
                break;
            }
            self.advance();
            self.enter(L::BINARY_RIGHT)?;
            let right = self.binary(prec + 1)?;
            self.leave(L::BINARY_RIGHT);
            let n = self.add(Kind::BinOp, op, left.s, right.e, [left.n, right.n, NONE, NONE]);
            left = Ex { n, s: left.s, e: right.e };
        }
        Ok(left)
    }

    /// The unary operators before a power: (start, op) pairs on the stack.
    fn unary_prefixes(&mut self) -> R<u32> {
        let mut k = 0;
        loop {
            let t = self.tok();
            let op = match (t.t, t.k) {
                (T::Op, PLUS) => UADD,
                (T::Op, MINUS) => USUB,
                (T::Op, TILDE) => INVERT,
                _ => break,
            };
            self.advance();
            self.stack.push(t.s);
            self.stack.push(op as u32);
            self.enter(L::UNARY)?;
            k += 1;
        }
        Ok(k)
    }

    /// Wraps `x` in the `k` unary operators on top of the stack.
    fn wrap_unary(&mut self, mut x: Ex, k: u32) -> Ex {
        for _ in 0..k {
            let op = self.stack.pop().unwrap_or(0) as u8;
            let s = self.stack.pop().unwrap_or(0);
            let n = self.add(Kind::UnaryOp, op, s, x.e, [x.n, NONE, NONE, NONE]);
            x = Ex { n, s, e: x.e };
        }
        x
    }

    /// `factor`: unary operators, then a power; `**` binds to the right,
    /// and its right side is a factor again (all read in one loop).
    fn factor(&mut self) -> R<Ex> {
        let k0 = self.unary_prefixes()?;
        let mut cur = self.await_primary()?;
        // each `**`: the stack gets the left operand (n, s, e), then the
        // unary operators after the `**`, then how many there are
        let mut frames = 0u32;
        let mut entered = k0 * L::UNARY;
        while self.at_op(DOUBLESTAR) {
            self.advance();
            let cost = if frames == 0 { L::POWER + L::POWER_RIGHT } else { L::POWER };
            self.enter(cost)?;
            entered += cost;
            self.stack.push(cur.n);
            self.stack.push(cur.s);
            self.stack.push(cur.e);
            let k = self.unary_prefixes()?;
            entered += k * L::UNARY;
            self.stack.push(k);
            frames += 1;
            cur = self.await_primary()?;
        }
        for _ in 0..frames {
            let k = self.stack.pop().unwrap_or(0);
            // the unary operators sit under k
            let right = self.wrap_unary(cur, k);
            let e = self.stack.pop().unwrap_or(0);
            let s = self.stack.pop().unwrap_or(0);
            let n = self.stack.pop().unwrap_or(NONE);
            let b = self.add(Kind::BinOp, POW, s, right.e, [n, right.n, NONE, NONE]);
            let _ = e;
            cur = Ex { n: b, s, e: right.e };
        }
        let x = self.wrap_unary(cur, k0);
        self.leave(entered);
        Ok(x)
    }

    fn await_primary(&mut self) -> R<Ex> {
        if self.at_kw(KW_AWAIT) {
            let s = self.advance().s;
            self.enter(L::AWAIT)?;
            let x = self.primary()?;
            self.leave(L::AWAIT);
            let n = self.add(Kind::Await, 0, s, x.e, [x.n, NONE, NONE, NONE]);
            return Ok(Ex { n, s, e: x.e });
        }
        self.primary()
    }

    /// An atom and its trailers: `.name`, `(arguments)`, `[slices]`.
    pub fn primary(&mut self) -> R<Ex> {
        let cheap = self.p == self.cheap_at;
        let mut x = self.atom()?;
        loop {
            let t = self.tok();
            if t.t != T::Op {
                break;
            }
            match t.k {
                DOT => {
                    self.advance();
                    let name = self.expect_name()?;
                    let n = self.add(Kind::Attribute, LOAD, x.s, name.e, [x.n, name.v, NONE, NONE]);
                    x = Ex { n, s: x.s, e: name.e };
                }
                LPAR => {
                    let cost = if cheap { L::CHEAP_CALL } else { L::CALL };
                    let (args, keywords, e) = self.call_args(true, cost)?;
                    let n = self.add(Kind::Call, 0, x.s, e, [x.n, args, keywords, NONE]);
                    x = Ex { n, s: x.s, e };
                }
                LSQB => {
                    self.advance();
                    let cost = if cheap { L::CHEAP_SUBSCRIPT } else { L::SUBSCRIPT };
                    self.enter(cost)?;
                    let slice = self.slices()?;
                    self.leave(cost);
                    let rb = self.expect_op(RSQB)?;
                    let n = self.add(Kind::Subscript, LOAD, x.s, rb.e, [x.n, slice.n, NONE, NONE]);
                    x = Ex { n, s: x.s, e: rb.e };
                }
                _ => break,
            }
        }
        Ok(x)
    }

    fn constant(&mut self, t: Tok, v: u8) -> Ex {
        let n = self.add(Kind::Constant, v, t.s, t.e, [NONE, NONE, NONE, NONE]);
        Ex { n, s: t.s, e: t.e }
    }

    pub fn atom(&mut self) -> R<Ex> {
        self.enter(L::ATOM)?;
        self.leave(L::ATOM);
        let t = self.tok();
        let cheap = self.p == self.cheap_at;
        match t.t {
            T::Name => {
                self.advance();
                let n = self.add(Kind::Name, LOAD, t.s, t.e, [t.v, NONE, NONE, NONE]);
                Ok(Ex { n, s: t.s, e: t.e })
            }
            T::Number => {
                self.advance();
                let text = &self.src[t.s as usize..t.e as usize];
                match literal::number(text) {
                    Ok(Num::Int(digits)) => {
                        let id = self.tree.strings.intern(&digits);
                        let n = self.add(Kind::Constant, V_INT, t.s, t.e, [id, NONE, NONE, NONE]);
                        Ok(Ex { n, s: t.s, e: t.e })
                    }
                    Ok(Num::Float(f)) | Ok(Num::Imag(f)) => {
                        let v = if matches!(literal::number(text), Ok(Num::Imag(_))) { V_COMPLEX } else { V_FLOAT };
                        let bits = f.to_bits();
                        let n = self.add(Kind::Constant, v, t.s, t.e, [NONE, bits as u32, (bits >> 32) as u32, NONE]);
                        Ok(Ex { n, s: t.s, e: t.e })
                    }
                    Err(why) => self.fatal_at(t.s, &why),
                }
            }
            T::Str | T::FStart => self.strings(),
            T::Kw => match t.k {
                KW_NONE => {
                    self.advance();
                    Ok(self.constant(t, V_NONE))
                }
                KW_TRUE => {
                    self.advance();
                    Ok(self.constant(t, V_TRUE))
                }
                KW_FALSE => {
                    self.advance();
                    Ok(self.constant(t, V_FALSE))
                }
                _ => self.fail("invalid syntax"),
            },
            T::Op => match t.k {
                LPAR => {
                    let cost = if cheap {
                        L::CHEAP_PAREN
                    } else if self.p == self.second_paren_at {
                        L::SECOND_PAREN
                    } else {
                        L::PAREN
                    };
                    self.paren_atom(cost)
                }
                LSQB => self.list_atom(if cheap { L::CHEAP_LIST } else { L::LIST }),
                LBRACE => self.brace_atom(if cheap { L::CHEAP_BRACE } else { L::BRACE }),
                ELLIPSIS => {
                    self.advance();
                    Ok(self.constant(t, V_ELLIPSIS))
                }
                _ => self.fail("invalid syntax"),
            },
            _ => self.fail("invalid syntax"),
        }
    }

    fn is_starred(&self, x: Ex) -> bool {
        self.kind(x.n) == Kind::Starred && x.s == self.tree.nodes[x.n as usize].start
    }

    fn at_for(&self) -> bool {
        self.at_kw(KW_FOR) || (self.at_kw(KW_ASYNC) && self.peek(1).t == T::Kw && self.peek(1).k == KW_FOR)
    }

    /// `(`: a tuple, an expression in parentheses, a generator expression,
    /// `(yield …)`.
    fn paren_atom(&mut self, cost: u32) -> R<Ex> {
        let lp = self.advance();
        self.enter(cost)?;
        if let Some(rp) = self.eat_op(RPAR) {
            self.leave(cost);
            let n = self.add(Kind::Tuple, LOAD, lp.s, rp.e, [0, NONE, NONE, NONE]);
            return Ok(Ex { n, s: lp.s, e: rp.e });
        }
        if self.at_kw(KW_YIELD) {
            let y = self.yield_expr()?;
            let rp = self.expect_op(RPAR)?;
            self.leave(cost);
            return Ok(Ex { n: y.n, s: lp.s, e: rp.e });
        }
        let first = self.star_named_expression()?;
        if self.at_for() {
            if self.is_starred(first) {
                return self.fail("iterable unpacking cannot be used in comprehension");
            }
            let generators = self.comprehension_clauses()?;
            let rp = self.expect_op(RPAR)?;
            self.leave(cost);
            let n = self.add(Kind::GeneratorExp, 0, lp.s, rp.e, [first.n, generators, NONE, NONE]);
            return Ok(Ex { n, s: lp.s, e: rp.e });
        }
        if self.at_op(COMMA) {
            let mark = self.stack.len();
            self.stack.push(first.n);
            self.enter(L::LATER_ITEM)?;
            while self.eat_op(COMMA).is_some() {
                if self.at_op(RPAR) {
                    break;
                }
                let x = self.star_named_expression()?;
                self.stack.push(x.n);
            }
            self.leave(L::LATER_ITEM);
            let rp = self.expect_op(RPAR)?;
            self.leave(cost);
            let elts = self.list_from(mark);
            let n = self.add(Kind::Tuple, LOAD, lp.s, rp.e, [elts, NONE, NONE, NONE]);
            return Ok(Ex { n, s: lp.s, e: rp.e });
        }
        let rp = self.expect_op(RPAR)?;
        if self.is_starred(first) {
            return self.fail_at(first.s, "cannot use starred expression here");
        }
        self.leave(cost);
        Ok(Ex { n: first.n, s: lp.s, e: rp.e })
    }

    fn list_atom(&mut self, cost: u32) -> R<Ex> {
        let lb = self.advance();
        self.enter(cost)?;
        if let Some(rb) = self.eat_op(RSQB) {
            self.leave(cost);
            let n = self.add(Kind::List, LOAD, lb.s, rb.e, [0, NONE, NONE, NONE]);
            return Ok(Ex { n, s: lb.s, e: rb.e });
        }
        let first = self.star_named_expression()?;
        if self.at_for() {
            if self.is_starred(first) {
                return self.fail("iterable unpacking cannot be used in comprehension");
            }
            let generators = self.comprehension_clauses()?;
            let rb = self.expect_op(RSQB)?;
            self.leave(cost);
            let n = self.add(Kind::ListComp, 0, lb.s, rb.e, [first.n, generators, NONE, NONE]);
            return Ok(Ex { n, s: lb.s, e: rb.e });
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        self.enter(L::LATER_ITEM)?;
        while self.eat_op(COMMA).is_some() {
            if self.at_op(RSQB) {
                break;
            }
            let x = self.star_named_expression()?;
            self.stack.push(x.n);
        }
        self.leave(L::LATER_ITEM);
        let rb = self.expect_op(RSQB)?;
        self.leave(cost);
        let elts = self.list_from(mark);
        let n = self.add(Kind::List, LOAD, lb.s, rb.e, [elts, NONE, NONE, NONE]);
        Ok(Ex { n, s: lb.s, e: rb.e })
    }

    /// `{`: a dict, a set, or their comprehensions.
    fn brace_atom(&mut self, cost: u32) -> R<Ex> {
        let lb = self.advance();
        self.enter(cost)?;
        if let Some(rb) = self.eat_op(RBRACE) {
            self.leave(cost);
            let n = self.add(Kind::Dict, 0, lb.s, rb.e, [0, 0, NONE, NONE]);
            return Ok(Ex { n, s: lb.s, e: rb.e });
        }
        let mark = self.stack.len();
        if self.at_op(DOUBLESTAR) {
            // a dict whose first item is `**mapping`
            self.advance();
            let v = self.bitor()?;
            self.stack.push(NONE);
            self.stack.push(v.n);
            return self.dict_rest(lb, mark, cost);
        }
        let first = self.star_named_expression()?;
        if self.at_op(COLON) && !self.is_starred(first) && !self.bare_walrus(first) {
            let colon = self.advance();
            self.dict_value_follows(colon)?;
            let value = self.expression()?;
            if self.at_for() {
                let generators = self.comprehension_clauses()?;
                let rb = self.expect_op(RBRACE)?;
                self.leave(cost);
                let n = self.add(Kind::DictComp, 0, lb.s, rb.e, [first.n, value.n, generators, NONE]);
                return Ok(Ex { n, s: lb.s, e: rb.e });
            }
            self.stack.push(first.n);
            self.stack.push(value.n);
            return self.dict_rest(lb, mark, cost);
        }
        if self.at_for() {
            if self.is_starred(first) {
                return self.fail("iterable unpacking cannot be used in comprehension");
            }
            let generators = self.comprehension_clauses()?;
            let rb = self.expect_op(RBRACE)?;
            self.leave(cost);
            let n = self.add(Kind::SetComp, 0, lb.s, rb.e, [first.n, generators, NONE, NONE]);
            return Ok(Ex { n, s: lb.s, e: rb.e });
        }
        self.stack.push(first.n);
        self.enter(L::LATER_ITEM)?;
        while self.eat_op(COMMA).is_some() {
            if self.at_op(RBRACE) {
                break;
            }
            let x = self.star_named_expression()?;
            self.stack.push(x.n);
        }
        self.leave(L::LATER_ITEM);
        let rb = self.expect_op(RBRACE)?;
        self.leave(cost);
        let elts = self.list_from(mark);
        let n = self.add(Kind::Set, 0, lb.s, rb.e, [elts, NONE, NONE, NONE]);
        Ok(Ex { n, s: lb.s, e: rb.e })
    }

    /// After a dict key's `:`, a value must follow: none before `}` or `,`
    /// is an error Python's error pass reports at the `:`.
    fn dict_value_follows(&mut self, colon: Tok) -> R<()> {
        if self.at_op(RBRACE) || self.at_op(COMMA) {
            return self.pass_fail_at(colon.s, "expression expected after dictionary key and ':'");
        }
        Ok(())
    }

    /// A dict's items after its first (key and value pairs on the stack
    /// from `mark`; a `**` item's key is NONE).
    fn dict_rest(&mut self, lb: Tok, mark: usize, cost: u32) -> R<Ex> {
        self.enter(L::LATER_ITEM)?;
        while self.eat_op(COMMA).is_some() {
            if self.at_op(RBRACE) {
                break;
            }
            if self.eat_op(DOUBLESTAR).is_some() {
                let v = self.bitor()?;
                self.stack.push(NONE);
                self.stack.push(v.n);
                continue;
            }
            // (a key not followed by `:` is reported at the key, by Python's
            // error pass, whatever follows it — two expressions side by side,
            // an `if` without `else` — as long as an expression reads there
            // at least in part)
            let kp = self.p;
            self.unchecked_at = kp;
            let k = self.expression();
            self.unchecked_at = usize::MAX;
            let k = match k {
                Ok(k) => k,
                Err(Fail::Syntax) if self.prefix_reads_at(kp) => {
                    let at = self.toks.get(kp).map_or(0, |t| t.s);
                    return self.pass_fail_at(at, "':' expected after dictionary key");
                }
                Err(e) => return Err(e),
            };
            if !self.at_op(COLON) {
                let at = self.tree.nodes[k.n as usize].start;
                return self.pass_fail_at(at, "':' expected after dictionary key");
            }
            let colon = self.advance();
            self.dict_value_follows(colon)?;
            let v = self.expression()?;
            self.stack.push(k.n);
            self.stack.push(v.n);
        }
        self.leave(L::LATER_ITEM);
        let rb = self.expect_op(RBRACE)?;
        self.leave(cost);
        let pairs: Vec<u32> = self.stack.split_off(mark);
        let keys: Vec<u32> = pairs.iter().step_by(2).copied().collect();
        let values: Vec<u32> = pairs.iter().skip(1).step_by(2).copied().collect();
        let keys = self.tree.push_list(&keys);
        let values = self.tree.push_list(&values);
        let n = self.add(Kind::Dict, 0, lb.s, rb.e, [keys, values, NONE, NONE]);
        Ok(Ex { n, s: lb.s, e: rb.e })
    }

    /// The inside of `[…]` after an expression: a slice, an index, or a
    /// tuple of them (a lone `*x` too).
    fn slices(&mut self) -> R<Ex> {
        let first = self.slice_item()?;
        if !self.at_op(COMMA) {
            if self.is_starred(first) {
                let elts = self.tree.push_list(&[first.n]);
                let n = self.add(Kind::Tuple, LOAD, first.s, first.e, [elts, NONE, NONE, NONE]);
                return Ok(Ex { n, s: first.s, e: first.e });
            }
            return Ok(first);
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        let mut e = first.e;
        self.enter(L::LATER_SLICE)?;
        while let Some(c) = self.eat_op(COMMA) {
            e = c.e;
            if self.at_op(RSQB) {
                break;
            }
            let x = self.slice_item()?;
            self.stack.push(x.n);
            e = x.e;
        }
        self.leave(L::LATER_SLICE);
        let elts = self.list_from(mark);
        let n = self.add(Kind::Tuple, LOAD, first.s, e, [elts, NONE, NONE, NONE]);
        Ok(Ex { n, s: first.s, e })
    }

    fn slice_item(&mut self) -> R<Ex> {
        if let Some(star) = self.eat_op(STAR) {
            let x = self.expression()?;
            let n = self.add(Kind::Starred, LOAD, star.s, x.e, [x.n, NONE, NONE, NONE]);
            return Ok(Ex { n, s: star.s, e: x.e });
        }
        let s = self.tok().s;
        let mut lower = NONE;
        if !self.at_op(COLON) {
            let x = self.named_expression()?;
            if !self.at_op(COLON) {
                return Ok(x);
            }
            if self.bare_walrus(x) {
                return self.fail("invalid syntax");
            }
            lower = x.n;
        }
        let mut e = self.expect_op(COLON)?.e;
        let mut upper = NONE;
        let mut step = NONE;
        if self.starts_expression() && !self.at_op(STAR) {
            let x = self.expression()?;
            upper = x.n;
            e = x.e;
        }
        if let Some(c) = self.eat_op(COLON) {
            e = c.e;
            if self.starts_expression() && !self.at_op(STAR) {
                self.enter(L::STEP)?;
                let x = self.expression()?;
                self.leave(L::STEP);
                step = x.n;
                e = x.e;
            }
        }
        let n = self.add(Kind::Slice, 0, s, e, [lower, upper, step, NONE]);
        Ok(Ex { n, s, e })
    }

    /// A call's arguments, `(` to `)`: (args, keywords, the end). A
    /// generator expression alone in them (`genexp`) spans the parentheses.
    pub fn call_args(&mut self, genexp: bool, cost: u32) -> R<(u32, u32, u32)> {
        let lp = self.expect_op(LPAR)?;
        self.enter(cost)?;
        let mut later = 0;
        let mark = self.stack.len();
        // positional arguments on the stack; keywords in their own list
        let mut keywords: Vec<u32> = Vec::new();
        let (mut seen_kw, mut seen_dstar) = (false, false);
        // A positional argument after a keyword: Python's error pass reads
        // the arguments after it before it raises its error, at the last
        // token it read (`a=args ',' args`; RAISE_SYNTAX_ERROR's place, the
        // furthest token fetched): its message, and the rest read on, an
        // argument that does not read ending them.
        let mut misplaced: Option<&'static str> = None;
        macro_rules! arg {
            ($e:expr) => {
                match $e {
                    Ok(v) => v,
                    Err(Fail::Syntax) if misplaced.is_some() => break,
                    Err(f) => return Err(f),
                }
            };
        }
        while !self.at_op(RPAR) {
            let t = self.tok();
            if t.t == T::Op && t.k == STAR {
                self.advance();
                if seen_dstar && misplaced.is_none() {
                    return self.fail("iterable argument unpacking follows keyword argument unpacking");
                }
                arg!(self.enter(L::KEYWORD_ARG));
                let x = arg!(self.expression());
                self.leave(L::KEYWORD_ARG);
                let n = self.add(Kind::Starred, LOAD, t.s, x.e, [x.n, NONE, NONE, NONE]);
                self.stack.push(n);
            } else if t.t == T::Op && t.k == DOUBLESTAR {
                self.advance();
                arg!(self.enter(L::KEYWORD_ARG));
                let x = arg!(self.expression());
                self.leave(L::KEYWORD_ARG);
                let n = self.add(Kind::keyword, 0, t.s, x.e, [NONE, x.n, NONE, NONE]);
                keywords.push(n);
                seen_dstar = true;
            } else if t.t == T::Name && self.peek(1).t == T::Op && self.peek(1).k == EQUAL {
                self.advance();
                self.advance();
                arg!(self.enter(L::KEYWORD_ARG));
                let x = arg!(self.expression());
                self.leave(L::KEYWORD_ARG);
                let n = self.add(Kind::keyword, 0, t.s, x.e, [t.v, x.n, NONE, NONE]);
                keywords.push(n);
                seen_kw = true;
            } else {
                let at = self.p;
                let x = match self.named_expression() {
                    Ok(v) => v,
                    // (a positional argument after a keyword whose whole
                    // does not read: Python's error pass takes the part of
                    // it that does, `h` of `h(…)`, for the argument)
                    Err(Fail::Syntax) if misplaced.is_none() && (seen_kw || seen_dstar) && self.prefix_reads_at(at) => {
                        misplaced = Some(if seen_dstar {
                            "positional argument follows keyword argument unpacking"
                        } else {
                            "positional argument follows keyword argument"
                        });
                        break;
                    }
                    Err(Fail::Syntax) if misplaced.is_some() => break,
                    Err(f) => return Err(f),
                };
                if self.at_op(EQUAL) && self.ahead == 0 {
                    // (where Python's error pass puts it: at the expression)
                    let s = self.tree.nodes[x.n as usize].start;
                    return self.fatal_at(s, "expression cannot contain assignment, perhaps you meant \"==\"?");
                }
                if self.at_for() && misplaced.is_none() {
                    if !genexp || self.stack.len() > mark || !keywords.is_empty() {
                        return self.fail("Generator expression must be parenthesized");
                    }
                    let generators = self.comprehension_clauses()?;
                    let rp = self.expect_op(RPAR)?;
                    self.leave(later);
                    self.leave(cost);
                    let g = self.add(Kind::GeneratorExp, 0, lp.s, rp.e, [x.n, generators, NONE, NONE]);
                    let args = self.tree.push_list(&[g]);
                    return Ok((args, 0, rp.e));
                }
                if (seen_kw || seen_dstar) && misplaced.is_none() {
                    misplaced = Some(if seen_dstar {
                        "positional argument follows keyword argument unpacking"
                    } else {
                        "positional argument follows keyword argument"
                    });
                }
                self.stack.push(x.n);
            }
            if self.eat_op(COMMA).is_none() {
                break;
            }
            if later == 0 {
                later = L::LATER_ARG;
                arg!(self.enter(later));
            }
        }
        if let Some(why) = misplaced {
            let k = self.p_max.max(self.p);
            let at = self.toks.get(k).map_or(self.src.len() as u32, |t| t.s);
            return self.fail_at(at, why);
        }
        self.leave(later);
        let rp = self.expect_op(RPAR)?;
        self.leave(cost);
        let args = self.list_from(mark);
        let keywords = self.tree.push_list(&keywords);
        Ok((args, keywords, rp.e))
    }

    /// A function's (`def`: with annotations, up to `)`) or a lambda's (up
    /// to `:`) parameters: an `arguments` node starting at `at`.
    pub fn parameters(&mut self, def: bool, at: u32) -> R<NodeId> {
        let end_op = if def { RPAR } else { COLON };
        let mut posonly: Vec<u32> = Vec::new();
        let mut args: Vec<u32> = Vec::new();
        let mut defaults: Vec<u32> = Vec::new();
        let mut kwonly: Vec<u32> = Vec::new();
        let mut kw_defaults: Vec<u32> = Vec::new();
        let (mut vararg, mut kwarg) = (NONE, NONE);
        let (mut seen_default, mut slash, mut star, mut bare) = (false, false, false, false);
        let mut end = at;
        loop {
            if self.at_op(end_op) {
                break;
            }
            let t = self.tok();
            if t.t == T::Op && t.k == SLASH {
                if star || slash || args.is_empty() {
                    return self.fail("invalid syntax");
                }
                slash = true;
                posonly = std::mem::take(&mut args);
                end = self.advance().e;
            } else if t.t == T::Op && t.k == STAR {
                if star {
                    return self.fail("* argument may appear only once");
                }
                star = true;
                end = self.advance().e;
                if self.at_op(COMMA) || self.at_op(end_op) {
                    bare = true;
                } else {
                    let (a, e) = self.param(def, true)?;
                    vararg = a;
                    end = e;
                }
            } else if t.t == T::Op && t.k == DOUBLESTAR {
                self.advance();
                let (a, e) = self.param(def, false)?;
                kwarg = a;
                end = e;
                if let Some(c) = self.eat_op(COMMA) {
                    end = c.e;
                }
                if !self.at_op(end_op) {
                    return self.fail("arguments cannot follow var-keyword argument");
                }
                break;
            } else {
                let (a, e) = self.param(def, false)?;
                end = e;
                let mut default = NONE;
                if self.eat_op(EQUAL).is_some() {
                    // (a lambda's default: in a chain of them, the body's once)
                    let cost = if def {
                        L::STMT + L::DEFAULT
                    } else if self.lambda_defaults == 0 {
                        L::DEFAULT + L::LAMBDA + L::LAMBDA_BODY
                    } else {
                        L::DEFAULT + L::LAMBDA
                    };
                    self.enter(cost)?;
                    if !def {
                        self.lambda_defaults += 1;
                    }
                    let d = self.expression();
                    if !def {
                        self.lambda_defaults -= 1;
                    }
                    let d = d?;
                    self.leave(cost);
                    default = d.n;
                    end = d.e;
                }
                if star {
                    kwonly.push(a);
                    kw_defaults.push(default);
                } else {
                    if default != NONE {
                        defaults.push(default);
                        seen_default = true;
                    } else if seen_default {
                        return self.fail("parameter without a default follows parameter with a default");
                    }
                    args.push(a);
                }
            }
            match self.eat_op(COMMA) {
                Some(c) => end = c.e,
                None => break,
            }
        }
        if bare && kwonly.is_empty() {
            return self.fail("named arguments must follow bare *");
        }
        if !self.at_op(end_op) {
            return self.fail("invalid syntax");
        }
        let posonly = self.tree.push_list(&posonly);
        let args = self.tree.push_list(&args);
        let kwonly = self.tree.push_list(&kwonly);
        let kw_defaults = self.tree.push_list(&kw_defaults);
        let defaults = self.tree.push_list(&defaults);
        let ext = self.ext(&[kwonly, kw_defaults, kwarg, defaults]);
        Ok(self.add(Kind::arguments, 0, at, end, [posonly, args, vararg, ext]))
    }

    /// A parameter's name and annotation (`star`: `*args`, whose annotation
    /// may be starred): (its arg node, its end).
    fn param(&mut self, def: bool, star: bool) -> R<(NodeId, u32)> {
        let name = self.expect_name()?;
        let mut e = name.e;
        let mut ann = NONE;
        if def && self.eat_op(COLON).is_some() {
            self.enter(L::STMT + L::ANNOTATION)?;
            let a = if star { self.star_expression()? } else { self.expression()? };
            self.leave(L::STMT + L::ANNOTATION);
            ann = a.n;
            e = a.e;
        }
        Ok((self.add(Kind::arg, 0, name.s, e, [name.v, ann, NONE, NONE]), e))
    }

    /// `for … in … if …` clauses: a list of comprehension nodes.
    pub fn comprehension_clauses(&mut self) -> R<u32> {
        let mark = self.stack.len();
        self.enter(L::COMPREHENSION)?;
        while self.at_for() {
            let s = self.tok().s;
            let is_async = self.at_kw(KW_ASYNC);
            if is_async {
                self.advance();
            }
            self.advance(); // for
            let target = self.star_targets()?;
            self.expect_kw(KW_IN)?;
            let iter = self.disjunction()?;
            let mut e = iter.e;
            let imark = self.stack.len();
            while self.at_kw(KW_IF) {
                self.advance();
                let c = self.disjunction()?;
                self.stack.push(c.n);
                e = c.e;
            }
            let ifs = self.list_from(imark);
            let n = self.add(Kind::comprehension, 0, s, e, [target.n, iter.n, ifs, NONE]);
            if is_async {
                self.tree.nodes[n as usize].flags |= ASYNC;
            }
            self.stack.push(n);
        }
        self.leave(L::COMPREHENSION);
        Ok(self.list_from(mark))
    }

    pub fn yield_expr(&mut self) -> R<Ex> {
        let y = self.advance();
        if self.at_kw(KW_FROM) {
            self.advance();
            self.enter(L::YIELD)?;
            let x = self.expression()?;
            self.leave(L::YIELD);
            let n = self.add(Kind::YieldFrom, 0, y.s, x.e, [x.n, NONE, NONE, NONE]);
            return Ok(Ex { n, s: y.s, e: x.e });
        }
        if self.starts_expression() {
            self.enter(L::YIELD)?;
            let x = self.star_expressions()?;
            self.leave(L::YIELD);
            let n = self.add(Kind::Yield, 0, y.s, x.e, [x.n, NONE, NONE, NONE]);
            return Ok(Ex { n, s: y.s, e: x.e });
        }
        let n = self.add(Kind::Yield, 0, y.s, y.e, [NONE, NONE, NONE, NONE]);
        Ok(Ex { n, s: y.s, e: y.e })
    }

    // ---- targets ----

    /// `star_targets` (a `for`'s, a comprehension's): primaries, starred or
    /// not, a tuple of them after a comma; given Store.
    pub fn star_targets(&mut self) -> R<Ex> {
        let first = self.star_target()?;
        if !self.at_op(COMMA) {
            self.to_target(first.n, STORE, true)?;
            return Ok(first);
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        let mut e = first.e;
        while let Some(c) = self.eat_op(COMMA) {
            e = c.e;
            if !self.starts_target() {
                break;
            }
            let x = self.star_target()?;
            self.stack.push(x.n);
            e = x.e;
        }
        let elts = self.list_from(mark);
        let n = self.add(Kind::Tuple, STORE, first.s, e, [elts, NONE, NONE, NONE]);
        self.to_target(n, STORE, true)?;
        Ok(Ex { n, s: first.s, e })
    }

    /// One target: `*target` or a primary (checked by `to_target`).
    pub fn star_target(&mut self) -> R<Ex> {
        if let Some(star) = self.eat_op(STAR) {
            if self.at_op(STAR) {
                return self.fail("invalid syntax");
            }
            let x = self.star_target()?;
            let n = self.add(Kind::Starred, STORE, star.s, x.e, [x.n, NONE, NONE, NONE]);
            return Ok(Ex { n, s: star.s, e: x.e });
        }
        self.primary()
    }

    /// A target of `del`.
    pub fn del_target_expr(&mut self) -> R<Ex> {
        self.expression()
    }

    /// Checks that node `n` can be assigned to (or deleted: `ctx` Del) and
    /// gives it and its parts the context. `star`: starred parts may be.
    pub fn to_target(&mut self, n: NodeId, ctx: u8, star: bool) -> R<()> {
        // (an explicit stack: a target may nest as deep as its brackets)
        let mut todo: Vec<NodeId> = vec![n];
        while let Some(id) = todo.pop() {
            let node = self.tree.nodes[id as usize];
            match node.kind {
                Kind::Name | Kind::Attribute | Kind::Subscript => {
                    self.tree.nodes[id as usize].op = ctx;
                }
                Kind::Starred if star => {
                    self.tree.nodes[id as usize].op = ctx;
                    todo.push(node.f[A as usize]);
                }
                Kind::Tuple | Kind::List => {
                    self.tree.nodes[id as usize].op = ctx;
                    let items: Vec<u32> = self.tree.list(node.f[A as usize]).to_vec();
                    todo.extend(items);
                }
                _ => {
                    let why = if ctx == DEL { "cannot delete this expression" } else { "cannot assign to this expression" };
                    return self.fail_at(node.start, why);
                }
            }
        }
        Ok(())
    }

    // ---- strings ----

    /// Adjacent string literals and f-strings: a Constant (str or bytes),
    /// or a JoinedStr when an f-string is among them.
    pub fn strings(&mut self) -> R<Ex> {
        let s = self.tok().s;
        // (where Python reads the strings first as a possible assignment
        // target, the shorter way, its f-strings cost less: `limits::FSTRING`)
        let costly = self.p != self.cheap_at && self.p != self.first_in_paren_at;
        let pmark = self.pieces.len();
        let tmark = self.text.len();
        let (mut any_f, mut any_bytes, mut any_str) = (false, false, false);
        let mut first_u = false;
        let mut first = true;
        let mut e = s;
        self.enter(L::STRINGS)?;
        loop {
            let t = self.tok();
            match t.t {
                T::Str => {
                    self.advance();
                    let bytes = t.k & S_BYTES != 0;
                    if bytes {
                        any_bytes = true;
                    } else {
                        any_str = true;
                    }
                    if first {
                        first_u = t.k & S_U != 0;
                    }
                    let at = self.text.len() as u32;
                    let body = string_body(self.src, t);
                    let how = literal::Body { raw: t.k & S_RAW != 0, bytes, braces: false };
                    if let Err(why) = literal::body(body, how, &mut self.text) {
                        return self.fatal_at(t.s, &why);
                    }
                    let len = self.text.len() as u32 - at;
                    self.pieces.push(Piece::Text { at, len, s: t.s, e: t.e, u: t.k & S_U != 0 });
                    e = t.e;
                }
                T::FStart => {
                    any_f = true;
                    self.fstring(costly)?;
                    e = self.toks.get(self.p.wrapping_sub(1)).map_or(e, |t| t.e);
                }
                _ => break,
            }
            first = false;
        }
        self.leave(L::STRINGS);
        if any_bytes && (any_str || any_f) {
            // (Python reports it at the token after the strings, the last it read)
            let at = self.tok().s;
            return self.fatal_at(at, "cannot mix bytes and nonbytes literals");
        }
        let n = if !any_f {
            let id = self.tree.strings.intern(&self.text[tmark..]);
            let n = self.add(Kind::Constant, if any_bytes { V_BYTES } else { V_STR }, s, e, [id, NONE, NONE, NONE]);
            if first_u {
                self.tree.nodes[n as usize].flags |= KIND_U;
            }
            n
        } else {
            let values = self.joined_values(pmark);
            self.add(Kind::JoinedStr, 0, s, e, [values, NONE, NONE, NONE])
        };
        self.pieces.truncate(pmark);
        self.text.truncate(tmark);
        Ok(Ex { n, s, e })
    }

    /// The values of a JoinedStr: the pieces from `pmark` on, each run of
    /// text one Constant (none when it is empty; its span from the run's
    /// first piece to its last, its kind the first's).
    fn joined_values(&mut self, pmark: usize) -> u32 {
        let vmark = self.stack.len();
        let mut i = pmark;
        while i < self.pieces.len() {
            match self.pieces[i] {
                Piece::Node(id) => {
                    self.stack.push(id);
                    i += 1;
                }
                Piece::Text { at, s, u, .. } => {
                    let mut j = i;
                    let mut end_at = at;
                    let mut e = s;
                    while let Some(&Piece::Text { at: a, len, e: pe, .. }) = self.pieces.get(j) {
                        end_at = a + len;
                        e = pe;
                        j += 1;
                    }
                    if end_at > at {
                        let id = self.tree.strings.intern(&self.text[at as usize..end_at as usize]);
                        let n = self.add(Kind::Constant, V_STR, s, e, [id, NONE, NONE, NONE]);
                        if u {
                            self.tree.nodes[n as usize].flags |= KIND_U;
                        }
                        self.stack.push(n);
                    }
                    i = j;
                }
            }
        }
        self.list_from(vmark)
    }

    /// An f-string: its pieces pushed. (`costly`: not where Python reads it
    /// first as a possible assignment target, `limits::FSTRING`.)
    fn fstring(&mut self, costly: bool) -> R<()> {
        let start = self.advance();
        let raw = start.k & S_RAW != 0;
        let cost = if self.fdepth > 0 || costly { L::FSTRING } else { 0 };
        self.enter(cost)?;
        self.fdepth += 1;
        loop {
            let t = self.tok();
            match t.t {
                T::FMiddle => {
                    self.advance();
                    let at = self.text.len() as u32;
                    let how = literal::Body { raw, bytes: false, braces: true };
                    if let Err(why) = literal::body(&self.src[t.s as usize..t.e as usize], how, &mut self.text) {
                        return self.fatal_at(t.s, &why);
                    }
                    let len = self.text.len() as u32 - at;
                    self.pieces.push(Piece::Text { at, len, s: t.s, e: t.e, u: false });
                }
                T::Op if t.k == LBRACE => self.replacement_field(raw)?,
                T::FEnd => {
                    self.advance();
                    break;
                }
                _ => return self.fail("f-string: expecting '}'"),
            }
        }
        self.fdepth -= 1;
        self.leave(cost);
        Ok(())
    }

    /// `{expression[=][!conversion][:format_spec]}`: a FormattedValue piece
    /// (after its text, when `=` asks for it).
    fn replacement_field(&mut self, raw: bool) -> R<()> {
        let lb = self.advance();
        let cost = if self.spec_depth > 0 { L::SPEC_FIELD } else { L::FIELD };
        self.enter(cost)?;
        let spec_depth = self.spec_depth;
        self.spec_depth = 0;
        if self.at_op(RBRACE) {
            return self.pass_fail_at(self.tok().s, "f-string: valid expression required before '}'");
        }
        let first = self.p;
        let read = if self.at_kw(KW_YIELD) { self.yield_expr() } else { self.star_expressions() };
        let x = match read {
            Ok(x) => x,
            Err(Fail::Syntax) if !self.prefix_reads_at(first) => {
                // (no part of an expression reads: Python's error pass
                // reports it at the field's first token)
                let at = self.toks.get(first).map_or(lb.e, |t| t.s);
                return self.pass_fail_at(at, "f-string: expecting a valid expression after '{'");
            }
            Err(Fail::Syntax) if self.ahead == 0 => {
                // (a part reads: Python's error pass reports the token after
                // it — after the field's first atom, for the line)
                let mut k = first;
                while let Some(t) = self.toks.get(k) {
                    let prefix = matches!((t.t, t.k), (T::Op, MINUS | PLUS | TILDE | STAR))
                        || matches!((t.t, t.k), (T::Kw, KW_NOT | KW_AWAIT));
                    if !prefix {
                        break;
                    }
                    k += 1;
                }
                let at = self.toks.get(k + 1).map_or(lb.e, |t| t.s);
                return self.fatal_at(at, "f-string: expecting '=', or '!', or ':', or '}'");
            }
            Err(e) => return Err(e),
        };
        let mut debug_end = None;
        if self.eat_op(EQUAL).is_some() {
            debug_end = Some(self.tok().s);
        }
        let mut conversion: u8 = 0;
        // (a conversion is checked once the field is read whole, as Python does)
        let mut conv = None;
        if let Some(ex) = self.eat_op(EXCLAMATION) {
            let c = self.tok();
            if c.t != T::Name {
                return self.pass_fail_at(c.s, "f-string: invalid conversion character");
            }
            if c.s != ex.e {
                return self.fatal_at(ex.s, "f-string: conversion type must come right after the exclamation mark");
            }
            conv = Some(c);
            self.advance();
        }
        let mut spec = NONE;
        if let Some(colon) = self.eat_op(COLON) {
            self.spec_depth = spec_depth + 1;
            spec = self.format_spec(colon, raw)?;
        }
        self.spec_depth = spec_depth;
        let rb = self.expect_op(RBRACE)?;
        if let Some(c) = conv {
            // (the name as Python normalizes it: `!ｒ` is `!r`)
            conversion = match self.tree.str(c.v) {
                [0x73] => 1,
                [0x72] => 2,
                [0x61] => 3,
                _ => return self.fatal_at(c.s, "f-string: invalid conversion character"),
            };
        }
        if let Some(end) = debug_end {
            // the field's text, `=` included, comments left out
            let at = self.text.len() as u32;
            self.debug_text(lb.e, end);
            let len = self.text.len() as u32 - at;
            self.pieces.push(Piece::Text { at, len, s: lb.e, e: end, u: false });
            if conversion == 0 && spec == NONE {
                conversion = 2; // !r
            }
        }
        let n = self.add(Kind::FormattedValue, conversion, lb.s, rb.e, [x.n, spec, NONE, NONE]);
        self.pieces.push(Piece::Node(n));
        self.leave(cost);
        Ok(())
    }

    /// The source from `s` to `e`, its comments left out and its line breaks "\n".
    fn debug_text(&mut self, s: u32, e: u32) {
        let first = self.comments.partition_point(|&(cs, _)| cs < s);
        let mut i = s as usize;
        let mut k = first;
        while i < e as usize {
            if let Some(&(cs, ce)) = self.comments.get(k) {
                if cs as usize == i {
                    i = (ce as usize).min(e as usize);
                    k += 1;
                    continue;
                }
            }
            let c = self.src[i];
            if c == 0x0D {
                self.text.push(0x0A);
                i += if self.src.get(i + 1) == Some(&0x0A) { 2 } else { 1 };
                continue;
            }
            self.text.push(c);
            i += 1;
        }
    }

    /// A format specifier, after its `:`: a JoinedStr up to the field's `}`.
    fn format_spec(&mut self, colon: Tok, raw: bool) -> R<NodeId> {
        let pmark = self.pieces.len();
        let tmark = self.text.len();
        loop {
            let t = self.tok();
            match t.t {
                T::FMiddle => {
                    self.advance();
                    let at = self.text.len() as u32;
                    let how = literal::Body { raw, bytes: false, braces: false };
                    if let Err(why) = literal::body(&self.src[t.s as usize..t.e as usize], how, &mut self.text) {
                        return self.fatal_at(t.s, &why);
                    }
                    let len = self.text.len() as u32 - at;
                    self.pieces.push(Piece::Text { at, len, s: t.s, e: t.e, u: false });
                }
                T::Op if t.k == LBRACE => self.replacement_field(raw)?,
                T::Op if t.k == RBRACE => break,
                _ => return self.fail("f-string: expecting '}'"),
            }
        }
        let values = self.joined_values(pmark);
        self.pieces.truncate(pmark);
        self.text.truncate(tmark);
        let end = self.tok().s;
        Ok(self.add(Kind::JoinedStr, 0, colon.s, end, [values, NONE, NONE, NONE]))
    }
}

/// A string token's body: between its quotes, after its prefix.
pub fn string_body(src: &[u32], t: Tok) -> &[u32] {
    let mut a = t.s as usize;
    while a < t.e as usize && src[a] != 0x27 && src[a] != 0x22 {
        a += 1;
    }
    let q = if t.k & S_TRIPLE != 0 { 3 } else { 1 };
    let b = (t.e as usize).saturating_sub(q);
    let a = (a + q).min(b);
    &src[a..b]
}
