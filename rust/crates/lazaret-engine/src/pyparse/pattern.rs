//! A match statement's patterns (PEP 634).

use super::lexer::*;
use super::limits as L;
use super::literal::{self, Num};
use super::parser::{Ex, Parser, R};
use super::tree::*;

impl<'a> Parser<'a> {
    /// A case's patterns: an open sequence (a MatchSequence without
    /// brackets) or one pattern.
    pub fn patterns(&mut self) -> R<NodeId> {
        let first = self.maybe_star_pattern()?;
        if !self.at_op(COMMA) {
            if self.kind(first.n) == Kind::MatchStar {
                return self.fail_at(first.s, "invalid syntax");
            }
            return Ok(first.n);
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        let mut e = first.e;
        self.enter(L::PATTERN_LATER)?;
        while let Some(c) = self.eat_op(COMMA) {
            e = c.e;
            if self.at_op(COLON) || self.at_kw(KW_IF) {
                break;
            }
            let p = self.maybe_star_pattern()?;
            self.stack.push(p.n);
            e = p.e;
        }
        self.leave(L::PATTERN_LATER);
        let patterns = self.list_from(mark);
        Ok(self.add(Kind::MatchSequence, 0, first.s, e, [patterns, NONE, NONE, NONE]))
    }

    fn maybe_star_pattern(&mut self) -> R<Ex> {
        if let Some(star) = self.eat_op(STAR) {
            let n = self.expect_name()?;
            let name = if Self::is_soft(n, S_UNDERSCORE) {
                NONE
            } else {
                self.capture_follows()?;
                n.v
            };
            let id = self.add(Kind::MatchStar, 0, star.s, n.e, [name, NONE, NONE, NONE]);
            return Ok(Ex { n: id, s: star.s, e: n.e });
        }
        self.pattern()
    }

    /// After a capture name: not `.`, `(` or `=`.
    fn capture_follows(&mut self) -> R<()> {
        if self.at_op(DOT) || self.at_op(LPAR) || self.at_op(EQUAL) {
            return self.fail("invalid syntax");
        }
        Ok(())
    }

    /// `or_pattern ['as' NAME]`
    pub fn pattern(&mut self) -> R<Ex> {
        let p = self.or_pattern()?;
        let r = if self.at_kw(KW_AS) {
            self.advance();
            let n = self.expect_name()?;
            if Self::is_soft(n, S_UNDERSCORE) {
                return self.fail_at(n.s, "cannot use '_' as a target");
            }
            self.capture_follows()?;
            let id = self.add(Kind::MatchAs, 0, p.s, n.e, [p.n, n.v, NONE, NONE]);
            Ex { n: id, s: p.s, e: n.e }
        } else {
            p
        };
        Ok(r)
    }

    fn or_pattern(&mut self) -> R<Ex> {
        let first = self.closed_pattern()?;
        if !self.at_op(VBAR) {
            return Ok(first);
        }
        let mark = self.stack.len();
        self.stack.push(first.n);
        let mut e = first.e;
        self.enter(L::PATTERN_OR)?;
        while self.eat_op(VBAR).is_some() {
            let p = self.closed_pattern()?;
            self.stack.push(p.n);
            e = p.e;
        }
        self.leave(L::PATTERN_OR);
        let patterns = self.list_from(mark);
        let id = self.add(Kind::MatchOr, 0, first.s, e, [patterns, NONE, NONE, NONE]);
        Ok(Ex { n: id, s: first.s, e })
    }

    /// A number token's Constant; `imag`: it must be imaginary (Some(true))
    /// or real (Some(false)).
    fn number_constant(&mut self, imag: Option<bool>) -> R<Ex> {
        let t = self.tok();
        if t.t != T::Number {
            return self.fail("invalid syntax");
        }
        if let Some(want) = imag {
            let is_imag = matches!(literal::number(&self.src[t.s as usize..t.e as usize]), Ok(Num::Imag(_)));
            if is_imag != want {
                let why = if want {
                    "imaginary number required in complex literal"
                } else {
                    "real number required in complex literal"
                };
                return self.fatal_at(t.s, why);
            }
        }
        self.atom()
    }

    /// A signed number, or a complex literal `real ± imaginary`.
    fn signed_number_expr(&mut self) -> R<Ex> {
        let left = if let Some(minus) = self.eat_op(MINUS) {
            let x = self.number_constant(None)?;
            let n = self.add(Kind::UnaryOp, USUB, minus.s, x.e, [x.n, NONE, NONE, NONE]);
            Ex { n, s: minus.s, e: x.e }
        } else {
            self.number_constant(None)?
        };
        if !(self.at_op(PLUS) || self.at_op(MINUS)) {
            return Ok(left);
        }
        // a complex literal: the left part real, the right imaginary
        let lnum = if self.kind(left.n) == Kind::UnaryOp { self.tree.nodes[left.n as usize].f[A as usize] } else { left.n };
        if self.tree.nodes[lnum as usize].op == V_COMPLEX {
            let at = self.tree.nodes[lnum as usize].start;
            return self.fatal_at(at, "real number required in complex literal");
        }
        let op = if self.advance().k == PLUS { ADD } else { SUB };
        let right = self.number_constant(Some(true))?;
        let n = self.add(Kind::BinOp, op, left.s, right.e, [left.n, right.n, NONE, NONE]);
        Ok(Ex { n, s: left.s, e: right.e })
    }

    /// `name.attr.attr…` (Load), starting at a name.
    fn dotted_value(&mut self) -> R<Ex> {
        let t = self.expect_name()?;
        let mut x = Ex { n: self.add(Kind::Name, LOAD, t.s, t.e, [t.v, NONE, NONE, NONE]), s: t.s, e: t.e };
        while self.eat_op(DOT).is_some() {
            let a = self.expect_name()?;
            let n = self.add(Kind::Attribute, LOAD, x.s, a.e, [x.n, a.v, NONE, NONE]);
            x = Ex { n, s: x.s, e: a.e };
        }
        Ok(x)
    }

    fn closed_pattern(&mut self) -> R<Ex> {
        let t = self.tok();
        match t.t {
            T::Number => self.value_pattern_of_number(),
            T::Op if t.k == MINUS => self.value_pattern_of_number(),
            T::Str | T::FStart => {
                let x = self.strings()?;
                let id = self.add(Kind::MatchValue, 0, x.s, x.e, [x.n, NONE, NONE, NONE]);
                Ok(Ex { n: id, s: x.s, e: x.e })
            }
            T::Kw if matches!(t.k, KW_NONE | KW_TRUE | KW_FALSE) => {
                self.advance();
                let v = match t.k {
                    KW_NONE => V_NONE,
                    KW_TRUE => V_TRUE,
                    _ => V_FALSE,
                };
                let id = self.add(Kind::MatchSingleton, v, t.s, t.e, [NONE; 4]);
                Ok(Ex { n: id, s: t.s, e: t.e })
            }
            T::Name => {
                let next = self.peek(1);
                let dot_or_call = next.t == T::Op && (next.k == DOT || next.k == LPAR);
                if Self::is_soft(t, S_UNDERSCORE) {
                    // the wildcard (it is not a name a value or a class is read from)
                    self.advance();
                    let id = self.add(Kind::MatchAs, 0, t.s, t.e, [NONE, NONE, NONE, NONE]);
                    return Ok(Ex { n: id, s: t.s, e: t.e });
                }
                if !dot_or_call {
                    self.advance();
                    self.capture_follows()?;
                    let id = self.add(Kind::MatchAs, 0, t.s, t.e, [NONE, t.v, NONE, NONE]);
                    return Ok(Ex { n: id, s: t.s, e: t.e });
                }
                let x = self.dotted_value()?;
                if self.at_op(LPAR) {
                    return self.class_pattern(x);
                }
                if self.at_op(EQUAL) {
                    return self.fail("invalid syntax");
                }
                let id = self.add(Kind::MatchValue, 0, x.s, x.e, [x.n, NONE, NONE, NONE]);
                Ok(Ex { n: id, s: x.s, e: x.e })
            }
            T::Op if t.k == LPAR => {
                let lp = self.advance();
                self.enter(L::PATTERN_PAREN)?;
                if let Some(rp) = self.eat_op(RPAR) {
                    self.leave(L::PATTERN_PAREN);
                    let id = self.add(Kind::MatchSequence, 0, lp.s, rp.e, [0, NONE, NONE, NONE]);
                    return Ok(Ex { n: id, s: lp.s, e: rp.e });
                }
                let first = self.maybe_star_pattern()?;
                if !self.at_op(COMMA) {
                    let rp = self.expect_op(RPAR)?;
                    self.leave(L::PATTERN_PAREN);
                    if self.kind(first.n) == Kind::MatchStar {
                        return self.fail_at(first.s, "invalid syntax");
                    }
                    return Ok(Ex { n: first.n, s: lp.s, e: rp.e });
                }
                let mark = self.stack.len();
                self.stack.push(first.n);
                while self.eat_op(COMMA).is_some() {
                    if self.at_op(RPAR) {
                        break;
                    }
                    let p = self.maybe_star_pattern()?;
                    self.stack.push(p.n);
                }
                let rp = self.expect_op(RPAR)?;
                self.leave(L::PATTERN_PAREN);
                let patterns = self.list_from(mark);
                let id = self.add(Kind::MatchSequence, 0, lp.s, rp.e, [patterns, NONE, NONE, NONE]);
                Ok(Ex { n: id, s: lp.s, e: rp.e })
            }
            T::Op if t.k == LSQB => {
                let lb = self.advance();
                self.enter(L::PATTERN)?;
                let mark = self.stack.len();
                while !self.at_op(RSQB) {
                    let p = self.maybe_star_pattern()?;
                    self.stack.push(p.n);
                    if self.eat_op(COMMA).is_none() {
                        break;
                    }
                }
                let rb = self.expect_op(RSQB)?;
                self.leave(L::PATTERN);
                let patterns = self.list_from(mark);
                let id = self.add(Kind::MatchSequence, 0, lb.s, rb.e, [patterns, NONE, NONE, NONE]);
                Ok(Ex { n: id, s: lb.s, e: rb.e })
            }
            T::Op if t.k == LBRACE => self.mapping_pattern(),
            _ => self.fail("invalid syntax"),
        }
    }

    fn value_pattern_of_number(&mut self) -> R<Ex> {
        let x = self.signed_number_expr()?;
        let id = self.add(Kind::MatchValue, 0, x.s, x.e, [x.n, NONE, NONE, NONE]);
        Ok(Ex { n: id, s: x.s, e: x.e })
    }

    /// `cls(positional…, name=pattern…)`
    fn class_pattern(&mut self, cls: Ex) -> R<Ex> {
        self.expect_op(LPAR)?;
        self.enter(L::PATTERN_CLASS)?;
        let mark = self.stack.len();
        let mut kw_attrs: Vec<u32> = Vec::new();
        let mut kw_patterns: Vec<u32> = Vec::new();
        while !self.at_op(RPAR) {
            let t = self.tok();
            if t.t == T::Name && self.peek(1).t == T::Op && self.peek(1).k == EQUAL {
                self.advance();
                self.advance();
                let p = self.pattern()?;
                kw_attrs.push(t.v);
                kw_patterns.push(p.n);
            } else {
                if !kw_attrs.is_empty() {
                    return self.fail("positional patterns follow keyword patterns");
                }
                let p = self.pattern()?;
                self.stack.push(p.n);
            }
            if self.eat_op(COMMA).is_none() {
                break;
            }
        }
        let rp = self.expect_op(RPAR)?;
        self.leave(L::PATTERN_CLASS);
        let patterns = self.list_from(mark);
        let kw_attrs = self.tree.push_list(&kw_attrs);
        let kw_patterns = self.tree.push_list(&kw_patterns);
        let id = self.add(Kind::MatchClass, 0, cls.s, rp.e, [cls.n, patterns, kw_attrs, kw_patterns]);
        Ok(Ex { n: id, s: cls.s, e: rp.e })
    }

    /// `{key: pattern, …, **rest}`
    fn mapping_pattern(&mut self) -> R<Ex> {
        let lb = self.advance();
        self.enter(L::PATTERN)?;
        let mut keys: Vec<u32> = Vec::new();
        let mut patterns: Vec<u32> = Vec::new();
        let mut rest = NONE;
        while !self.at_op(RBRACE) {
            if self.eat_op(DOUBLESTAR).is_some() {
                let n = self.expect_name()?;
                if Self::is_soft(n, S_UNDERSCORE) {
                    return self.fail_at(n.s, "invalid syntax");
                }
                rest = n.v;
                self.eat_op(COMMA);
                break;
            }
            let t = self.tok();
            let key = match t.t {
                T::Number => self.signed_number_expr()?,
                T::Op if t.k == MINUS => self.signed_number_expr()?,
                T::Str | T::FStart => self.strings()?,
                T::Kw if matches!(t.k, KW_NONE | KW_TRUE | KW_FALSE) => self.atom()?,
                T::Name => {
                    let x = self.dotted_value()?;
                    if self.kind(x.n) != Kind::Attribute {
                        return self.fail_at(x.s, "invalid syntax");
                    }
                    x
                }
                _ => return self.fail("invalid syntax"),
            };
            self.expect_op(COLON)?;
            let p = self.pattern()?;
            keys.push(key.n);
            patterns.push(p.n);
            if self.eat_op(COMMA).is_none() {
                break;
            }
        }
        let rb = self.expect_op(RBRACE)?;
        self.leave(L::PATTERN);
        let keys = self.tree.push_list(&keys);
        let patterns = self.tree.push_list(&patterns);
        let id = self.add(Kind::MatchMapping, 0, lb.s, rb.e, [keys, patterns, rest, NONE]);
        Ok(Ex { n: id, s: lb.s, e: rb.e })
    }
}
