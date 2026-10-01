//! TypeScript's types, read and left out: jsparse.py's `parse_type` and
//! what it calls.

use super::parser::*;
use super::scan::*;

impl<'a> Parser<'a> {
    pub(super) fn parse_type(&mut self) -> R<()> {
        self.enter()?;
        if self.function_type_ahead()? {
            self.parse_function_type()?;
        } else {
            self.parse_union_type()?;
            if self.is_n(W_EXTENDS) && !self.tok.nl && !self.no_conditional {
                self.next()?;
                let saved = self.no_conditional;
                self.no_conditional = true;
                self.parse_type()?;
                self.no_conditional = false;
                self.expect_p(P_QUESTION)?;
                self.parse_type()?;
                self.expect_p(P_COLON)?;
                self.parse_type()?;
                self.no_conditional = saved;
            }
        }
        self.depth -= 1;
        Ok(())
    }

    /// `: T` after a parameter list; type predicates too.
    pub(super) fn parse_return_type(&mut self) -> R<()> {
        self.expect_p(P_COLON)?;
        let outer = self.no_conditional;
        self.no_conditional = false;
        self.parse_type_or_predicate()?;
        self.no_conditional = outer;
        Ok(())
    }

    fn parse_type_or_predicate(&mut self) -> R<()> {
        if self.tok.t == T::Name {
            let (pk, pv, pnl) = self.peek();
            if self.is_n(W_ASSERTS) && pk == T::Name && !pnl {
                self.next()?;
                self.next()?;
                if self.eat_n(W_IS)? {
                    self.parse_type()?;
                }
                return Ok(());
            }
            if pk == T::Name && pv == W_IS && !pnl {
                self.next()?;
                self.next()?;
                return self.parse_type();
            }
        }
        self.parse_type()
    }

    fn function_type_ahead(&mut self) -> R<bool> {
        if self.is_p(P_LT) {
            return Ok(true);
        }
        if self.is_n(W_NEW) {
            return Ok(true);
        }
        if self.is_n(W_ABSTRACT) {
            let (pk, pv, _) = self.peek();
            return Ok(pk == T::Name && pv == W_NEW);
        }
        if !self.is_p(P_LPAREN) {
            return Ok(false);
        }
        self.look(
            |p| {
                p.next()?;
                if p.tok.t == T::P && (p.tok.v == P_RPAREN || p.tok.v == P_ELLIPSIS) {
                    return Ok(true);
                }
                if p.skip_param_start()? {
                    if p.tok.t == T::P && matches!(p.tok.v, P_COLON | P_COMMA | P_QUESTION | P_ASSIGN) {
                        return Ok(true);
                    }
                    if p.is_p(P_RPAREN) {
                        p.next()?;
                        return Ok(p.is_p(P_ARROW));
                    }
                }
                Ok(false)
            },
            256,
        )
    }

    /// At the start of a parameter in a type: a name or a pattern
    /// (skipped); true when one was there.
    fn skip_param_start(&mut self) -> R<bool> {
        if self.tok.t == T::Name {
            self.next()?;
            return Ok(true);
        }
        if self.tok.t == T::P && (self.tok.v == P_LBRACK || self.tok.v == P_LBRACE) {
            let mut depth = 0i64;
            while self.tok.t != T::Eof {
                if self.tok.t == T::P && matches!(self.tok.v, P_LBRACK | P_LBRACE | P_LPAREN) {
                    depth += 1;
                } else if self.tok.t == T::P && matches!(self.tok.v, P_RBRACK | P_RBRACE | P_RPAREN) {
                    depth -= 1;
                    if depth == 0 {
                        self.next()?;
                        return Ok(true);
                    }
                }
                self.next()?;
            }
        }
        Ok(false)
    }

    fn parse_function_type(&mut self) -> R<()> {
        self.eat_n(W_ABSTRACT)?;
        self.eat_n(W_NEW)?;
        if self.is_p(P_LT) {
            self.parse_type_params()?;
        }
        let saved = self.function_context(false, false);
        let r = self.parse_params();
        self.restore_context(saved);
        r?;
        self.expect_p(P_ARROW)?;
        let outer = self.no_conditional;
        self.no_conditional = false;
        self.parse_type_or_predicate()?;
        self.no_conditional = outer;
        Ok(())
    }

    fn parse_union_type(&mut self) -> R<()> {
        self.eat_p(P_BITOR)?;
        self.parse_intersection_type()?;
        while self.eat_p(P_BITOR)? {
            self.parse_intersection_type()?;
        }
        Ok(())
    }

    fn parse_intersection_type(&mut self) -> R<()> {
        self.eat_p(P_BITAND)?;
        self.parse_type_operator()?;
        while self.eat_p(P_BITAND)? {
            self.parse_type_operator()?;
        }
        Ok(())
    }

    fn parse_type_operator(&mut self) -> R<()> {
        self.enter()?;
        if self.tok.t == T::Name && !self.tok.esc && matches!(self.tok.v, W_KEYOF | W_UNIQUE | W_READONLY) {
            let (pk, pv, _) = self.peek();
            if matches!(pk, T::Name | T::Str | T::Num | T::Tmpl)
                || (pk == T::P && matches!(pv, P_LPAREN | P_LBRACK | P_LBRACE | P_MINUS))
            {
                self.next()?;
                self.parse_type_operator()?;
                self.depth -= 1;
                return Ok(());
            }
        }
        if self.is_n(W_INFER) {
            self.next()?;
            self.ident(true)?;
            if self.is_n(W_EXTENDS) {
                // a constraint, unless `infer U extends X ? …` starts a
                // conditional type where one may stand
                let outer = self.no_conditional;
                let st = self.save();
                self.next()?;
                self.no_conditional = true;
                let keep = match self.parse_type() {
                    Ok(()) => outer || !self.is_p(P_QUESTION),
                    Err(Fail::Syntax) => false,
                    Err(e) => return Err(e),
                };
                self.no_conditional = outer;
                if !keep {
                    let spent = self.spec_budget;
                    self.restore(&st);
                    if self.spec > 0 {
                        self.spec_budget = spent;
                    }
                }
            }
            self.depth -= 1;
            return Ok(());
        }
        let outer = self.no_conditional;
        self.no_conditional = false;
        if self.function_type_ahead()? {
            self.parse_function_type()?;
        } else {
            self.parse_primary_type()?;
            while !self.tok.nl {
                if self.is_p(P_LBRACK) {
                    self.next()?;
                    if !self.is_p(P_RBRACK) {
                        self.parse_type()?;
                    }
                    self.expect_p(P_RBRACK)?;
                } else if self.is_p(P_BANG) {
                    self.next()?;
                } else {
                    break;
                }
            }
        }
        self.no_conditional = outer;
        self.depth -= 1;
        Ok(())
    }

    /// A name, dotted (`A.B.C`).
    fn parse_entity_name(&mut self) -> R<()> {
        self.ident(true)?;
        while self.is_p(P_DOT) {
            self.next()?;
            if self.tok.t == T::Priv {
                self.next()?;
            } else {
                self.ident(true)?;
            }
        }
        Ok(())
    }

    fn parse_primary_type(&mut self) -> R<()> {
        // Flow's ?T: jsparse.py recurses once per `?`, without a depth check
        // (its recursion limit ends a long chain: PY_CHAIN_LIMIT)
        let mut chain: u32 = 0;
        while self.is_p(P_QUESTION) {
            self.next()?;
            chain += 1;
            if chain >= PY_CHAIN_LIMIT {
                return self.fatal(Fatal::Recursion);
            }
        }
        let (t, v) = (self.tok.t, self.tok.v);
        if t == T::Name {
            if !self.tok.esc {
                if v == W_TYPEOF {
                    self.next()?;
                    if self.is_n(W_IMPORT) {
                        self.parse_import_type()?;
                    } else {
                        self.parse_entity_name()?;
                    }
                    if self.is_p(P_LT) && !self.tok.nl {
                        self.parse_type_args()?;
                    }
                    return Ok(());
                }
                if v == W_IMPORT {
                    return self.parse_import_type();
                }
            }
            self.parse_entity_name()?;
            if self.is_p(P_LT) && !self.tok.nl {
                self.parse_type_args()?;
            }
            return Ok(());
        }
        if matches!(t, T::Str | T::Num | T::BigInt) {
            return self.next();
        }
        if t == T::Tmpl {
            while self.tok.y == 0 {
                self.next()?;
                self.parse_type()?;
                self.rescan_template_continuation()?;
            }
            return self.next();
        }
        if t == T::P {
            if v == P_MINUS {
                self.next()?;
                if !matches!(self.tok.t, T::Num | T::BigInt) {
                    return self.fail();
                }
                return self.next();
            }
            if v == P_LBRACE {
                if self.mapped_type_ahead()? {
                    return self.parse_mapped_type();
                }
                return self.parse_object_type();
            }
            if v == P_LBRACK {
                return self.parse_tuple_type();
            }
            if v == P_LPAREN {
                self.next()?;
                self.parse_type()?;
                return self.expect_p(P_RPAREN);
            }
            if v == P_STAR {
                return self.next();
            }
        }
        self.fail()
    }

    fn parse_import_type(&mut self) -> R<()> {
        self.expect_n(W_IMPORT)?;
        self.expect_p(P_LPAREN)?;
        if self.tok.t != T::Str {
            return self.fail();
        }
        self.next()?;
        if self.eat_p(P_COMMA)? && !self.is_p(P_RPAREN) {
            self.parse_object_like()?;
            self.eat_p(P_COMMA)?;
        }
        self.expect_p(P_RPAREN)?;
        while self.eat_p(P_DOT)? {
            self.ident(true)?;
        }
        if self.is_p(P_LT) && !self.tok.nl {
            self.parse_type_args()?;
        }
        Ok(())
    }

    fn parse_tuple_type(&mut self) -> R<()> {
        self.expect_p(P_LBRACK)?;
        while !self.is_p(P_RBRACK) {
            self.eat_p(P_ELLIPSIS)?;
            let labeled = if self.tok.t == T::Name {
                let (pk, pv, _) = self.peek();
                pk == T::P && (pv == P_COLON || (pv == P_QUESTION && self.look(|p| p.labeled_optional_ahead(), 3)?))
            } else {
                false
            };
            if labeled {
                self.next()?;
                self.eat_p(P_QUESTION)?;
                self.expect_p(P_COLON)?;
            }
            self.parse_type()?;
            self.eat_p(P_QUESTION)?;
            if !self.is_p(P_RBRACK) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()
    }

    fn labeled_optional_ahead(&mut self) -> R<bool> {
        self.next()?;
        self.next()?;
        Ok(self.is_p(P_COLON))
    }

    fn mapped_type_ahead(&mut self) -> R<bool> {
        self.look(
            |p| {
                p.next()?;
                if p.is_p(P_PLUS) || p.is_p(P_MINUS) {
                    p.next()?;
                    return Ok(p.is_n(W_READONLY));
                }
                if p.is_n(W_READONLY) {
                    p.next()?;
                }
                if !p.is_p(P_LBRACK) {
                    return Ok(false);
                }
                p.next()?;
                if p.tok.t != T::Name {
                    return Ok(false);
                }
                p.next()?;
                Ok(p.is_n(W_IN))
            },
            6,
        )
    }

    fn parse_mapped_type(&mut self) -> R<()> {
        self.expect_p(P_LBRACE)?;
        if self.is_p(P_PLUS) || self.is_p(P_MINUS) {
            self.next()?;
        }
        self.eat_n(W_READONLY)?;
        self.expect_p(P_LBRACK)?;
        self.ident(true)?;
        self.expect_n(W_IN)?;
        self.parse_type()?;
        if self.eat_n(W_AS)? {
            self.parse_type()?;
        }
        self.expect_p(P_RBRACK)?;
        if self.is_p(P_PLUS) || self.is_p(P_MINUS) {
            self.next()?;
            self.expect_p(P_QUESTION)?;
        } else {
            self.eat_p(P_QUESTION)?;
        }
        if self.eat_p(P_COLON)? {
            self.parse_type()?;
        }
        if !self.eat_p(P_SEMI)? {
            self.eat_p(P_COMMA)?;
        }
        self.expect_p(P_RBRACE)
    }

    pub(super) fn parse_object_type(&mut self) -> R<()> {
        self.expect_p(P_LBRACE)?;
        while !self.is_p(P_RBRACE) {
            if self.tok.t == T::Eof {
                return self.fail();
            }
            self.enter()?;
            self.parse_type_member()?;
            self.depth -= 1;
            if !(self.eat_p(P_SEMI)? || self.eat_p(P_COMMA)? || self.is_p(P_RBRACE) || self.tok.nl) {
                return self.fail();
            }
        }
        self.next()
    }

    /// `<T>(params): R` of a call, construct or method signature.
    fn parse_signature_rest(&mut self) -> R<()> {
        if self.is_p(P_LT) {
            self.parse_type_params()?;
        }
        let saved = self.function_context(false, false);
        let r = self.parse_params();
        self.restore_context(saved);
        r?;
        if self.is_p(P_COLON) {
            self.parse_return_type()?;
        }
        Ok(())
    }

    fn parse_type_member(&mut self) -> R<()> {
        if self.is_p(P_LPAREN) || self.is_p(P_LT) {
            return self.parse_signature_rest();
        }
        if self.is_n(W_NEW) {
            let (pk, pv, _) = self.peek();
            if pk == T::P && (pv == P_LPAREN || pv == P_LT) {
                self.next()?;
                return self.parse_signature_rest();
            }
        }
        while self.tok.t == T::Name && matches!(self.tok.v, W_READONLY | W_GET | W_SET) && !self.tok.esc {
            let (pk, pv, _) = self.peek();
            if matches!(pk, T::Name | T::Str | T::Num) || (pk == T::P && pv == P_LBRACK) {
                self.next()?;
            } else {
                break;
            }
        }
        if self.is_p(P_LBRACK) {
            if self.index_signature_ahead()? {
                return self.parse_index_signature();
            }
            self.next()?;
            self.parse_maybe_assign(false, true)?;
            self.expect_p(P_RBRACK)?;
        } else {
            self.parse_property_name()?;
        }
        self.eat_p(P_QUESTION)?;
        if self.is_p(P_LPAREN) || self.is_p(P_LT) {
            return self.parse_signature_rest();
        }
        if self.eat_p(P_COLON)? {
            self.parse_type()?;
        }
        Ok(())
    }

    pub(super) fn parse_type_params(&mut self) -> R<()> {
        self.expect_p(P_LT)?;
        while !self.is_p(P_GT) {
            while self.tok.t == T::Name && matches!(self.tok.v, W_IN | W_OUT | W_CONST) && self.peek().0 == T::Name {
                self.next()?;
            }
            self.ident(true)?;
            if self.eat_n(W_EXTENDS)? {
                self.parse_type()?;
            }
            if self.eat_p(P_ASSIGN)? {
                self.parse_type()?;
            }
            if !self.is_p(P_GT) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()
    }

    pub(super) fn parse_type_args(&mut self) -> R<bool> {
        self.expect_p(P_LT)?;
        while !self.is_p(P_GT) {
            self.parse_type()?;
            if !self.is_p(P_GT) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()?;
        Ok(true)
    }
}
