//! Expressions, the patterns they turn into, templates and JSX: the
//! second half of jsparse.py's `_Parser`.

use super::parser::*;
use super::scan::*;
use super::tree::*;

/// What parse_paren_items read: the items are on the scratch stack from
/// `mark` (a rest item is a RestElement node, nothing else is).
pub(super) struct Items {
    mark: usize,
    typed: bool,
    trailing: bool,
    cast: bool,
    /// the line (and start) of the first item, when the list was empty there
    line: Option<At>,
}

impl<'a> Parser<'a> {
    pub(super) fn parse_expression(&mut self, no_in: bool) -> R<NodeId> {
        let at = self.at();
        let expr = self.parse_maybe_assign(no_in, true)?;
        if self.is_p(P_COMMA) {
            let mark = self.scratch.len();
            self.scratch.push(expr);
            while self.eat_p(P_COMMA)? {
                let e = self.parse_maybe_assign(no_in, true)?;
                self.scratch.push(e);
            }
            let exprs = self.commit(mark);
            return Ok(self.fin(Kind::SequenceExpression, at, [exprs, NONE, NONE, NONE]));
        }
        Ok(expr)
    }

    /// An assignment expression. ret_ok=false: `(x): T => …` is no arrow
    /// function with a return type here (a conditional's consequent, where
    /// `c ? (x) : y => z` reads as TypeScript reads it).
    pub(super) fn parse_maybe_assign(&mut self, no_in: bool, ret_ok: bool) -> R<NodeId> {
        self.enter()?;
        let saved = self.ret_ok;
        self.ret_ok = ret_ok;
        let expr = self.parse_maybe_assign_inner(no_in)?;
        self.ret_ok = saved;
        self.depth -= 1;
        Ok(expr)
    }

    fn parse_maybe_assign_inner(&mut self, no_in: bool) -> R<NodeId> {
        let at = self.at();
        let (t, v) = (self.tok.t, self.tok.v);
        if t == T::Name && !self.tok.esc {
            if v == W_YIELD && self.in_gen {
                self.next()?;
                let mut delegate = false;
                let mut arg = NONE;
                if !self.tok.nl {
                    delegate = self.eat_p(P_STAR)?;
                    if delegate || self.starts_expression() {
                        arg = self.parse_maybe_assign(no_in, true)?;
                    }
                }
                let flags = if delegate { DELEGATE } else { 0 };
                return Ok(self.fin_x(Kind::YieldExpression, at, 0, flags, [arg, NONE, NONE, NONE]));
            }
            let (pk, pv, pnl) = self.peek();
            if pk == T::P && pv == P_ARROW && !pnl && !reserved(v) {
                let param = self.ident(false)?;
                let params = self.list_of(&[param]);
                return self.parse_arrow_rest(params, false, at);
            }
            if v == W_ASYNC && !pnl {
                if pk == T::Name && !reserved(pv) {
                    let st = self.save();
                    self.next()?;
                    let param = self.ident(false)?;
                    if self.is_p(P_ARROW) && !self.tok.nl {
                        let params = self.list_of(&[param]);
                        return self.parse_arrow_rest(params, true, at);
                    }
                    self.restore(&st);
                } else if self.ts && pk == T::P && pv == P_LT {
                    if let Some(node) = self.speculate(|p| p.parse_generic_arrow(true, at))? {
                        return Ok(node);
                    }
                }
            }
        } else if t == T::P && v == P_LT && self.ts {
            if let Some(node) = self.speculate(|p| p.parse_generic_arrow(false, at))? {
                return Ok(node);
            }
        }
        let left = self.parse_maybe_conditional(no_in)?;
        if self.tok.t == T::P {
            let mut op = self.tok.v;
            if op == P_GT {
                op = self.gt_op();
                if op == P_SHR_ASSIGN || op == P_USHR_ASSIGN {
                    self.take_gt();
                }
            }
            if assign_op(op) {
                let target = if op == P_ASSIGN { self.to_pattern(left, false)? } else { self.simple_target(left)? };
                self.next()?;
                let right = self.parse_maybe_assign(no_in, true)?;
                return Ok(self.fin_x(Kind::AssignmentExpression, at, op as u8, 0, [target, right, NONE, NONE]));
            }
        }
        Ok(left)
    }

    pub(super) fn simple_target(&mut self, node: NodeId) -> R<NodeId> {
        let n = *self.node(node);
        if n.kind == Kind::Identifier || n.kind == Kind::MemberExpression {
            return Ok(node);
        }
        self.fail_at("invalid assignment target", n.line)
    }

    pub(super) fn starts_expression(&self) -> bool {
        match self.tok.t {
            T::Name | T::Num | T::BigInt | T::Str | T::Tmpl | T::Priv | T::Regex => true,
            T::P => matches!(
                self.tok.v,
                P_LPAREN
                    | P_LBRACK
                    | P_LBRACE
                    | P_PLUS
                    | P_MINUS
                    | P_BANG
                    | P_TILDE
                    | P_INC
                    | P_DEC
                    | P_SLASH
                    | P_DIV_ASSIGN
                    | P_LT
                    | P_AT
                    | P_HASH
                    | P_ELLIPSIS
            ),
            _ => false,
        }
    }

    fn parse_generic_arrow(&mut self, is_async: bool, at: At) -> R<NodeId> {
        if is_async {
            self.next()?;
        }
        self.parse_type_params()?;
        if !self.is_p(P_LPAREN) {
            return Err(Fail::Backtrack);
        }
        let saved = self.function_context(is_async, false);
        let r = self.parse_params();
        self.restore_context(saved);
        let params = r?;
        if self.is_p(P_COLON) {
            self.parse_return_type()?;
        }
        if !self.is_p(P_ARROW) || self.tok.nl {
            return Err(Fail::Backtrack);
        }
        self.parse_arrow_rest(params, is_async, at)
    }

    /// `=> body` (the current token).
    fn parse_arrow_rest(&mut self, params: u32, is_async: bool, at: At) -> R<NodeId> {
        if self.tok.nl || !self.is_p(P_ARROW) {
            return self.fail();
        }
        self.next()?;
        let saved = self.function_context(is_async, false);
        let r = if self.is_p(P_LBRACE) {
            self.parse_block().map(|b| (b, false))
        } else {
            self.parse_maybe_assign(false, true).map(|b| (b, true))
        };
        self.restore_context(saved);
        let (body, expression) = r?;
        let flags = if expression { EXPRESSION } else { 0 } | if is_async { ASYNC } else { 0 };
        Ok(self.fin_x(Kind::ArrowFunctionExpression, at, 0, flags, [NONE, params, body, NONE]))
    }

    fn parse_maybe_conditional(&mut self, no_in: bool) -> R<NodeId> {
        let at = self.at();
        let expr = self.parse_expr_ops(no_in)?;
        if self.is_p(P_QUESTION) {
            self.next()?;
            let cons = self.parse_maybe_assign(false, false)?;
            self.expect_p(P_COLON)?;
            let alt = self.parse_maybe_assign(no_in, true)?;
            return Ok(self.fin(Kind::ConditionalExpression, at, [expr, cons, alt, NONE]));
        }
        Ok(expr)
    }

    /// (operator, precedence) of the current token as a binary operator,
    /// else (NONE, 0).
    pub(super) fn binary_op(&self, no_in: bool) -> (u32, u8) {
        let (t, v) = (self.tok.t, self.tok.v);
        if t == T::P {
            if v == P_GT {
                let op = self.gt_op();
                if op == P_SHR_ASSIGN || op == P_USHR_ASSIGN {
                    return (NONE, 0);
                }
                return (op, binary_prec(op));
            }
            let prec = binary_prec(v);
            if prec > 0 {
                return (v, prec);
            }
            return (NONE, 0);
        }
        if t == T::Name && !self.tok.esc {
            if v == W_INSTANCEOF || (v == W_IN && !no_in) {
                return (v, 7);
            }
            if (v == W_AS || v == W_SATISFIES) && self.ts && !self.tok.nl {
                return (v, 7);
            }
        }
        (NONE, 0)
    }

    /// Binary operators by precedence: operands and operators on stacks, no
    /// recursion per operand.
    fn parse_expr_ops(&mut self, no_in: bool) -> R<NodeId> {
        let at = self.at();
        let left = self.parse_maybe_unary()?;
        if self.node(left).kind == Kind::ArrowFunctionExpression && !self.prev_rparen {
            return Ok(left);
        }
        let (mut op, mut prec) = self.binary_op(no_in);
        if op == NONE {
            return Ok(left);
        }
        let omark = self.operands.len();
        let pmark = self.ops.len();
        self.operands.push((left, at));
        while op != NONE {
            if op == W_AS || op == W_SATISFIES {
                while self.ops.len() > pmark && self.ops[self.ops.len() - 1].1 >= prec {
                    self.reduce();
                }
                self.next()?;
                if self.is_n(W_CONST) {
                    self.next()?;
                } else {
                    self.parse_type()?;
                }
                (op, prec) = self.binary_op(no_in);
                continue;
            }
            while self.ops.len() > pmark && {
                let top = self.ops[self.ops.len() - 1].1;
                top > prec || (top == prec && op != P_POW)
            } {
                self.reduce();
            }
            if self.tok.v == P_GT {
                self.take_gt();
            }
            self.ops.push((op, prec));
            self.next()?;
            let oat = self.at();
            let operand = self.parse_maybe_unary()?;
            self.operands.push((operand, oat));
            (op, prec) = self.binary_op(no_in);
        }
        while self.ops.len() > pmark {
            self.reduce();
        }
        let out = self.operands[omark].0;
        self.operands.truncate(omark);
        Ok(out)
    }

    fn reduce(&mut self) {
        let (right, _) = self.operands.pop().unwrap_or((NONE, At { line: 0, start: 0 }));
        let (left, at) = self.operands.pop().unwrap_or((NONE, At { line: 0, start: 0 }));
        let (op, _) = self.ops.pop().unwrap_or((NONE, 0));
        let kind = if op == P_OR || op == P_AND || op == P_NULLISH { Kind::LogicalExpression } else { Kind::BinaryExpression };
        let end = if right == NONE { self.pe } else { self.node(right).end };
        let node = self.mk(kind, at, end, op as u8, 0, [left, right, NONE, NONE]);
        self.operands.push((node, at));
    }

    fn parse_maybe_unary(&mut self) -> R<NodeId> {
        let pmark = self.prefix.len();
        let at = self.at();
        loop {
            let (t, v) = (self.tok.t, self.tok.v);
            if t == T::P && matches!(v, P_BANG | P_TILDE | P_PLUS | P_MINUS | P_INC | P_DEC) {
                let kind = if v == P_INC || v == P_DEC { Kind::UpdateExpression } else { Kind::UnaryExpression };
                let pat = self.at();
                self.prefix.push((kind, v, pat));
                self.next()?;
            } else if t == T::Name && !self.tok.esc && (v == W_TYPEOF || v == W_VOID || v == W_DELETE) {
                let pat = self.at();
                self.prefix.push((Kind::UnaryExpression, v, pat));
                self.next()?;
            } else if t == T::Name && !self.tok.esc && v == W_AWAIT && self.await_here() {
                let pat = self.at();
                self.prefix.push((Kind::AwaitExpression, v, pat));
                self.next()?;
            } else if t == T::P && v == P_LT && self.ts && !self.jsx {
                self.next()?; // <T>expr: a type assertion
                self.parse_type()?;
                self.expect_p(P_GT)?;
            } else {
                break;
            }
            if self.prefix.len() - pmark > MAX_DEPTH as usize {
                return self.fail_msg("nesting too deep");
            }
        }
        let oat = if self.prefix.len() > pmark { self.at() } else { at };
        let mut expr = self.parse_expr_subscripts()?;
        if self.tok.t == T::P && (self.tok.v == P_INC || self.tok.v == P_DEC) && !self.tok.nl {
            let (op, e) = (self.tok.v, self.tok.e);
            let arg = self.simple_target(expr)?;
            expr = self.mk(Kind::UpdateExpression, oat, e, op as u8, 0, [arg, NONE, NONE, NONE]);
            self.next()?;
        }
        while self.prefix.len() > pmark {
            let (kind, op, pat) = self.prefix[self.prefix.len() - 1];
            self.prefix.pop();
            expr = match kind {
                Kind::AwaitExpression => self.fin(Kind::AwaitExpression, pat, [expr, NONE, NONE, NONE]),
                Kind::UpdateExpression => {
                    let arg = self.simple_target(expr)?;
                    self.fin_x(Kind::UpdateExpression, pat, op as u8, PREFIX, [arg, NONE, NONE, NONE])
                }
                _ => self.fin_x(Kind::UnaryExpression, pat, op as u8, PREFIX, [expr, NONE, NONE, NONE]),
            };
        }
        Ok(expr)
    }

    /// `await` as an operator: in an async function, or outside any
    /// function (a module's top level) when an operand follows on its line.
    fn await_here(&mut self) -> bool {
        if self.in_async {
            return true;
        }
        if self.in_func {
            return false;
        }
        let (pk, pv, pnl) = self.peek();
        if pnl {
            return false;
        }
        if matches!(pk, T::Name | T::Num | T::BigInt | T::Str | T::Tmpl | T::Priv) {
            return !matches!(pv, W_IN | W_OF | W_INSTANCEOF | W_AS | W_SATISFIES);
        }
        pk == T::P
            && matches!(pv, P_LPAREN | P_LBRACK | P_LBRACE | P_BANG | P_TILDE | P_PLUS | P_MINUS | P_INC | P_DEC | P_SLASH | P_DIV_ASSIGN)
    }

    pub(super) fn parse_expr_subscripts(&mut self) -> R<NodeId> {
        let at = self.at();
        let expr = self.parse_expr_atom()?;
        if self.node(expr).kind == Kind::ArrowFunctionExpression && !self.prev_rparen {
            return Ok(expr); // `(a) => b` ends here: no call or member follows it
        }
        self.parse_subscripts(expr, at)
    }

    fn parse_subscripts(&mut self, expr: NodeId, at: At) -> R<NodeId> {
        let mut expr = expr;
        let mut chained = false;
        loop {
            let (t, v) = (self.tok.t, self.tok.v);
            if t == T::P {
                if v == P_DOT {
                    self.next()?;
                    let prop = if self.tok.t == T::Priv { self.parse_property_name()? } else { self.ident(true)? };
                    expr = self.fin(Kind::MemberExpression, at, [expr, prop, NONE, NONE]);
                    continue;
                }
                if v == P_OPTIONAL {
                    chained = true;
                    self.next()?;
                    if self.is_p(P_LPAREN) {
                        let args = self.parse_arguments()?;
                        expr = self.fin_x(Kind::CallExpression, at, 0, OPTIONAL, [expr, args, NONE, NONE]);
                    } else if self.is_p(P_LBRACK) {
                        self.next()?;
                        let prop = self.parse_expression(false)?;
                        self.expect_p(P_RBRACK)?;
                        expr = self.fin_x(Kind::MemberExpression, at, 0, COMPUTED | OPTIONAL, [expr, prop, NONE, NONE]);
                    } else if self.is_p(P_LT) && self.ts {
                        self.parse_type_args()?;
                        let args = self.parse_arguments()?;
                        expr = self.fin_x(Kind::CallExpression, at, 0, OPTIONAL, [expr, args, NONE, NONE]);
                    } else {
                        let prop = if self.tok.t == T::Priv { self.parse_property_name()? } else { self.ident(true)? };
                        expr = self.fin_x(Kind::MemberExpression, at, 0, OPTIONAL, [expr, prop, NONE, NONE]);
                    }
                    continue;
                }
                if v == P_LBRACK {
                    self.next()?;
                    let prop = self.parse_expression(false)?;
                    self.expect_p(P_RBRACK)?;
                    expr = self.fin_x(Kind::MemberExpression, at, 0, COMPUTED, [expr, prop, NONE, NONE]);
                    continue;
                }
                if v == P_LPAREN {
                    let args = self.parse_arguments()?;
                    expr = self.fin(Kind::CallExpression, at, [expr, args, NONE, NONE]);
                    continue;
                }
                if v == P_BANG && self.ts && !self.tok.nl {
                    self.next()?; // a non-null assertion
                    continue;
                }
                if v == P_LT
                    && self.ts
                    && !self.tok.nl
                    && self.speculate(|p| p.parse_type_args_in_expression())?.is_some()
                {
                    if self.is_p(P_LPAREN) {
                        let args = self.parse_arguments()?;
                        expr = self.fin(Kind::CallExpression, at, [expr, args, NONE, NONE]);
                    }
                    continue;
                }
                break;
            }
            if t == T::Tmpl {
                if chained {
                    return self.fail_msg("tagged template in an optional chain");
                }
                let quasi = self.parse_template()?;
                expr = self.fin(Kind::TaggedTemplateExpression, at, [expr, quasi, NONE, NONE]);
                continue;
            }
            break;
        }
        if chained {
            expr = self.fin(Kind::ChainExpression, at, [expr, NONE, NONE, NONE]);
        }
        Ok(expr)
    }

    /// `<T>` after an expression, when TypeScript's rule lets type arguments
    /// stand there (else a backtrack: `a < b > c`).
    fn parse_type_args_in_expression(&mut self) -> R<bool> {
        self.parse_type_args()?;
        let (t, v) = (self.tok.t, self.tok.v);
        if t == T::Tmpl || (t == T::P && v == P_LPAREN) {
            return Ok(true);
        }
        if t == T::P && matches!(v, P_LT | P_GT | P_PLUS | P_MINUS) {
            return Err(Fail::Backtrack);
        }
        if self.tok.nl || self.binary_op(false).0 != NONE || !self.starts_expression() {
            return Ok(true);
        }
        Err(Fail::Backtrack)
    }

    pub(super) fn parse_arguments(&mut self) -> R<u32> {
        self.expect_p(P_LPAREN)?;
        let mark = self.scratch.len();
        while !self.is_p(P_RPAREN) {
            if self.is_p(P_ELLIPSIS) {
                let at = self.at();
                self.next()?;
                let arg = self.parse_maybe_assign(false, true)?;
                let spread = self.fin(Kind::SpreadElement, at, [arg, NONE, NONE, NONE]);
                self.scratch.push(spread);
            } else {
                let arg = self.parse_maybe_assign(false, true)?;
                self.scratch.push(arg);
            }
            if !self.is_p(P_RPAREN) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()?;
        Ok(self.commit(mark))
    }

    pub(super) fn parse_template(&mut self) -> R<NodeId> {
        let at = self.at();
        let mark = self.scratch.len();
        loop {
            let (raw, tail) = (self.tok.x, self.tok.y == 1);
            let qat = self.at();
            let qend = self.tok.e;
            let flags = if tail { TAIL } else { 0 };
            let quasi = self.mk(Kind::TemplateElement, qat, qend, 0, flags, [raw, NONE, NONE, NONE]);
            self.scratch.push(quasi);
            self.next()?;
            if tail {
                break;
            }
            let e = self.parse_expression(false)?;
            self.scratch.push(e);
            self.rescan_template_continuation()?;
        }
        // (quasis and expressions alternate on the stack)
        let all: Vec<u32> = self.scratch[mark..].to_vec();
        self.scratch.truncate(mark);
        let quasis: Vec<u32> = all.iter().step_by(2).copied().collect();
        let exprs: Vec<u32> = all.iter().skip(1).step_by(2).copied().collect();
        let q = self.list_of(&quasis);
        let x = self.list_of(&exprs);
        Ok(self.fin(Kind::TemplateLiteral, at, [q, x, NONE, NONE]))
    }

    fn parse_expr_atom(&mut self) -> R<NodeId> {
        self.enter()?;
        let expr = self.parse_expr_atom_inner()?;
        self.depth -= 1;
        Ok(expr)
    }

    fn parse_expr_atom_inner(&mut self) -> R<NodeId> {
        let (t, v) = (self.tok.t, self.tok.v);
        let at = self.at();
        if t == T::Name {
            if !self.tok.esc {
                if v == W_FUNCTION {
                    return self.parse_function(false, false, at).and_then(|f| match f {
                        Some(f) => Ok(f),
                        None => Err(Fail::Syntax), // (an expression always has its body)
                    });
                }
                if v == W_ASYNC {
                    let (pk, pv, pnl) = self.peek();
                    if pk == T::Name && pv == W_FUNCTION && !pnl {
                        self.next()?;
                        return self.parse_function(false, true, at).and_then(|f| match f {
                            Some(f) => Ok(f),
                            None => Err(Fail::Syntax),
                        });
                    }
                    if pk == T::P && pv == P_LPAREN && !pnl {
                        return self.parse_async_call_or_arrow(at);
                    }
                }
                if v == W_CLASS || (v == W_ABSTRACT && self.peek().1 == W_CLASS) {
                    return self.parse_class(false, NONE);
                }
                if v == W_NEW {
                    return self.parse_new();
                }
                if v == W_THIS {
                    self.next()?;
                    return Ok(self.fin(Kind::ThisExpression, at, [NONE; 4]));
                }
                if v == W_SUPER {
                    self.next()?;
                    return Ok(self.fin(Kind::Super, at, [NONE; 4]));
                }
                if v == W_NULL {
                    self.next()?;
                    return Ok(self.fin_x(Kind::Literal, at, L_NULL, 0, [NONE; 4]));
                }
                if v == W_TRUE || v == W_FALSE {
                    self.next()?;
                    let flags = if v == W_TRUE { VALUE } else { 0 };
                    return Ok(self.fin_x(Kind::Literal, at, L_BOOLEAN, flags, [NONE; 4]));
                }
                if v == W_IMPORT {
                    let e = self.tok.e;
                    self.next()?;
                    if self.eat_p(P_DOT)? {
                        let meta = self.mk(Kind::Identifier, at, e, 0, 0, [W_IMPORT, NONE, NONE, NONE]);
                        let prop = self.ident(true)?;
                        return Ok(self.fin(Kind::MetaProperty, at, [meta, prop, NONE, NONE]));
                    }
                    self.expect_p(P_LPAREN)?;
                    let source = self.parse_maybe_assign(false, true)?;
                    let mut options = NONE;
                    if self.eat_p(P_COMMA)? && !self.is_p(P_RPAREN) {
                        options = self.parse_maybe_assign(false, true)?;
                        self.eat_p(P_COMMA)?;
                    }
                    self.expect_p(P_RPAREN)?;
                    return Ok(self.fin(Kind::ImportExpression, at, [source, options, NONE, NONE]));
                }
                if reserved(v) {
                    return self.fail();
                }
            }
            return self.ident(true);
        }
        if t == T::Num || t == T::BigInt {
            self.next()?;
            let op = if t == T::Num { L_NUMBER } else { L_BIGINT };
            return Ok(self.fin_x(Kind::Literal, at, op, 0, [v, NONE, NONE, NONE]));
        }
        if t == T::Str {
            self.next()?;
            return Ok(self.fin_x(Kind::Literal, at, L_STRING, 0, [v, NONE, NONE, NONE]));
        }
        if t == T::Tmpl {
            return self.parse_template();
        }
        if t == T::Priv {
            self.next()?; // `#x in obj`
            return Ok(self.fin(Kind::PrivateIdentifier, at, [v, NONE, NONE, NONE]));
        }
        if t == T::P {
            if v == P_LPAREN {
                return self.parse_paren_or_arrow();
            }
            if v == P_LBRACK {
                return self.parse_array_literal();
            }
            if v == P_LBRACE {
                return self.parse_object_like();
            }
            if v == P_SLASH || v == P_DIV_ASSIGN {
                self.rescan_regex()?;
                let (pattern, flags) = (self.tok.x, self.tok.y);
                self.next()?;
                return Ok(self.fin_x(Kind::Literal, at, L_REGEX, 0, [pattern, flags, NONE, NONE]));
            }
            if v == P_LT && self.jsx {
                self.enter()?;
                self.jsx_tag_next()?;
                let node = self.parse_jsx_element(at, Where::Expr)?;
                self.depth -= 1;
                return Ok(node);
            }
            if v == P_AT {
                let decorators = self.parse_decorators()?;
                return self.parse_class(false, decorators);
            }
        }
        self.fail()
    }

    fn parse_new(&mut self) -> R<NodeId> {
        let at = self.at();
        let e = self.tok.e;
        self.next()?;
        if self.eat_p(P_DOT)? {
            let meta = self.mk(Kind::Identifier, at, e, 0, 0, [W_NEW, NONE, NONE, NONE]);
            let prop = self.ident(true)?;
            return Ok(self.fin(Kind::MetaProperty, at, [meta, prop, NONE, NONE]));
        }
        self.enter()?;
        let cat = self.at();
        let mut callee = if self.is_n(W_NEW) { self.parse_new()? } else { self.parse_expr_atom()? };
        loop {
            if self.is_p(P_DOT) {
                self.next()?;
                let prop = if self.tok.t == T::Priv { self.parse_property_name()? } else { self.ident(true)? };
                callee = self.fin(Kind::MemberExpression, cat, [callee, prop, NONE, NONE]);
            } else if self.is_p(P_LBRACK) {
                self.next()?;
                let prop = self.parse_expression(false)?;
                self.expect_p(P_RBRACK)?;
                callee = self.fin_x(Kind::MemberExpression, cat, 0, COMPUTED, [callee, prop, NONE, NONE]);
            } else if self.tok.t == T::Tmpl {
                let quasi = self.parse_template()?;
                callee = self.fin(Kind::TaggedTemplateExpression, cat, [callee, quasi, NONE, NONE]);
            } else if self.ts && self.is_p(P_BANG) && !self.tok.nl {
                self.next()?;
            } else {
                break;
            }
        }
        if self.ts && self.is_p(P_LT) {
            self.speculate(|p| p.parse_type_args())?;
        }
        let args = if self.is_p(P_LPAREN) { self.parse_arguments()? } else { 0 };
        self.depth -= 1;
        Ok(self.fin(Kind::NewExpression, at, [callee, args, NONE, NONE]))
    }

    /// `async (…)`: an async arrow function's parameters, or a call of a
    /// function named async.
    fn parse_async_call_or_arrow(&mut self, at: At) -> R<NodeId> {
        let callee = self.ident(true)?;
        let items = self.parse_paren_items()?;
        if self.is_p(P_ARROW) && !self.tok.nl {
            let params = self.items_to_params(&items)?;
            return self.parse_arrow_rest(params, true, at);
        }
        if self.is_p(P_COLON) && !self.tok.nl && self.arrow_return_type_ahead(&items)? {
            let params = self.items_to_params(&items)?;
            return self.parse_arrow_rest(params, true, at);
        }
        if items.typed {
            return self.fail();
        }
        let list: Vec<u32> = self.scratch[items.mark..].to_vec();
        self.scratch.truncate(items.mark);
        let mut args = Vec::with_capacity(list.len());
        for node in list {
            let n = *self.node(node);
            if n.kind == Kind::RestElement {
                let spread = self.mk(Kind::SpreadElement, At { line: n.line, start: n.start }, n.end, 0, 0, [n.f[A as usize], NONE, NONE, NONE]);
                args.push(spread);
            } else {
                args.push(node);
            }
        }
        let args = self.list_of(&args);
        let call = self.fin(Kind::CallExpression, at, [callee, args, NONE, NONE]);
        self.parse_subscripts(call, at)
    }

    fn parse_paren_or_arrow(&mut self) -> R<NodeId> {
        let at = self.at();
        let items = self.parse_paren_items()?;
        if self.is_p(P_ARROW) && !self.tok.nl {
            let params = self.items_to_params(&items)?;
            return self.parse_arrow_rest(params, false, at);
        }
        if self.is_p(P_COLON) && !self.tok.nl && self.arrow_return_type_ahead(&items)? {
            let params = self.items_to_params(&items)?;
            return self.parse_arrow_rest(params, false, at);
        }
        let count = self.scratch.len() - items.mark;
        let last_rest = count > 0 && self.node(self.scratch[self.scratch.len() - 1]).kind == Kind::RestElement;
        if items.trailing || count == 0 || last_rest {
            return self.fail();
        }
        if items.typed && !(count == 1 && items.cast) {
            return self.fail();
        }
        if count == 1 {
            let e = self.scratch[items.mark];
            self.scratch.truncate(items.mark);
            return Ok(e);
        }
        let line = match items.line {
            Some(l) => l,
            None => return self.fatal(Fatal::KeyErrorLine),
        };
        let exprs = self.commit(items.mark);
        // (the end: the last item's, not the parenthesis)
        let last = *self.tree.list(exprs).last().unwrap_or(&NONE);
        let end = if last == NONE { self.pe } else { self.node(last).end };
        Ok(self.mk(Kind::SequenceExpression, line, end, 0, 0, [exprs, NONE, NONE, NONE]))
    }

    /// At `:` after `( … )`: the items are parameters, and a return type and
    /// `=>` follow (read ahead; `c ? (a) : b` is a conditional).
    fn arrow_return_type_ahead(&mut self, items: &Items) -> R<bool> {
        if !self.ret_ok {
            return Ok(false);
        }
        for k in items.mark..self.scratch.len() {
            let node = self.scratch[k];
            if self.node(node).kind != Kind::RestElement && !self.param_ok(node) {
                return Ok(false);
            }
        }
        let r = self.speculate(|p| {
            p.parse_return_type()?;
            if !p.is_p(P_ARROW) || p.tok.nl {
                return Err(Fail::Backtrack);
            }
            Ok(true)
        })?;
        Ok(r.is_some())
    }

    /// The contents of `( … )` read as expressions that may turn out to be
    /// arrow parameters: the items on the scratch stack.
    fn parse_paren_items(&mut self) -> R<Items> {
        self.expect_p(P_LPAREN)?;
        let mut out = Items { mark: self.scratch.len(), typed: false, trailing: false, cast: false, line: None };
        while !self.is_p(P_RPAREN) {
            let at = self.at();
            if self.is_p(P_ELLIPSIS) {
                self.next()?;
                let binding = self.tok.t != T::Name || {
                    let pv = self.peek().1;
                    matches!(pv, P_RPAREN | P_COMMA | P_COLON | P_QUESTION | P_ASSIGN)
                };
                let target = if binding { self.parse_binding_target()? } else { self.parse_maybe_assign(false, true)? };
                self.eat_p(P_QUESTION)?;
                if self.eat_p(P_COLON)? {
                    self.parse_type()?;
                    out.typed = true;
                }
                if self.eat_p(P_ASSIGN)? {
                    self.parse_maybe_assign(false, true)?;
                    out.typed = true;
                }
                let rest = self.fin(Kind::RestElement, at, [target, NONE, NONE, NONE]);
                self.scratch.push(rest);
                if !self.is_p(P_RPAREN) {
                    self.expect_p(P_COMMA)?;
                }
                continue;
            }
            if self.is_p(P_AT) {
                self.parse_decorators()?;
                out.typed = true;
            }
            while self.tok.t == T::Name && param_modifier(self.tok.v) && !self.tok.esc && self.peek().0 == T::Name {
                self.next()?;
                out.typed = true;
            }
            if self.is_n(W_THIS) {
                let (pk, pv, _) = self.peek();
                if pk == T::P && pv == P_COLON {
                    self.next()?;
                    self.next()?;
                    self.parse_type()?;
                    out.typed = true;
                    if !self.is_p(P_RPAREN) {
                        self.expect_p(P_COMMA)?;
                    }
                    continue;
                }
            }
            if self.scratch.len() == out.mark {
                out.line = Some(self.at());
            }
            let mut typed = false;
            let mut node;
            if self.tok.t == T::Name && self.peek().1 == P_QUESTION && self.look(|p| p.optional_param_ahead(), 2)? {
                node = self.ident(false)?;
                self.next()?; // ?
                typed = true;
            } else {
                node = self.parse_maybe_assign(false, true)?;
            }
            if self.eat_p(P_COLON)? {
                self.parse_type()?;
                if !typed {
                    out.cast = true; // (x: T): Flow's type cast, or a parameter
                }
                typed = true;
            }
            if typed {
                out.typed = true;
                if self.eat_p(P_ASSIGN)? {
                    let nat = self.at_of(node);
                    let right = self.parse_maybe_assign(false, true)?;
                    node = self.fin_x(Kind::AssignmentExpression, nat, P_ASSIGN as u8, 0, [node, right, NONE, NONE]);
                }
            }
            self.scratch.push(node);
            if !self.is_p(P_RPAREN) {
                self.expect_p(P_COMMA)?;
                if self.is_p(P_RPAREN) {
                    out.trailing = true;
                }
            }
        }
        self.next()?;
        Ok(out)
    }

    /// At `name ?`: `name?:`, `name?,`, `name?)` or `name?=` (an optional
    /// parameter, not a conditional expression).
    fn optional_param_ahead(&mut self) -> R<bool> {
        self.next()?;
        if !self.is_p(P_QUESTION) {
            return Ok(false);
        }
        self.next()?;
        Ok(self.tok.t == T::P && matches!(self.tok.v, P_COLON | P_COMMA | P_RPAREN | P_ASSIGN))
    }

    /// The items as parameters (the items leave the scratch stack).
    fn items_to_params(&mut self, items: &Items) -> R<u32> {
        let list: Vec<u32> = self.scratch[items.mark..].to_vec();
        self.scratch.truncate(items.mark);
        let mut params = Vec::with_capacity(list.len());
        for node in list {
            if self.node(node).kind == Kind::RestElement {
                params.push(node);
            } else {
                params.push(self.to_pattern(node, true)?);
            }
        }
        Ok(self.list_of(&params))
    }

    /// _param_ok: can a cover item be read as a parameter (to_pattern with binding)?
    fn param_ok(&self, node: NodeId) -> bool {
        let mut stack = vec![node];
        while let Some(id) = stack.pop() {
            let n = self.node(id);
            match n.kind {
                Kind::Identifier => continue,
                Kind::AssignmentExpression => {
                    if n.op as u32 != P_ASSIGN {
                        return false;
                    }
                    stack.push(n.f[A as usize]);
                }
                Kind::ObjectExpression => {
                    for &p in self.tree.list(n.f[A as usize]) {
                        let pn = self.node(p);
                        if pn.kind == Kind::SpreadElement {
                            stack.push(pn.f[A as usize]);
                        } else if pn.op != P_INIT || pn.flags & METHOD != 0 {
                            return false;
                        } else {
                            stack.push(pn.f[B as usize]);
                        }
                    }
                }
                Kind::ArrayExpression => {
                    for &el in self.tree.list(n.f[A as usize]) {
                        if el != NONE {
                            let en = self.node(el);
                            stack.push(if en.kind == Kind::SpreadElement { en.f[A as usize] } else { el });
                        }
                    }
                }
                Kind::ObjectPattern | Kind::ArrayPattern | Kind::AssignmentPattern | Kind::RestElement => {}
                _ => return false,
            }
        }
        true
    }

    /// An expression read again as an assignment target, or (binding) as a
    /// parameter. (Recursion: as deep as the expression, which nesting
    /// bounds.)
    #[allow(clippy::wrong_self_convention)] // (jsparse.py's name)
    pub(super) fn to_pattern(&mut self, node: NodeId, binding: bool) -> R<NodeId> {
        let n = *self.node(node);
        let at = At { line: n.line, start: n.start };
        match n.kind {
            Kind::Identifier | Kind::ObjectPattern | Kind::ArrayPattern | Kind::AssignmentPattern | Kind::RestElement => {
                Ok(node)
            }
            Kind::MemberExpression if !binding => Ok(node),
            Kind::ObjectExpression => {
                let props = self.items(n.f[A as usize]);
                let mut out = Vec::with_capacity(props.len());
                for p in props {
                    let pn = *self.node(p);
                    let pat = At { line: pn.line, start: pn.start };
                    if pn.kind == Kind::SpreadElement {
                        let arg = self.to_pattern(pn.f[A as usize], binding)?;
                        out.push(self.mk(Kind::RestElement, pat, pn.end, 0, 0, [arg, NONE, NONE, NONE]));
                        continue;
                    }
                    if pn.op != P_INIT || pn.flags & METHOD != 0 {
                        return self.fail_at("invalid destructuring target", pn.line);
                    }
                    let mut value = self.to_pattern(pn.f[B as usize], binding)?;
                    let cover = self.node(p).f[C as usize];
                    if cover != NONE {
                        self.tree.nodes[p as usize].f[C as usize] = NONE; // p.pop("_cover")
                        value = self.mk(Kind::AssignmentPattern, pat, pn.end, 0, 0, [value, cover, NONE, NONE]);
                    }
                    let flags = pn.flags & (SHORTHAND | COMPUTED);
                    out.push(self.mk(Kind::Property, pat, pn.end, P_INIT, flags, [pn.f[A as usize], value, NONE, NONE]));
                }
                let list = self.list_of(&out);
                Ok(self.mk(Kind::ObjectPattern, at, n.end, 0, 0, [list, NONE, NONE, NONE]))
            }
            Kind::ArrayExpression => {
                let elements = self.items(n.f[A as usize]);
                let mut out = Vec::with_capacity(elements.len());
                for el in elements {
                    if el == NONE {
                        out.push(NONE);
                        continue;
                    }
                    let en = *self.node(el);
                    if en.kind == Kind::SpreadElement {
                        let arg = self.to_pattern(en.f[A as usize], binding)?;
                        let eat = At { line: en.line, start: en.start };
                        out.push(self.mk(Kind::RestElement, eat, en.end, 0, 0, [arg, NONE, NONE, NONE]));
                    } else {
                        out.push(self.to_pattern(el, binding)?);
                    }
                }
                let list = self.list_of(&out);
                Ok(self.mk(Kind::ArrayPattern, at, n.end, 0, 0, [list, NONE, NONE, NONE]))
            }
            Kind::AssignmentExpression if n.op as u32 == P_ASSIGN => {
                let left = self.to_pattern(n.f[A as usize], binding)?;
                Ok(self.mk(Kind::AssignmentPattern, at, n.end, 0, 0, [left, n.f[B as usize], NONE, NONE]))
            }
            _ => self.fail_at("invalid destructuring target", n.line),
        }
    }

    fn parse_array_literal(&mut self) -> R<NodeId> {
        let at = self.at();
        self.next()?;
        let mark = self.scratch.len();
        while !self.is_p(P_RBRACK) {
            if self.is_p(P_COMMA) {
                self.next()?;
                self.scratch.push(NONE);
                continue;
            }
            if self.is_p(P_ELLIPSIS) {
                let sat = self.at();
                self.next()?;
                let arg = self.parse_maybe_assign(false, true)?;
                let spread = self.fin(Kind::SpreadElement, sat, [arg, NONE, NONE, NONE]);
                self.scratch.push(spread);
            } else {
                let el = self.parse_maybe_assign(false, true)?;
                self.scratch.push(el);
            }
            if !self.is_p(P_RBRACK) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()?;
        let elements = self.commit(mark);
        Ok(self.fin(Kind::ArrayExpression, at, [elements, NONE, NONE, NONE]))
    }

    /// An object literal (a pattern later, maybe: a shorthand with an
    /// initializer, `{ a = 1 }`, is kept for to_pattern).
    pub(super) fn parse_object_like(&mut self) -> R<NodeId> {
        let at = self.at();
        self.expect_p(P_LBRACE)?;
        let mark = self.scratch.len();
        while !self.is_p(P_RBRACE) {
            self.enter()?;
            let member = self.parse_object_member()?;
            self.scratch.push(member);
            self.depth -= 1;
            if !self.is_p(P_RBRACE) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()?;
        let props = self.commit(mark);
        Ok(self.fin(Kind::ObjectExpression, at, [props, NONE, NONE, NONE]))
    }

    fn parse_object_member(&mut self) -> R<NodeId> {
        let at = self.at();
        if self.is_p(P_ELLIPSIS) {
            self.next()?;
            let arg = self.parse_maybe_assign(false, true)?;
            return Ok(self.fin(Kind::SpreadElement, at, [arg, NONE, NONE, NONE]));
        }
        let mut is_async = false;
        let mut kind = P_INIT;
        if self.tok.t == T::Name && !self.tok.esc && matches!(self.tok.v, W_ASYNC | W_GET | W_SET) {
            let (pk, pv, pnl) = self.peek();
            if (key_kind(pk) || (pk == T::P && (pv == P_LBRACK || pv == P_STAR))) && !(self.tok.v == W_ASYNC && pnl) {
                match self.tok.v {
                    W_ASYNC => is_async = true,
                    W_GET => kind = P_GET,
                    _ => kind = P_SET,
                }
                self.next()?;
            }
        }
        let gen = self.eat_p(P_STAR)?;
        let mut computed = false;
        let key;
        if self.is_p(P_LBRACK) {
            self.next()?;
            key = self.parse_maybe_assign(false, true)?;
            self.expect_p(P_RBRACK)?;
            computed = true;
        } else {
            key = self.parse_property_name()?;
        }
        let ckey = if computed { COMPUTED } else { 0 };
        if self.is_p(P_LPAREN) || self.is_p(P_LT) {
            if self.is_p(P_LT) {
                self.parse_type_params()?;
            }
            let func = match self.parse_method(is_async, gen)? {
                Some(f) => f,
                None => return self.fail(),
            };
            let flags = if kind == P_INIT { METHOD } else { 0 } | ckey;
            return Ok(self.fin_x(Kind::Property, at, kind, flags, [key, func, NONE, NONE]));
        }
        if is_async || gen || kind != P_INIT {
            return self.fail();
        }
        if self.eat_p(P_COLON)? {
            let value = self.parse_maybe_assign(false, true)?;
            return Ok(self.fin_x(Kind::Property, at, P_INIT, ckey, [key, value, NONE, NONE]));
        }
        if computed || self.node(key).kind != Kind::Identifier {
            return self.fail();
        }
        let k = *self.node(key);
        let kat = At { line: k.line, start: k.start };
        let value = self.mk(Kind::Identifier, kat, k.end, 0, 0, [k.f[A as usize], NONE, NONE, NONE]);
        let node = self.fin_x(Kind::Property, at, P_INIT, SHORTHAND, [key, value, NONE, NONE]);
        if self.is_p(P_ASSIGN) {
            self.next()?; // only valid in a pattern
            let cover = self.parse_maybe_assign(false, true)?;
            let pe = self.pe;
            let n = &mut self.tree.nodes[node as usize];
            n.f[C as usize] = cover;
            n.end = pe;
            self.covers.push(node);
        }
        Ok(node)
    }

    // ---------------------------------------------------------------- JSX --

    fn parse_jsx_name(&mut self) -> R<NodeId> {
        let at = self.at();
        if self.tok.t != T::Name {
            return self.fail();
        }
        let mut name = self.mk(Kind::JSXIdentifier, at, self.tok.e, 0, 0, [self.tok.v, NONE, NONE, NONE]);
        self.jsx_tag_next()?;
        if self.is_p(P_COLON) {
            self.jsx_tag_next()?;
            if self.tok.t != T::Name {
                return self.fail();
            }
            let lat = self.at();
            let local = self.mk(Kind::JSXIdentifier, lat, self.tok.e, 0, 0, [self.tok.v, NONE, NONE, NONE]);
            self.jsx_tag_next()?;
            return Ok(self.fin(Kind::JSXNamespacedName, at, [name, local, NONE, NONE]));
        }
        while self.is_p(P_DOT) {
            self.jsx_tag_next()?;
            if self.tok.t != T::Name {
                return self.fail();
            }
            let pat = self.at();
            let prop = self.mk(Kind::JSXIdentifier, pat, self.tok.e, 0, 0, [self.tok.v, NONE, NONE, NONE]);
            self.jsx_tag_next()?;
            name = self.fin(Kind::JSXMemberExpression, at, [name, prop, NONE, NONE]);
        }
        Ok(name)
    }

    /// After an element's final `>`: the next token for where it was read
    /// (a regular token after an expression, a tag token after an attribute
    /// value, nothing for a child: its parent reads on).
    fn jsx_end(&mut self, place: Where) -> R<()> {
        match place {
            Where::Expr => self.next(),
            Where::Attr => self.jsx_tag_next(),
            Where::Child => Ok(()),
        }
    }

    /// An element or a fragment; the current token is the first one after
    /// its `<`, read in a tag.
    fn parse_jsx_element(&mut self, at: At, place: Where) -> R<NodeId> {
        if self.is_p(P_GT) {
            let children = self.parse_jsx_children()?;
            self.jsx_tag_next()?;
            if !self.is_p(P_GT) {
                return self.fail();
            }
            let end = self.tok.e;
            self.jsx_end(place)?;
            return Ok(self.mk(Kind::JSXFragment, at, end, 0, 0, [children, NONE, NONE, NONE]));
        }
        let name = self.parse_jsx_name()?;
        if self.ts && self.is_p(P_LT) {
            // a component's type arguments, read with the regular scanner
            self.next()?;
            let mut depth = 1;
            loop {
                if self.tok.t == T::Eof {
                    return self.fail();
                }
                if self.is_p(P_LT) {
                    depth += 1;
                } else if self.is_p(P_GT) {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                self.next()?;
            }
            self.jsx_tag_next()?;
        }
        let mark = self.scratch.len();
        while !(self.is_p(P_GT) || self.is_p(P_SLASH)) {
            let aat = self.at();
            if self.is_p(P_LBRACE) {
                self.next()?;
                self.expect_p(P_ELLIPSIS)?;
                let arg = self.parse_maybe_assign(false, true)?;
                if !self.is_p(P_RBRACE) {
                    return self.fail();
                }
                self.jsx_tag_next()?;
                let spread = self.fin(Kind::JSXSpreadAttribute, aat, [arg, NONE, NONE, NONE]);
                self.scratch.push(spread);
                continue;
            }
            if self.tok.t != T::Name {
                return self.fail();
            }
            let mut aname = self.mk(Kind::JSXIdentifier, aat, self.tok.e, 0, 0, [self.tok.v, NONE, NONE, NONE]);
            self.jsx_tag_next()?;
            if self.is_p(P_COLON) {
                self.jsx_tag_next()?;
                if self.tok.t != T::Name {
                    return self.fail();
                }
                let lat = self.at();
                let local = self.mk(Kind::JSXIdentifier, lat, self.tok.e, 0, 0, [self.tok.v, NONE, NONE, NONE]);
                aname = self.mk(Kind::JSXNamespacedName, aat, self.tok.e, 0, 0, [aname, local, NONE, NONE]);
                self.jsx_tag_next()?;
            }
            let mut value = NONE;
            if self.is_p(P_ASSIGN) {
                self.jsx_tag_next()?;
                let vat = self.at();
                if self.tok.t == T::Str {
                    value = self.mk(Kind::Literal, vat, self.tok.e, L_STRING, 0, [self.tok.v, NONE, NONE, NONE]);
                    self.jsx_tag_next()?;
                } else if self.is_p(P_LBRACE) {
                    self.next()?;
                    let expr = self.parse_maybe_assign(false, true)?;
                    if !self.is_p(P_RBRACE) {
                        return self.fail();
                    }
                    value = self.mk(Kind::JSXExpressionContainer, vat, self.tok.e, 0, 0, [expr, NONE, NONE, NONE]);
                    self.jsx_tag_next()?;
                } else if self.is_p(P_LT) {
                    self.enter()?;
                    self.jsx_tag_next()?;
                    value = self.parse_jsx_element(vat, Where::Attr)?;
                    self.depth -= 1;
                } else {
                    return self.fail();
                }
            }
            let attr = self.fin(Kind::JSXAttribute, aat, [aname, value, NONE, NONE]);
            self.scratch.push(attr);
        }
        let attrs = self.commit(mark);
        if self.is_p(P_SLASH) {
            self.jsx_tag_next()?;
            if !self.is_p(P_GT) {
                return self.fail();
            }
            let end = self.tok.e;
            let opening = self.mk(Kind::JSXOpeningElement, at, end, 0, SELF_CLOSING, [name, attrs, NONE, NONE]);
            self.jsx_end(place)?;
            return Ok(self.mk(Kind::JSXElement, at, end, 0, 0, [opening, NONE, 0, NONE]));
        }
        let opening = self.mk(Kind::JSXOpeningElement, at, self.tok.e, 0, 0, [name, attrs, NONE, NONE]);
        let children = self.parse_jsx_children()?;
        let cat = self.closer;
        self.jsx_tag_next()?;
        if self.is_p(P_GT) {
            return self.fail_msg("unexpected closing fragment");
        }
        let cname = self.parse_jsx_name()?;
        if !self.is_p(P_GT) {
            return self.fail();
        }
        if !self.same_jsx_name(cname, name)? {
            return self.fail_msg("mismatched closing tag");
        }
        let end = self.tok.e;
        let closing = self.mk(Kind::JSXClosingElement, cat, end, 0, 0, [cname, NONE, NONE, NONE]);
        self.jsx_end(place)?;
        Ok(self.mk(Kind::JSXElement, at, end, 0, 0, [opening, closing, children, NONE]))
    }

    /// `_jsx_name_text(cname) != _jsx_name_text(name)`, negated: built
    /// without recursion, but failing where jsparse.py's recursion does.
    fn same_jsx_name(&mut self, cname: NodeId, name: NodeId) -> R<bool> {
        let a = self.jsx_name_text(cname)?;
        let b = self.jsx_name_text(name)?;
        Ok(a == b)
    }

    fn jsx_name_text(&mut self, node: NodeId) -> R<Vec<u32>> {
        // the member chain, outermost first
        let mut chain = Vec::new();
        let mut cur = node;
        while self.node(cur).kind == Kind::JSXMemberExpression {
            chain.push(cur);
            cur = self.node(cur).f[A as usize];
        }
        if chain.len() as u32 >= PY_CHAIN_LIMIT {
            return self.fatal(Fatal::Recursion);
        }
        let n = *self.node(cur);
        let mut out: Vec<u32> = Vec::new();
        if n.kind == Kind::JSXNamespacedName {
            out.extend_from_slice(self.tree.str(self.node(n.f[A as usize]).f[A as usize]));
            out.push(':' as u32);
            out.extend_from_slice(self.tree.str(self.node(n.f[B as usize]).f[A as usize]));
        } else {
            out.extend_from_slice(self.tree.str(n.f[A as usize]));
        }
        for &m in chain.iter().rev() {
            out.push('.' as u32);
            let prop = self.node(m).f[B as usize];
            out.extend_from_slice(self.tree.str(self.node(prop).f[A as usize]));
        }
        Ok(out)
    }

    /// Children up to the `</` that closes them: the current token is the
    /// `>` of the opening tag; on return it is the `/` after the closer's
    /// `<` (self.closer: the `<`'s place).
    fn parse_jsx_children(&mut self) -> R<u32> {
        let mark = self.scratch.len();
        loop {
            self.jsx_text_next();
            if self.tok.t == T::Eof {
                return self.fail_msg("unterminated JSX contents");
            }
            if self.tok.t == T::JsxText {
                let at = self.at();
                let text = self.mk(Kind::JSXText, at, self.tok.e, 0, 0, [self.tok.v, NONE, NONE, NONE]);
                self.scratch.push(text);
                continue;
            }
            if self.tok.v == P_LBRACE {
                let cat = self.at();
                let after_brace = self.tok.e;
                self.next()?;
                if self.is_p(P_RBRACE) {
                    let empty_at = At { line: cat.line, start: after_brace };
                    let empty = self.mk(Kind::JSXEmptyExpression, empty_at, self.tok.s, 0, 0, [NONE; 4]);
                    let c = self.mk(Kind::JSXExpressionContainer, cat, self.tok.e, 0, 0, [empty, NONE, NONE, NONE]);
                    self.scratch.push(c);
                } else if self.is_p(P_ELLIPSIS) {
                    self.next()?;
                    let expr = self.parse_expression(false)?;
                    if !self.is_p(P_RBRACE) {
                        return self.fail();
                    }
                    let c = self.mk(Kind::JSXSpreadChild, cat, self.tok.e, 0, 0, [expr, NONE, NONE, NONE]);
                    self.scratch.push(c);
                } else {
                    let expr = self.parse_expression(false)?;
                    if !self.is_p(P_RBRACE) {
                        return self.fail();
                    }
                    let c = self.mk(Kind::JSXExpressionContainer, cat, self.tok.e, 0, 0, [expr, NONE, NONE, NONE]);
                    self.scratch.push(c);
                }
                continue;
            }
            let lt = self.at(); // `<`
            self.jsx_tag_next()?;
            if self.is_p(P_SLASH) {
                self.closer = lt;
                return Ok(self.commit(mark));
            }
            self.enter()?;
            let child = self.parse_jsx_element(lt, Where::Child)?;
            self.scratch.push(child);
            self.depth -= 1;
        }
    }
}

/// Where a JSX element was read: what jsx_end reads after it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Where {
    Expr,
    Attr,
    Child,
}
