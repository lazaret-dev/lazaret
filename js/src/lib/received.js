// Code that runs what it receives over the network — twin of
// lazaret.scanner.core's runs_received_code (see the section comment there:
// what it follows, what counts, the bounds). The patterns are core's text,
// compiled with Python `re` semantics by pyRe; offsets and lengths are
// counted in code points where core's are (a row's length, the characters
// of a call's arguments and of an argument's value read, the look-back on a
// minified row), so the answer is core's for every text. A leaf module:
// lib/hooks.js uses it.

import { readFileSync } from "node:fs";
import { pyRe, pyStrip, pyLstrip, cpLen, isPySpace, isWordChar } from "./pycompat.js";

// The received-code detector's shared data (name sets, character sets, limits,
// and the patterns) is authored once in the Python package's received_spec.json
// and synced here to received-spec.json by scripts/sync-received-spec.py; both
// engines load and compile it, so a needle, limit or pattern is edited in one place.
const DL_SPEC = JSON.parse(readFileSync(new URL("./received-spec.json", import.meta.url), "utf8"));
const DL_SPEC_ARRAYS = DL_SPEC.arrays, DL_SPEC_CHARS = DL_SPEC.charstrings, DL_SPEC_LIMITS = DL_SPEC.limits;

/** pyRe for core's pattern text, whose named groups are Python's (?P<name>…). */
const pyReNamed = (src, flags = "") => pyRe(src.replaceAll("(?P<", "(?<"), flags);

/**
 * [exact, candidate] regexes (sticky, and global) from [assertion, body]
 * alternatives: the candidate leaves the leading assertions out (core's
 * _dl_alternatives), and an exact match starts where a candidate one does.
 */
function alternatives(pairs, tail = "") {
  const exactSrc = pairs.map(([a, b]) => a + b).join("|");
  const candSrc = pairs.map(([, b]) => b).join("|");
  const exact = tail ? `(?:${exactSrc})${tail}` : exactSrc;
  const cand = tail ? `(?:${candSrc})${tail}` : candSrc;
  return { exactSrc: exact, candSrc: cand, exact: pyRe(exact, "y"), cand: pyRe(cand, "g") };
}

/** The UTF-16 index after the code point that starts at index i. */
const nextCp = (s, i) => {
  const c = s.charCodeAt(i);
  return c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? i + 2 : i + 1;
};

/**
 * The exact regex's matches in `row` that start in [pos, endpos), as
 * finditer gives them, found through the candidate regex (whose match must
 * end by endpos: Python's endpos is the end of the string). core._dl_finditer.
 * The candidate is searched in row[pos:endpos] (it has no look-behind), the
 * exact one at the candidate's start in the row.
 */
function* finditer(pair, row, pos = 0, endpos = null) {
  const whole = endpos === null && pos === 0;
  const base = whole ? 0 : pos;
  const text = whole ? row : row.slice(pos, endpos === null ? row.length : endpos);
  let p = pos;
  for (;;) {
    pair.cand.lastIndex = p - base;
    const m = pair.cand.exec(text);
    if (m === null) return;
    const at = m.index + base;
    pair.exact.lastIndex = at;
    const e = pair.exact.exec(row);
    if (e === null) { p = nextCp(row, at); continue; }
    yield e;
    const end = e.index + e[0].length;
    p = end > e.index ? end : nextCp(row, e.index);
  }
}

const firstMatch = (pair, row) => { for (const m of finditer(pair, row)) return m; return null; };

/** The UTF-16 index `n` code points after index i (at most the end). */
function cpForward(s, i, n) {
  for (let k = 0; k < n && i < s.length; k++) i = nextCp(s, i);
  return i;
}

/** The UTF-16 index `n` code points before index i (at least 0). */
export function cpBack(s, i, n) {
  for (let k = 0; k < n && i > 0; k++) {
    const c = s.charCodeAt(i - 1);
    i -= c >= 0xdc00 && c <= 0xdfff && i >= 2 && (s.charCodeAt(i - 2) & 0xfc00) === 0xd800 ? 2 : 1;
  }
  return i;
}

/** len(s) > n, in code points, without counting a short string. */
const longer = (s, n) => s.length > n && (s.length > 2 * n || cpLen(s) > n);

/** Python's str.split() (no argument): runs of whitespace, no empty strings. */
function pySplit(s) {
  const out = [];
  let word = "";
  for (const ch of s) {
    if (isPySpace(ch)) { if (word) out.push(word); word = ""; } else word += ch;
  }
  if (word) out.push(word);
  return out;
}

/** bisect.bisect_left over a sorted array of numbers. */
function bisectLeft(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] < x) lo = mid + 1; else hi = mid; }
  return lo;
}

/** bisect.bisect_right over a sorted array of numbers. */
function bisectRight(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] <= x) lo = mid + 1; else hi = mid; }
  return lo;
}

/** Is one of the sorted offsets in [lo, hi)? core._dl_any. */
function anyIn(offsets, lo, hi) {
  const i = bisectLeft(offsets, lo);
  return i < offsets.length && offsets[i] < hi;
}

/** Is one of the spans (sorted, not overlapping) inside [lo, hi)? core._dl_within. */
function within(starts, ends, lo, hi) {
  const i = bisectLeft(starts, lo);
  return i < starts.length && ends[i] <= hi;
}

const BT = "`";
const DL_SPEC_PATTERNS = DL_SPEC.patterns, DL_SPEC_ALTS = DL_SPEC.alternatives;

/** A plain received-code pattern, compiled from the spec. core._dl_re. */
function dlRe(name, flags = "") {
  const p = DL_SPEC_PATTERNS[name];
  return pyRe(p.src, flags + p.flags);
}
/** ...whose named groups are Python's (?P<name>…). core._dl_re with named groups. */
function dlReNamed(name, flags = "") {
  const p = DL_SPEC_PATTERNS[name];
  return pyReNamed(p.src, flags + p.flags);
}
/** An (exact, candidate) alternative group built from the spec; `extends`
 * prepends another group's pairs. core._dl_group. */
function dlGroup(name) {
  const g = DL_SPEC_ALTS[name];
  const base = g.extends ? DL_SPEC_ALTS[g.extends].pairs : [];
  return alternatives([...base, ...g.pairs], g.tail ?? "");
}

const DL_SOURCE = dlGroup("_DL_SOURCE");            // a value received over the network
const DL_SOURCE_RE = pyRe(DL_SOURCE.exactSrc, "g");
export const DL_NEEDLES = DL_SPEC_ARRAYS._DL_NEEDLES;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
const DL_NEEDLE_RE = new RegExp([...DL_NEEDLES]
  .sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0)).map(escapeRe).join("|"), "gu");
export const DL_RUN_NEEDLES = DL_SPEC_ARRAYS._DL_RUN_NEEDLES;
export const DL_DESERIAL_NEEDLES = DL_SPEC_ARRAYS._DL_DESERIAL_NEEDLES;
export const DL_IMPORT_NEEDLES = DL_SPEC_ARRAYS._DL_IMPORT_NEEDLES;
export const DL_SINK_NEEDLES = [...DL_RUN_NEEDLES, ...DL_DESERIAL_NEEDLES, ...DL_IMPORT_NEEDLES];
const DL_MODULE_VALUE_RE = dlRe("_DL_MODULE_VALUE_RE", "y");
const DL_FUNCTION_VALUE_RE = dlRe("_DL_FUNCTION_VALUE_RE", "y");
const DL_IMPORT_RE = dlReNamed("_DL_IMPORT_RE", "g");
export const DL_PY_NET_MODULES = DL_SPEC_ARRAYS._DL_PY_NET_MODULES;
const DL_PY_NET_MODULE_SET = new Set(DL_PY_NET_MODULES);
export const DL_LIMITS = { _DL_LONG_ROW: DL_SPEC_LIMITS._DL_LONG_ROW, _DL_WINDOW: DL_SPEC_LIMITS._DL_WINDOW,
  _DL_ARG_SPAN: DL_SPEC_LIMITS._DL_ARG_SPAN, _DL_LOOKBACK: DL_SPEC_LIMITS._DL_LOOKBACK,
  _DL_NAMED_SEARCHES: DL_SPEC_LIMITS._DL_NAMED_SEARCHES, _DL_PHASES: DL_SPEC_LIMITS._DL_PHASES };
const { _DL_LONG_ROW: LONG_ROW, _DL_WINDOW: WINDOW, _DL_ARG_SPAN: ARG_SPAN, _DL_LOOKBACK: LOOKBACK,
  _DL_NAMED_SEARCHES: NAMED_SEARCHES, _DL_PHASES: PHASES } = DL_LIMITS;
const DL_CHAIN_RE = dlRe("_DL_CHAIN_RE", "g");
const DL_HEAD_RE = dlRe("_DL_HEAD_RE", "g");
const DL_WORD_RUN_RE = dlRe("_DL_WORD_RUN_RE", "g");
const DL_WORD_RUN_WHOLE_RE = pyRe(`^(?:${DL_SPEC_PATTERNS._DL_WORD_RUN_RE.src})$`);
const DL_STR_RE = dlRe("_DL_STR_RE", "g");
const DL_TEMPLATE_HOLE_RE = dlRe("_DL_TEMPLATE_HOLE_RE", "g");
const DL_FSTRING_HOLE_RE = dlRe("_DL_FSTRING_HOLE_RE", "g");
export const DL_PREFIX_CHARS = [...DL_SPEC_CHARS._DL_PREFIX_CHARS];
const PREFIX_CHARS = new Set(DL_PREFIX_CHARS);
const DL_BIND_RE = dlReNamed("_DL_BIND_RE", "g");
const DL_PARAMS_RE = dlReNamed("_DL_PARAMS_RE", "g");
const DL_FN_HEADER_RE = dlReNamed("_DL_FN_HEADER_RE");
const DL_NAME_RE = dlRe("_DL_NAME_RE", "g");
const DL_DEFAULT_RE = dlRe("_DL_DEFAULT_RE", "g");
const DL_DOT_RE = dlRe("_DL_DOT_RE", "g");
export const DL_NOT_NAMES = DL_SPEC_ARRAYS._DL_NOT_NAMES;
const NOT_NAMES = new Set(DL_NOT_NAMES);
const DL_RUNNER = dlGroup("_DL_RUNNER");            // a call that runs its argument as code
const DL_SHELL_TRUE_RE = dlRe("_DL_SHELL_TRUE_RE");
const DL_SHELL_CALL_WHOLE_RE = pyRe(`^(?:${DL_SPEC_PATTERNS._DL_SHELL_CALL_RE.src})$`);
const DL_SHELL_ARG_RE = dlRe("_DL_SHELL_ARG_RE", "g");
const DL_RUNNER_SHELL = dlGroup("_DL_RUNNER_SHELL");   // ...plus run-family calls, when the file has shell=True
const DL_DESERIAL = dlGroup("_DL_DESERIAL");        // a deserializer that runs code embedded in its argument (CWE-502)
const DL_IMPORT_SINK = dlGroup("_DL_IMPORT_SINK");  // a dynamic import of a received specifier
const DL_FROM_IMPORT_RE = dlRe("_DL_FROM_IMPORT_RE");   // a Python from-import line: skip the bare import( sink there
const DL_BARE_IMPORT_WHOLE_RE = pyRe(`^(?:${DL_SPEC_PATTERNS._DL_BARE_IMPORT_RE.src})$`);
const DL_ALIAS_RE = dlReNamed("_DL_ALIAS_RE", "g");    // a runner-alias definition
export const DL_ALIAS_NEEDLES = DL_SPEC_ARRAYS._DL_ALIAS_NEEDLES;
export const DL_ALIAS_MAX = DL_SPEC_LIMITS._DL_ALIAS_MAX;
const DL_FILE_WRITE_RE = dlReNamed("_DL_FILE_WRITE_RE", "g");   // a received value written to a file
export const DL_FILE_WRITE_NEEDLES = DL_SPEC_ARRAYS._DL_FILE_WRITE_NEEDLES;
const DL_PATHRUN_SINK_RE = dlRe("_DL_PATHRUN_SINK_RE", "g");    // the opener of a call that runs a path
export const DL_PATHRUN_NEEDLES = DL_SPEC_ARRAYS._DL_PATHRUN_NEEDLES;
export const DL_DEFINING = DL_SPEC_ARRAYS._DL_DEFINING;
const DL_INTERP = dlGroup("_DL_INTERP");            // an interpreter given inline code as argv
const DL_EMBED_RE = dlRe("_DL_EMBED_RE", "y");      // ...or written into its command line
const DL_LEAD_RE = dlRe("_DL_LEAD_RE", "y");
const DL_CALLEE_RE = dlReNamed("_DL_CALLEE_RE", "y");
export const DL_CALLEE_CHARS = [...DL_SPEC_CHARS._DL_CALLEE_CHARS];
const CALLEE_CHAR_SET = new Set(DL_CALLEE_CHARS);

/** The names an assignment's left side binds (a member chain stays whole). core._dl_lhs_names. */
function lhsNames(lhs) {
  lhs = pyStrip(lhs);
  if (lhs.startsWith("{") || lhs.startsWith("[")) {
    return [...lhs.matchAll(DL_NAME_RE)].map((m) => m[0]).filter((n) => !NOT_NAMES.has(n));
  }
  const out = [];
  for (let part of lhs.split(",")) {
    part = pyStrip(part).replace(DL_DOT_RE, ".");
    if (part && !NOT_NAMES.has(part)) out.push(part);
  }
  return out;
}

/** Is the call at row[i] the name in a definition: def exec(…), function exec(…), async exec(…)? core._dl_defined_here. */
function definedHere(row, i) {
  let j = i;
  while (j > 0 && isPySpace(row[j - 1])) j--;
  if (j === i) return false;
  for (const word of DL_DEFINING) {
    const s = j - word.length;
    if (s >= 0 && row.startsWith(word, s) && (s === 0 || !isWordChar(String.fromCodePoint(row.codePointAt(cpBack(row, s, 1)))))) {
      return true;
    }
  }
  return false;
}

/**
 * The names holding a received value, with the row each was last bound on,
 * the names that carry the network wherever they are used, and their first
 * names (heads). core._DlTaint.
 */
class Taint {
  constructor(always) {
    this.always = new Set(always);
    this.at = new Map();
    this.heads = new Set([...this.always].map((n) => n.split(".")[0]));
  }

  nameLive(name, row) {
    if (this.always.has(name)) return true;
    const t = this.at.get(name);
    return t !== undefined && row - t <= WINDOW;
  }

  live(chain, row) {
    let acc = null;
    for (const part of chain.split(DL_DOT_RE)) {
      acc = acc === null ? part : `${acc}.${part}`;
      if (this.nameLive(acc, row)) return true;
    }
    return false;
  }
}

/** Does the row name one of the heads (as a chain starts)? */
function namesHead(row, heads) {
  if (!heads.size) return false;
  const found = row.match(DL_HEAD_RE);
  return found !== null && found.some((w) => heads.has(w));
}

/** The end of the whitespace, `await`s and parentheses at row[i]. */
function leadEnd(row, i) {
  DL_LEAD_RE.lastIndex = i;
  return i + DL_LEAD_RE.exec(row)[0].length;
}

/**
 * Does the value at row[i] begin with a received value (taint null: sources
 * only), read for ARG_SPAN code points after its lead? core._dl_carried.
 */
function carried(row, i, taint, k) {
  i = leadEnd(row, i);
  const base = cpBack(row, i, 1);                       // (the sources' look-behind reads one before)
  const text = row.slice(base, cpForward(row, i, ARG_SPAN));
  let j = i - base;
  for (let n = 0; n < 4; n++) {
    if (n) {
      DL_LEAD_RE.lastIndex = j;
      j += DL_LEAD_RE.exec(text)[0].length;
    }
    DL_CALLEE_RE.lastIndex = j;
    const m = DL_CALLEE_RE.exec(text);
    if (m === null) return false;
    const end = j + m[0].length;
    DL_SOURCE_RE.lastIndex = j;
    if (DL_SOURCE_RE.exec(end === text.length ? text : text.slice(0, end)) !== null) return true;
    if (taint !== null && taint.live(m.groups.chain, k)) return true;
    if (m.groups.call === undefined) return false;
    j = end;
  }
  return false;
}

/** The member chains of `code` (strings blanked) by the names they start with, as a Map. core._dl_chain_index. */
function chainIndex(code, lo = 0) {
  const by = new Map();
  const add = (name, s) => { const offs = by.get(name); if (offs === undefined) by.set(name, [s]); else offs.push(s); };
  for (const m of code.matchAll(DL_CHAIN_RE)) {
    const c = m[0], s = m.index + lo;
    if (!c.includes(".")) { add(c, s); continue; }
    let acc = null;
    for (const part of c.split(DL_DOT_RE)) {
      acc = acc === null ? part : `${acc}.${part}`;
      add(acc, s);
    }
  }
  return by;
}

/** Insert x into the sorted array a. */
function insort(a, x) {
  a.splice(bisectRight(a, x), 0, x);
}

const OPEN = new Set(["(", "[", "{"]), CLOSE = new Set([")", "]", "}"]);

/**
 * row[lo:hi] read as code: string literals' contents blanked, their spans,
 * and on demand the brackets, sources, chains and interpolating literals.
 * core._DlCode (offsets are UTF-16 indices of the row).
 */
class Code {
  constructor(row, lo, hi) {
    this.row = row; this.lo = lo; this.hi = hi;
    const text = row.slice(lo, hi);
    this.litS = []; this.litE = [];
    let out = "", at = 0;
    for (const m of text.matchAll(DL_STR_RE)) {
      const s = m.index, e = s + m[0].length;
      out += text.slice(at, s + 1) + " ".repeat(e - s - 2);
      at = e - 1;
      this.litS.push(s + lo); this.litE.push(e + lo);
    }
    this.code = out + text.slice(at);
    this.close = null; this.opener = null; this.commas = null;
    this.openParen = new Map(); this.es = new Map(); this.inner = new Map();
    this.by = null; this.liveOffs = []; this.holes = null;
  }

  literalAt(p) {
    const i = bisectRight(this.litS, p) - 1;
    return i >= 0 && this.litS[i] < p && p < this.litE[i] - 1 ? i : -1;
  }

  segmentAt(p) {
    const i = this.literalAt(p);
    if (i < 0) return this;
    let seg = this.inner.get(i);
    if (seg === undefined) {
      seg = new Code(this.row, this.litS[i] + 1, this.litE[i] - 1);
      this.inner.set(i, seg);
    }
    return seg.segmentAt(p);
  }

  brackets(queries = []) {
    if (this.close !== null) return;
    const close = new Map(), opener = new Map(), commas = new Map(), answers = this.openParen;
    const stack = [], parens = [];
    const { code, lo } = this;
    let qi = 0;
    for (let r = 0; r < code.length; r++) {
      const ch = code[r];
      if (ch !== "," && !OPEN.has(ch) && !CLOSE.has(ch)) continue;
      const q = r + lo;
      while (qi < queries.length && queries[qi] <= q) {
        answers.set(queries[qi], parens.length ? parens[parens.length - 1] : null);
        qi++;
      }
      if (ch === ",") {
        if (stack.length) {
          const top = stack[stack.length - 1];
          const list = commas.get(top);
          if (list === undefined) commas.set(top, [q]); else list.push(q);
        }
      } else if (OPEN.has(ch)) {
        stack.push(q);
        if (ch === "(") parens.push(q);
      } else if (stack.length) {
        const o = stack.pop();
        if (parens.length && parens[parens.length - 1] === o) parens.pop();
        close.set(o, q);
        opener.set(q, o);
      }
    }
    for (; qi < queries.length; qi++) answers.set(queries[qi], parens.length ? parens[parens.length - 1] : null);
    this.close = close; this.opener = opener; this.commas = commas;
  }

  exprStart(j) {
    const memo = this.es, { code, lo } = this, n = code.length;
    const path = [];
    let q = j, res;
    for (;;) {
      if (memo.has(q)) { res = memo.get(q); break; }
      path.push(q);
      const r = q - lo;
      if (r === 0) { res = q; break; }
      const ch = code[r - 1];
      if (CALLEE_CHAR_SET.has(ch)) q--;
      else if (ch === ")" || ch === "]") {
        const o = this.opener.get(q - 1);
        if (o === undefined) { res = null; break; }
        q = o;
      } else if ((ch === " " || ch === "\t") && ((r < n && code[r] === ".") || (r >= 2 && code[r - 2] === "."))) q--;
      else { res = q; break; }
    }
    for (const p of path) memo.set(p, res);
    return res;
  }

  index(taint, k) {
    this.by = chainIndex(this.code, this.lo);
    const offs = [];
    for (const [name, list] of this.by) if (taint.nameLive(name, k)) offs.push(...list);
    this.liveOffs = offs.sort((a, b) => a - b);
  }

  bound(name) {
    for (const s of this.by.get(name) ?? []) insort(this.liveOffs, s);
  }

  liveHoles(taint, k) {
    if (this.holes === null) {
      const starts = [], ends = [], row = this.row;
      for (let i = 0; i < this.litS.length; i++) {
        const s = this.litS[i], e = this.litE[i];
        let holes;
        if (row[s] === BT) holes = [...row.slice(s, e).matchAll(DL_TEMPLATE_HOLE_RE)].map((m) => m[1]);
        else {
          let pre = [...row.slice(Math.max(this.lo, cpBack(row, s, 2)), s)];
          while (pre.length && !PREFIX_CHARS.has(pre[0])) pre = pre.slice(1);
          if (!pre.includes("f") && !pre.includes("F")) continue;
          holes = [...row.slice(s, e).matchAll(DL_FSTRING_HOLE_RE)].map((m) => m[1]);
        }
        if (holes.length && [...holes.join(" ").matchAll(DL_CHAIN_RE)].some((c) => taint.live(c[0], k))) {
          starts.push(s); ends.push(e);
        }
      }
      this.holes = [starts, ends];
    }
    return this.holes;
  }
}

/**
 * One row (or a minified row's stretch) as runsReceivedCode reads it: its
 * code, and quotes paired from each runner's "(" for its arguments. core._DlRow.
 */
class Row {
  constructor(reader, k, row, lo, hi, taint, sources, top = true) {
    this.reader = reader; this.k = k; this.row = row; this.taint = taint; this.hi = hi;
    this.top = top ? new Code(row, lo, hi) : null;
    this.phases = top ? [this.top] : [];
    this.srcS = sources.map(([s]) => s);
    this.srcE = sources.map(([, e]) => e);
    this.dirty = false;
    this.indexed = [];
  }

  live(seg) {
    if (seg.by === null) {
      seg.index(this.taint, this.k);
      this.indexed.push(seg);
    }
    return seg.liveOffs;
  }

  bound(name) {
    for (const seg of this.indexed) seg.bound(name);
  }

  phaseAt(o) {
    for (const ph of this.phases) if (ph.lo <= o && o < ph.hi && ph.literalAt(o) < 0) return ph;
    if (this.phases.length - (this.top !== null ? 1 : 0) >= PHASES) return null;
    const ph = new Code(this.row, o, this.hi);
    this.phases.push(ph);
    return ph;
  }

  runs(r, taint) {
    const { row, k } = this;
    if (definedHere(row, r.index)) return false;                           // def exec(…), function exec(…)
    const rEnd = r.index + r[0].length;
    if (DL_SHELL_CALL_WHOLE_RE.test(r[0]) && !this.reader.shellWithin(k, row, rEnd)) return false;
    const o = rEnd - 1;
    if (o >= this.hi) return false;
    const ph = this.phaseAt(o);
    if (ph === null) return false;
    ph.brackets();
    const end = Math.min(ph.hi, cpForward(row, o + 1, ARG_SPAN));
    const c = ph.close.get(o);
    const close = c !== undefined && c < end ? c : null;
    if (close !== null && pyLstrip(row.slice(close + 1, close + 3)).startsWith("{")) return false;   // exec(x) {
    const starts = [o + 1], ends = [];
    for (const x of ph.commas.get(o) ?? []) {
      if (x >= end) break;
      ends.push(x);
      starts.push(x + 1);
    }
    ends.push(close === null ? end : close);
    const { srcS, srcE } = this;
    let live = [], holes = [[], []];
    if (taint !== null && this.dirty) { live = this.live(ph); holes = ph.liveHoles(taint, k); }
    const last = starts.length - 1;
    for (let i = 0; i < starts.length; i++) {
      const s = starts[i];
      const e = close === null && i === last ? Math.min(this.hi, cpForward(row, leadEnd(row, s), ARG_SPAN)) : ends[i];
      if ((anyIn(srcS, s, e) || anyIn(live, s, e)) && carried(row, s, taint, k)) return true;
    }
    const s = starts[0], e = ends[0];
    DL_EMBED_RE.lastIndex = 0;
    if (!DL_EMBED_RE.test(row.slice(s, e))) return false;
    return within(srcS, srcE, s, e) || anyIn(live, s, e) || within(holes[0], holes[1], s, e);
  }
}

/** The rows where a name stands whole ([\w$]+ runs are names). core._DlNamed. */
class Named {
  constructor(text, rows, starts) {
    this.text = text; this.rows = rows; this.starts = starts;
    this.searches = 0; this.index = null;
  }

  find(name) {
    const head = name.split(".")[0];
    if (!DL_WORD_RUN_WHOLE_RE.test(head)) return [];
    if (this.index === null && this.searches < NAMED_SEARCHES) {
      this.searches++;
      const esc = head.replaceAll("$", "\\$");
      const rx = pyRe(esc + String.raw`(?<![\w$]` + esc + String.raw`)(?![\w$])`, "g");
      const out = [], { text, starts } = this;
      rx.lastIndex = 0;
      for (let m = rx.exec(text); m !== null;) {
        const k = bisectRight(starts, m.index) - 1;
        out.push(k);
        if (k + 1 >= starts.length) break;
        rx.lastIndex = starts[k + 1];
        m = rx.exec(text);
      }
      return out;
    }
    if (this.index === null) {
      const index = new Map();
      this.rows.forEach((row, k) => {
        for (const word of new Set(row.match(DL_WORD_RUN_RE) ?? [])) {
          const list = index.get(word);
          if (list === undefined) index.set(word, [k]); else list.push(k);
        }
      });
      this.index = index;
    }
    return this.index.get(head) ?? [];
  }
}

/** The names a network module is imported under, on the rows `near`. core._dl_import_names. */
function importNames(rows, near) {
  const out = new Set();
  for (const k of [...near].sort((a, b) => a - b)) {
    const row = rows[k];
    if (!row.includes("import") || longer(row, LONG_ROW)) continue;
    for (const m of row.matchAll(DL_IMPORT_RE)) {
      const g = m.groups;
      if (g.py !== undefined) {
        for (const item of g.py.split(",")) {
          const parts = pySplit(item);
          if (parts.length && DL_PY_NET_MODULE_SET.has(parts[0])) {
            out.add(parts.length === 3 && parts[1] === "as" ? parts[2] : parts[0]);
          }
        }
        continue;
      }
      const items = g.pyfrom !== undefined ? g.pyfrom : g.esn;
      if (items === undefined) { out.add(g.es); continue; }
      for (const item of items.split(",")) {
        const parts = pySplit(item);
        if (parts.length) out.add(parts.length === 3 && parts[1] === "as" ? parts[2] : parts[0]);
      }
    }
  }
  return out;
}

/**
 * What a row says about the function a `return` below it belongs to: the
 * function's name on a header, "" on a minified row, null otherwise. core._dl_header.
 */
function header(row) {
  if (longer(row, LONG_ROW)) return "";
  const h = DL_FN_HEADER_RE.exec(row);
  return h === null ? null : h.groups.py || h.groups.js || h.groups.var || null;
}

/** The nearest non-blank row above k (in the window), unless minified. core._dl_row_above. */
function rowAbove(rows, k) {
  for (let j = k - 1; j > Math.max(-1, k - WINDOW - 1); j--) {
    if (pyStrip(rows[j])) return longer(rows[j], LONG_ROW) ? null : j;
  }
  return null;
}

/** runsReceivedCode's pass over the rows. core._DlReader. */
class Reader {
  constructor(rows, taint, sources, runners, named, seeds, sinks) {
    this.rows = rows; this.taint = taint; this.sources = sources; this.runners = runners;
    this.named = named; this.seeds = seeds;
    this.sinks = sinks;                                  // extra [category, alternatives] families
    this.aliases = new Map();                            // runner-alias name -> [definition rows]
    this.aliasCall = null;                               // a call of any runner alias, or null
    this.until = -1;
    this.headers = new Map();
    this.lastTop = [-1, null];                          // the row read last, and its code
    this.shellRow = -1; this.shell = [];
  }

  shellWithin(k, row, i) {
    if (this.shellRow !== k) {
      this.shellRow = k;
      this.shell = [...row.matchAll(DL_SHELL_ARG_RE)].map((m) => m.index);
    }
    return anyIn(this.shell, i, cpForward(row, i, ARG_SPAN) + 1);
  }

  shortRow(k, row) {
    const { taint, rows, sources } = this;
    const heads = taint.heads;
    const found = namesHead(row, heads);
    const hot = sources.has(k);
    const above = pyLstrip(row).startsWith(".") ? rowAbove(rows, k) : null;
    if (!(hot || found || (above !== null && (sources.has(above) || namesHead(rows[above], heads))))) return null;
    const srcs = hot ? [...finditer(DL_SOURCE, row)].map((m) => [m.index, m.index + m[0].length]) : [];
    const rd = new Row(this, k, row, 0, row.length, taint, srcs);
    rd.dirty = found;
    const top = rd.top;
    const facts = [];                                   // [kind, lo, hi, match or names, continued, code]
    let semi = -1;
    const bindable = row.includes("=") || row.includes("as") || row.includes("for") || row.includes("return");
    for (const m of bindable ? row.matchAll(DL_BIND_RE) : []) {
      const g = m.groups, seg = top.segmentAt(m.index), mEnd = m.index + m[0].length;
      let kind, lo, hi;
      if (g.ann !== undefined || g.lhs || g.ret !== undefined) {
        lo = mEnd;
        if (semi < lo) { semi = row.indexOf(";", lo); if (semi < 0) semi = row.length; }
        kind = g.ret !== undefined ? "return" : "bind"; hi = semi;
      } else if (g.with) { kind = "with"; lo = 0; hi = m.index; }
      else { kind = "for"; lo = mEnd; hi = row.length; }
      facts.push([kind, lo, hi, m, false, seg]);
    }
    const params = [], queries = new Map();
    const paramable = row.includes("=>") || row.includes("function") || row.includes("lambda");
    for (const m of paramable ? row.matchAll(DL_PARAMS_RE) : []) {
      const g = m.groups;
      const ps = g.fp || g.ap || g.one || g.lp || "";
      const names = [...ps.replace(DL_DEFAULT_RE, "").matchAll(DL_NAME_RE)].map((x) => x[0]).filter((n) => !NOT_NAMES.has(n));
      if (names.length) {
        const seg = top.segmentAt(m.index);
        params.push([m.index, names, seg]);
        const list = queries.get(seg);
        if (list === undefined) queries.set(seg, [m.index]); else list.push(m.index);
      }
    }
    for (const [seg, offsets] of queries) seg.brackets(offsets);
    const first = row.length - pyLstrip(row).length;
    for (const [p, names, seg] of params) {
      const j = seg.openParen.get(p);
      const start = j === null || j === undefined ? null : seg.exprStart(j);
      if (start === null) continue;
      const continued = seg === top && start <= first && first < j && row[first] === ".";
      facts.push(["param", start, j, names, continued, seg]);
    }
    // which facts hold a received value; binding their names can feed the others
    let aboveBy = null, aboveLive = false;
    if (above !== null && facts.some((f) => f[4])) {
      if (sources.has(above)) aboveLive = true;
      else {
        const [j, code] = this.lastTop;
        if (j === above && code.by !== null) aboveBy = code.by;         // (read just now: its chains are indexed)
        else {
          const aRow = rows[above];
          aboveBy = chainIndex(new Code(aRow, 0, aRow.length).code);
        }
        aboveLive = [...aboveBy.keys()].some((n) => taint.nameLive(n, k));
      }
    }
    const added = [];
    let pending = facts;
    for (let pass = 0; pass < 3; pass++) {
      let grew = false;
      const rest = [];
      for (const f of pending) {
        const [, lo, hi, , cont, seg] = f;
        if (!(within(rd.srcS, rd.srcE, lo, hi) || (cont && aboveLive) || (rd.dirty && anyIn(rd.live(seg), lo, hi)))) {
          rest.push(f);
          continue;
        }
        const [names, how] = this.names(f, row, k);
        for (const name of names) {
          if (how === "always") {
            if (taint.always.has(name)) continue;
            taint.always.add(name);
            added.push(name);
          } else if (taint.at.get(name) !== k) {
            taint.at.set(name, k);
            this.until = Math.max(this.until, k + WINDOW);
          } else continue;
          grew = true;
          rd.dirty = true;
          taint.heads.add(name.split(".")[0]);
          rd.bound(name);
          if (aboveBy !== null && aboveBy.has(name)) aboveLive = true;
        }
      }
      pending = rest;
      if (!grew) break;
    }
    for (const name of added) for (const r of this.named.find(name)) if (r > k) this.seeds[r] = 1;
    this.lastTop = [k, top];
    // its runners, with what it binds
    for (const r of finditer(this.runners, row)) if (rd.runs(r, taint)) return "run";
    for (const r of finditer(DL_INTERP, row)) if (carried(row, r.index + r[0].length, taint, k)) return "run";
    const fromImport = this.sinks.length > 0 && DL_FROM_IMPORT_RE.test(row);
    for (const [cat, sink] of this.sinks) {
      for (const r of finditer(sink, row)) {
        if (fromImport && DL_BARE_IMPORT_WHOLE_RE.test(r[0])) continue;   // a Python from-import list
        if (rd.runs(r, taint)) return cat;
      }
    }
    if (this.aliasCall !== null) {                        // a call of a runner alias near its definition
      this.aliasCall.lastIndex = 0;
      for (let r = this.aliasCall.exec(row); r !== null; r = this.aliasCall.exec(row)) {
        if (aliasNear(this.aliases.get(r[1]), k) && rd.runs(r, taint)) return "run";
      }
    }
    return null;
  }

  names(f, row, k) {
    const kind = f[0];
    if (kind === "param") return [f[3], "value"];
    const g = f[3].groups;
    if (kind === "bind") {
      const names = (g.ann !== undefined ? [g.ann] : lhsNames(g.lhs)).filter((n) => !NOT_NAMES.has(n));
      if (names.length === 1 && !names[0].includes(".")) {
        const value = row.slice(f[1], f[2]);
        DL_MODULE_VALUE_RE.lastIndex = 0;
        if (DL_MODULE_VALUE_RE.test(value)) return [names, "always"];
        DL_FUNCTION_VALUE_RE.lastIndex = 0;
        if (cpLen(names[0]) >= 3 && DL_FUNCTION_VALUE_RE.test(value)) return [names, "always"];
      }
      return [names, "value"];
    }
    if (kind === "with") return [[g.with], "value"];
    if (kind === "for") return [lhsNames(g.for), "value"];
    const fn = this.functionAbove(k);                   // return VALUE: the function nearest above carries it
    return [fn && cpLen(fn) >= 3 ? [fn] : [], "always"];
  }

  functionAbove(k) {
    const { headers, rows } = this;
    for (let j = k; j > Math.max(-1, k - WINDOW - 1); j--) {
      let h = headers.get(j);
      if (h === undefined) { h = header(rows[j]); headers.set(j, h); }
      if (h !== null) return h;
    }
    return null;
  }

  longRow(k, row) {
    const stretches = [];
    for (const n of row.matchAll(DL_NEEDLE_RE)) {
      const lo = cpBack(row, n.index, LOOKBACK);
      if (stretches.length && lo <= stretches[stretches.length - 1][1]) stretches[stretches.length - 1][1] = n.index;
      else stretches.push([lo, n.index]);
    }
    const families = [["run", this.runners], ...this.sinks];
    const fromImport = this.sinks.length > 0 && DL_FROM_IMPORT_RE.test(row);
    for (const [lo, hi] of stretches) {
      const end = cpForward(row, hi, 3 * ARG_SPAN);    // a sink's name, its arguments, the last one's value
      const searchEnd = Math.min(end, cpForward(row, hi, ARG_SPAN));
      let rd = null;
      for (const [cat, family] of families) {
        for (const r of finditer(family, row, lo, searchEnd)) {
          if (r.index >= hi) break;
          if (fromImport && cat === "import" && DL_BARE_IMPORT_WHOLE_RE.test(r[0])) continue;
          if (rd === null) {
            rd = new Row(this, k, row, lo, end, null,
              [...finditer(DL_SOURCE, row, lo, end)].map((m) => [m.index, m.index + m[0].length]), false);
          }
          if (rd.runs(r, null)) return cat;
        }
      }
      for (const r of finditer(DL_INTERP, row, lo, searchEnd)) {
        if (r.index >= hi) break;
        if (carried(row, r.index + r[0].length, null, k)) return "run";
      }
    }
    return null;
  }
}

/**
 * Map name -> [definition rows] for names bound to a direct code-runner
 * reference (core._dl_runner_aliases): a call within WINDOW rows below a
 * definition is a runner. Read from rows naming a runner and holding "="; at
 * most DL_ALIAS_MAX names are kept.
 */
function runnerAliases(rows) {
  const defs = new Map();
  for (let k = 0; k < rows.length; k++) {
    const row = rows[k];
    if (!row.includes("=") || longer(row, LONG_ROW) || !DL_ALIAS_NEEDLES.some((nd) => row.includes(nd))) continue;
    DL_ALIAS_RE.lastIndex = 0;
    for (let m = DL_ALIAS_RE.exec(row); m !== null; m = DL_ALIAS_RE.exec(row)) {
      const name = m.groups.alias;
      if (NOT_NAMES.has(name)) continue;
      let d = defs.get(name);
      if (d === undefined) {
        if (defs.size >= DL_ALIAS_MAX) continue;
        d = []; defs.set(name, d);
      }
      d.push(k);
    }
  }
  return defs;
}

/** Is a definition row at or within WINDOW rows above k? core._dl_alias_near. */
function aliasNear(defRows, k) {
  const i = bisectRight(defRows, k) - 1;
  return i >= 0 && k - defRows[i] <= WINDOW;
}

/**
 * [1-based line, category] for the first place code runs, deserializes or
 * imports a value it received over the network, or null. Category is "run",
 * "deserialize" or "import". Twin of lazaret.scanner.core._received_code_kind.
 */
export function receivedCodeKind(text) {
  if (!DL_NEEDLES.some((n) => text.includes(n)) || !DL_SINK_NEEDLES.some((n) => text.includes(n))) return null;
  const rows = text.split("\n");
  const starts = new Array(rows.length);
  for (let k = 0, at = 0; k < rows.length; k++) { starts[k] = at; at += rows[k].length + 1; }
  const near = new Set();                                              // rows holding a network name
  DL_NEEDLE_RE.lastIndex = 0;
  for (let m = DL_NEEDLE_RE.exec(text); m !== null;) {
    const k = bisectRight(starts, m.index) - 1;
    near.add(k);
    if (k + 1 >= starts.length) break;
    DL_NEEDLE_RE.lastIndex = starts[k + 1];
    m = DL_NEEDLE_RE.exec(text);
  }
  DL_NEEDLE_RE.lastIndex = 0;                                         // (matchAll starts from it)
  const taint = new Taint(text.includes("import") ? importNames(rows, near) : []);
  const sources = new Set([...near].filter((k) => longer(rows[k], LONG_ROW) || firstMatch(DL_SOURCE, rows[k]) !== null));
  if (!taint.always.size && !sources.size) return null;
  const named = new Named(text, rows, starts);
  const seeds = new Uint8Array(rows.length);                          // rows where a received value can start
  for (const r of sources) seeds[r] = 1;
  for (const name of taint.always) for (const r of named.find(name)) seeds[r] = 1;
  const aliases = DL_ALIAS_NEEDLES.some((nd) => text.includes(nd)) ? runnerAliases(rows) : new Map();
  let aliasCall = null;
  if (aliases.size) {                                                // a call of a runner alias, near its def, is a runner
    const src = String.raw`(?<![\w$.])(` + [...aliases.keys()].sort().map((n) => n.replaceAll("$", "\\$")).join("|")
      + String.raw`)\s*\(`;
    aliasCall = pyRe(src, "g");
    for (const name of aliases.keys()) for (const r of named.find(name)) seeds[r] = 1;
  }
  const shellOn = text.includes("shell") && DL_SHELL_TRUE_RE.test(text);
  const runners = shellOn ? DL_RUNNER_SHELL : DL_RUNNER;
  const sinks = [];                                                   // the extra sink families this file names
  if (DL_DESERIAL_NEEDLES.some((n) => text.includes(n))) sinks.push(["deserialize", DL_DESERIAL]);
  if (DL_IMPORT_NEEDLES.some((n) => text.includes(n))) sinks.push(["import", DL_IMPORT_SINK]);
  const reader = new Reader(rows, taint, sources, runners, named, seeds, sinks);
  reader.aliases = aliases; reader.aliasCall = aliasCall;
  let k = seeds.indexOf(1);
  if (k < 0) k = rows.length;
  while (k < rows.length) {
    const row = rows[k];
    if (longer(row, LONG_ROW)) {
      const cat = reader.longRow(k, row);
      if (cat) return [k + 1, cat];
    } else {
      if (seeds[k]) reader.until = Math.max(reader.until, k + WINDOW);
      const cat = reader.shortRow(k, row);
      if (cat) return [k + 1, cat];
    }
    let nk = k + 1;
    if (nk > reader.until) {
      nk = seeds.indexOf(1, nk);
      if (nk < 0) nk = rows.length;
    }
    k = nk;
  }
  return null;
}

/**
 * The 1-based line where code runs, deserializes or dynamically imports a
 * value it received over the network, else null. `text` has \n line endings.
 * Twin of lazaret.scanner.core.runs_received_code.
 */
export function runsReceivedCode(text) {
  const res = receivedCodeKind(text);
  return res === null ? null : res[0];
}

/** core._dl_norm_path: quotes and a leading "./" dropped. */
function normPath(tok) {
  if (tok[0] === '"' || tok[0] === "'") {
    tok = tok.slice(1, -1);
    while (tok.startsWith("./")) tok = tok.slice(2);
  }
  return tok;
}

/** The normalized path token a write match names (core._dl_path_token). */
function pathToken(m) {
  const g = m.groups;
  return normPath(g.p1 ?? g.p2 ?? g.p3 ?? g.p4);
}

/** Does the run sink's argument region name the file `path`? core._dl_region_names_path. */
function regionNamesPath(region, path) {
  for (const m of region.matchAll(DL_NAME_RE)) if (m[0] === path) return true;
  for (const m of region.matchAll(DL_STR_RE)) if (normPath(m[0]) === path) return true;
  return false;
}

/** The row in [k, k+WINDOW] that runs the file `path`, else null. core._dl_pathrun_after. */
function pathrunAfter(rows, k, path) {
  const end = Math.min(rows.length, k + WINDOW + 1);
  for (let j = k; j < end; j++) {
    const row = rows[j];
    if (longer(row, LONG_ROW) || !DL_PATHRUN_NEEDLES.some((n) => row.includes(n))) continue;
    DL_PATHRUN_SINK_RE.lastIndex = 0;
    for (let sm = DL_PATHRUN_SINK_RE.exec(row); sm !== null; sm = DL_PATHRUN_SINK_RE.exec(row)) {
      const e = sm.index + sm[0].length;
      if (regionNamesPath(row.slice(e, cpForward(row, e, ARG_SPAN)), path)) return j;
    }
  }
  return null;
}

/**
 * The 1-based line where a received value is written to a file that is then
 * run, else null. MAJOR only. Twin of core._downloads_and_runs_file.
 */
export function downloadsAndRunsFile(text) {
  if (!DL_NEEDLES.some((n) => text.includes(n)) || !DL_FILE_WRITE_NEEDLES.some((n) => text.includes(n))
      || !DL_PATHRUN_NEEDLES.some((n) => text.includes(n))) return null;
  const rows = text.split("\n");
  const src = [];                                                    // rows holding a network source
  for (let k = 0; k < rows.length; k++) {
    if (!longer(rows[k], LONG_ROW) && firstMatch(DL_SOURCE, rows[k]) !== null) src.push(k);
  }
  for (let k = 0; k < rows.length; k++) {
    const row = rows[k];
    if (longer(row, LONG_ROW) || !DL_FILE_WRITE_NEEDLES.some((n) => row.includes(n))) continue;
    const nearSrc = anyIn(src, k - WINDOW, k + WINDOW + 1);
    DL_FILE_WRITE_RE.lastIndex = 0;
    for (let wm = DL_FILE_WRITE_RE.exec(row); wm !== null; wm = DL_FILE_WRITE_RE.exec(row)) {
      if (wm.groups.p4 === undefined && !nearSrc) continue;         // a plain write needs a download near it
      const path = pathToken(wm);
      if (!path) continue;
      const hit = pathrunAfter(rows, k, path);
      if (hit !== null) return hit + 1;
    }
  }
  return null;
}

/**
 * core's pattern text for the received-code twins, built from the shared spec:
 * every plain pattern by name, then each alternative group's exact and candidate
 * forms (core._DL_<group>_RE / _CANDIDATE_RE). The parity test compiles core's
 * regex of the same name and compares .pattern and flags exactly, so the source
 * here is the spec's — the one both engines compile from
 * (tests/architecture/test_js_parity_hooks.py).
 */
const DL_TWIN_FLAGS = (f) => (f.includes("i") ? "i" : "") + (f.includes("m") ? "m" : "");
const DL_TWIN_GROUPS = {
  _DL_SOURCE: DL_SOURCE, _DL_RUNNER: DL_RUNNER, _DL_RUNNER_SHELL: DL_RUNNER_SHELL,
  _DL_DESERIAL: DL_DESERIAL, _DL_IMPORT_SINK: DL_IMPORT_SINK, _DL_INTERP: DL_INTERP,
};
export const RECEIVED_TWINS = (() => {
  const twins = {};
  for (const [name, p] of Object.entries(DL_SPEC_PATTERNS)) twins[name] = [p.src, DL_TWIN_FLAGS(p.flags || "")];
  for (const [name, g] of Object.entries(DL_TWIN_GROUPS)) {
    twins[name + "_RE"] = [g.exactSrc, ""];
    twins[name + "_CANDIDATE_RE"] = [g.candSrc, ""];
  }
  return twins;
})();
