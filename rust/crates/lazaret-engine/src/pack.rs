//! The rule pack: every pattern, name set, table and limit the engine reads,
//! as data (rules/lazaret-rules.json, extracted from lazaret.scanner.core by
//! scripts/make_rust_tables.py).
//!
//! The engine embeds the pack it was built with, and a binding may install
//! another at run time (the Python package hands over core's live values, so
//! the patterns that run are core's own even if the embedded copy were
//! stale). Values keep core's names; a pattern is compiled on first use, by
//! pyre, from its text and flags, and kept.

use crate::json::{self, Value};
use crate::pyre::{self, Regex};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

/// The pack this engine was built with.
pub const EMBEDDED: &str = include_str!("../rules/lazaret-rules.json");

pub struct Pack {
    pub rule_set: Option<String>,
    entries: HashMap<String, Entry>,
}

struct Entry {
    raw: Value,
    re: OnceLock<Result<Regex, String>>,
    res: OnceLock<Vec<Regex>>,
    strs: OnceLock<Vec<Vec<u32>>>,
    needles: OnceLock<crate::pystr::Needles>,
    map_strs: OnceLock<Vec<(Vec<u32>, Vec<Vec<u32>>)>>,
    items_re: OnceLock<Vec<(Value, Regex)>>,
}

fn compile_entry(v: &Value) -> Result<Regex, String> {
    let src = v.get("re").and_then(|s| s.as_str()).ok_or("not a pattern")?;
    let flags = v.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
    Regex::new(src, pyre::flags_from_letters(&flags)).map_err(|e| e.0)
}

fn strings_of(v: &Value) -> Vec<Vec<u32>> {
    let items = v.get("set").or_else(|| v.get("list")).and_then(|x| x.as_arr()).unwrap_or(&[]);
    items
        .iter()
        .filter_map(|x| x.as_str().map(|s| s.to_vec()).or_else(|| x.get("value").and_then(|y| y.as_str()).map(|s| s.to_vec())))
        .collect()
}

impl Pack {
    pub fn from_json(text: &str) -> Result<Pack, String> {
        let root = json::parse_str(text).map_err(|e| e.0)?;
        let rule_set = root.get("rule_set").and_then(|v| v.as_string());
        let values = root.get("values").and_then(|v| v.as_obj()).ok_or("no values")?;
        let mut entries = HashMap::with_capacity(values.len());
        for (k, v) in values {
            entries.insert(
                crate::pystr::to_string(k),
                Entry {
                    raw: v.clone(),
                    re: OnceLock::new(),
                    res: OnceLock::new(),
                    strs: OnceLock::new(),
                    needles: OnceLock::new(),
                    map_strs: OnceLock::new(),
                    items_re: OnceLock::new(),
                },
            );
        }
        Ok(Pack { rule_set, entries })
    }

    fn entry(&self, name: &str) -> &Entry {
        match self.entries.get(name) {
            Some(e) => e,
            None => panic!("the rule pack has no value {}", name),
        }
    }

    pub fn has(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub fn raw(&self, name: &str) -> Option<&Value> {
        self.entries.get(name).map(|e| &e.raw)
    }

    /// A compiled pattern.
    pub fn re(&self, name: &str) -> &Regex {
        let e = self.entry(name);
        match e.re.get_or_init(|| compile_entry(&e.raw)) {
            Ok(rx) => rx,
            Err(msg) => panic!("pattern {} does not compile: {}", name, msg),
        }
    }

    /// A list of compiled patterns ((exact, candidate) pairs, per-language tables …).
    pub fn res(&self, name: &str) -> &[Regex] {
        let e = self.entry(name);
        e.res.get_or_init(|| {
            e.raw
                .get("list")
                .and_then(|l| l.as_arr())
                .unwrap_or(&[])
                .iter()
                .map(|v| compile_entry(v).unwrap_or_else(|m| panic!("pattern in {} does not compile: {}", name, m)))
                .collect()
        })
    }

    /// An (exact, candidate) pattern pair.
    pub fn pair(&self, name: &str) -> (&Regex, &Regex) {
        let r = self.res(name);
        (&r[0], &r[1])
    }

    /// A set or list of strings (a set sorted, as the pack writes it).
    pub fn strs(&self, name: &str) -> &[Vec<u32>] {
        let e = self.entry(name);
        e.strs.get_or_init(|| strings_of(&e.raw))
    }

    /// A set or list of strings, to look for all at once.
    pub fn needles(&self, name: &str) -> &crate::pystr::Needles {
        let e = self.entry(name);
        e.needles.get_or_init(|| crate::pystr::Needles::new(self.strs(name)))
    }

    /// A string value (pattern text core composes, a message …).
    pub fn text(&self, name: &str) -> Vec<u32> {
        self.entry(name).raw.get("value").and_then(|v| v.as_str()).map(|s| s.to_vec()).unwrap_or_default()
    }

    pub fn string(&self, name: &str) -> String {
        crate::pystr::to_string(&self.text(name))
    }

    /// An integer limit.
    pub fn int(&self, name: &str) -> i64 {
        match self.entry(name).raw.get("value").and_then(|v| v.as_i64()) {
            Some(i) => i,
            None => panic!("{} is not an integer", name),
        }
    }

    pub fn usize(&self, name: &str) -> usize {
        self.int(name).max(0) as usize
    }

    /// A map of strings to string sets ({"env": {"-u", …}, …}).
    pub fn map_strs(&self, name: &str) -> &[(Vec<u32>, Vec<Vec<u32>>)] {
        let e = self.entry(name);
        e.map_strs.get_or_init(|| {
            e.raw
                .get("map")
                .and_then(|m| m.as_obj())
                .unwrap_or(&[])
                .iter()
                .map(|(k, v)| {
                    let vals = if let Some(s) = v.get("value").and_then(|x| x.as_str()) {
                        vec![s.to_vec()]
                    } else {
                        strings_of(v)
                    };
                    (k.clone(), vals)
                })
                .collect()
        })
    }

    /// A table of patterns keyed by other than strings (core's dicts keyed by
    /// None or tuples, the pack's {"items": [[key, pattern], …]}): the pattern
    /// for `key` (a JSON value: a string, null, or a list of strings).
    pub fn item_re(&self, name: &str, key: &Value) -> &Regex {
        let e = self.entry(name);
        let items = e.items_re.get_or_init(|| {
            e.raw
                .get("items")
                .and_then(|l| l.as_arr())
                .unwrap_or(&[])
                .iter()
                .filter_map(|kv| {
                    let kv = kv.as_arr()?;
                    let rx = compile_entry(kv.get(1)?).ok()?;
                    Some((kv.first()?.clone(), rx))
                })
                .collect()
        });
        match items.iter().find(|(k, _)| k == key) {
            Some((_, rx)) => rx,
            None => panic!("{} has no pattern for {:?}", name, key),
        }
    }

    /// A map of strings to patterns (core's dicts of compiled patterns).
    pub fn map_re(&self, name: &str, key: &str) -> &Regex {
        self.item_re_map(name, key)
    }

    fn item_re_map(&self, name: &str, key: &str) -> &Regex {
        let e = self.entry(name);
        let items = e.items_re.get_or_init(|| {
            e.raw
                .get("map")
                .and_then(|m| m.as_obj())
                .unwrap_or(&[])
                .iter()
                .filter_map(|(k, v)| Some((Value::Str(k.clone()), compile_entry(v).ok()?)))
                .collect()
        });
        let k = Value::str(key);
        match items.iter().find(|(kk, _)| *kk == k) {
            Some((_, rx)) => rx,
            None => panic!("{} has no pattern for {}", name, key),
        }
    }

    /// Names of every value (for the pack's own tests).
    pub fn names(&self) -> Vec<&str> {
        let mut n: Vec<&str> = self.entries.keys().map(|s| s.as_str()).collect();
        n.sort_unstable();
        n
    }
}

fn slot() -> &'static RwLock<Option<Arc<Pack>>> {
    static CURRENT: OnceLock<RwLock<Option<Arc<Pack>>>> = OnceLock::new();
    CURRENT.get_or_init(|| RwLock::new(None))
}

/// The pack in use: one installed at run time, else the embedded one.
pub fn current() -> Arc<Pack> {
    if let Ok(g) = slot().read() {
        if let Some(p) = g.as_ref() {
            return p.clone();
        }
    }
    let pack = Arc::new(Pack::from_json(EMBEDDED).unwrap_or_else(|e| panic!("embedded rule pack: {}", e)));
    if let Ok(mut g) = slot().write() {
        if g.is_none() {
            *g = Some(pack.clone());
        } else if let Some(p) = g.as_ref() {
            return p.clone();
        }
    }
    pack
}

/// Install a pack (JSON text) for the calls that follow.
pub fn install(text: &str) -> Result<(), String> {
    let pack = Arc::new(Pack::from_json(text)?);
    match slot().write() {
        Ok(mut g) => {
            *g = Some(pack);
            Ok(())
        }
        Err(_) => Err("rule pack lock poisoned".into()),
    }
}

/// Back to the embedded pack.
pub fn reset() {
    if let Ok(mut g) = slot().write() {
        *g = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_pack_compiles_every_pattern() {
        let p = Pack::from_json(EMBEDDED).unwrap();
        let mut n = 0;
        for name in p.names() {
            let raw = p.raw(name).unwrap();
            if raw.get("re").is_some() {
                let _ = p.re(name);
                n += 1;
            } else if let Some(items) = raw.get("list").and_then(|l| l.as_arr()) {
                if items.iter().all(|x| x.get("re").is_some()) && !items.is_empty() {
                    n += p.res(name).len();
                }
            }
        }
        assert!(n > 280, "{} patterns", n);
        assert_eq!(p.usize("HOOK_MAX_CHARS"), 100_000);
        assert!(p.strs("_HOOK_WRAPPERS").iter().any(|s| *s == crate::pystr::u("env")));
    }
}
