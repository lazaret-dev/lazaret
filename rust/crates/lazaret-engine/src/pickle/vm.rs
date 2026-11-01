//! The pickle reader (FP-MODEL-FILES): a pickle's opcodes read once, front to back, as CPython's unpickler reads
//! them — every protocol, 0 to 5 — on values that stand for what the unpickler would build. Nothing is unpickled,
//! imported or called: what a global would be is its module and name, what a call would return is the call itself.
//! The reader records each global the pickle imports and how the pickle uses it (calls it with REDUCE, OBJ or INST,
//! makes one with NEWOBJ, hands it to another call, keeps it as data), in a [`Book`] that the file's parts share.
//!
//! Bounds: one pass (an opcode is at least a byte, and what an opcode pops was pushed once), a step of the call's work
//! budget per opcode, at most [`MAX_MEMO`] memo entries, [`MAX_STACK`] values on the stack, [`MAX_KEPT`] items kept in
//! all containers (an item past it is read and dropped, its container marked so), [`ITEMS`] items kept in one, and
//! [`MAX_FORKS`] readings of a joblib array's bytes as plain pickle (each at most [`MAX_FORK_OPS`] opcodes). A limit
//! reached is an error: the pickle was not read to its end.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::{Classes, Kind, Model, TextKind};

/// The bytes of a string kept (a longer one keeps its first ones and its length).
pub const KEEP: usize = 4096;
/// The items one container keeps.
pub const ITEMS: usize = 64;
/// The items all containers keep together.
pub const MAX_KEPT: usize = 2_000_000;
pub const MAX_MEMO: usize = 2_000_000;
pub const MAX_STACK: usize = 4_000_000;
/// joblib arrays read again as plain pickle would read their bytes, and the opcodes of each such reading.
pub const MAX_FORKS: usize = 100_000;
pub const MAX_FORK_OPS: u64 = 65_536;
/// The stack a fork copies.
pub const MAX_FORK_STACK: usize = 65_536;
/// The text kept for a finding's message.
pub const SAMPLE: usize = 60;
/// The byte strings handed a loader that one reading queues to read (more: a cut).
pub const MAX_NESTED: usize = 64;
/// The places a reading finds code run that it lists (more: counted, and the count said: Book::code_dropped).
pub const MAX_CODE: usize = 64;

#[derive(Clone)]
pub struct Str {
    pub b: Vec<u8>,
    pub len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SK {
    Tuple,
    List,
    Dict,
    Set,
}

pub struct Seq {
    pub kind: SK,
    pub items: Vec<V>,
    /// items were dropped (past ITEMS or MAX_KEPT, or holding the container itself): what it holds is not all known
    pub dropped: bool,
    /// a dropped item could have given a special method a callable (one past MAX_KEPT): what it does is not known
    pub lost: bool,
}

/// What a call or a NEWOBJ made: the callee, its arguments, the state a BUILD gave it, and what the pickle gave it as
/// the attributes pickle's own opcodes call (none, mostly: kept apart so that an object costs one pointer for it).
pub struct Made {
    pub callee: V,
    pub args: V,
    pub state: RefCell<Option<V>>,
    pub given: RefCell<Option<Box<Given>>>,
}

impl Made {
    pub fn new(callee: V, args: V) -> Made {
        Made { callee, args, state: RefCell::new(None), given: RefCell::new(None) }
    }

    /// Add what a state, a helper's or a SETITEM gave the object (Given).
    fn add_given(&self, g: Given) {
        if g.is_empty() {
            return;
        }
        if let Ok(mut have) = self.given.try_borrow_mut() {
            match have.as_mut() {
                Some(h) => h.merge(g),
                None => *have = Some(Box::new(g)),
            }
        }
    }
}

/// What the pickle gave an object as the attributes pickle's own opcodes look up on it and call (N1 of the re-review
/// of Oct 30): APPEND and APPENDS call its `extend`, or its `append` (C's do_append, pickle.py's load_append and
/// load_appends, and their fallback), ADDITEMS its `add` (load_additems). A BUILD gives them (load_build: its state's
/// dict, and its slots' setattr), and so do the helpers that set an object's attributes from a state (torch's
/// _set_obj_state, types.SimpleNamespace's mapping) and SETITEM on an object whose items may be its attributes. Every
/// one given is kept (a later BUILD may set it again, or not): what APPEND calls is among them. (This object's own
/// record, for what it calls of any kind; a member of the standard library's data enums any object was given is the
/// book's too, AnyGiven, whatever object an APPEND reaches.)
#[derive(Default)]
pub struct Given {
    /// the globals given: (as `add`, rather than `extend` or `append`; the global; it is one of the format's helpers,
    /// a model of its own, whose call depends on its arguments' values), in the order given
    pub globals: Vec<(bool, u32, bool)>,
    /// how many of them are helpers
    helpers: u32,
    /// a state whose names the reader does not see (a mapping the pickle computed or names, a dict past what the
    /// reader keeps, a name the pickle computes given a callable, more globals than ITEMS, a state not looked at once
    /// the record was full or the reading's looks were spent): what it gave is not known
    pub unseen: bool,
    /// unseen for a bound of the reader's (a global past the ITEMS kept, a state not looked at once the record was
    /// full, a dict's or a tuple's items past what the reader keeps, the looks at what objects are given spent): what
    /// it was given may be a function an APPEND, APPENDS or ADDITEMS on the object calls, and that is said
    /// (SC-TRUNCATED; round 5, A2; round 6, A7: a record unseen was not looked at again, and hid one given later)
    pub cut: bool,
    /// an object the pickle computed given as `extend` or `append` [0], or as `add` [1]: what it is (none, mostly)
    computed: Option<Box<[Option<String>; 2]>>,
    /// how many of `globals` an APPEND or APPENDS [0] or an ADDITEMS [1] has called with items of no object, by the
    /// text they hold (TextKind) and how many they are (none, 1, 2, 3, 4 or more: what the format's helpers look at):
    /// a global that is no helper, called with such items again, does nothing new (made when first needed)
    upto: Option<Box<[[[usize; 5]; 4]; 2]>>,
}

impl Given {
    fn is_empty(&self) -> bool {
        self.globals.is_empty() && self.computed.as_ref().is_none_or(|c| c.iter().all(Option::is_none)) && !self.unseen
    }

    /// It holds all the globals it keeps (ITEMS): one more given is unseen.
    fn full(&self) -> bool {
        self.globals.len() >= ITEMS
    }

    /// What a state the reader does not look at, for a bound of its own, gives: unseen, and said at an APPEND (`cut`).
    fn skipped() -> Given {
        Given { unseen: true, cut: true, ..Given::default() }
    }

    /// A container's items past what the reader keeps (Seq::dropped) give what is not known: a function given as
    /// `extend` among them would be called by an APPEND, so that is said there (`cut`; round 6, A7).
    fn past_kept(&mut self, dropped: bool) {
        if dropped {
            self.unseen = true;
            self.cut = true;
        }
    }

    /// A global given, kept unless it is already (looked for among the ITEMS at most kept, one by one: what that costs
    /// `give` charges, and a full record is not looked at again; round 4, a set beside them doubled a record's memory).
    fn add_global(&mut self, (add, g, helper): (bool, u32, bool)) {
        if self.globals.iter().any(|&(a, h, _)| (a, h) == (add, g)) {
            return;
        }
        if self.globals.len() >= ITEMS {
            self.unseen = true;
            self.cut = true;
            return;
        }
        if self.globals.capacity() == 0 {
            self.globals.reserve_exact(1);
        }
        self.globals.push((add, g, helper));
        self.helpers += helper as u32;
    }

    /// An object the pickle computed given as `extend` or `append`, or as `add` (`add`): the first kept.
    fn add_computed(&mut self, add: bool, what: impl FnOnce() -> String) {
        let c = self.computed.get_or_insert_with(Default::default);
        if c[add as usize].is_none() {
            c[add as usize] = Some(what());
        }
    }

    fn merge(&mut self, o: Given) {
        for x in o.globals {
            self.add_global(x);
        }
        if let Some(c) = o.computed {
            for (add, w) in [false, true].into_iter().zip(*c) {
                if let Some(w) = w {
                    self.add_computed(add, || w);
                }
            }
        }
        self.unseen |= o.unseen;
        self.cut |= o.cut;
    }

    /// What an opcode calls: ADDITEMS's `add` (`add`), or APPEND's and APPENDS's `extend` or `append`. With items of no
    /// object (`shape`: the text they hold, how many), the helpers and only the globals given since the last such
    /// call. And whether what it was given is unseen, and unseen for a bound of the reader's (`cut`).
    fn for_op(&mut self, add: bool, shape: Option<(usize, usize)>) -> (Vec<u32>, Option<String>, bool, bool) {
        let from = match shape {
            Some((t, n)) => {
                let len = self.globals.len();
                let upto = self.upto.get_or_insert_with(Default::default);
                std::mem::replace(&mut upto[add as usize][t.min(3)][n.min(4)], len)
            }
            None => 0,
        };
        let globals = if from >= self.globals.len() && self.helpers == 0 {
            Vec::new()
        } else {
            self.globals.iter().enumerate().filter(|(i, (a, _, helper))| *a == add && (*i >= from || *helper))
                .map(|(_, (_, g, _))| *g).collect()
        };
        let computed = self.computed.as_ref().and_then(|c| c[add as usize].clone());
        (globals, computed, self.unseen, self.cut)
    }
}

/// The book's record of what any object may have been given as the attributes APPEND, APPENDS and ADDITEMS call
/// (round 3 of the review of FP-MODEL-FILES-PY311, of Oct 30). A member of the standard library's data enums under the
/// literal name `extend` or `append` [0], or `add` [1], wherever a dict, a SETITEM or a call's arguments write it
/// (whatever the dict ends up as: an object's BUILD state, a slot state's `__dict__`, torch's setattr-style state, a
/// dict installed by reference and filled later, a joblib wrapper's state; `_operator.setitem(d, 'extend', m)`,
/// `dict.update(d, [('extend', m)])`); and, where a dict is or becomes an attribute state (a BUILD's state, its pairs
/// and halves, a helper's state, SETITEM on an object that is no plain mapping, a dict installed by reference: round
/// 4, M1), a member under a key the pickle computes, an object the pickle computed given as one, and a mapping of
/// attributes the reader does not see. Any object an APPEND, APPENDS or ADDITEMS reaches may be the one given it
/// (through a memo entry, getitem((obj,), 0), logging.getLogger('x') twice, an enum's member, joblib's memoised
/// wrapper: aliases the reader does not follow), so each of those members is called there, and the rest passes no
/// member over (Machine::call_any_given).
#[derive(Default)]
pub struct AnyGiven {
    /// the members given, in the order given
    pub members: [Vec<u32>; 2],
    /// how many of them an APPEND, APPENDS or ADDITEMS has called (each is called once: its call is then recorded)
    called: [usize; 2],
    /// an object the pickle computed given as one (what it calls is not followed: it may call a member)
    pub computed: [bool; 2],
    /// attributes the reader does not see: a mapping the pickle computed in place of a state's dict, a slot state's
    /// `__dict__` or a helper's mapping (what is in it is not known), dicts installed by reference past those kept
    pub unseen: bool,
    /// the dicts installed as an object's attributes by reference (a slot or setattr-style state's `__dict__`,
    /// functools.partial's dict, torch's _rebuild_from_type's), kept alive so that their address names them: what a
    /// SETITEM puts in them later is an attribute state's (at most MAX_ATTR_DICTS; past it, unseen)
    attr_dicts: Vec<V>,
    attr_ptrs: HashSet<*const RefCell<Seq>>,
}

/// The dicts installed by reference AnyGiven keeps.
pub const MAX_ATTR_DICTS: usize = 65_536;

// Values are dropped without recursion, however deep the pickle nests them (a list in a list a million times, a call
// of what a call returned a million times): each container hands its values to one loop.
impl Drop for Seq {
    fn drop(&mut self) {
        drain(std::mem::take(&mut self.items));
    }
}

impl Drop for Made {
    fn drop(&mut self) {
        let mut out = vec![std::mem::replace(&mut self.callee, V::Plain), std::mem::replace(&mut self.args, V::Plain)];
        if let Some(s) = self.state.get_mut().take() {
            out.push(s);
        }
        drain(out);
    }
}

fn drain(mut stack: Vec<V>) {
    while let Some(v) = stack.pop() {
        match v {
            V::Seq(rc) => {
                if let Ok(cell) = Rc::try_unwrap(rc) {
                    let mut s = cell.into_inner();
                    stack.append(&mut s.items);
                }
            }
            V::Call(rc) | V::Obj(rc) => {
                if let Ok(mut m) = Rc::try_unwrap(rc) {
                    stack.push(std::mem::replace(&mut m.callee, V::Plain));
                    stack.push(std::mem::replace(&mut m.args, V::Plain));
                    if let Some(s) = m.state.get_mut().take() {
                        stack.push(s);
                    }
                }
            }
            _ => {}
        }
    }
}

/// The values looked at to find whether a value holds the container it is put in.
pub const CYCLE_LOOK: u32 = 64;
/// The containers kept that may close a cycle (their contents let go of when the reading ends).
pub const MAX_SUSPECTS: usize = 1_000_000;

fn ptr(v: &V) -> Option<*const ()> {
    match v {
        V::Seq(s) => Some(Rc::as_ptr(s) as *const ()),
        V::Call(m) | V::Obj(m) => Some(Rc::as_ptr(m) as *const ()),
        _ => None,
    }
}

/// Whether `v` holds (or is) the container at `target`, looking at no more than `budget` values: None when it could
/// not tell.
fn reaches(v: &V, target: *const (), budget: &mut u32) -> Option<bool> {
    if ptr(v) == Some(target) {
        return Some(true);
    }
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    match v {
        V::Seq(s) => {
            let s = s.try_borrow().ok()?;
            for x in &s.items {
                if reaches(x, target, budget)? {
                    return Some(true);
                }
            }
            Some(false)
        }
        V::Call(m) | V::Obj(m) => {
            if reaches(&m.callee, target, budget)? || reaches(&m.args, target, budget)? {
                return Some(true);
            }
            let st = m.state.try_borrow().ok()?;
            match &*st {
                Some(x) => reaches(x, target, budget),
                None => Some(false),
            }
        }
        _ => Some(false),
    }
}

#[derive(Clone)]
pub enum V {
    Num(i64),
    /// an int past i64, a float, None, a bool: no text, no call
    Plain,
    Str(Rc<Str>),
    /// text made by a call (bytes(), bytearray(), _codecs.encode …): its content is not known
    Made_,
    /// a str made by a call (str(), chr()): it may be any name
    MadeStr,
    /// raw bytes: their span in the buffer
    Bytes(usize, usize),
    Global(u32),
    Seq(Rc<RefCell<Seq>>),
    /// the result of REDUCE, OBJ or INST
    Call(Rc<Made>),
    /// the result of NEWOBJ or NEWOBJ_EX
    Obj(Rc<Made>),
    /// a persistent id's object, a buffer, an array joblib read: what it is does not matter
    Opaque,
}

/// Where in the file a use was seen: the part (a zip entry, an array) and the byte in it.
#[derive(Clone, Debug)]
pub struct Hit {
    pub part: usize,
    pub at: usize,
    pub how: &'static str,
    pub text: Option<String>,
    /// the callee or value it names, when it is not the global the hit belongs to
    pub what: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Glob {
    pub module: Vec<u8>,
    pub name: Vec<u8>,
    pub kind: Kind,
    pub model: Model,
    pub first: Hit,
    /// the worst call: its text kind (a reconstructor's call handed its class: no worse than a plain name), and the
    /// call
    pub called: Option<(TextKind, Hit)>,
    pub restored: Option<Hit>,
    /// it is an attribute of a global, getattr(<a GLOBAL>, '<name>') read as that dotted global: getattr again on it
    /// is not read so (a chain stays builtins.getattr's)
    pub attr: bool,
    /// the times the pickles put it on their stack, and the times it was getattr called as getattr(<a GLOBAL>,
    /// '<name>') (builtins.getattr: when every one was, the attributes it named are judged, not getattr)
    pub pushes: u32,
    pub resolved: u32,
    /// an extension code (EXT1, EXT2, EXT4): the global the loading program registered for it with
    /// copyreg.add_extension (none by default), which the file does not name
    pub ext: Option<i64>,
    /// it names a member of the standard library's data enums exactly (Classes::is_member), and a dotted name where
    /// Python walks it (Book::plain_lookup): data unless it is called, made or changed
    pub member: bool,
    /// such a member given as `extend` or `append` (1) or as `add` (2) by some dict or helper (Book::any_given: noted
    /// once)
    pub given_as: u8,
}

/// Bytes the pickle hands a loader (torch.storage._load_from_bytes, pickle.loads …): read as a file of their own.
#[derive(Clone, Debug)]
pub struct Nested {
    pub part: usize,
    pub start: usize,
    pub len: usize,
    pub loader: u32,
    pub at: usize,
}

/// What every pickle of a file did, kept together.
pub struct Book<'c> {
    pub cls: &'c Classes,
    pub globals: Vec<Glob>,
    index: HashMap<(Vec<u8>, Vec<u8>), u32>,
    /// the part being read
    pub part: usize,
    /// shapes that run code whatever the globals: a computed object called, a callable put where BUILD calls it, a
    /// class or function changed, a class made, text naming code handed to a call
    pub code: Vec<(String, Hit)>,
    /// a call of an object the pickle computed (MAJOR unless code runs)
    pub dynamic: Option<Hit>,
    pub nested: Vec<Nested>,
    pub forks: usize,
    /// a fork reached its opcode limit, or there were too many: the plain reading of joblib's arrays was not finished
    pub fork_cut: Option<String>,
    kept: usize,
    /// containers a value was put in that may hold it (keepable): their contents are let go of with the book
    suspects: Vec<V>,
    /// the pickles are a TorchScript archive's (Classes::classify_in)
    pub torchscript: bool,
    /// byte strings handed a loader past MAX_NESTED (not read: a cut)
    pub nested_dropped: usize,
    /// places code runs past MAX_CODE (not listed: their count is said)
    pub code_dropped: usize,
    /// what the looks at states and arguments could not see (SC-TRUNCATED), and the items they went through
    pub state_cut: Option<String>,
    pub state_work: u64,
    /// what BUILD and SETITEM gave the objects the reader cannot tell apart (V::Opaque: a persistent id's, a buffer)
    /// as their extend, append or add, all together
    pub opaque_given: Given,
    /// an APPEND, APPENDS or ADDITEMS that calls an extend, append or add the pickle may have given the object and the
    /// reader does not see (Given::unseen, AnyGiven): no member of the standard library's data enums is passed over as
    /// data
    pub unseen_given: Option<Hit>,
    /// the members of the standard library's data enums, and the rest, any object may have been given as what APPEND,
    /// APPENDS and ADDITEMS call (round 3)
    pub any_given: AnyGiven,
    /// (global, add, text, items) an APPEND, APPENDS or ADDITEMS called a given global that is no helper with, items of
    /// no object: such a call again does nothing new (Given::upto)
    plain_calls: HashSet<(u32, bool, u8, u8)>,
    /// the items the looks at what objects are given, and the calls of what they were given, go through (GIVE_WORK:
    /// their own, apart from `state_work`, so that the reading's other looks reach as far as before: round 4, M2)
    pub give_work: u64,
    /// an APPEND, APPENDS or ADDITEMS whose call of what the object was given was not made, or not known, for a bound
    /// of the reader's (Given::cut; SC-TRUNCATED: round 5, A2, and round 6, A7; said at the APPEND, so a file that only
    /// gives its objects much is whole)
    pub give_cut: Option<String>,
}

impl Drop for Book<'_> {
    fn drop(&mut self) {
        // every cycle the readings made runs through a suspect's contents: let go of them
        for v in self.suspects.drain(..) {
            match &v {
                V::Seq(s) => {
                    if let Ok(mut s) = s.try_borrow_mut() {
                        let items = std::mem::take(&mut s.items);
                        drop(s);
                        drain(items);
                    }
                }
                V::Call(m) | V::Obj(m) => {
                    let st = m.state.try_borrow_mut().ok().and_then(|mut st| st.take());
                    if let Some(st) = st {
                        drain(vec![st]);
                    }
                }
                _ => {}
            }
        }
    }
}

impl<'c> Book<'c> {
    pub fn new(cls: &'c Classes) -> Book<'c> {
        Book { cls, globals: Vec::new(), index: HashMap::new(), part: 0, code: Vec::new(), dynamic: None,
               nested: Vec::new(), forks: 0, fork_cut: None, kept: 0, suspects: Vec::new(), torchscript: false,
               nested_dropped: 0, code_dropped: 0, state_cut: None, state_work: 0, opaque_given: Given::default(),
               unseen_given: None, any_given: AnyGiven::default(), plain_calls: HashSet::new(), give_work: 0,
               give_cut: None }
    }

    /// A global Python looks up with a plain getattr: GLOBAL, INST and STACK_GLOBAL below protocol 4 (find_class's
    /// getattr; protocol 4's _getattribute walks a dotted name) and numpy's _ufunc_reconstruct. A dotted name is no
    /// attribute there: the load stops with AttributeError, and the name is no member's (N3 of the re-review of
    /// Oct 30: GLOBAL 'ssl' 'TLSVersion.TLSv1_2' at protocol 2 was read as the member). Once so, always so.
    pub fn plain_lookup(&mut self, g: u32) {
        if let Some(gl) = self.globals.get_mut(g as usize) {
            if gl.member && gl.name.contains(&b'.') {
                gl.member = false;
            }
        }
    }

    /// The global module.name, entered once (its kind from the pack's tables).
    pub fn intern(&mut self, module: &[u8], name: &[u8], at: usize, how: &'static str) -> u32 {
        if let Some(&g) = self.index.get(&(module.to_vec(), name.to_vec())) {
            return g;
        }
        let (kind, model) = self.cls.classify_in(module, name, self.torchscript);
        let member = self.cls.is_member(module, name);
        let g = self.globals.len() as u32;
        self.globals.push(Glob {
            module: module.to_vec(),
            name: name.to_vec(),
            kind,
            model,
            first: Hit { part: self.part, at, how, text: None, what: None },
            called: None,
            restored: None,
            attr: false,
            pushes: 0,
            resolved: 0,
            ext: None,
            member,
            given_as: 0,
        });
        self.index.insert((module.to_vec(), name.to_vec()), g);
        g
    }

    /// An extension code (M3, the external review of Oct 21): no name of the file's, and no kind but unknown; called
    /// or made, it is SC-PICKLE-GLOBAL, MAJOR, whatever its arguments.
    pub fn intern_ext(&mut self, code: i64, at: usize) -> u32 {
        let key = (b"\0ext".to_vec(), code.to_string().into_bytes());
        if let Some(&g) = self.index.get(&key) {
            return g;
        }
        let g = self.globals.len() as u32;
        self.globals.push(Glob {
            module: Vec::new(),
            name: Vec::new(),
            kind: Kind::Other,
            model: Model::None,
            first: Hit { part: self.part, at, how: "EXT", text: None, what: None },
            called: None,
            restored: None,
            attr: true,
            pushes: 0,
            resolved: 0,
            ext: Some(code),
            member: false,
            given_as: 0,
        });
        self.index.insert(key, g);
        g
    }

    pub fn qual(&self, g: u32) -> String {
        let gl = &self.globals[g as usize];
        if let Some(code) = gl.ext {
            return format!("extension code {code}");
        }
        format!("{}.{}", String::from_utf8_lossy(&gl.module), String::from_utf8_lossy(&gl.name))
    }

    fn keep(&mut self) -> bool {
        if self.kept >= MAX_KEPT {
            return false;
        }
        self.kept += 1;
        true
    }

    fn hit(&self, at: usize, how: &'static str) -> Hit {
        Hit { part: self.part, at, how, text: None, what: None }
    }

    fn code(&mut self, why: String, hit: Hit) {
        if self.code.len() < MAX_CODE {
            self.code.push((why, hit));
        } else {
            self.code_dropped += 1;
        }
    }
}

/// How a reading ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// at STOP; the byte after it
    Stop(usize),
    /// it could not go on: where, and why
    Error(usize, String),
}

/// A byte that is one of the opcodes of protocols 0 to 5.
pub fn is_opcode(b: u8) -> bool {
    matches!(b, b'(' | b'.' | b'0' | b'1' | b'2' | b'F' | b'I' | b'J' | b'K' | b'L' | b'M' | b'N' | b'P' | b'Q' | b'R'
        | b'S' | b'T' | b'U' | b'V' | b'X' | b'a' | b'b' | b'c' | b'd' | b'}' | b'e' | b'g' | b'h' | b'i' | b'j'
        | b'l' | b']' | b'o' | b'p' | b'q' | b'r' | b's' | b't' | b')' | b'u' | b'G' | b'B' | b'C' | 0x80..=0x98)
}

pub struct Machine<'b, 'm> {
    buf: &'b [u8],
    pub pos: usize,
    stack: Vec<V>,
    marks: Vec<usize>,
    memo: HashMap<u32, V>,
    /// a fork's view of the memo of the reading it was forked from
    base: Option<&'m HashMap<u32, V>>,
    /// a joblib array's bytes read as plain pickle reads them: no container is changed (they may be the parent's),
    /// and no array is skipped
    spec: bool,
    /// joblib's reading: a NumpyArrayWrapper's BUILD is followed by its array's bytes
    joblib: bool,
    ops: u64,
    max_ops: u64,
    /// persistent ids are answered (PyTorch's loader); otherwise pickle.load stops at one, and the reader goes on
    pub persistent: bool,
    /// the format's helpers' calls of their arguments followed now (bounded: MAX_DISPATCH)
    dispatch: usize,
    /// the times each global was put on the stack (Glob::pushes, added to the book when the reading ends)
    pushed: HashMap<u32, u32>,
    /// the protocol the last PROTO named (the Unpickler's proto, 0 before one): find_class walks a dotted name only
    /// from 4 on
    proto: u8,
}

/// How deep the format's helpers' calls of their arguments are followed (one handed another, and so on).
pub const MAX_DISPATCH: usize = 16;

type R<T> = Result<T, (usize, String)>;

impl<'b, 'm> Machine<'b, 'm> {
    pub fn new(buf: &'b [u8], pos: usize, joblib: bool) -> Machine<'b, 'm> {
        Machine { buf, pos, stack: Vec::new(), marks: Vec::new(), memo: HashMap::new(), base: None, spec: false,
                  joblib, ops: 0, max_ops: u64::MAX, persistent: true, dispatch: 0, pushed: HashMap::new(), proto: 0 }
    }

    fn err<T>(&self, at: usize, why: impl Into<String>) -> R<T> {
        Err((at, why.into()))
    }

    fn take(&mut self, n: usize, at: usize) -> R<&'b [u8]> {
        self.take64(n as u64, at)
    }

    /// `n` bytes (a length the pickle wrote, compared before it is a usize: the same answer on 32 bits).
    fn take64(&mut self, n: u64, at: usize) -> R<&'b [u8]> {
        if n > (self.buf.len() - self.pos) as u64 {
            return self.err(at, "it ends inside an opcode's argument");
        }
        let e = self.pos + n as usize;
        let s = &self.buf[self.pos..e];
        self.pos = e;
        Ok(s)
    }

    fn u8_(&mut self, at: usize) -> R<u8> {
        Ok(self.take(1, at)?[0])
    }

    fn u16_(&mut self, at: usize) -> R<u16> {
        let s = self.take(2, at)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32_(&mut self, at: usize) -> R<u32> {
        let s = self.take(4, at)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn i32_(&mut self, at: usize) -> R<i32> {
        Ok(self.u32_(at)? as i32)
    }

    fn u64_(&mut self, at: usize) -> R<u64> {
        let s = self.take(8, at)?;
        Ok(u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
    }

    /// A line, without its "\n" (an opcode of protocol 0's argument).
    fn line(&mut self, at: usize) -> R<&'b [u8]> {
        let rest = &self.buf[self.pos..];
        match rest.iter().position(|&c| c == b'\n') {
            Some(k) => {
                self.pos += k + 1;
                Ok(&rest[..k])
            }
            None => self.err(at, "it ends inside a line"),
        }
    }

    fn fence(&self) -> usize {
        self.marks.last().copied().unwrap_or(0)
    }

    fn push(&mut self, v: V, at: usize) -> R<()> {
        if self.stack.len() >= MAX_STACK {
            return self.err(at, format!("more than {MAX_STACK} values on its stack"));
        }
        if let V::Global(g) = &v {
            *self.pushed.entry(*g).or_insert(0) += 1;
        }
        self.stack.push(v);
        Ok(())
    }

    fn pop(&mut self, at: usize) -> R<V> {
        if self.stack.len() <= self.fence() {
            return self.err(at, "an opcode pops more than its stack holds");
        }
        Ok(self.stack.pop().unwrap_or(V::Opaque))
    }

    fn top(&self, at: usize) -> R<V> {
        if self.stack.len() <= self.fence() {
            return self.err(at, "an opcode reads a stack that is empty");
        }
        Ok(self.stack[self.stack.len() - 1].clone())
    }

    fn pop_mark(&mut self, at: usize) -> R<Vec<V>> {
        let Some(k) = self.marks.pop() else {
            return self.err(at, "an opcode needs a MARK that is not there");
        };
        Ok(self.stack.split_off(k.min(self.stack.len())))
    }

    fn memo_get(&self, k: u32) -> Option<V> {
        self.memo.get(&k).cloned().or_else(|| self.base.and_then(|b| b.get(&k).cloned()))
    }

    fn memo_len(&self) -> usize {
        self.memo.len() + self.base.map_or(0, |b| b.len())
    }

    fn memo_put(&mut self, k: u32, at: usize) -> R<()> {
        let v = self.top(at)?;
        if self.memo.len() >= MAX_MEMO && !self.memo.contains_key(&k) {
            return self.err(at, format!("more than {MAX_MEMO} memo entries"));
        }
        self.memo.insert(k, v);
        Ok(())
    }

    fn get(&mut self, k: u64, at: usize) -> R<()> {
        let v = u32::try_from(k).ok().and_then(|k| self.memo_get(k));
        match v {
            Some(v) => self.push(v, at),
            None => self.err(at, format!("it reads memo entry {k}, which was never written")),
        }
    }

    fn seq(&self, book: &mut Book, kind: SK, items: Vec<V>) -> V {
        let mut kept = Vec::new();
        let (mut dropped, mut lost) = (false, false);
        if kind == SK::Dict {
            // (what its pairs may give an object, before any is dropped: Book::any_given)
            note_pairs(book, &items);
            let mut it = items.into_iter();
            while let (Some(k), Some(v)) = (it.next(), it.next()) {
                keep_pair(book, &mut kept, ITEMS, k, v, &mut dropped, &mut lost);
            }
        } else {
            for v in items {
                if kept.len() < ITEMS && book.keep() {
                    kept.push(v);
                } else {
                    keep_dropped(book, &mut kept, v, &mut dropped, &mut lost);
                }
            }
        }
        V::Seq(Rc::new(RefCell::new(Seq { kind, items: kept, dropped, lost })))
    }

    /// Items added to a container (APPEND, APPENDS, SETITEM, SETITEMS, ADDITEMS): kept while there is room. A fork
    /// changes nothing (the container may be the reading's it was forked from); nor does anything but a container. A
    /// member of the standard library's data enums given items is changed, as BUILD changes a global: code, in either
    /// reading (H2 of the review of Oct 29: SETITEM or APPEND on signal.SIGTERM was passed over as the member's data).
    /// An object the pickle made (or loads: V::Opaque) given items has what SETITEM gives it, and what APPEND, APPENDS
    /// or ADDITEMS call on it is called (Given, N1 of the re-review of Oct 30), in either reading. SETITEM's and
    /// SETITEMS's pairs that name `extend`, `append` or `add` literally, whatever they are given to, are what any object
    /// may be given (a dict installed as one's attributes and filled later: Book::any_given), and all their pairs where
    /// the target is an attribute state (an object that is no plain mapping, a dict installed by reference: round 4,
    /// M1); APPEND, APPENDS and ADDITEMS on anything but a container the pickle built call what any object was given
    /// (call_any_given: round 3 of the review of FP-MODEL-FILES-PY311).
    fn extend(&mut self, book: &mut Book, target: &V, items: Vec<V>, at: usize, how: &'static str) -> R<()> {
        if let V::Global(g) = target {
            if book.globals.get(*g as usize).is_some_and(|gl| gl.member) {
                let what = book.qual(*g);
                book.code(format!("changes {what} itself ({how} on it sets its items)"), book.hit(at, how));
            }
        }
        if matches!(how, "SETITEM" | "SETITEMS") {
            note_pairs(book, &items);
            if attr_target(book, target) {
                note_attr_pairs(book, &items, 0);
            }
        } else if matches!(target, V::Call(_) | V::Obj(_) | V::Opaque | V::Global(_)) {
            self.call_any_given(book, how == "ADDITEMS", &items, at, how)?;
        }
        match target {
            V::Call(m) | V::Obj(m) => return self.extend_object(book, Some(m), items, at, how),
            V::Opaque => return self.extend_object(book, None, items, at, how),
            _ => {}
        }
        if self.spec {
            return Ok(());
        }
        if let V::Seq(s) = target {
            // (each value looked at before the container is borrowed: it may be the container, or hold it)
            let (kind, have) = { let b = s.borrow(); (b.kind, b.items.len()) };
            let mut add = Vec::new();
            let (mut dropped, mut lost) = (false, false);
            let mut items: Vec<V> = items.into_iter().map(|v| {
                let (v, cut) = keepable(book, v, target);
                dropped |= cut;
                v
            }).collect();
            if kind == SK::Dict && items.len() % 2 == 0 {
                // pairs: kept while there is room, and one that gives a special method a callable kept past it (H7,
                // the external review of Oct 21: 64 pairs pushed __setstate__ out of what the reader kept)
                let mut it = items.drain(..);
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    keep_pair(book, &mut add, (ITEMS * 2).saturating_sub(have), k, v, &mut dropped, &mut lost);
                }
            } else {
                let room = (ITEMS * 2).saturating_sub(have);
                for v in items {
                    if add.len() < room && book.keep() {
                        add.push(v);
                    } else {
                        keep_dropped(book, &mut add, v, &mut dropped, &mut lost);
                    }
                }
            }
            let mut s = s.borrow_mut();
            s.items.extend(add);
            s.dropped |= dropped;
            s.lost |= lost;
        }
        Ok(())
    }

    /// Items given to an object (`m`; none: one the reader cannot tell apart, V::Opaque). SETITEM and SETITEMS may give
    /// it attributes (an object whose items are its attributes: Given). APPEND and APPENDS call its `extend`, or its
    /// `append`, and ADDITEMS its `add`, each looked up on the object (C's do_append and load_additems): those the
    /// pickle gave it are called with the items, as REDUCE calls a callee; an object the pickle computed so given is a
    /// call of what the pickle computed (book.dynamic); and when what it gave is not seen, no member of the standard
    /// library's data enums is passed over as data (book.unseen_given). Python's pickle writes an object's APPENDS
    /// and SETITEMS before its BUILD (save_reduce: listitems, dictitems, then state), so a file Python wrote calls
    /// nothing given here.
    /// Its cost (round 3): a global called again with items of no object, of the same text kind and number, does
    /// nothing new and is not called again (Given::upto, Book::plain_calls; but text that names code, each of whose
    /// calls is a finding of its own), and each call is charged to the looks at what objects are given (GIVE_WORK):
    /// past them none is made, no member is passed over (book.unseen_given), and an APPEND whose call is not made, or
    /// on an object whose record was not looked at for them, says so (book.give_cut, SC-TRUNCATED: round 5, A2).
    fn extend_object(&mut self, book: &mut Book, m: Option<&Rc<Made>>, items: Vec<V>, at: usize, how: &'static str)
                     -> R<()> {
        if matches!(how, "SETITEM" | "SETITEMS") {
            // (as a BUILD's: a record full or unseen is not looked at again, the rest charged to the looks)
            let done = match m {
                Some(m) => record_done(m),
                None => book.opaque_given.full(),
            };
            let g = if done {
                Given::skipped()
            } else {
                give_charged(book, |b, g, left| give_pairs(b, g, &items, left, 0))
            };
            match m {
                Some(m) => m.add_given(g),
                None => book.opaque_given.merge(g),
            }
            return Ok(());
        }
        let add = how == "ADDITEMS";
        // (an object given nothing: nothing to do, and nothing looked at: round 4, k1)
        let given = match m {
            Some(m) => match m.given.try_borrow() {
                Ok(g) => g.as_ref().is_some_and(|g| !g.is_empty()),
                Err(_) => true,
            },
            None => !book.opaque_given.is_empty(),
        };
        if !given {
            return Ok(());
        }
        // items of no object, kept whole (no more than a tuple keeps, the reading's items not spent): what a global
        // that is no helper does with them is what the text they hold and their number say (Given::upto); text that
        // names code is a finding at each call
        let scalar = items.len() <= ITEMS && book.kept + items.len() < MAX_KEPT
            && items.iter().all(|v| matches!(v, V::Num(_) | V::Plain | V::Str(_) | V::Bytes(..) | V::Made_ | V::MadeStr));
        let shape = if scalar {
            // (the kind text_of finds in such items, without its sample)
            let kind = |v: &V| match v {
                V::Str(s) => book.cls.text_kind(&s.b, s.len),
                V::Bytes(..) | V::Made_ | V::MadeStr => TextKind::Text,
                _ => TextKind::Plain,
            };
            let text = items.iter().map(kind).max().unwrap_or(TextKind::Plain);
            (text != TextKind::CodeName).then_some((text as usize, items.len().min(4)))
        } else {
            None
        };
        let (globals, computed, unseen, cut) = match m {
            Some(m) => match m.given.try_borrow_mut() {
                Ok(mut have) => match have.as_mut() {
                    Some(g) => g.for_op(add, shape),
                    None => return Ok(()),
                },
                // (it cannot be read: what was given is not known, and that is said)
                Err(_) => (Vec::new(), None, true, true),
            },
            None => book.opaque_given.for_op(add, shape),
        };
        if globals.is_empty() && computed.is_none() && !unseen {
            return Ok(());
        }
        // what the object was given is not known for a bound of the reader's: what this calls is not, and that is said
        // (round 5, A2: a function that runs code given after the looks were spent, and called here, was quiet; round
        // 6, A7: and one given after a state the reader did not see)
        if cut {
            give_cut(book, at, how);
        }
        let (called, attr) = append_how(how);
        let work = CALL_WORK + items.len() as u64;
        let args = self.seq(book, SK::Tuple, items);
        for g in globals {
            if let Some((t, n)) = shape {
                let helper = book.globals.get(g as usize).is_none_or(|gl| gl.model != Model::None);
                if !helper && !book.plain_calls.insert((g, add, t as u8, n as u8)) {
                    continue;
                }
            }
            if !spend_give(book, work) {
                // (a call not made, for the looks spent: said)
                if book.unseen_given.is_none() {
                    book.unseen_given = Some(book.hit(at, how));
                }
                give_cut(book, at, how);
                break;
            }
            self.call(book, V::Global(g), args.clone(), at, called)?;
        }
        if let Some(what) = computed {
            if spend_give(book, work) {
                let what = format!("{what}, which the pickle gave the object as its {attr}");
                let (kind, sample) = text_of(book, &args);
                if kind == TextKind::CodeName {
                    book.code(format!("calls {what} with {}", quote(&sample)), book.hit(at, how));
                }
                if book.dynamic.is_none() {
                    book.dynamic = Some(Hit { what: Some(what), text: sample, ..book.hit(at, how) });
                }
            } else {
                if book.unseen_given.is_none() {
                    book.unseen_given = Some(book.hit(at, how));
                }
                give_cut(book, at, how);
            }
        }
        if unseen && book.unseen_given.is_none() {
            book.unseen_given = Some(book.hit(at, how));
        }
        Ok(())
    }

    /// APPEND, APPENDS or ADDITEMS on what may be an object (anything but a list, a set, a dict or a tuple the pickle
    /// built: a call's or a NEWOBJ's result, an object the file loads, a global). Python looks its extend, append or
    /// add up on it (C's do_append and load_additems, pickle.py's load_append, load_appends and load_additems), and
    /// any object the pickle gave one may be this one, reached through an alias the reader does not follow (a memo
    /// entry, getitem((obj,), 0), logging.getLogger('x') twice, an enum's member, joblib's memoised wrapper). So each
    /// member of the standard library's data enums that any dict or helper gave as one (Book::any_given) is called
    /// here, as REDUCE calls a callee (once: its call is then recorded); and where an object the pickle computed was
    /// given as one, or attributes the reader does not see were, no member is passed over (book.unseen_given). Round 3
    /// of the review of FP-MODEL-FILES-PY311 (the gaps (a) to (d) of its re-check of Oct 30). Python writes an
    /// object's APPENDS before its own state (save_reduce), but a file it wrote may well APPEND to one object (a deque,
    /// a list subclass) after another's state: so the record notes what a key the pickle computes, or an object it
    /// computed, gives only where a dict is an attribute state, never in a plain dict (round 4, M1).
    fn call_any_given(&mut self, book: &mut Book, add: bool, items: &[V], at: usize, how: &'static str) -> R<()> {
        let k = add as usize;
        let (from, to) = (book.any_given.called[k], book.any_given.members[k].len());
        if from < to {
            book.any_given.called[k] = to;
            let (called, _) = append_how(how);
            let args = self.seq(book, SK::Tuple, items.to_vec());
            for i in from..to {
                let g = book.any_given.members[k][i];
                self.call(book, V::Global(g), args.clone(), at, called)?;
            }
        }
        if (book.any_given.computed[k] || book.any_given.unseen) && book.unseen_given.is_none() {
            book.unseen_given = Some(book.hit(at, how));
        }
        Ok(())
    }

    /// A string value from bytes (the first KEEP of them).
    fn text(b: &[u8]) -> V {
        V::Str(Rc::new(Str { b: b[..b.len().min(KEEP)].to_vec(), len: b.len() }))
    }

    fn text_owned(b: Vec<u8>) -> V {
        let len = b.len();
        let mut b = b;
        b.truncate(KEEP);
        V::Str(Rc::new(Str { b, len }))
    }

    /// What STOP returns: the value on top of the stack.
    pub fn result(&self) -> Option<V> {
        self.stack.last().cloned()
    }

    /// Read until STOP, an error, or the opcode limit (a fork's).
    pub fn run(&mut self, book: &mut Book) -> End {
        let end = match self.steps(book) {
            Ok(end) => End::Stop(end),
            Err((at, why)) => End::Error(at, why),
        };
        for (g, n) in self.pushed.drain() {
            if let Some(gl) = book.globals.get_mut(g as usize) {
                gl.pushes = gl.pushes.saturating_add(n);
            }
        }
        end
    }

    fn steps(&mut self, book: &mut Book) -> R<usize> {
        loop {
            let at = self.pos;
            if self.ops >= self.max_ops {
                return self.err(at, format!("more than {} opcodes in a fork", self.max_ops));
            }
            self.ops += 1;
            if self.ops & 4095 == 0 && (!crate::budget::spend(4096) || crate::budget::exhausted()) {
                return self.err(at, "the engine's work budget was spent");
            }
            let Some(&op) = self.buf.get(at) else {
                return self.err(at, "it ends before its STOP opcode");
            };
            self.pos += 1;
            match op {
                b'.' => return Ok(self.pos),
                0x80 => {
                    let v = self.u8_(at)?;
                    if v > 5 {
                        return self.err(at, format!("protocol {v}, which no Python reads"));
                    }
                    self.proto = v;
                }
                0x95 => {
                    let n = self.u64_(at)?;
                    if n > (self.buf.len() - self.pos) as u64 {
                        return self.err(at, "a FRAME longer than what follows it");
                    }
                }
                b'(' => {
                    if self.marks.len() >= MAX_STACK {
                        return self.err(at, "too many MARKs");
                    }
                    self.marks.push(self.stack.len());
                }
                b'0' => {
                    if self.stack.len() > self.fence() {
                        self.stack.pop();
                    } else {
                        self.pop_mark(at)?;
                    }
                }
                b'1' => {
                    self.pop_mark(at)?;
                }
                b'2' => {
                    let v = self.top(at)?;
                    self.push(v, at)?;
                }
                b'N' | 0x88 | 0x89 => self.push(V::Plain, at)?,
                b'F' => {
                    self.line(at)?;
                    self.push(V::Plain, at)?;
                }
                b'G' => {
                    self.take(8, at)?;
                    self.push(V::Plain, at)?;
                }
                b'I' => {
                    let l = self.line(at)?;
                    let v = match l {
                        b"00" | b"01" => V::Plain,
                        _ => num_line(l).ok_or((at, "an INT that is not a number".to_string()))?,
                    };
                    self.push(v, at)?;
                }
                b'L' => {
                    let l = self.line(at)?;
                    let l = l.strip_suffix(b"L").unwrap_or(l);
                    let v = num_line(l).ok_or((at, "a LONG that is not a number".to_string()))?;
                    self.push(v, at)?;
                }
                b'J' => {
                    let v = self.i32_(at)?;
                    self.push(V::Num(v as i64), at)?;
                }
                b'K' => {
                    let v = self.u8_(at)?;
                    self.push(V::Num(v as i64), at)?;
                }
                b'M' => {
                    let v = self.u16_(at)?;
                    self.push(V::Num(v as i64), at)?;
                }
                0x8a | 0x8b => {
                    let n = if op == 0x8a { self.u8_(at)? as i64 } else { self.i32_(at)? as i64 };
                    if n < 0 {
                        return self.err(at, "a LONG4 of negative length");
                    }
                    let b = self.take(n as usize, at)?;
                    self.push(long_le(b), at)?;
                }
                b'S' => {
                    let l = self.line(at)?;
                    let inner = match l {
                        [q, mid @ .., q2] if (*q == b'\'' || *q == b'"') && q == q2 => mid,
                        _ => return self.err(at, "a STRING that is not quoted"),
                    };
                    let v = escape_decode(inner).ok_or((at, "a STRING with a bad escape".to_string()))?;
                    self.push(Self::text_owned(v), at)?;
                }
                b'V' => {
                    let l = self.line(at)?;
                    let v = raw_unicode_escape(l).ok_or((at, "a UNICODE with a bad escape".to_string()))?;
                    self.push(Self::text_owned(v), at)?;
                }
                b'T' => {
                    let n = self.i32_(at)?;
                    if n < 0 {
                        return self.err(at, "a BINSTRING of negative length");
                    }
                    let b = self.take(n as usize, at)?;
                    self.push(Self::text(b), at)?;
                }
                b'U' => {
                    let n = self.u8_(at)? as usize;
                    let b = self.take(n, at)?;
                    self.push(Self::text(b), at)?;
                }
                b'X' | 0x8c | 0x8d => {
                    let n = match op {
                        b'X' => self.u32_(at)? as u64,
                        0x8c => self.u8_(at)? as u64,
                        _ => self.u64_(at)?,
                    };
                    let b = self.take64(n, at)?;
                    if std::str::from_utf8(b).is_err() {
                        return self.err(at, "a unicode string that is not UTF-8");
                    }
                    self.push(Self::text(b), at)?;
                }
                b'B' | b'C' | 0x8e | 0x96 => {
                    let n = match op {
                        b'B' => self.u32_(at)? as u64,
                        b'C' => self.u8_(at)? as u64,
                        _ => self.u64_(at)?,
                    };
                    let start = self.pos;
                    let b = self.take64(n, at)?;
                    self.push(V::Bytes(start, b.len()), at)?;
                }
                0x97 => self.push(V::Opaque, at)?,
                0x98 => {
                    self.top(at)?;
                }
                b'}' => {
                    let v = self.seq(book, SK::Dict, Vec::new());
                    self.push(v, at)?;
                }
                b']' => {
                    let v = self.seq(book, SK::List, Vec::new());
                    self.push(v, at)?;
                }
                b')' => {
                    let v = self.seq(book, SK::Tuple, Vec::new());
                    self.push(v, at)?;
                }
                0x8f => {
                    let v = self.seq(book, SK::Set, Vec::new());
                    self.push(v, at)?;
                }
                b'd' | b'l' | b't' | 0x91 => {
                    let items = self.pop_mark(at)?;
                    if op == b'd' && items.len() % 2 == 1 {
                        return self.err(at, "a DICT of an odd number of items");
                    }
                    let kind = match op {
                        b'd' => SK::Dict,
                        b'l' => SK::List,
                        b't' => SK::Tuple,
                        _ => SK::Set,
                    };
                    let v = self.seq(book, kind, items);
                    self.push(v, at)?;
                }
                0x85..=0x87 => {
                    let k = (op - 0x84) as usize;
                    if self.stack.len() < self.fence() + k {
                        return self.err(at, "a TUPLE of more items than its stack holds");
                    }
                    let items = self.stack.split_off(self.stack.len() - k);
                    let v = self.seq(book, SK::Tuple, items);
                    self.push(v, at)?;
                }
                b'a' => {
                    let v = self.pop(at)?;
                    let t = self.top(at)?;
                    self.extend(book, &t, vec![v], at, "APPEND")?;
                }
                b'e' | 0x90 => {
                    let items = self.pop_mark(at)?;
                    let t = self.top(at)?;
                    self.extend(book, &t, items, at, if op == b'e' { "APPENDS" } else { "ADDITEMS" })?;
                }
                b's' => {
                    let v = self.pop(at)?;
                    let k = self.pop(at)?;
                    let t = self.top(at)?;
                    self.extend(book, &t, vec![k, v], at, "SETITEM")?;
                }
                b'u' => {
                    let items = self.pop_mark(at)?;
                    if items.len() % 2 == 1 {
                        return self.err(at, "a SETITEMS of an odd number of items");
                    }
                    let t = self.top(at)?;
                    self.extend(book, &t, items, at, "SETITEMS")?;
                }
                b'p' => {
                    let l = self.line(at)?;
                    let k = dec_line(l).ok_or((at, "a PUT whose index is not a number".to_string()))?;
                    let k = u32::try_from(k).map_err(|_| (at, "a PUT index past the reader's".to_string()))?;
                    self.memo_put(k, at)?;
                }
                b'q' => {
                    let k = self.u8_(at)? as u32;
                    self.memo_put(k, at)?;
                }
                b'r' => {
                    let k = self.u32_(at)?;
                    self.memo_put(k, at)?;
                }
                0x94 => {
                    let k = self.memo_len();
                    let k = u32::try_from(k).map_err(|_| (at, "too many memo entries".to_string()))?;
                    self.memo_put(k, at)?;
                }
                b'g' => {
                    let l = self.line(at)?;
                    let k = dec_line(l).ok_or((at, "a GET whose index is not a number".to_string()))?;
                    self.get(k, at)?;
                }
                b'h' => {
                    let k = self.u8_(at)? as u64;
                    self.get(k, at)?;
                }
                b'j' => {
                    let k = self.u32_(at)? as u64;
                    self.get(k, at)?;
                }
                b'c' | b'i' => {
                    let module = self.line(at)?;
                    let name = self.line(at)?;
                    if std::str::from_utf8(module).is_err() || std::str::from_utf8(name).is_err() {
                        return self.err(at, "a global whose name is not UTF-8");
                    }
                    let how = if op == b'c' { "GLOBAL" } else { "INST" };
                    let g = book.intern(module, name, at, how);
                    if self.proto < 4 {
                        book.plain_lookup(g);
                    }
                    if op == b'c' {
                        self.push(V::Global(g), at)?;
                    } else {
                        let items = self.pop_mark(at)?;
                        let args = self.seq(book, SK::Tuple, items);
                        let r = self.call(book, V::Global(g), args, at, "INST")?;
                        self.push(r, at)?;
                    }
                }
                0x93 => {
                    let name = self.pop(at)?;
                    let module = self.pop(at)?;
                    let (V::Str(m), V::Str(n)) = (&module, &name) else {
                        return self.err(at, "a STACK_GLOBAL whose module and name are not strings");
                    };
                    if m.len > KEEP || n.len > KEEP {
                        return self.err(at, "a STACK_GLOBAL name longer than the reader keeps");
                    }
                    let g = book.intern(&m.b, &n.b, at, "STACK_GLOBAL");
                    if self.proto < 4 {
                        book.plain_lookup(g);
                    }
                    self.push(V::Global(g), at)?;
                }
                0x82..=0x84 => {
                    let code = match op {
                        0x82 => self.u8_(at)? as i64,
                        0x83 => self.u16_(at)? as i64,
                        _ => self.i32_(at)? as i64,
                    };
                    let g = book.intern_ext(code, at);
                    self.push(V::Global(g), at)?;
                }
                b'R' => {
                    let args = self.pop(at)?;
                    let callee = self.pop(at)?;
                    let r = self.call(book, callee, args, at, "REDUCE")?;
                    self.push(r, at)?;
                }
                b'o' => {
                    let mut items = self.pop_mark(at)?;
                    if items.is_empty() {
                        return self.err(at, "an OBJ without its class");
                    }
                    let callee = items.remove(0);
                    let args = self.seq(book, SK::Tuple, items);
                    let r = self.call(book, callee, args, at, "OBJ")?;
                    self.push(r, at)?;
                }
                0x81 | 0x92 => {
                    let kwargs = if op == 0x92 { Some(self.pop(at)?) } else { None };
                    let args = self.pop(at)?;
                    let cls = self.pop(at)?;
                    let how = if op == 0x81 { "NEWOBJ" } else { "NEWOBJ_EX" };
                    self.restore(book, &cls, at, how);
                    self.scan_args(book, &args, at, how);
                    if let Some(kw) = &kwargs {
                        self.scan_args(book, kw, at, how);
                    }
                    self.push(V::Obj(Rc::new(Made::new(cls, args))), at)?;
                }
                b'b' => {
                    let state = self.pop(at)?;
                    let inst = self.top(at)?;
                    self.build(book, inst, state, at)?;
                }
                b'P' => {
                    self.line(at)?;
                    self.push(V::Opaque, at)?;
                }
                b'Q' => {
                    self.pop(at)?;
                    self.push(V::Opaque, at)?;
                }
                other => return self.err(at, format!("opcode 0x{other:02x}, which no protocol has")),
            }
        }
    }

    /// A class the pickle makes an object of (NEWOBJ, copyreg.__newobj__, a reconstructor's first argument): the
    /// class's own __new__ and __setstate__ run, no function of the file's choosing.
    fn restore(&mut self, book: &mut Book, cls: &V, at: usize, how: &'static str) {
        match cls {
            V::Global(g) => {
                let hit = book.hit(at, how);
                let gl = &mut book.globals[*g as usize];
                if gl.restored.is_none() {
                    gl.restored = Some(hit);
                }
            }
            V::Call(_) | V::Obj(_) | V::Opaque => {
                // a class the pickle computed: its making was read where it was made; what it is, is not known
                if book.dynamic.is_none() {
                    book.dynamic = Some(Hit { what: Some(describe(book, cls)), ..book.hit(at, how) });
                }
            }
            _ => {}
        }
    }

    /// What the arguments of a call hold that matters whoever is called: a dict that gives a special method a
    /// callable (a class made with type(), an object's __setstate__).
    fn scan_args(&mut self, book: &mut Book, args: &V, at: usize, how: &'static str) {
        dunders(book, args, at, how);
    }

    fn build(&mut self, book: &mut Book, inst: V, state: V, at: usize) -> R<()> {
        dunders(book, &state, at, "BUILD");
        if matches!(inst, V::Obj(_) | V::Call(_) | V::Opaque) {
            // (a mapping the pickle computed in place of its dict: what it gives any object is not seen, AnyGiven)
            note_state(book, &state, StateOf::Build);
        }
        match &inst {
            V::Global(g) => {
                let what = book.qual(*g);
                book.code(format!("changes {what} itself (BUILD on a class or function sets its attributes)"),
                          book.hit(at, "BUILD"));
            }
            V::Obj(m) | V::Call(m) => {
                // joblib's array wrappers make an object of the class their state names with numpy's _reconstruct
                // (numpy before 2.0): that class is made, as NEWOBJ makes it (N2 of the re-review of Oct 30)
                if let Some(c @ V::Global(_)) = wrapper_class(book, m, &state) {
                    self.restore(book, &c, at, "joblib's array wrapper");
                }
                let wrapper = matches!(&m.callee, V::Global(g) if book.globals[*g as usize].model == Model::ArrayWrapper);
                if wrapper && self.joblib && !self.spec {
                    // joblib's load_build runs pickle's first, which gives the wrapper its state's attributes, and a
                    // memo entry may still hold the wrapper when its array takes its place (round 3, g17)
                    give_object(book, m, &state);
                    return self.joblib_array(book, &state, at);
                }
                // a __setstate__ an earlier BUILD gave the object (its __dict__ or its slots): load_build calls it with
                // this state, and the object's state stays as it was
                let installed = m.state.try_borrow().ok().and_then(|st| st.as_ref().and_then(|st| setstate_of(book, st)));
                if let Some(f) = installed {
                    let what = describe(book, &f);
                    book.code(format!("calls {what}, the __setstate__ an earlier BUILD gave the object, with this state"),
                              book.hit(at, "BUILD"));
                    return Ok(());
                }
                // the attributes it gives the object that APPEND, APPENDS and ADDITEMS call (N1), in either reading:
                // kept with those earlier BUILDs gave
                give_object(book, m, &state);
                if !self.spec {
                    let (state, _) = keepable(book, state, &inst);
                    if let Ok(mut st) = m.state.try_borrow_mut() {
                        *st = Some(state);
                    }
                }
            }
            V::Opaque => {
                let g = if book.opaque_given.full() {
                    Given::skipped()
                } else {
                    give_charged(book, |b, g, left| give(b, g, &state, left))
                };
                book.opaque_given.merge(g);
            }
            _ => {}
        }
        Ok(())
    }

    /// A call: REDUCE, OBJ, INST, and the calls the format's own helpers make of their arguments.
    fn call(&mut self, book: &mut Book, callee: V, args: V, at: usize, how: &'static str) -> R<V> {
        let made = |callee: V, args: V| V::Call(Rc::new(Made::new(callee, args)));
        let items: Vec<V> = match &args {
            V::Seq(s) => s.borrow().items.clone(),
            _ => Vec::new(),
        };
        self.scan_args(book, &args, at, how);
        let V::Global(g) = callee else {
            // a call of an object the pickle computed: a gadget chain's shape
            let (kind, sample) = text_of(book, &args);
            let what = describe(book, &callee);
            if kind == TextKind::CodeName {
                book.code(format!("calls {what} with {}", quote(&sample)), book.hit(at, how));
            }
            if book.dynamic.is_none() {
                book.dynamic = Some(Hit { what: Some(what), text: sample, ..book.hit(at, how) });
            }
            return Ok(made(callee, args));
        };
        let (kind, mut model) = { let gl = &book.globals[g as usize]; (gl.kind, gl.model) };
        let mut result = None;
        if self.dispatch >= MAX_DISPATCH && model != Model::None {
            // helpers handed helpers past the reader's depth: what the innermost calls is not followed
            if book.dynamic.is_none() {
                book.dynamic = Some(Hit { what: Some(format!("{} nested past {MAX_DISPATCH} helpers", book.qual(g))),
                                          ..book.hit(at, how) });
            }
            model = Model::None;
        }
        self.dispatch += 1;
        match model {
            Model::Reconstructor => {
                // copyreg._reconstructor(cls, base, state): base.__new__(cls, state), and base.__init__(obj, state)
                // unless base is object
                if let Some(cls) = items.first() {
                    self.restore(book, cls, at, "copyreg._reconstructor");
                }
                if let Some(base) = items.get(1) {
                    let is_object = matches!(base, V::Global(b) if book.globals[*b as usize].model == Model::Object);
                    if !is_object {
                        let st = items.get(2).cloned().unwrap_or(V::Plain);
                        let a = self.seq(book, SK::Tuple, vec![st]);
                        self.call(book, base.clone(), a, at, "copyreg._reconstructor's base")?;
                    }
                }
            }
            Model::NewObj => {
                if let Some(cls) = items.first() {
                    self.restore(book, cls, at, "copyreg.__newobj__");
                }
            }
            Model::FromType => {
                // torch._tensor._rebuild_from_type_v2(func, new_type, args, state): func(*args)
                if let Some(f) = items.first() {
                    let a = items.get(2).cloned().unwrap_or(V::Plain);
                    self.call(book, f.clone(), a, at, "torch's _rebuild_from_type_v2")?;
                }
                if let Some(t) = items.get(1) {
                    self.restore(book, t, at, "torch's _rebuild_from_type_v2");
                }
            }
            Model::RandomCtor => {
                // numpy.random._pickle.__randomstate_ctor / __generator_ctor(name, ctor): ctor(name)
                if let Some(c @ (V::Global(_) | V::Call(_) | V::Obj(_) | V::Opaque)) = items.get(1) {
                    let a = self.seq(book, SK::Tuple, items.first().cloned().into_iter().collect());
                    self.call(book, c.clone(), a, at, "numpy's random state constructor")?;
                }
            }
            Model::BitCtor => {
                // numpy.random._pickle.__bit_generator_ctor(bit_generator): a class is called
                if let Some(c @ (V::Global(_) | V::Call(_) | V::Obj(_) | V::Opaque)) = items.first() {
                    let a = self.seq(book, SK::Tuple, Vec::new());
                    self.call(book, c.clone(), a, at, "numpy's bit generator constructor")?;
                }
            }
            Model::Ufunc => {
                // numpy's _ufunc_reconstruct(module, name): getattr(__import__(module), name)
                match (items.first(), items.get(1)) {
                    (Some(V::Str(m)), Some(V::Str(n))) if m.len <= KEEP && n.len <= KEEP => {
                        let ng = book.intern(&m.b, &n.b, at, "numpy's _ufunc_reconstruct");
                        // (getattr(__import__(module), name): a dotted name is no attribute, N3)
                        book.plain_lookup(ng);
                        result = Some(V::Global(ng));
                    }
                    _ => book.code("hands numpy's _ufunc_reconstruct a name it builds, which it imports".into(),
                                   book.hit(at, how)),
                }
            }
            Model::GetAttr => {
                // getattr(<a GLOBAL>, '<name>'): how pickle writes a bound class method (ZoneInfo.__reduce__ gives
                // ZoneInfo._unpickle, written getattr(zoneinfo.ZoneInfo, '_unpickle')) or a member by its name: read
                // as that dotted global (judged as any global is, its call as its call). Anything else, getattr on
                // what the pickle computed or on such an attribute (a chain), a default, a name that is not one,
                // stays builtins.getattr's (code)
                if let (2, Some(V::Global(h)), Some(V::Str(a))) = (items.len(), items.first(), items.get(1)) {
                    let ident = !a.b.is_empty() && a.len == a.b.len() && a.len <= KEEP
                        && (a.b[0].is_ascii_alphabetic() || a.b[0] == b'_')
                        && a.b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
                    let (hm, hn, hattr) = { let gl = &book.globals[*h as usize]; (gl.module.clone(), gl.name.clone(), gl.attr) };
                    if ident && !hattr {
                        let mut name = hn;
                        name.push(b'.');
                        name.extend_from_slice(&a.b);
                        let ng = book.intern(&hm, &name, at, "getattr");
                        book.globals[ng as usize].attr = true;
                        book.globals[g as usize].resolved += 1;
                        result = Some(V::Global(ng));
                    }
                }
            }
            Model::TextMaker => {
                let name = &book.globals[g as usize].name;
                result = Some(if name == b"str" || name == b"chr" { V::MadeStr } else { V::Made_ });
            }
            Model::TypeCall => {
                if items.len() != 1 {
                    book.code("makes a class with builtins.type".into(), book.hit(at, how));
                }
            }
            Model::LoadFromBytes | Model::NestedLoad => {
                match items.first() {
                    Some(&V::Bytes(start, len)) if book.nested.len() < MAX_NESTED => {
                        book.nested.push(Nested { part: book.part, start, len, loader: g, at });
                    }
                    Some(V::Bytes(..)) => book.nested_dropped += 1,
                    _ if model == Model::LoadFromBytes => book.code(
                        format!("hands {} bytes it builds, which it loads with torch.load", book.qual(g)),
                        book.hit(at, how)),
                    _ => {}
                }
            }
            _ => {}
        }
        // the format's constructors of an object of the class they are handed (numpy's _reconstruct ...: data_maker's):
        // that class is made, as NEWOBJ makes it (N2 of the re-review of Oct 30: a member there was passed over)
        if kind == Kind::Safe {
            let (classes, maker) = made_classes(&book.globals[g as usize].name);
            for &i in classes {
                if let Some(c @ V::Global(_)) = items.get(i) {
                    self.restore(book, c, at, maker);
                }
            }
        }
        self.dispatch -= 1;
        if kind != Kind::Safe {
            let (mut tk, sample) = text_of(book, &args);
            if tk == TextKind::CodeName && kind != Kind::Code {
                let what = book.qual(g);
                book.code(format!("calls {what} with {}, which names code", quote(&sample)), book.hit(at, how));
            }
            // a reconstructor handed the class it rebuilds (Cython's __pyx_unpickle_*, pandas' _new_Index, sklearn's
            // newObj): this call restores an object, whatever text its state holds
            if matches!(items.first(), Some(V::Global(_))) && tk == TextKind::Text {
                tk = TextKind::Word;
            }
            let hit = Hit { text: sample, ..book.hit(at, how) };
            let gl = &mut book.globals[g as usize];
            let worse = match &gl.called {
                None => true,
                Some((k, _)) => tk > *k,
            };
            if worse {
                gl.called = Some((tk, hit));
            }
        }
        let r = result.unwrap_or_else(|| made(callee, args));
        // a helper that sets the object it returns attributes from a state, as BUILD does (N1): that object's, and an
        // attribute state's for any object (round 3); torch's _rebuild_from_type installs its dict by reference
        // (ret.__dict__ = dict)
        if let (V::Call(m), Some((st, of))) = (&r, attr_state(book, g, &items)) {
            note_state(book, &st, of);
            if book.globals[g as usize].name == b"_rebuild_from_type" {
                note_installed(book, &st);
            }
            let given = give_charged(book, |b, g, left| give(b, g, &st, left));
            m.add_given(given);
        }
        // a call that may fill a dict (`_operator.setitem(d, 'extend', m)`, `dict.setdefault(d, 'extend', m)` or
        // `dict.update(d, [('extend', m)])` through getattr), unless it is one of the format's data constructors:
        // the literal names beside members among its arguments, and in the pairs of a list or tuple among them, are
        // what any object may be given (round 4, (f))
        let pairs = call_pairs(book, &items);
        if !pairs.is_empty() && !matches!(&r, V::Call(m) if data_maker(book, m).is_some()) {
            for (mg, add) in pairs {
                note_member(book, mg, add);
            }
        }
        Ok(r)
    }

    /// joblib's NumpyArrayWrapper: its array's bytes follow its BUILD (numpy_pickle.py's write_array and
    /// read_array): an object array's as a pickle of its own; another's after a padding byte and the padding it
    /// counts, when the wrapper has numpy_array_alignment_bytes, as shape × itemsize bytes. Plain pickle.load would
    /// read those bytes as opcodes: when the first is one, that reading is read too (a fork).
    fn joblib_array(&mut self, book: &mut Book, state: &V, at: usize) -> R<()> {
        let bad = |why: &str| (at, format!("a joblib array whose {why} could not be read"));
        let shape = dict_get(state, b"shape").ok_or_else(|| bad("shape"))?;
        let mut count: u64 = 1;
        match &shape {
            V::Seq(s) => {
                let s = s.borrow();
                if s.dropped {
                    return Err(bad("shape"));
                }
                for v in &s.items {
                    let V::Num(n) = v else { return Err(bad("shape")) };
                    if *n < 0 {
                        return Err(bad("shape"));
                    }
                    count = count.checked_mul(*n as u64).ok_or_else(|| bad("size"))?;
                }
            }
            _ => return Err(bad("shape")),
        }
        let dtype = dict_get(state, b"dtype").ok_or_else(|| bad("dtype"))?;
        let (itemsize, hasobject) = dtype_size(book, &dtype).ok_or_else(|| bad("dtype"))?;
        let x = self.pos;
        if hasobject {
            // a nested pickle stream, read by pickle's own Unpickler on the same file
            let mut inner = Machine::new(self.buf, x, false);
            inner.persistent = self.persistent;
            match inner.run(book) {
                End::Stop(e) => self.pos = e,
                End::Error(a, why) => return Err((a, format!("{why} (in a joblib object array's pickle)"))),
            }
        } else {
            let first = self.buf.get(x).copied();
            if first.is_some_and(is_opcode) {
                self.fork(book, x);
            }
            let align = matches!(dict_get(state, b"numpy_array_alignment_bytes"), Some(V::Num(_)));
            let mut skip = 0usize;
            if align {
                skip = 1 + first.ok_or_else(|| bad("padding"))? as usize;
            }
            let bytes = count.checked_mul(itemsize).ok_or_else(|| bad("size"))?;
            let end = (x as u64).checked_add(skip as u64).and_then(|e| e.checked_add(bytes));
            match end {
                Some(e) if e <= self.buf.len() as u64 => self.pos = e as usize,
                _ => return Err((at, "a joblib array runs past the file's end".into())),
            }
        }
        // read_array's array takes the wrapper's place
        self.stack.pop();
        self.push(V::Opaque, at)
    }

    /// Read the bytes at `x` as plain pickle.load reads them (a fork of this reading: its stack copied, its memo seen
    /// through, nothing it holds changed); what that reading imports and calls is recorded with the rest.
    fn fork(&self, book: &mut Book, x: usize) {
        if book.forks >= MAX_FORKS || self.stack.len() > MAX_FORK_STACK {
            book.fork_cut.get_or_insert_with(|| "more joblib arrays than the reader reads again as plain pickle".into());
            return;
        }
        book.forks += 1;
        // (the values it starts from are this reading's, put on the stack again in the fork's: a global among them is
        // pushed once more, so getattr there is judged by both readings' uses)
        let mut pushed: HashMap<u32, u32> = HashMap::new();
        for v in &self.stack {
            if let V::Global(g) = v {
                *pushed.entry(*g).or_insert(0) += 1;
            }
        }
        let mut f = Machine {
            buf: self.buf,
            pos: x,
            stack: self.stack.clone(),
            marks: self.marks.clone(),
            memo: HashMap::new(),
            base: Some(&self.memo),
            spec: true,
            joblib: false,
            ops: 0,
            max_ops: MAX_FORK_OPS,
            persistent: self.persistent,
            dispatch: 0,
            pushed,
            proto: self.proto,
        };
        if let End::Error(_, why) = f.run(book) {
            if why.starts_with("more than") && why.ends_with("opcodes in a fork") {
                book.fork_cut.get_or_insert_with(|| format!("a joblib array's bytes read as plain pickle run past {MAX_FORK_OPS} opcodes"));
            }
        }
    }
}

/// A dict's value for a key (the first; a dict built by SETITEM(S) too).
pub fn dict_get(v: &V, key: &[u8]) -> Option<V> {
    let V::Seq(s) = v else { return None };
    let s = s.borrow();
    if s.kind != SK::Dict {
        return None;
    }
    let mut i = 0;
    while i + 1 < s.items.len() {
        if let V::Str(k) = &s.items[i] {
            if k.b == key {
                return Some(s.items[i + 1].clone());
            }
        }
        i += 2;
    }
    None
}

/// A numpy dtype the pickle made (numpy.dtype(descr, align, copy) and the state its BUILD gave it): its itemsize,
/// and whether it holds objects (NPY_ITEM_HASOBJECT among its flags, or an "O" descr).
fn dtype_size(book: &Book, v: &V) -> Option<(u64, bool)> {
    let V::Call(m) = v else { return None };
    let V::Global(g) = &m.callee else { return None };
    if book.globals[*g as usize].model != Model::Dtype {
        return None;
    }
    let V::Seq(a) = &m.args else { return None };
    let descr = match a.borrow().items.first() {
        Some(V::Str(s)) => s.b.clone(),
        _ => return None,
    };
    let body: &[u8] = descr.strip_prefix(b"<").or(descr.strip_prefix(b">")).or(descr.strip_prefix(b"|"))
        .or(descr.strip_prefix(b"=")).unwrap_or(&descr);
    let kind = *body.first()?;
    let digits: Vec<u8> = body[1..].iter().copied().take_while(|c| c.is_ascii_digit()).collect();
    let n: u64 = std::str::from_utf8(&digits).ok().and_then(|d| d.parse().ok()).unwrap_or(0);
    let (mut elsize, mut flags) = (None, 0i64);
    if let Some(V::Seq(st)) = &*m.state.borrow() {
        let st = st.borrow();
        if let Some(V::Num(e)) = st.items.get(5) {
            if *e > 0 {
                elsize = Some(*e as u64);
            }
        }
        if let Some(V::Num(f)) = st.items.get(7) {
            flags = *f;
        }
    }
    // (the dtype's string read as numpy reads it: one it cannot place for certain is no dtype the reader knows)
    let class = super::npy::dtype_str_class(&String::from_utf8_lossy(&descr));
    if class == super::npy::DClass::Unknown {
        return None;
    }
    let hasobject = class == super::npy::DClass::Object || flags & 1 != 0;
    let size = match elsize {
        Some(e) => e,
        None if kind == b'?' => 1,
        None if kind == b'U' => n.checked_mul(4)?,
        None if n > 0 => n,
        None => return None,
    };
    Some((size, hasobject))
}

/// `v` as it may be put inside the container `target` (a list's APPEND, a dict's SETITEM, an object's BUILD): itself, or
/// an opaque value when it holds the container (a cycle); one the look cannot tell about is kept, and the container is
/// a suspect whose contents the book lets go of at the end, so that no cycle outlives the reading.
fn keepable(book: &mut Book, v: V, target: &V) -> (V, bool) {
    let (Some(t), Some(_)) = (ptr(target), ptr(&v)) else { return (v, false) };
    let mut budget = CYCLE_LOOK;
    match reaches(&v, t, &mut budget) {
        Some(false) => (v, false),
        None if book.suspects.len() < MAX_SUSPECTS => {
            book.suspects.push(target.clone());
            (v, false)
        }
        _ => (V::Opaque, true),
    }
}

/// The worst text a call's arguments hold (a str or bytes written in them, directly or in the tuples, lists and
/// dicts written inside them), and a sample of it: a name that names code (a dotted name, or module:name, that
/// classifies as code), other text (anything but a plain name: spaces, punctuation, a path, a URL, a module path,
/// bytes), a plain name, or none. Objects the pickle made are not text, but text that bytes(), bytearray() or
/// _codecs.encode made is.
pub fn text_of(book: &Book, v: &V) -> (TextKind, Option<String>) {
    let mut budget = 256u32;
    let mut best = (TextKind::Plain, None);
    walk_text(book, v, &mut budget, 0, &mut best);
    best
}

fn walk_text(book: &Book, v: &V, budget: &mut u32, depth: usize, best: &mut (TextKind, Option<String>)) {
    if *budget == 0 || depth > 8 {
        if best.0 < TextKind::Text {
            *best = (TextKind::Text, Some("(more than the reader looks at)".into()));
        }
        return;
    }
    *budget -= 1;
    let mut note = |k: TextKind, s: String| {
        if k > best.0 {
            *best = (k, Some(s));
        }
    };
    match v {
        V::Str(s) => {
            let k = book.cls.text_kind(&s.b, s.len);
            note(k, sample(&s.b, s.len));
        }
        V::Bytes(_, n) => note(TextKind::Text, format!("{n} bytes")),
        V::Made_ | V::MadeStr => note(TextKind::Text, "text it builds".into()),
        V::Seq(s) => {
            let s = s.borrow();
            if s.dropped {
                note(TextKind::Text, "(more than the reader keeps)".into());
            }
            for x in &s.items {
                walk_text(book, x, budget, depth + 1, best);
            }
        }
        _ => {}
    }
}

/// A key that names a special method (__x__), but those that hold data, not behaviour.
fn special_key(k: &[u8]) -> bool {
    let data_name = matches!(k, b"__wrapped__" | b"__dict__" | b"__doc__" | b"__module__" | b"__name__" | b"__qualname__"
        | b"__annotations__" | b"__weakref__" | b"__slots__" | b"__version__");
    k.len() > 4 && k.starts_with(b"__") && k.ends_with(b"__") && !data_name
}

/// The global a call (REDUCE, NEWOBJ) made its value with, when it is one of the format's data constructors, whose
/// value is data: a safe global named exactly (a numpy scalar or dtype, a datetime, a tensor ...), but not one that
/// makes an object of another class (copyreg's), a class (type), a callable (functools.partial), a value it looks
/// up (getitem, getattr), or a TorchScript class's object.
fn data_maker<'b>(book: &'b Book, m: &Made) -> Option<&'b Glob> {
    data_maker_at(book, m, 0)
}

/// How deep data_maker follows what a constructor's value is made of (a parameter of a parameter of …): past it, a
/// value is not known to be data.
const DATA_DEPTH: usize = 16;

fn data_maker_at<'b>(book: &'b Book, m: &Made, depth: usize) -> Option<&'b Glob> {
    let V::Global(g) = &m.callee else { return None };
    let gl = book.globals.get(*g as usize)?;
    let data = gl.kind == Kind::Safe && gl.ext.is_none()
        && matches!(gl.model, Model::None | Model::Dtype | Model::ArrayWrapper)
        && !matches!(gl.name.as_slice(), b"partial" | b"getitem")
        && !gl.module.starts_with(b"__torch__");
    if !data || depth > DATA_DEPTH {
        return None;
    }
    // the safe constructors audited for what their value may be (H2 of the external re-reviews of Oct 27; DESIGN.md
    // lists them). (copyreg's reconstructors, __newobj__, type, object, getattr, partial, getitem, the random
    // generators', numpy's _ufunc_reconstruct, torch's _rebuild_from_type and _load_from_bytes are no data makers:
    // their models say so above.)
    let (module, name) = (gl.module.as_slice(), gl.name.as_slice());
    let full = [module, b".", name].concat();
    let items: Option<Vec<V>> = match &m.args {
        V::Seq(s) => s.try_borrow().ok().map(|s| s.items.clone()),
        _ => None,
    };
    let arg = |i: usize| items.as_ref().and_then(|a| a.get(i).cloned());
    // ... their value is what they are handed, or a class: never data (numpy's _DType_reconstruct, torch.jit's
    // restore_type_tag and build_*list; numpy's scalar of dtype object)
    if matches!(name, b"_DType_reconstruct" | b"restore_type_tag" | b"build_intlist" | b"build_tensorlist"
                | b"build_doublelist" | b"build_boollist") {
        return None;
    }
    if name == b"scalar" && module.starts_with(b"numpy") && !scalar_is_data(m) {
        return None;
    }
    // ... an object of the class they are handed (numpy's _reconstruct, _internal._reconstruct and _mareconstruct,
    // array's _array_reconstructor, numpy's __pyx_unpickle_SeedSequence, torch's _rebuild_wrapper_subclass): data
    // only when that class is one of the format's own data types, named by its global (_reconstruct(<a subclass with
    // __call__>, …) makes a callable)
    if matches!(name, b"_reconstruct" | b"_mareconstruct" | b"_array_reconstructor" | b"__pyx_unpickle_SeedSequence"
                | b"_rebuild_wrapper_subclass") && !own_type(book, arg(0).as_ref()) {
        return None;
    }
    // ... joblib's wrappers, which joblib.load replaces with what they read: under numpy before 2.0, an object of the
    // class their state names (subclass; ZNDArrayWrapper's init_args[0]) made by _reconstruct
    let named: Option<&[u8]> = match full.as_slice() {
        b"joblib.numpy_pickle_compat.NDArrayWrapper" | b"joblib.numpy_pickle.NumpyArrayWrapper"
        | b"sklearn.externals.joblib.numpy_pickle.NumpyArrayWrapper" => Some(b"subclass"),
        b"joblib.numpy_pickle_compat.ZNDArrayWrapper" => Some(b"init_args"),
        _ => None,
    };
    if let Some(key) = named {
        let state = m.state.try_borrow().ok().map(|s| s.clone());
        match state {
            None => return None,
            Some(None) => {}                                 // no BUILD yet: the wrapper itself, no callable
            Some(Some(st)) => {
                let cls = dict_get(&st, key);
                let cls = if key == b"init_args" { cls.as_ref().and_then(first_item) } else { cls };
                if !own_type(book, cls.as_ref()) {
                    return None;
                }
            }
        }
    }
    // ... an object of their argument's own type when it is not the base type (torch's Parameter and Buffer and their
    // rebuilds, _rebuild_device_tensor_from_cpu_tensor's data.to(), numpy's MaskedArray(data)): data only when what
    // they are handed is
    let typed_by_arg = (module.starts_with(b"torch") && matches!(name, b"Parameter" | b"Buffer" | b"_rebuild_parameter"
                        | b"_rebuild_parameter_with_state" | b"_rebuild_device_tensor_from_cpu_tensor"))
        || (module.starts_with(b"numpy.ma") && name == b"MaskedArray");
    if typed_by_arg && (items.is_none() || !is_data(book, arg(0).as_ref(), depth)) {
        return None;
    }
    // ... pyarrow's array and scalar, of the class their type names (an extension type's __arrow_ext_class__ or
    // __arrow_ext_scalar_class__): data only when that type is one pyarrow's or pandas' own constructors made
    let ty = match full.as_slice() {
        b"pyarrow.lib._restore_array" => Some(arg(0).as_ref().and_then(first_item)),
        b"pyarrow.lib.scalar" => Some(arg(1)),
        _ => None,
    };
    if let Some(t) = ty {
        let own = match &t {
            Some(V::Call(tm) | V::Obj(tm)) => data_maker_at(book, tm, depth + 1)
                .is_some_and(|tg| tg.module.starts_with(b"pyarrow") || tg.module.starts_with(b"pandas")),
            Some(V::Global(_) | V::Opaque) => false,
            _ => items.is_some(),
        };
        if !own {
            return None;
        }
    }
    Some(gl)
}

/// Whether `v`, a constructor's argument, is data (none: the constructor's default).
fn is_data(book: &Book, v: Option<&V>, depth: usize) -> bool {
    match v {
        None => true,
        Some(V::Call(m) | V::Obj(m)) => data_maker_at(book, m, depth + 1).is_some(),
        Some(V::Global(_) | V::Opaque) => false,
        Some(_) => true,
    }
}

/// Whether `v` is the global of one of the format's own data types (DATA_TYPES).
fn own_type(book: &Book, v: Option<&V>) -> bool {
    let Some(V::Global(t)) = v else { return false };
    book.globals.get(*t as usize).is_some_and(|t| {
        let full = [t.module.as_slice(), b".", t.name.as_slice()].concat();
        DATA_TYPES.iter().any(|d| d.as_bytes() == full.as_slice())
    })
}

/// A tuple's or a list's first item.
fn first_item(v: &V) -> Option<V> {
    let V::Seq(s) = v else { return None };
    let s = s.try_borrow().ok()?;
    if matches!(s.kind, SK::Tuple | SK::List) { s.items.first().cloned() } else { None }
}

/// The format's own data types a subtype-taking constructor makes data of: numpy's arrays, array's array, numpy's
/// SeedSequence, torch's tensor and parameter (none of them callable).
const DATA_TYPES: [&str; 25] = [
    "array.array", "numpy.random.bit_generator.SeedSequence", "numpy.random._bit_generator.SeedSequence",
    "numpy.ndarray", "numpy.ma.core.MaskedArray", "numpy.ma.MaskedArray", "numpy.matrix",
    "numpy.matrixlib.defmatrix.matrix", "numpy.recarray", "numpy.rec.recarray", "numpy._core.records.recarray",
    "numpy.core.records.recarray", "numpy.memmap", "numpy._core.memmap.memmap", "numpy.core.memmap.memmap",
    "numpy.chararray", "numpy.char.chararray", "numpy._core.defchararray.chararray",
    "numpy.core.defchararray.chararray", "numpy.core.multiarray.ndarray", "numpy._core.multiarray.ndarray",
    "torch.Tensor", "torch._tensor.Tensor", "torch.nn.parameter.Parameter", "torch.nn.Parameter",
];

/// A value that may be called: a global, what a call or NEWOBJ made (but data a data constructor made: a numpy
/// scalar is not called), an object the file loads.
fn callable(book: &Book, v: &V) -> bool {
    match v {
        V::Global(_) | V::Opaque => true,
        V::Call(m) | V::Obj(m) => data_maker(book, m).is_none(),
        _ => false,
    }
}

/// Whether a numpy scalar's dtype (scalar(dtype, bytes)) makes a number, a bool, a date or bytes: never a str (a
/// type code with its size, a datetime's unit, a name: `<i8`, `?`, `M8[ns]`, `float32`, `bytes_`).
fn numeric_scalar(m: &Made) -> bool {
    let Some(code) = scalar_code(m) else { return false };
    let c = code.as_slice();
    let unit = |r: &[u8]| r.iter().all(|b| b.is_ascii_alphanumeric() || b"[]_".contains(b));
    let code = match c.split_first() {
        Some((b'b' | b'i' | b'u' | b'f' | b'c' | b'?' | b'S', rest)) => rest.iter().all(u8::is_ascii_digit),
        Some((b'M' | b'm', rest)) => unit(rest),
        _ => false,
    };
    code || [&b"int"[..], b"uint", b"float", b"complex", b"bool", b"datetime64", b"timedelta64", b"bytes"].iter()
        .any(|n| c.strip_prefix(*n).is_some_and(unit))
}

/// A numpy scalar's dtype code (scalar(dtype(code, …), bytes)), its byte order dropped.
fn scalar_code(m: &Made) -> Option<Vec<u8>> {
    let first = |v: &V| -> Option<V> {
        let V::Seq(s) = v else { return None };
        s.try_borrow().ok()?.items.first().cloned()
    };
    let Some(V::Call(d)) = first(&m.args) else { return None };
    let Some(V::Str(code)) = first(&d.args) else { return None };
    Some(match code.b.first() {
        Some(b'<' | b'>' | b'|' | b'=') => code.b[1..].to_vec(),
        _ => code.b.clone(),
    })
}

/// Whether a numpy scalar is data: one of a number, a date, bytes, a str or a void; not one of dtype object (the
/// object it is handed), nor one whose dtype is not read.
fn scalar_is_data(m: &Made) -> bool {
    numeric_scalar(m) || scalar_code(m).is_some_and(|c| {
        let unit = |r: &[u8]| r.iter().all(u8::is_ascii_digit);
        match c.split_first() {
            Some((b'U' | b'V', rest)) => unit(rest),
            _ => [&b"str"[..], b"unicode", b"void"].iter().any(|n| c.strip_prefix(*n).is_some_and(|r| unit(r) || r == b"_")),
        }
    })
}

/// A key a pickle computes that may be any name (str(), a call's result, an object), not a literal; but not what a
/// data constructor made that never equals a str (a numpy scalar of a number, a date, a Decimal ...: a numpy str
/// scalar, a UserString do).
fn computed_key(book: &Book, k: &V) -> bool {
    match k {
        // (a member of the standard library's data enums by its exact name, signal.SIGTERM as 3.10 writes it, is an
        // int: a key no special method has, as signal.Signals(15), 3.12's, is: FP-MODEL-FILES-PY311)
        V::Global(g) if book.globals.get(*g as usize).is_some_and(|gl| gl.member) => false,
        V::MadeStr | V::Opaque | V::Global(_) => true,
        V::Call(m) | V::Obj(m) => match data_maker(book, m) {
            None => true,
            Some(gl) if gl.name.as_slice() == b"scalar" && gl.module.starts_with(b"numpy") => !numeric_scalar(m),
            Some(gl) => gl.name.as_slice() == b"UserString",
        },
        _ => false,
    }
}

/// (key, value) that gives a special method a callable, or may: what the reader keeps past its bounds.
fn behaviour_pair(book: &Book, k: &V, v: &V) -> bool {
    callable(book, v) && match k {
        V::Str(s) => special_key(&s.b),
        k => computed_key(book, k),
    }
}

/// A dict's pair: kept while `room` lasts; past it, kept still when it gives a special method a callable (the
/// container lost when even that cannot be kept: MAX_KEPT).
fn keep_pair(book: &mut Book, kept: &mut Vec<V>, room: usize, k: V, v: V, dropped: &mut bool, lost: &mut bool) {
    if kept.len() + 2 <= room && book.keep() && book.keep() {
        kept.push(k);
        kept.push(v);
    } else if behaviour_pair(book, &k, &v) {
        if book.keep() && book.keep() {
            kept.push(k);
            kept.push(v);
        } else {
            *lost = true;
        }
        *dropped = true;
    } else {
        *dropped = true;
    }
}

/// An item past a list's or a tuple's room: kept still when it is a (key, value) pair that gives a special method a
/// callable (dict.update reads a list of pairs as a dict's).
fn keep_dropped(book: &mut Book, kept: &mut Vec<V>, v: V, dropped: &mut bool, lost: &mut bool) {
    *dropped = true;
    let pair = match &v {
        V::Seq(s) => s.try_borrow().map(|s| s.items.len() == 2 && behaviour_pair(book, &s.items[0], &s.items[1])).unwrap_or(true),
        _ => false,
    };
    if pair {
        if book.keep() {
            kept.push(v);
        } else {
            *lost = true;
        }
    }
}

/// The __setstate__ a BUILD state gives an object (its dict, or a (dict, slots) pair's), when it is a callable.
fn setstate_of(book: &Book, st: &V) -> Option<V> {
    let find = |d: &V| -> Option<V> {
        let f = dict_get(d, b"__setstate__")?;
        callable(book, &f).then_some(f)
    };
    if let Some(f) = find(st) {
        return Some(f);
    }
    let V::Seq(s) = st else { return None };
    let s = s.try_borrow().ok()?;
    if s.kind == SK::Tuple && s.items.len() == 2 {
        return find(&s.items[0]).or_else(|| find(&s.items[1]));
    }
    None
}

/// What a state gives an object as the attributes APPEND, APPENDS and ADDITEMS call (Given): its dict's names, and a
/// tuple's or a list's dicts (load_build's (dict, slots), functools.partial's (func, args, kwds, dict)) and pairs
/// (types.SimpleNamespace's iterable). A mapping the pickle computed or names (a dict subclass made by a call, an
/// object, a global) or a dict past what the reader keeps is unseen. (No more than one level down, and a `__dict__`
/// key's dict one more: load_build sets the attributes of the dicts it is handed, and a slot state's `__dict__`, set
/// with setattr, replaces the object's.) Each item looked at is one of `left` (the reading's looks, STATE_WORK): past
/// them the rest is unseen (round 3 of the review of FP-MODEL-FILES-PY311, the cost).
fn give(book: &Book, to: &mut Given, state: &V, left: &mut u64) {
    match state {
        V::Seq(s) => {
            let Ok(s) = s.try_borrow() else {
                to.unseen = true;
                return;
            };
            match s.kind {
                SK::Dict => {
                    to.past_kept(s.dropped);
                    give_pairs(book, to, &s.items, left, 0);
                }
                SK::Tuple | SK::List => {
                    to.past_kept(s.dropped);
                    // (a dict it holds twice gives the same twice: looked at once; a pair is cheaper to look at again
                    // than to look for, round 6, A5)
                    let mut seen: Vec<*const RefCell<Seq>> = Vec::new();
                    for x in &s.items {
                        if !look(to, left) {
                            return;
                        }
                        match x {
                            V::Seq(d) => {
                                let Ok(d2) = d.try_borrow() else {
                                    to.unseen = true;
                                    continue;
                                };
                                match d2.kind {
                                    SK::Dict if seen.contains(&Rc::as_ptr(d)) => {}
                                    SK::Dict => {
                                        seen.push(Rc::as_ptr(d));
                                        to.past_kept(d2.dropped);
                                        give_pairs(book, to, &d2.items, left, 0);
                                    }
                                    SK::Tuple | SK::List if d2.items.len() == 2 => {
                                        give_pair(book, to, &d2.items[0], &d2.items[1], left, 0)
                                    }
                                    _ => {}
                                }
                            }
                            V::Call(_) | V::Obj(_) | V::Opaque | V::Global(_) => to.unseen = true,
                            _ => {}
                        }
                    }
                }
                SK::Set => {}
            }
        }
        V::Call(_) | V::Obj(_) | V::Opaque | V::Global(_) => to.unseen = true,
        _ => {}
    }
}

/// One item of a state looked at, of `left`: false, and what the state gives unseen, once they are spent.
fn look(to: &mut Given, left: &mut u64) -> bool {
    if *left == 0 {
        to.unseen = true;
        return false;
    }
    *left -= 1;
    true
}

/// A dict's items, (key, value) after (key, value) (`depth`: 1 inside a `__dict__` key's dict).
fn give_pairs(book: &Book, to: &mut Given, items: &[V], left: &mut u64, depth: u8) {
    for p in items.chunks_exact(2) {
        if !look(to, left) {
            return;
        }
        give_pair(book, to, &p[0], &p[1], left, depth);
    }
}

/// An attribute given: by the name `extend` or `append` (what APPEND and APPENDS call), or `add` (ADDITEMS'), a global
/// or an object the pickle computed that may be called (not data a data constructor made, nor text, a number or a
/// container). A key the pickle computes (it may be any name) given a callable is unseen. A `__dict__` key's dict
/// gives its own pairs (setattr(obj, '__dict__', d) makes d the object's attributes: round 3, g01 and g02), once; a
/// mapping the pickle computed there is unseen.
fn give_pair(book: &Book, to: &mut Given, k: &V, v: &V, left: &mut u64, depth: u8) {
    let add = match k {
        V::Str(s) if s.b == b"extend" || s.b == b"append" => false,
        V::Str(s) if s.b == b"add" => true,
        V::Str(s) if s.b == b"__dict__" && depth == 0 => {
            match v {
                V::Seq(d) => match d.try_borrow() {
                    Ok(d) if d.kind == SK::Dict => {
                        to.past_kept(d.dropped);
                        give_pairs(book, to, &d.items, left, 1);
                    }
                    Ok(_) => {}
                    Err(_) => to.unseen = true,
                },
                V::Call(_) | V::Obj(_) | V::Opaque | V::Global(_) => to.unseen = true,
                _ => {}
            }
            return;
        }
        V::Str(_) => return,
        k => {
            // (the value looked at first: a key the pickle computes is costly to tell, round 4, k2b; and not again once
            // the record is unseen, round 6, A5)
            if !to.unseen && callable(book, v) && computed_key(book, k) {
                to.unseen = true;
            }
            return;
        }
    };
    match v {
        V::Global(g) => {
            let helper = book.globals.get(*g as usize).is_none_or(|gl| gl.model != Model::None);
            // (the record looked through for it: charged)
            *left = left.saturating_sub(to.globals.len() as u64);
            to.add_global((add, *g, helper))
        }
        V::Call(_) | V::Obj(_) | V::Opaque if callable(book, v) => to.add_computed(add, || describe(book, v)),
        _ => {}
    }
}

/// The items the looks at what objects are given (`give`, `note_state`, a call's pairs) and the calls of what they were
/// given go through together, apart from the reading's other looks (STATE_WORK): past them, what any object is given
/// is unseen and no member is passed over (round 4, M2: sharing STATE_WORK, they made BUILD-heavy files reach it
/// sooner than base), and an APPEND that would call what an object was given says what it cannot (give_cut).
pub const GIVE_WORK: u64 = 50_000_000;

/// Charge `n` to the looks at what objects are given (GIVE_WORK): false once they are spent (and from then on), what
/// any object is given then unseen. The cut is said where it matters, at an APPEND (give_cut): an object's record
/// unseen passes no member over, but hides what a function it was given does with the items (round 5, A2).
fn spend_give(book: &mut Book, n: u64) -> bool {
    if book.give_work < GIVE_WORK {
        book.give_work = book.give_work.saturating_add(n);
        if book.give_work < GIVE_WORK {
            return true;
        }
    }
    book.any_given.unseen = true;
    false
}

/// What `walk` finds a state gives an object (its BUILD, SETITEM on it, a helper's call), each item it looks at
/// charged to GIVE_WORK: past it, unseen for the looks spent (`cut`: what an APPEND on the object calls is not known, and
/// is said there; round 5, A2: an empty record here hid a function given after them), and, once it is spent, what any
/// object is given (AnyGiven).
fn give_charged(book: &mut Book, walk: impl FnOnce(&Book, &mut Given, &mut u64)) -> Given {
    if book.give_work >= GIVE_WORK {
        book.any_given.unseen = true;
        return Given::skipped();
    }
    let mut g = Given::default();
    let start = GIVE_WORK - book.give_work;
    let mut left = start;
    walk(book, &mut g, &mut left);
    book.give_work += start - left;
    if book.give_work >= GIVE_WORK {
        book.any_given.unseen = true;
        g.unseen = true;
        g.cut = true;
    }
    g
}

/// An APPEND, APPENDS or ADDITEMS (`how`, at `at`) whose call of what the object was given is not made, or not known,
/// for a bound of the reader's (the looks at what objects are given spent, a record full, a state's items past what it
/// keeps): SC-TRUNCATED, once (round 5, A2; round 6, A7).
fn give_cut(book: &mut Book, at: usize, how: &str) {
    if book.give_cut.is_none() {
        book.give_cut = Some(format!("what the pickle gave the object passes what the reader keeps of it or looks at \
                                      ({ITEMS} globals, a container's items, the {GIVE_WORK} items of its looks; {how}, \
                                      byte {at}): what {how} calls on the object is not known"));
    }
}

/// An object's record is full (what more it is given cannot be kept) or cannot be read: what it is given next is not
/// looked at, and is unseen and said at an APPEND (Given::skipped; round 3, the cost: twenty thousand BUILDs of one state
/// of 64 dicts walked each). A record only unseen is looked at again (round 6, A7: a state the pickle computed, then
/// a function given as `extend` and called by an APPEND, was quiet), GIVE_WORK bounding what that costs.
fn record_done(m: &Made) -> bool {
    match m.given.try_borrow() {
        Ok(g) => g.as_ref().is_some_and(|g| g.full()),
        Err(_) => true,
    }
}

/// What a BUILD's state gives an object, kept with what earlier ones gave it (Made::add_given); not looked at when the
/// object's record is done (record_done).
fn give_object(book: &mut Book, m: &Made, state: &V) {
    let g = if record_done(m) {
        Given::skipped()
    } else {
        give_charged(book, |b, g, left| give(b, g, state, left))
    };
    m.add_given(g);
}

/// What one call of a given global costs the looks, besides its items: about what a look at that many items costs (a
/// call looks at its arguments' text and dunders, and builds its record: several dozen items' worth).
const CALL_WORK: u64 = 64;

/// How an APPEND, APPENDS or ADDITEMS calls what the object was given, for a finding, and the attribute's name.
fn append_how(how: &str) -> (&'static str, &'static str) {
    match how {
        "APPEND" => ("APPEND, calling the object's extend or append", "extend or append"),
        "APPENDS" => ("APPENDS, calling the object's extend or append", "extend or append"),
        _ => ("ADDITEMS, calling the object's add", "add"),
    }
}

/// A dict's pairs that name what APPEND, APPENDS or ADDITEMS call literally, for what any object may be given
/// (Book::any_given): every dict the pickles build (DICT, and EMPTY_DICT filled by SETITEM and SETITEMS) and every
/// SETITEM or SETITEMS on anything, before the reader drops any, whatever the dict becomes (an object's state, a slot
/// state's `__dict__`, torch's setattr-style state, a dict installed by reference and filled after it was given, a
/// joblib wrapper's state). One look at each pair, the value first.
fn note_pairs(book: &mut Book, items: &[V]) {
    for p in items.chunks_exact(2) {
        if let Some((g, add)) = literal_pair(book, &p[0], &p[1]) {
            note_member(book, g, add);
        }
    }
}

/// A member of the standard library's data enums under the literal name `extend` or `append` (add: false), or `add`.
fn literal_pair(book: &Book, k: &V, v: &V) -> Option<(u32, bool)> {
    let V::Global(g) = v else { return None };
    if !book.globals.get(*g as usize).is_some_and(|gl| gl.member) {
        return None;
    }
    match k {
        V::Str(s) if s.b == b"extend" || s.b == b"append" => Some((*g, false)),
        V::Str(s) if s.b == b"add" => Some((*g, true)),
        _ => None,
    }
}

/// A global given as one (`add`: as `add`): kept when it is a member of the standard library's data enums, once.
fn note_member(book: &mut Book, g: u32, add: bool) {
    let bit = 1u8 << add as u8;
    let Some(gl) = book.globals.get_mut(g as usize) else { return };
    if !gl.member || gl.given_as & bit != 0 {
        return;
    }
    gl.given_as |= bit;
    book.any_given.members[add as usize].push(g);
}

/// An attribute state's pairs (`depth`: 1 inside a `__dict__` key's dict), charged to GIVE_WORK all at once (round 5,
/// A5: one charge a dict, not one a pair).
fn note_attr_pairs(book: &mut Book, items: &[V], depth: u8) {
    if !spend_give(book, items.len() as u64 / 2 + 1) {
        return;
    }
    for p in items.chunks_exact(2) {
        note_attr_pair(book, &p[0], &p[1], depth);
    }
}

/// A pair of a dict that is, or becomes, an object's attributes (round 4, M1: only there, never in a plain dict, a
/// file Python wrote may hold a dict keyed by an enum's member or a class and then APPEND to a deque). Under the name
/// `extend` or `append` [0], or `add` [1], a member is given as one and an object the pickle computed that may be
/// called is a computed one; under a key the pickle computes (it may be any name: the value looked at first, the key
/// only when the value matters), an object the pickle computed that may be called is a computed one, as either, and a
/// member is passed over (round 6, A1': a known limit, PY311-MEMBER-PARITY: no member of PICKLE_DATA_MEMBERS can be
/// called, and a file Python wrote holds a state keyed by an enum's member or a class with members in it); under
/// `__dict__`, its dict is installed by reference (note_installed).
fn note_attr_pair(book: &mut Book, k: &V, v: &V, depth: u8) {
    let add = match k {
        V::Str(s) if s.b == b"extend" || s.b == b"append" => Some(false),
        V::Str(s) if s.b == b"add" => Some(true),
        V::Str(s) if s.b == b"__dict__" && depth == 0 => {
            note_installed(book, v);
            return;
        }
        V::Str(_) => return,
        _ => None,
    };
    let computed = |book: &Book| matches!(v, V::Call(_) | V::Obj(_) | V::Opaque) && callable(book, v);
    match (add, v) {
        (Some(add), V::Global(g)) => note_member(book, *g, add),
        (Some(add), _) if computed(book) => book.any_given.computed[add as usize] = true,
        (None, _) if computed(book) && computed_key(book, k) => book.any_given.computed = [true, true],
        _ => {}
    }
}

/// A dict installed as an object's attributes by reference (setattr(obj, '__dict__', d) in a slot state or torch's
/// _set_obj_state, functools.partial's dict, torch's _rebuild_from_type's): its pairs are an attribute state's, and so
/// are those a SETITEM puts in it later (kept by address, MAX_ATTR_DICTS; past it, unseen); a mapping the pickle
/// computed there is attributes not seen.
fn note_installed(book: &mut Book, v: &V) {
    match v {
        V::Seq(d) => {
            let Ok(b) = d.try_borrow() else {
                book.any_given.unseen = true;
                return;
            };
            if b.kind != SK::Dict {
                return;
            }
            book.any_given.unseen |= b.lost;
            note_attr_pairs(book, &b.items, 1);
            drop(b);
            let ptr = Rc::as_ptr(d);
            if !book.any_given.attr_ptrs.contains(&ptr) {
                if book.any_given.attr_ptrs.len() >= MAX_ATTR_DICTS {
                    book.any_given.unseen = true;
                } else {
                    book.any_given.attr_ptrs.insert(ptr);
                    book.any_given.attr_dicts.push(v.clone());
                }
            }
        }
        V::Call(_) | V::Obj(_) | V::Opaque | V::Global(_) => book.any_given.unseen = true,
        _ => {}
    }
}

/// A container SETITEM gives attributes to: an object the pickle made or loads that is no plain mapping (OrderedDict,
/// defaultdict, Counter, ChainMap, UserDict, dict, named exactly, whose items are no attributes), and a dict installed
/// as an object's attributes by reference.
fn attr_target(book: &Book, target: &V) -> bool {
    match target {
        V::Seq(s) => book.any_given.attr_ptrs.contains(&Rc::as_ptr(s)),
        V::Opaque => true,
        V::Call(m) | V::Obj(m) => {
            // (the class: NEWOBJ's, a call's callee, copyreg.__newobj__'s first argument)
            let class = match &m.callee {
                V::Global(g) if book.globals.get(*g as usize).is_some_and(|gl| gl.model == Model::NewObj) => {
                    match &m.args {
                        V::Seq(a) => a.try_borrow().ok().and_then(|a| a.items.first().cloned()),
                        _ => None,
                    }
                }
                c => Some(c.clone()),
            };
            let plain = matches!(class, Some(V::Global(c)) if book.globals.get(c as usize).is_some_and(|gl| {
                gl.kind == Kind::Safe && gl.ext.is_none() && matches!(
                    [gl.module.as_slice(), b".", gl.name.as_slice()].concat().as_slice(),
                    b"collections.OrderedDict" | b"collections.defaultdict" | b"collections.Counter"
                    | b"collections.ChainMap" | b"collections.UserDict" | b"builtins.dict" | b"__builtin__.dict")
            }));
            !plain
        }
        _ => false,
    }
}

/// (f, round 4) A call's arguments that may fill a dict: a literal name beside a member among them
/// (`_operator.setitem(d, 'extend', m)`, `dict.setdefault(d, 'extend', m)`), and in the pairs of a list or tuple among
/// them (`dict.update(d, [('extend', m)])`): (member, add). Each item looked at charged to GIVE_WORK.
fn call_pairs(book: &mut Book, items: &[V]) -> Vec<(u32, bool)> {
    let mut out = Vec::new();
    for w in items.windows(2) {
        if let Some(x) = literal_pair(book, &w[0], &w[1]) {
            out.push(x);
        }
    }
    for x in items {
        let V::Seq(s) = x else { continue };
        let Ok(b) = s.try_borrow() else { continue };
        if !matches!(b.kind, SK::Tuple | SK::List) {
            continue;
        }
        if !spend_give(book, b.items.len() as u64 + 1) {
            break;
        }
        for p in &b.items {
            let V::Seq(p) = p else { continue };
            let Ok(p) = p.try_borrow() else { continue };
            if matches!(p.kind, SK::Tuple | SK::List) && p.items.len() == 2 {
                if let Some(x) = literal_pair(book, &p.items[0], &p.items[1]) {
                    out.push(x);
                }
            }
        }
    }
    out
}

/// How a state sets an object's attributes (note_state): a BUILD's (load_build: a dict, or a (dict, slots) pair; a
/// list or a tuple only to a __setstate__ of the object's own), a helper's that sets them one by one (torch's
/// _set_obj_state: a dict or a (dict, slots) pair; _rebuild_from_type's dict), or a helper's that reads a mapping or an
/// iterable of pairs (types.SimpleNamespace, and copyreg._reconstructor with it as the base).
#[derive(Clone, Copy, PartialEq, Eq)]
enum StateOf {
    Build,
    Setattr,
    Pairs,
}

/// A 2-item tuple or list: a pair dict.update reads as one key and its value.
fn is_pair_seq(p: &Seq) -> bool {
    matches!(p.kind, SK::Tuple | SK::List) && p.items.len() == 2
}

fn is_pair(x: &V) -> bool {
    matches!(x, V::Seq(p) if p.try_borrow().is_ok_and(|p| is_pair_seq(&p)))
}

/// A state an object's attributes are set from, for what any object may be given (Book::any_given), charged to
/// GIVE_WORK: a dict's pairs (note_attr_pair); in place of a dict, a mapping the pickle computed (a dict subclass a call
/// made, an object, a global) is attributes not seen: a BUILD's state, the halves of its (state, slotstate) pair
/// (load_build), the fourth of functools.partial's (func, args, kwds, dict), which it installs by reference; a
/// helper's state and each item of it. A list or a tuple is read as pairs (round 4, (e): the pairs dict.update reads,
/// torch.nn.Module.__setstate__'s `self.__dict__.update(state)`) only where the helper reads pairs (StateOf::Pairs:
/// types.SimpleNamespace's iterable), or where every item is a pair (a 2-item tuple or list: is_pair); and there, no
/// helper reading it, its literal names only (round 6, A1'; round 5, A1: any 2-item container
/// in any tuple state read as a pair made pandas' BlockManager axes, a numpy object array of two objects,
/// functools.partial's two arguments and a custom __setstate__'s list of (enum member, object) pairs an attribute
/// state; elsewhere only its attribute positions are read, as before).
fn note_state(book: &mut Book, state: &V, of: StateOf) {
    let computed = |v: &V| matches!(v, V::Call(_) | V::Obj(_) | V::Opaque | V::Global(_));
    if computed(state) {
        book.any_given.unseen = true;
        return;
    }
    let V::Seq(s) = state else { return };
    let Ok(b) = s.try_borrow() else {
        book.any_given.unseen = true;
        return;
    };
    match b.kind {
        SK::Dict => {
            book.any_given.unseen |= b.lost;
            note_attr_pairs(book, &b.items, 0);
        }
        SK::Tuple | SK::List => {
            let helper = of != StateOf::Build;
            if helper {
                book.any_given.unseen |= b.dropped;
            }
            let n = b.items.len();
            if !spend_give(book, n as u64 + 1) {
                return;
            }
            // (a state of pairs: what the helper reads, or every item a pair; there no helper reads it, its literal names
            // only, round 6, A1': a key the pickle computes holding a member is a known limit, and one holding an object
            // a state Python writes, p17)
            if of == StateOf::Pairs || (n > 0 && b.items.iter().all(|x| is_pair(x))) {
                for x in b.items.iter() {
                    match x {
                        V::Seq(p) => {
                            let Ok(p) = p.try_borrow() else { continue };
                            if is_pair_seq(&p) && (of == StateOf::Pairs || matches!(p.items[0], V::Str(_))) {
                                note_attr_pair(book, &p.items[0], &p.items[1], 0);
                            }
                        }
                        x if computed(x) => book.any_given.unseen = true,
                        _ => {}
                    }
                }
                return;
            }
            for (i, x) in b.items.iter().enumerate() {
                // (load_build's halves; functools.partial's dict; any of a helper's)
                let attrs = helper || (b.kind == SK::Tuple && (n == 2 || (n == 4 && i == 3)));
                if !attrs {
                    continue;
                }
                match x {
                    V::Seq(pr) => {
                        let Ok(p) = pr.try_borrow() else {
                            book.any_given.unseen = true;
                            continue;
                        };
                        if p.kind != SK::Dict {
                            continue;
                        }
                        if !helper && n == 4 {
                            drop(p);
                            note_installed(book, x);
                        } else {
                            book.any_given.unseen |= p.lost;
                            note_attr_pairs(book, &p.items, 0);
                        }
                    }
                    x if computed(x) => book.any_given.unseen = true,
                    _ => {}
                }
            }
        }
        SK::Set => {}
    }
}

/// The argument a helper sets the attributes of the object it returns from, as BUILD does from its state: torch's
/// _rebuild_parameter_with_state and _rebuild_from_type_v2 (torch._utils._set_obj_state: a (dict, slots) or a dict)
/// and _rebuild_from_type (ret.__dict__ = dict), types.SimpleNamespace's mapping or pairs (3.13's), and
/// copyreg._reconstructor's state when its base is types.SimpleNamespace (base.__init__(obj, state)). And how the helper
/// reads it: SimpleNamespace a mapping or an iterable of pairs (StateOf::Pairs), torch a dict or a (dict, slots) pair.
fn attr_state(book: &Book, g: u32, items: &[V]) -> Option<(V, StateOf)> {
    // (safe globals, so named exactly: a safe name is its module's)
    let safe = |g: u32| book.globals.get(g as usize).filter(|gl| gl.kind == Kind::Safe && gl.ext.is_none());
    let gl = safe(g)?;
    let namespace = |gl: &Glob| gl.module == b"types" && gl.name == b"SimpleNamespace";
    let st = |i: usize, how: StateOf| items.get(i).cloned().map(|v| (v, how));
    match gl.model {
        Model::FromType => st(3, StateOf::Setattr),
        Model::Reconstructor => match items.get(1) {
            Some(V::Global(b)) if safe(*b).is_some_and(namespace) => st(2, StateOf::Pairs),
            _ => None,
        },
        _ if gl.module == b"torch._utils" && gl.name == b"_rebuild_parameter_with_state" => st(3, StateOf::Setattr),
        _ if namespace(gl) => st(0, StateOf::Pairs),
        _ => None,
    }
}

/// The format's constructors that make an object of a class they are handed (data_maker's: numpy's _reconstruct,
/// _internal._reconstruct and _mareconstruct, array's _array_reconstructor, numpy's __pyx_unpickle_SeedSequence,
/// torch's _rebuild_wrapper_subclass), by a safe global's name: the arguments that are classes, and the constructor
/// for a finding. (_mareconstruct(subtype, baseclass, …) makes an object of each.)
fn made_classes(name: &[u8]) -> (&'static [usize], &'static str) {
    const FIRST: &[usize] = &[0];
    const BOTH: &[usize] = &[0, 1];
    const NONE: &[usize] = &[];
    match name {
        b"_reconstruct" => (FIRST, "numpy's _reconstruct"),
        b"_mareconstruct" => (BOTH, "numpy's _mareconstruct"),
        b"_array_reconstructor" => (FIRST, "array's _array_reconstructor"),
        b"__pyx_unpickle_SeedSequence" => (FIRST, "numpy's __pyx_unpickle_SeedSequence"),
        b"_rebuild_wrapper_subclass" => (FIRST, "torch's _rebuild_wrapper_subclass"),
        _ => (NONE, ""),
    }
}

/// The class a joblib array wrapper's state names, of which joblib makes an object (numpy before 2.0: _reconstruct of
/// NumpyArrayWrapper's and NDArrayWrapper's subclass, ZNDArrayWrapper's init_args[0]).
fn wrapper_class(book: &Book, m: &Made, state: &V) -> Option<V> {
    let V::Global(w) = &m.callee else { return None };
    let gl = book.globals.get(*w as usize)?;
    if gl.kind != Kind::Safe || gl.ext.is_some() {
        return None;
    }
    match [gl.module.as_slice(), b".", gl.name.as_slice()].concat().as_slice() {
        b"joblib.numpy_pickle.NumpyArrayWrapper" | b"sklearn.externals.joblib.numpy_pickle.NumpyArrayWrapper"
        | b"joblib.numpy_pickle_compat.NDArrayWrapper" => dict_get(state, b"subclass"),
        b"joblib.numpy_pickle_compat.ZNDArrayWrapper" => dict_get(state, b"init_args").as_ref().and_then(first_item),
        _ => None,
    }
}

/// The containers one look at a state or a call's arguments goes through, and how deep (more: SC-TRUNCATED).
pub const STATE_LOOK: usize = 16_384;
pub const STATE_DEPTH: usize = 32;
/// The items all looks of a reading go through together (more: SC-TRUNCATED, and no more looks).
pub const STATE_WORK: u64 = 50_000_000;

/// Dicts (in a call's arguments or a BUILD's state, and a slot state's) that give a special method (__x__) a
/// callable: the next BUILD calls an object's __setstate__ with its state, and a class made from such a dict runs it;
/// and the (key, value) pairs of a list or a tuple, which dict.update reads as a dict. What the look cannot see is
/// said (H7, the external review of Oct 21): a container that lost such a pair, a key the pickle computes with a
/// callable value, more containers or a deeper nesting than one look goes through, or the reading's whole bound.
fn dunders(book: &mut Book, v: &V, at: usize, how: &'static str) {
    if book.state_work >= STATE_WORK {
        return;                                              // (said once, when it was reached)
    }
    let unseen = |book: &mut Book, why: &str| {
        if book.state_cut.is_none() {
            book.state_cut = Some(format!("{why} ({how}, byte {at}): whether it gives a special method a callable is \
                                           not known"));
        }
    };
    let mut todo: Vec<(V, usize)> = vec![(v.clone(), 0)];
    let mut looked = 0usize;
    while let Some((x, depth)) = todo.pop() {
        let V::Seq(s) = &x else { continue };
        looked += 1;
        if looked > STATE_LOOK || depth > STATE_DEPTH {
            unseen(book, &format!("a value nests more than {STATE_LOOK} containers, or deeper than {STATE_DEPTH}, \
                                   than the reader looks through"));
            return;
        }
        let Ok(b) = s.try_borrow() else { continue };
        let (kind, items, lost) = (b.kind, b.items.clone(), b.lost);
        drop(b);
        book.state_work = book.state_work.saturating_add(items.len() as u64 + 1);
        if book.state_work >= STATE_WORK {
            unseen(book, &format!("the values the pickles build pass the {STATE_WORK} the reader looks through"));
            return;
        }
        if lost {
            unseen(book, "a container holds more than the reader keeps");
        }
        let mut pairs: Vec<(&V, &V)> = Vec::new();
        if kind == SK::Dict {
            pairs.extend(items.chunks_exact(2).map(|p| (&p[0], &p[1])));
        } else if items.len() == 2 {
            pairs.push((&items[0], &items[1]));
        }
        for (k, val) in pairs {
            if !callable(book, val) {
                continue;
            }
            match k {
                V::Str(ks) if special_key(&ks.b) => {
                    let key = String::from_utf8_lossy(&ks.b).to_string();
                    let what = describe(book, val);
                    let hit = Hit { part: book.part, at, how, text: None, what: None };
                    book.code(format!("gives {key} the callable {what} ({how}): calling it is what that does"), hit);
                }
                k if computed_key(book, k) && kind == SK::Dict => {
                    let what = describe(book, k);
                    unseen(book, &format!("a dict's key the pickle computes ({what}) holds a callable"));
                }
                _ => {}
            }
        }
        for item in items {
            if matches!(item, V::Seq(_)) {
                todo.push((item, depth + 1));
            }
        }
    }
}

/// A value named for a message.
fn describe(book: &Book, v: &V) -> String {
    describe_at(book, v, 0)
}

fn describe_at(book: &Book, v: &V, depth: usize) -> String {
    if depth > 4 {
        return "a value".into();
    }
    match v {
        V::Global(g) => book.qual(*g),
        V::Call(m) => format!("what {}(…) returned", describe_at(book, &m.callee, depth + 1)),
        V::Obj(m) => format!("an object of {}", describe_at(book, &m.callee, depth + 1)),
        V::Opaque => "an object the file loads".into(),
        _ => "a value".into(),
    }
}

/// A short, printable sample of a text.
pub fn sample(b: &[u8], len: usize) -> String {
    let s = String::from_utf8_lossy(&b[..b.len().min(SAMPLE * 4)]);
    let mut out = String::new();
    for c in s.chars() {
        if out.chars().count() >= SAMPLE {
            out.push('…');
            return out;
        }
        if c.is_control() {
            out.push_str(&c.escape_default().to_string());
        } else {
            out.push(c);
        }
    }
    if len > b.len() {
        out.push('…');
    }
    out
}

pub fn quote(s: &Option<String>) -> String {
    match s {
        Some(t) if t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.ends_with(" bytes") => t.clone(),
        Some(t) => format!("'{t}'"),
        None => "text".into(),
    }
}

/// A decimal line (an INT, a LONG): a number, or None.
fn num_line(l: &[u8]) -> Option<V> {
    let s = std::str::from_utf8(l).ok()?.trim();
    let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit() || c == b'_') {
        return None;
    }
    Some(s.replace('_', "").parse::<i64>().map(V::Num).unwrap_or(V::Plain))
}

fn dec_line(l: &[u8]) -> Option<u64> {
    std::str::from_utf8(l).ok()?.trim().parse::<u64>().ok()
}

/// LONG1 / LONG4: little-endian two's complement.
fn long_le(b: &[u8]) -> V {
    if b.is_empty() {
        return V::Num(0);
    }
    if b.len() > 8 {
        return V::Plain;
    }
    let neg = b[b.len() - 1] & 0x80 != 0;
    let mut buf = if neg { [0xffu8; 8] } else { [0u8; 8] };
    buf[..b.len()].copy_from_slice(b);
    V::Num(i64::from_le_bytes(buf))
}

/// Python's codecs.escape_decode (a protocol 0 STRING's quoted text).
fn escape_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&e) = s.get(i) else { return None };
        i += 1;
        match e {
            b'\n' => {}
            b'\\' => out.push(b'\\'),
            b'\'' => out.push(b'\''),
            b'"' => out.push(b'"'),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(11),
            b'0'..=b'7' => {
                let mut v = (e - b'0') as u32;
                for _ in 0..2 {
                    match s.get(i) {
                        Some(&d @ b'0'..=b'7') => {
                            v = v * 8 + (d - b'0') as u32;
                            i += 1;
                        }
                        _ => break,
                    }
                }
                out.push((v & 0xff) as u8);
            }
            b'x' => {
                let h = s.get(i..i + 2)?;
                let v = u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
                out.push(v);
                i += 2;
            }
            other => {
                out.push(b'\\');
                out.push(other);
            }
        }
    }
    Some(out)
}

/// Python's raw-unicode-escape decoding (a protocol 0 UNICODE's line), as UTF-8.
fn raw_unicode_escape(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'\\' {
            // a run of backslashes: \u only after an odd number of them
            let mut j = i;
            while j < s.len() && s[j] == b'\\' {
                j += 1;
            }
            let run = j - i;
            let next = s.get(j).copied();
            if run % 2 == 1 && (next == Some(b'u') || next == Some(b'U')) {
                for _ in 0..run - 1 {
                    out.push('\\');
                }
                let n = if next == Some(b'u') { 4 } else { 8 };
                let h = s.get(j + 1..j + 1 + n)?;
                let v = u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
                out.push(char::from_u32(v)?);
                i = j + 1 + n;
                continue;
            }
            for _ in 0..run {
                out.push('\\');
            }
            i = j;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    Some(out.into_bytes())
}
