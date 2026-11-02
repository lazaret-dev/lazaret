//! Positive, scope-qualified provenance for RA-6 exemptions. Sink discovery
//! deliberately uses may-resolve names; an exemption must not use that model.
use super::*;
use crate::pystr::u;
use std::collections::{HashMap, HashSet, VecDeque};

pub(super) type Binding = (FnId, PyStr);
#[derive(Default)]
struct Scope {
    parent: Option<FnId>,
    bound: HashSet<PyStr>,
    global: HashSet<PyStr>,
    nonlocal: HashSet<PyStr>,
}
#[derive(Default)]
pub(super) struct Definition {
    pub writes: usize,
    pub value: Option<NodeId>,
    native: Option<PyStr>,
}
pub(super) struct Index {
    pub complete: bool,
    pub owners: Vec<FnId>,
    scopes: HashMap<FnId, Scope>,
    pub defs: HashMap<Binding, Definition>,
    pub escaped: HashSet<Binding>,
    pub aliased: HashSet<Binding>,
    body: FnId,
}

impl Index {
    pub fn binding(&self, mut f: FnId, name: &[u32]) -> Option<Binding> {
        for _ in 0..32 {
            let s=self.scopes.get(&f)?;
            if s.global.contains(name) {return Some((self.body,name.to_vec()))}
            if !s.nonlocal.contains(name) && (s.bound.contains(name) || f==self.body) {return Some((f,name.to_vec()))}
            f=s.parent.unwrap_or(self.body);
        }
        None
    }
    pub fn at(&self,t:&Tree,n:NodeId)->Option<Binding> {
        if n==NONE || t.kind(n)!=Kind::Name {return None}
        self.binding(*self.owners.get(n as usize)?,t.str(a_(t,n)))
    }

    pub fn native(&self,t:&Tree,n:NodeId,depth:usize)->Option<PyStr> {
        if n==NONE || depth>24 {return None}
        match t.kind(n) {
            Kind::Name => {
                let k=self.at(t,n)?;
                if self.escaped.contains(&k) {return None}
                if let Some(d)=self.defs.get(&k) {
                    if d.writes!=1 {return None}
                    if let Some(s)=&d.native {return Some(s.clone())}
                    return self.native(t,d.value?,depth+1)
                }
                (k.0==self.body && pystr::eq(&k.1,"filter")).then(||u("filter"))
            }
            Kind::Attribute => {
                let mut s=self.native(t,a_(t,n),depth+1)?;
                s.push('.' as u32);s.extend(t.str(b_(t,n)));Some(s)
            }
            Kind::Call => {
                let f=self.native(t,a_(t,n),depth+1)?;
                pystr::eq(&f,"pathlib.Path").then(||u("pathlib.Path()"))
            }
            _=>None,
        }
    }

    pub fn directory(&self,t:&Tree,n:NodeId,depth:usize,work:&mut usize)->bool {
        if !self.complete || n==NONE || depth>24 || *work==0 {return false} *work-=1;
        match t.kind(n) {
            Kind::Constant => matches!(t.node(n).op,pt::V_STR|pt::V_BYTES),
            Kind::Name => self.at(t,n).filter(|k|!self.escaped.contains(k)).and_then(|k|self.defs.get(&k)).is_some_and(|d|
                d.writes==1 && d.value.is_some_and(|v|self.directory(t,v,depth+1,work))),
            Kind::BinOp if matches!(t.node(n).op,pt::ADD|pt::DIV) =>
                self.directory(t,a_(t,n),depth+1,work) && self.directory(t,b_(t,n),depth+1,work),
            Kind::Call => {
                let f=a_(t,n);
                let native=self.native(t,f,0);
                let safe=native.as_ref().is_some_and(|s|["os.path.join","posixpath.join","ntpath.join","pathlib.Path","pathlib.Path.home","os.path.expanduser","os.path.abspath","os.path.normpath","os.path.dirname","os.getenv","os.environ.get"].iter().any(|x|pystr::eq(s,x)));
                let method=t.kind(f)==Kind::Attribute && ["resolve","absolute","expanduser","as_posix","joinpath"].iter().any(|x|pystr::eq(t.str(b_(t,f)),x)) && self.directory(t,a_(t,f),depth+1,work);
                (safe || method) && t.list(c_(t,n)).is_empty() && t.list(b_(t,n)).iter().all(|&v|self.directory(t,v,depth+1,work))
            }
            Kind::Attribute if pystr::eq(t.str(b_(t,n)),"parent") => self.directory(t,a_(t,n),depth+1,work),
            Kind::Subscript => self.native(t,a_(t,n),0).is_some_and(|s|pystr::eq(&s,"os.environ")) && self.directory(t,b_(t,n),depth+1,work),
            _=>false,
        }
    }

    // A value escaping in a keyword, *args, **kwargs, or a container counts
    // just as a positional argument. A call's result is a new value; its own
    // arguments are visited separately, without a quadratic subtree walk.
    fn expose(&mut self,t:&Tree,start:NodeId) {
        let mut nodes=vec![start];
        while let Some(n)=nodes.pop() {
            if n==NONE {continue}
            match t.kind(n) {
                Kind::Name => {if let Some(k)=self.at(t,n) {self.escaped.insert(k);}}
                Kind::Attribute|Kind::Subscript|Kind::Starred => nodes.push(a_(t,n)),
                Kind::List|Kind::Tuple|Kind::Set|Kind::Dict|Kind::IfExp|Kind::BoolOp|Kind::keyword => t.each_child(n,|c|nodes.push(c)),
                _=>{}
            }
        }
    }

    pub fn build(p:&Project,m:ModId)->Self {
        let t=p.tree(m);let body=p.mods[m as usize].body_fn;
        let mut ix=Index{complete:true,owners:vec![NONE;t.nodes.len()],scopes:HashMap::new(),defs:HashMap::new(),escaped:HashSet::new(),aliased:HashSet::new(),body};
        let mut imports=Vec::new();let mut extra=Vec::new();
        for f in p.fns.iter().filter(|f|f.module==m) {
            let mut scope=Scope{parent:f.parent,..Scope::default()};
            for &name in &f.pnames {
                let name=p.names.get(name).to_vec();scope.bound.insert(name.clone());extra.push((f.id,name));
            }
            for n in own_nodes(t,body_of(t,f.node)) {
                ix.owners[n as usize]=f.id;
                match t.kind(n) {
                    Kind::Global|Kind::Nonlocal => {
                        ix.complete=false;
                        for &s in t.list(a_(t,n)) {
                            if t.kind(n)==Kind::Global {scope.global.insert(t.str(s).to_vec());}
                            else {scope.nonlocal.insert(t.str(s).to_vec());}
                        }
                    }
                    Kind::Name if t.node(n).op!=pt::LOAD => {scope.bound.insert(t.str(a_(t,n)).to_vec());}
                    Kind::ExceptHandler if b_(t,n)!=NONE => {
                        let name=t.str(b_(t,n)).to_vec();scope.bound.insert(name.clone());extra.push((f.id,name));
                    }
                    Kind::FunctionDef|Kind::AsyncFunctionDef|Kind::ClassDef => {
                        let name=t.str(a_(t,n)).to_vec();scope.bound.insert(name.clone());extra.push((f.id,name));
                    }
                    Kind::Import|Kind::ImportFrom => {
                        let from=t.kind(n)==Kind::ImportFrom;
                        for &al in t.list(if from {b_(t,n)} else {a_(t,n)}) {
                            let name=t.str(a_(t,al));let asname=b_(t,al);
                            if pystr::eq(name,"*") {ix.complete=false;}
                            let local=if asname!=NONE {t.str(asname)} else if from {name} else {name.split(|&c|c=='.' as u32).next().unwrap_or(name)};
                            scope.bound.insert(local.to_vec());
                            let native=if from {
                                let base=a_(t,n);
                                if base==NONE || (c_(t,n)!=NONE && c_(t,n)!=0) {Vec::new()}
                                else {pystr::concat(&[t.str(base),&u("."),name])}
                            } else if asname==NONE {local.to_vec()} else {name.to_vec()};
                            imports.push((f.id,local.to_vec(),native));
                        }
                    }
                    _=>{}
                }
            }
            ix.scopes.insert(f.id,scope);
        }
        for (f,name) in extra {
            if let Some(k)=ix.binding(f,&name) {ix.defs.entry(k).or_default().writes+=1;}
        }
        for (f,name,native) in imports {
            if let Some(k)=ix.binding(f,&name) {
                let d=ix.defs.entry(k).or_default();d.writes+=1;
                let root=native.split(|&c|c=='.' as u32).next().unwrap_or(&[]);
                if ["os","pathlib","shutil","posixpath","ntpath","builtins"].iter().any(|s|pystr::eq(root,s)) {d.native=Some(native);}
            }
        }
        for n in 0..t.nodes.len() as NodeId {
            if t.kind(n)==Kind::Name && t.node(n).op!=pt::LOAD {
                if let Some(k)=ix.at(t,n) {ix.defs.entry(k).or_default().writes+=1;}
            }
            if t.kind(n)==Kind::Assign {
                if let [target]=t.list(a_(t,n)) {
                    if let Some(k)=ix.at(t,*target) {ix.defs.entry(k).or_default().value=Some(b_(t,n));}
                }
            }
        }
        let mut aliases:HashMap<Binding,Vec<Binding>>=HashMap::new();
        let mut calls=Vec::new();
        // Lambdas have no FnIndex scope. Recognize only a direct, immutable
        // string predicate over native listdir names, so an ordinary filter
        // does not make the whole provenance index incomplete. Every other
        // unowned call (including a lambda that invokes user code) fails closed.
        let mut string_predicates=HashSet::new();
        for n in 0..t.nodes.len() as NodeId {
            if t.kind(n)!=Kind::Call || !ix.native(t,a_(t,n),0).is_some_and(|s|pystr::eq(&s,"filter") || pystr::eq(&s,"builtins.filter")) {continue}
            let args=t.list(b_(t,n));
            if args.len()!=2 || !t.list(c_(t,n)).is_empty() || t.kind(args[0])!=Kind::Lambda || t.kind(args[1])!=Kind::Call {continue}
            if !ix.native(t,a_(t,args[1]),0).is_some_and(|s|pystr::eq(&s,"os.listdir")) {continue}
            let params=a_(t,args[0]);let body=b_(t,args[0]);
            let positional:Vec<_>=t.list(a_(t,params)).iter().chain(t.list(b_(t,params))).copied().collect();
            if positional.len()!=1 || c_(t,params)!=NONE || ext(t,params,2)!=NONE || !t.list(ext(t,params,0)).is_empty() || !t.list(ext(t,params,1)).is_empty() || !t.list(ext(t,params,3)).is_empty() || t.kind(body)!=Kind::Call {continue}
            let f=a_(t,body);
            if t.kind(f)!=Kind::Attribute || !["startswith","endswith"].iter().any(|s|pystr::eq(t.str(b_(t,f)),s)) {continue}
            let obj=a_(t,f);
            if t.kind(obj)!=Kind::Name || t.str(a_(t,obj))!=t.str(a_(t,positional[0])) {continue}
            let call_args=t.list(b_(t,body));
            if call_args.len()==1 && t.kind(call_args[0])==Kind::Constant && t.node(call_args[0]).op==pt::V_STR && t.list(c_(t,body)).is_empty() {string_predicates.insert(body);}
        }
        for n in 0..t.nodes.len() as NodeId {
            if ix.owners[n as usize]==NONE && ((t.kind(n)==Kind::Call && !string_predicates.contains(&n)) || (t.kind(n)==Kind::Name && t.node(n).op!=pt::LOAD)) {ix.complete=false;}
            match t.kind(n) {
                // Taking a dynamic runner as a value is enough: an alias can
                // mutate a module namespace without a visible assignment.
                Kind::Name if ["globals","vars","locals","exec","eval","__builtins__"].iter().any(|s|pystr::eq(t.str(a_(t,n)),s)) => ix.complete=false,
                Kind::Attribute if pystr::eq(t.str(b_(t,n)),"modules") => ix.complete=false,
                Kind::Assign => {
                    let value=b_(t,n);
                    if let Some(source)=ix.at(t,value) {
                        ix.aliased.insert(source.clone());
                        for &target in t.list(a_(t,n)) {
                            if let Some(dest)=ix.at(t,target) {aliases.entry(dest).or_default().push(source.clone());}
                            else {ix.expose(t,value);}
                        }
                    }
                }
                Kind::Attribute|Kind::Subscript if t.node(n).op!=pt::LOAD => ix.expose(t,a_(t,n)),
                Kind::List|Kind::Tuple|Kind::Set|Kind::Dict => {
                    // Nested containers get their own visit; do not walk them
                    // again for each enclosing container.
                    t.each_child(n,|c|if !matches!(t.kind(c),Kind::List|Kind::Tuple|Kind::Set|Kind::Dict) {ix.expose(t,c)});
                }
                Kind::Return|Kind::Yield => ix.expose(t,a_(t,n)),
                Kind::Call => calls.push(n),
                _=>{}
            }
        }
        if ix.defs.values().any(|d|d.native.as_ref().is_some_and(|s|["builtins.exec","builtins.eval"].iter().any(|n|pystr::eq(s,n)))) {ix.complete=false;}
        for n in calls {
                    let f=a_(t,n);let native=ix.native(t,f,0);
                    let safe=native.as_ref().is_some_and(|s|["filter","builtins.filter","os.listdir","os.scandir","os.path.join","posixpath.join","ntpath.join","pathlib.Path","pathlib.Path.home","os.path.expanduser","os.path.abspath","os.path.normpath","os.path.dirname","os.getenv","os.environ.get","shutil.rmtree","os.remove","os.unlink","os.rmdir"].iter().any(|x|pystr::eq(s,x)));
                    if !safe {
                        for &a in t.list(b_(t,n)) {ix.expose(t,a);}
                        for &kw in t.list(c_(t,n)) {ix.expose(t,b_(t,kw));}
                        // A mutating method receives its object implicitly.
                        if t.kind(f)==Kind::Attribute && !["is_dir","is_file","is_symlink","unlink","rmdir","iterdir"].iter().any(|s|pystr::eq(t.str(b_(t,f)),s)) {ix.expose(t,a_(t,f));}
                    }
        }
        // Escaping a local alias also escapes the original object.
        let mut pending:VecDeque<_>=ix.escaped.iter().cloned().collect();
        while let Some(k)=pending.pop_front() {
            for source in aliases.get(&k).into_iter().flatten() {
                if ix.escaped.insert(source.clone()) {pending.push_back(source.clone());}
            }
        }
        // A native namespace escaping can also replace other supposedly safe
        // consumers (e.g. shutil.rmtree). Do not keep exemptions based on the
        // argument classification made before that escape was propagated.
        if ix.escaped.iter().any(|k|ix.defs.get(k).is_some_and(|d|d.native.is_some())) {ix.complete=false;}
        ix
    }
}
