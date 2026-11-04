# Mail-gateway attachment analysis requirements

Status: proposed requirements for the Lazaret owner. This document is a handoff,
not a claim that the requirements are implemented.

The November 4, 2026 gateway review added six P0 clarifications: cancellation
is always present in the scan context; completeness is relative to a versioned
profile and the supplied view; incompleteness can have several simultaneous
reasons; a scan pins one immutable rule pack; redaction and evidence limits are
P0; and reports version their API, profile and coverage as well as their engine
and rule pack.

Workglen Mail Security needs more of Lazaret than `lazaret-archive`. Lazaret
already has a dependency-free native engine for source and supply-chain
analysis, compiled-artifact classification, model/pickle inspection, structural
media walking, keystore recognition and bounded archive extraction. The goal is
to expose those capabilities through a stable, policy-neutral attachment API
and add the document formats that matter to an email gateway.

## 1. Ownership and boundaries

### LMG-01 — Lazaret owns content analysis

Lazaret owns parsing, classification and evidence about the bytes it is given.
It must report what it found, what it could not inspect and which resource limit
stopped it. It must not decide whether Workglen delivers, quarantines, releases
or deletes a message.

Workglen continues to own:

- MIME parsing, transfer decoding and message-level budgets;
- recursive orchestration across attachments and archive members;
- recipient, tenant, rule-lifecycle and release policy;
- persistence, audit, quarantine and delivery; and
- conversion of Lazaret signals into administrator-only or ordinary policy.

Changes to shared Lazaret behavior land and are validated in Lazaret first.
Workglen then refreshes a pinned snapshot. Workglen must not carry an untracked
behavioral fork of Lazaret.

### LMG-02 — Explicit non-goals

This work does not:

- move Workglen's ZIP reader into `lazaret-archive`;
- turn Lazaret into an MTA, MIME parser or quarantine service;
- execute, emulate, import, load, render or detonate an attachment;
- invoke a shell, installed extractor, antivirus daemon or cloud scanner;
- contact a registry, secret provider or reputation service during the default
  attachment scan;
- add a required runtime, subprocess or external Rust crate; or
- justify a blanket antivirus or detection-efficacy claim.

Optional reputation or sandbox services, if ever authorized, must remain a
separate policy layer with explicit privacy, availability and failure behavior.

## 2. Required API

### LMG-03 — Stable native Rust contract (P0)

Provide a documented Rust API intended for another first-party application to
call directly. Workglen must not depend on internal modules or reconstruct the
JSON/Latin-1 FFI protocol used by the Python and WebAssembly bindings.

The exact Rust types are the Lazaret owner's choice, but the contract must
accept at least:

- the attachment bytes, or a bounded/ranged view for a large file;
- the untrusted filename and optional declared media type;
- a logical container path for evidence (`invoice.zip/document.pdf`);
- the caller's complete resource limits;
- a versioned analysis profile and coverage contract; and
- a scan context that always contains cooperative cancellation and work-budget
  controls. Callers that do not need external cancellation supply the explicit
  no-op cancellation implementation; absence of a cancellation control is not
  an API state.

It must return a typed, deterministic report containing at least:

- attachment API/schema, analysis-profile and coverage versions, including the
  requested and supported capability manifest;
- Lazaret engine and rule-pack versions and the rule-pack content hash;
- detected formats, independently of the filename;
- whether the scan is complete for the pinned profile and the exact bytes and
  container view supplied;
- zero or more simultaneous incompleteness reasons, including unsupported,
  structurally ambiguous, corrupt, truncated, unavailable input,
  limit-exhausted, cancelled and internal engine failure;
- findings with stable rule/signal identifiers, class, evidence and location;
- byte ranges or member paths supporting each finding where meaningful;
- requested-but-unread ranges or content, if a staged scan needs more input;
- input, decoded and work units consumed; and
- whether any result was redacted.

`Complete` never means that every future Lazaret detector, every file format or
every possible malware technique was applied. It means only that the versioned
analysis profile completed its declared coverage over the exact bytes and
container view supplied. Missing members, unread ranges or caller-truncated
input therefore prevent completeness for a profile that requires them.

Incompleteness is not one exclusive status: a result can be encrypted,
structurally ambiguous and over a resource limit at the same time, and the
report must preserve every reason reached within the evidence and finding
limits. Reason collection itself must have an explicit bound; crossing it adds
an `incompleteness-reasons-truncated` reason rather than silently dropping the
fact. The presence of any incompleteness reason forces `complete` to false.
Errors caused by bad caller arguments must remain distinguishable from
hostile-input findings.

### LMG-04 — Policy-neutral signals (P0)

Current package-oriented findings and messages must not be the only integration
surface. For example, a prebuilt executable is a reviewable capability in some
software packages but ordinarily mandatory quarantine in email; an attached
keystore can be sensitive without being malware.

Expose stable signal classes such as:

- executable or loadable program;
- script or command content;
- active document content;
- unsafe deserialization / code run while loading;
- decoded, downloaded or obfuscated code execution;
- persistence, credential access or exfiltration behavior;
- credential or private-key material;
- embedded or nested container;
- opaque or unaccounted payload;
- structural ambiguity or parser disagreement;
- encrypted or password-protected content;
- malformed, truncated or unsupported content; and
- resource limit or cancellation.

Lazaret may retain its existing severities for its own product. The attachment
API must let Workglen map the underlying signal without parsing a human message
or treating Lazaret's package verdict as a mail disposition.

### LMG-05 — Content and name are separate evidence (P0)

Detection must be based on bytes first. The filename, media type and container
path are untrusted hints. The report must preserve both the detected type and
the declared/name-implied type and signal meaningful disagreement, including a
valid executable, archive or script hidden behind an ordinary document name.

Polyglots, prepended data, appended data, overlapping members, duplicate names,
case/Unicode/Windows path collisions and different common-reader
interpretations must not silently select the most permissive reading.

### LMG-06 — Caller-supplied container view (P0)

Workglen already performs safe ZIP and Lazaret archive extraction. Provide a
way to analyze a logical container using the canonical member list and member
bytes supplied by the caller, so document-level analysis can correlate files
such as OOXML relationships, content types, macros and embedded objects without
requiring `lazaret-archive` to own ZIP.

The container contract must preserve directories, empty members, aliases,
collisions, unsupported entries and extraction errors. A document analyzer may
request selected members, but absence because of a caller limit must be
reported as incomplete rather than interpreted as absence from the document.
Each member must have a stable identity separate from its display path, and the
view must state its immutable source identity and length, completeness,
canonical path, aliases and extraction status.

Ranged analysis uses a staged `need ranges` result rather than allowing host I/O
callbacks inside the engine. Repeated or overlapping requests, out-of-range
requests and a caller's inability to supply a requested range need documented,
deterministic results. Every stage refers to the same immutable input identity;
changed bytes require a new scan.

## 3. Resource and failure requirements

### LMG-07 — One explicit work budget (P0)

Every attachment route must charge a caller-provided deterministic work budget:
source scanning, binary classification, model/pickle analysis, media walking,
document parsing and any Lazaret archive decoder used directly. The budget must
be checked inside long decoder/parser loops, not only before and after a call.

Limits must cover at least:

- bytes accepted and bytes read by range;
- decoded/decompressed bytes;
- members, objects, records, relationships and findings;
- per-finding and aggregate evidence bytes/characters;
- text/code characters analyzed;
- parser nesting and recursive embedded-content depth;
- retained allocations or an equivalent deterministic structure bound; and
- abstract work/operations.

Exact-boundary success and one-unit-over failure require tests. Nested content
must share the parent's budget rather than receive a fresh allowance.
Analyzers consume the shared budget in deterministic order. Parallel analyzers
may be introduced only with deterministic reservations that do not let thread
scheduling decide which analyzer receives the remaining work.

### LMG-08 — Cooperative cancellation and termination (P0)

Every scan context contains a cooperative cancellation control. The API
provides a no-op implementation for callers without an external cancellation
source, rather than making cancellation optional. The control must be checked
throughout every potentially long loop. Cancellation must add a typed
incompleteness reason with no partial-clean interpretation. The same
deterministic work limit must behave identically on native and WebAssembly
builds for identical input.

No hostile input may panic across the public API, abort the native process,
allocate from an attacker-declared size without a prior bound, or cause
unbounded recursion. A caught internal panic is an engine failure, never a
content-clean result.

A cancelled scan may retain bounded findings produced before a cancellation
checkpoint, but its overall result and affected analyzer coverage remain
incomplete. Callers must not need an empty finding list to recognize
cancellation.

### LMG-09 — No I/O in the engine (P0)

The attachment engine must retain Lazaret's current pure boundary: no file,
network, process, environment, clock or platform-service access. Hosts supply
bytes and perform any ranged reads. This keeps email content from causing
network callbacks, secret verification, URL fetching or renderer activity.

## 4. Required detection profile

### LMG-10 — Expose existing high-value Lazaret detectors (P0)

The attachment profile must make the following existing capabilities available
without package/registry orchestration:

- PE, ELF, Mach-O/fat Mach-O, WebAssembly, Java/DEX and other compiled-artifact
  recognition already modeled by the binary classifier;
- disguised executable and filename/content mismatch detection;
- Python, JavaScript/TypeScript and shell/script scanning for decoded execution,
  download-and-run, commands, persistence, credential access and exfiltration;
- Trojan Source, hidden Unicode, packed/obfuscated source and embedded payload
  indicators;
- pickle, PyTorch, NumPy object array and joblib analysis without loading them;
- media structural walking and appended/unaccounted payload detection;
- PKCS#12, JKS/JCEKS and related keystore/private-key recognition;
- opaque high-entropy payload classification; and
- incomplete/limit findings from every detector.

Project-wide taint and package install-hook analysis may be used when the input
is a source/package bundle. A single ordinary attachment must not be forced
through fictitious npm/PyPI package semantics.

### LMG-11 — Email document formats (P1)

Add bounded structural analyzers for the formats most likely to hide active
email content. Each analyzer must report active features and incomplete
inspection separately from corruption.

1. **OOXML and OpenDocument container views**
   - content types and relationships;
   - VBA projects, macros, ActiveX and embedded OLE/package objects;
   - external templates, external relationships and remote resources;
   - script-bearing or executable embedded members;
   - duplicate/colliding relationship targets and ambiguous member paths.
2. **OLE Compound File Binary Format**
   - directory and stream structure;
   - VBA/macro streams, embedded packages and executable objects;
   - malformed, overlapping, duplicate and unsupported structures.
3. **PDF**
   - encryption and unsupported filters as incomplete inspection;
   - JavaScript, OpenAction, additional actions, Launch, embedded files, XFA
     and external references;
   - cross-reference/object-stream ambiguity, incremental revisions and
     trailing/unaccounted bytes.
4. **Windows launch containers**
   - `.lnk`, `.url`, `.scf` and equivalent shortcut targets/arguments;
   - command interpreters, remote paths and disguised executable targets.
5. **HTML and SVG attachments**
   - executable script, event handlers and active embedded content;
   - credential-collection forms, external submission and deceptive redirects;
   - external resources as evidence only, without fetching them.

The analyzer need not render documents or decide whether an external link is
malicious. It must faithfully expose active capabilities and uncertainty for
Workglen policy.

### LMG-12 — Executable containers and disk images (P1)

Classify installers, JAR/APK archives, CAB/ISO/IMG/DMG/VHD-style containers and
other formats that commonly transport programs. Full filesystem implementation
is not required initially: a format that cannot be enumerated completely within
the limits must produce an explicit unsupported/incomplete signal suitable for
mandatory quarantine.

### LMG-13 — Redaction, evidence bounds and sensitive content (P0)

Keep data-loss signals distinct from malicious-behavior signals. Credentials,
private keys, database dumps and encrypted documents may be legitimate
attachments, but the gateway needs to identify and separately policy them.

Redaction is mandatory in the attachment profile, not an optional presentation
step. Reports must never contain credential values, private-key material, whole
attachment contents or unbounded attacker-controlled text. Evidence must have
caller-configurable per-finding and aggregate byte/character limits, with safe
P0 defaults and deterministic clipping. The report must state that clipping or
redaction occurred without reproducing the removed value. Filenames, paths,
format names and parser messages are attacker-controlled too and must be
bounded and sanitized before they enter evidence or logs.

## 5. Rule-pack and compatibility requirements

### LMG-14 — Versioned and reproducible rules (P0)

At scan creation the host pins one immutable rule-pack instance. Every nested
file, supplied container member, ranged read and later scan phase uses that
same instance; a refresh cannot change the pack beneath an in-flight scan.

Every report must identify the attachment API/schema version, analysis-profile
identifier and version, coverage version, engine version and rule-pack version.
It must also identify the rule-pack content hash and requested/supported
capability manifest.
The coverage version identifies the supported detector/format contract used to
interpret `complete`; it is not inferred from the engine version. A rule/signal
ID must have documented semantics and may not silently change meaning in a
patch release. Changes that alter findings require recorded-output review and
an explicit compatibility note.

The same input, rule pack and limits must produce the same ordered findings on
supported native platforms and WebAssembly, apart from explicitly documented
platform interpretation evidence. Human text can evolve; integrations must be
able to rely on typed status and stable identifiers.

### LMG-15 — Existing Lazaret behavior must not regress (P0)

The attachment profile must not weaken the project scanner, registry scanner,
install guard, SCA, Python/native parity or WebAssembly parity. Existing
package-context severities may remain, implemented as a policy over shared raw
signals where practical.

The Rust workspace must retain its no-external-crate rule, `unsafe` prohibition
in the engine, offline locked build and current MSRV unless a separately
reviewed change authorizes otherwise.

## 6. Validation and acceptance

### LMG-16 — Format fixtures (P0/P1 with the corresponding detector)

For every supported signal and format, include:

- independently generated benign files;
- files containing each active feature;
- misleading extensions and declared media types;
- nested active content;
- encrypted/password-protected variants;
- truncation at every meaningful structural boundary;
- corrupt lengths, checksums, offsets, cycles and overlapping records;
- duplicate and filesystem-colliding names;
- exact resource-limit boundaries; and
- deterministic bounded mutation tests that never panic.

Fixtures committed publicly must be inert. Functional or real malicious samples
remain in Lazaret's private sample process and are stored defanged/non-executable
according to the existing project rules.

### LMG-17 — Email-specific efficacy corpus (P1)

Create a separate evaluation corpus for email attachments. Do not reuse the
npm/PyPI malicious-package benchmark as evidence of mail-malware efficacy.

The corpus must contain representative benign business documents and media as
well as defanged malicious or active examples for Office/OLE, PDF, HTML/SVG,
shortcuts, scripts, executables, model files and nested containers. Publish:

- detection counts by signal and format;
- false-positive counts on the benign set;
- incomplete/unsupported counts;
- limits and exclusions; and
- whether examples were used to design the detector or held out.

No marketing detection-rate claim is accepted until a held-out set and review
method are documented.

### LMG-18 — Performance and memory evidence (P0)

Measure native debug/release and WebAssembly behavior on:

- maximum permitted files;
- deeply nested but valid structures;
- compressed or high-entropy content near limits;
- concurrent independent scans; and
- cancellation during each major parser/decoder.

Record wall time, work units and peak memory on supported test hosts. Work units
and structural limits are security contracts; wall-time and RSS measurements
are platform evidence, not universal guarantees.

### LMG-19 — Workglen integration acceptance (P0)

Before Workglen refreshes its snapshot, Lazaret must provide a pinned commit and
the following gates must pass:

- all Lazaret native and WebAssembly tests, offline and locked;
- warnings-denied Clippy for the supported Rust toolchain;
- no-external-dependency and notice/license checks;
- deterministic API fixtures consumed by a small independent Rust caller;
- supported/unsupported coverage matrix and rule-ID documentation;
- proof that simultaneous incompleteness reasons are retained and that any
  incomplete, unsupported, exhausted or cancelled input cannot return
  `complete`, regardless of whether it also has findings;
- proof that one immutable rule pack is used across the whole nested scan;
- redaction and per-finding/aggregate evidence-limit boundary tests; and
- assertions for API/schema, analysis-profile, coverage, engine and rule-pack
  versions in every report.

Workglen then adds product tests proving that its mapping makes executable,
active, unsafe-deserialization and incomplete signals administrator-only and
rechecks them before release. Those product-policy tests remain in Workglen,
not Lazaret.

## 7. Delivery order

1. **P0 foundation:** stable Rust attachment API, policy-neutral signals,
   profile-scoped completeness with multiple incompleteness reasons,
   content/name disagreement, caller-supplied container view, one work budget,
   mandatory cancellation control, immutable rule-pack pinning, bounded
   redacted evidence, full report versioning and exposure of existing
   binary/model/media/source detectors.
2. **P1 document coverage:** OOXML/OpenDocument, OLE, PDF, shortcuts, HTML/SVG
   and executable-container classification, each with format fixtures and
   failure semantics.
3. **P1 assurance:** email-specific benign/malicious corpus, held-out reporting,
   performance, memory and concurrent-scan evidence.
4. **Later, only if separately authorized:** maintained hash/signature or
   reputation inputs, sandbox integration and additional container formats.

Workglen integration should begin with the P0 API and existing detectors. It
must not wait for every P1 format, provided every unsupported or incomplete
case remains explicit and fail-closed at the gateway.
