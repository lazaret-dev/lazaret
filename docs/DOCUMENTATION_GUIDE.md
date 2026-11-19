# Documentation guide

This guide governs current Lazaret documentation. It exists so a human or agent
can update one topic without turning the README or architecture references into
another chronological change log.

## Reader path

1. `README.md` answers what Lazaret is, how to install it and where to go next.
2. `docs/README.md` routes readers by task.
3. `STRUCTURE.md` describes ownership and where code lives.
4. `docs/DESIGN.md` records stable architectural decisions and invariants.
5. `docs/RUST_ENGINE.md` explains the native engine.
6. `docs/TESTING.md` and `docs/RELEASING.md` contain operational procedures.

Do not copy a procedure into several documents. Link to its owner.

## Document classes

| Class | Examples | Update rule |
|---|---|---|
| Overview | `README.md`, `docs/README.md` | Keep concise; route to detail. |
| Current reference | `STRUCTURE.md`, `docs/DESIGN.md`, `docs/RUST_ENGINE.md` | Describe current behavior and stable invariants, not a chronological diary. |
| Procedure | `docs/TESTING.md`, `docs/RELEASING.md` | Give exact commands, prerequisites, expected results and recovery. One procedure has one owner. |
| Package documentation | `python/README.md`, `js/README.md` | Describe only what that published package provides. |
| Requirements | `docs/MAIL_GATEWAY_REQUIREMENTS.md` | State owner, status, scope and whether requirements are implemented. |
| Historical evidence | `CHANGELOG.md`, version-progress and review records | Preserve facts and dates. Do not rewrite history to match the current design. |
| Local artifact notes | fixture, recorded-response and script README files | Stay beside the artifact and document only it. |
| Synchronized upstream | `rust/crates/pratique/*.md` | Change upstream, then use the repository's sync procedure. |

## Required maintenance note

Current overview, reference, procedure and package documents link to this guide
or to `docs/README.md`. A new major document must do the same. Local fixture and
historical documents do not need boilerplate.

## Writing rules

- Lead with current behavior. Put change history in `CHANGELOG.md` or a dated
  review record.
- Prefer a short section and a link over repeating details.
- Keep headings task-oriented and make the first paragraph state audience and
  scope.
- Use relative Markdown links for repository files and verify that every target
  exists. Package READMEs rendered by PyPI or npm use absolute links to public
  GitHub because their repository-relative paths are not preserved by the
  registry renderer.
- Put commands in fenced `sh` blocks. Name the directory in which they run,
  required environment variables, success condition and safe recovery.
- Distinguish implemented behavior from proposals, future work and private
  deployment details.
- Do not expose credentials, private sample locations, private infrastructure
  details or malicious payloads in public documentation.
- Do not call generated output hand-maintained. Name its source and regeneration
  check.
- Wrap prose at a readable width. Tables and unavoidable generated examples may
  be wider, but a paragraph must not become a multi-thousand-character line.

## Repository boundary

The private GitLab repository is the full development source. Public GitHub is
a curated release repository and the authority for public release tags, PyPI
and npm. They are not mirrors. Documentation must never instruct a remote to
push automatically to both repositories or expose private branches, tools,
samples or infrastructure in the public tree.

Promotion and release commands belong only in [`RELEASING.md`](RELEASING.md).
Other documents describe the boundary and link there.

## Review checklist

Before committing documentation:

1. Confirm the statement against code, tests or the owning procedure.
2. Check that no other current document now contradicts it.
3. Verify relative links and fenced code blocks.
4. Run `git diff --check`.
5. If behavior changed, update the root README and changelog only as far as the
   reader needs; put details in the owning reference.
6. Preserve historical and upstream-synchronized files unless the change is
   specifically to those records.
