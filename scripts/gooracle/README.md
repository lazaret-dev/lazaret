# scripts/gooracle: Go's own answers, for `registry/ecosystems/golang.py`

Added in 0.1.9 (G-1 of `specs/lazaret-sources-and-languages-plan-2026-10-02`). The Go module (`python/src/lazaret/registry/ecosystems/golang.py`) has to read module
paths, versions, `go.mod` files, module zips and the checksum database's records as Go reads them: a different reading is
a way to hide a file from the scan, or to fetch a path the registry would not. The reference for all of those is Go's
own code, `golang.org/x/mod` (`module`, `semver`, `modfile`, `zip`, `sumdb`, `sumdb/dirhash`). This directory holds a
small Go program over those packages and the Python that feeds it cases and compares the answers.

| File | What |
|---|---|
| `main.go` | A batch oracle: one JSON line in (`op` and its arguments), one JSON line out. Ops: `checkpath`, `escapepath`, `split`, `semver`, `canonver`, `checkmajor`, `parsemodlax`, `checkzip`, `hashzip`, `hashfile`, `vcszip` (a module zip made from a git checkout at a tag, as the proxy makes one), `sumdbserve` (the body of `GET /lookup/<module>@<version>` from the checksum database's own server code, over records we choose and a key made from a fixed seed). It imports the standard library and `golang.org/x/mod/...`; it opens no connection and runs no program. |
| `gooracle.py` | `build`, `diff`, `golden` (below), and the case generators. Standard library only. |

```
python3 scripts/gooracle/gooracle.py build --out /tmp/gooracle-bin               # needs go 1.22 or later, and nothing from the network
python3 scripts/gooracle/gooracle.py diff --oracle /tmp/gooracle-bin/gooracle --scale 60
python3 scripts/gooracle/gooracle.py golden --oracle /tmp/gooracle-bin/gooracle --clone /tmp/gooracle-clones
```

* `build` copies the `golang.org/x/mod` that every Go toolchain carries (`$GOROOT/src/cmd/vendor/golang.org/x/mod`; v0.22.0
  in Go 1.24.7, the one the results below came from), puts `main.go` beside it and builds one binary.
* `diff` makes `--scale` thousand cases of each kind from a fixed seed, asks Go and asks the Python module, and compares:
  module paths (valid or not, the `!` escape, the split into path and major version), versions (valid, canonical, pseudo),
  the path-and-major check, zip member names (`CheckZip`), `go.mod` files (module, requirements, indirect marks), and the
  `h1:` hash of zips of every odd shape (stored or deflated, with and without data descriptors, names that are not UTF-8,
  a directory entry with data, a repeated name, a comment that looks like an end record). It exits 1 on a difference.
  At scale 60 (44,000 paths, 54,000 versions, 4,700 members, 15,000 `go.mod` files of which Go accepts 5,600, 2,000 zips) it
  found none. For zips the comparison is strict only for shapes a module could really have (`zip_is_strict`); for the
  rest Go and Python may differ, which `diff` counts and does not fail: they are not shapes `CreateFromVCS` makes, so no
  published module zip has them.
* `golden` runs `diff` at scale 8, refuses to write anything if it finds a difference, and then writes
  `python/tests/registry/recorded/go/` (see the README there): a selection of the cases with Go's answers, and two real
  module zips. It needs `git` and the network: three small repositories are cloned at tags, a module zip is made from each
  with `CreateFromVCS`, and the `h1:` of each is checked against the hash published go.sum files carry (`PUBLISHED`). If
  Go or this tool drifts, `golden` stops there.

The tests never run Go (`tests/registry/test_golang.py` reads the golden file; `tests/architecture/test_gooracle_script.py`
tests this script with a fake oracle). Run `diff` when `golang.py` changes, or when a new Go release changes `x/mod`.
