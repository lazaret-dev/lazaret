# recorded/go

Written by `scripts/gooracle/gooracle.py golden` (Oct 3, 2026; Go 1.24.7, `golang.org/x/mod` v0.22.0 from its `cmd/vendor`).
Do not edit by hand: run the tool again.

| File | What |
|---|---|
| `golden.json` | Go's answers. `paths` (valid or not, and the `!` escape), `splits` (`SplitPathVersion`), `versions` (valid, canonical, pseudo), `majors` (`CheckPathMajor`), `members` (`CheckZip` on one member), `gomods` (`ParseLax`: module and requirements), `zips` (the `h1:` of zips of odd shapes, the zip as name, data, flags and method of each member), `real` (three real modules with the `h1:` of the zip and of the `go.mod` that published go.sum files carry), `lookups` (the body of a checksum-database `/lookup/` response for each), `counts` (what the full run compared). Chosen so that every kind of answer is present. |
| `go-difflib@v1.0.0.zip` | The module zip of `github.com/pmezard/go-difflib` v1.0.0, made by Go (`CreateFromVCS`) from the git tag. Its `h1:` is `h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=`, the value in the go.sum of `github.com/stretchr/testify` v1.8.4 (and of many others). BSD 3-clause; the licence is inside. |
| `errors@v0.9.1.zip` | The same for `github.com/pkg/errors` v0.9.1, `h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=` (the same line in the go.sum of prometheus, terraform, moby and the GitHub CLI). BSD 2-clause; the licence is inside. |

`github.com/davecgh/go-spew` v1.1.1 is in `real` and was checked the same way (`h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=`), but its zip is not kept.

What is not recorded from the real services: the module proxy's responses (`.info`, `@latest`, `.mod`) and the checksum
database's answers were not reachable when this was made. The tests build the proxy documents in the shape `go help goproxy`
describes, and the `lookups` bodies are what the checksum database's server code of `golang.org/x/mod/sumdb` writes for
the real hashes, signed with a key made from a fixed seed (`vkey` in the file), not the key of `sum.golang.org`. So the
tests that use them leave out the check of a lookup's signature and proof (`golang.verify_lookup` is patched, and
`info["sumdb"]` is "tls"); `tests/registry/test_golang_sumdb.py` checks real answers, tiny_https's capture of
`sum.golang.org` (`rust/crates/tiny_https/tests/data/sumdb`). To record the real ones: `curl https://sum.golang.org/lookup/github.com/pmezard/go-difflib@v1.0.0` and
`curl https://proxy.golang.org/github.com/pmezard/go-difflib/@v/v1.0.0.info`.
