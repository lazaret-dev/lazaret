// A batch oracle over Go's own golang.org/x/mod packages (module, semver, modfile, zip, sumdb, sumdb/dirhash), for
// checking Lazaret's Python readings of module paths, versions, go.mod files, module zips and the checksum database
// against the real code. Input: JSON lines on stdin; output: one JSON line per input line. See README.md.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	modzip "golang.org/x/mod/zip"
)

type req struct {
	Op      string `json:"op"`
	Hex     string `json:"hex"` // the text to work on, as hex (it may not be valid UTF-8)
	Path    string `json:"path"`
	V       string `json:"v"`
	Module  string `json:"module"`
	Version string `json:"version"`
	File    string `json:"file"`
	Dir     string `json:"dir"`
	Out     string `json:"out"`
	H1Zip   string `json:"h1zip"`
	H1Mod   string `json:"h1mod"`
	Seed    int64  `json:"seed"`
	Rev     string `json:"rev"`
	Subdir  string `json:"subdir"`
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// The checksum database server of the golang.org/x/mod/sumdb test code: the same server code that sum.golang.org
// speaks the protocol with, over records we choose, signed with a key made from a fixed seed.
var (
	records = map[string][]byte{}
	server  *sumdb.Server
	vkey    string
)

func startServer(seed int64) {
	skey, v, err := note.GenerateKey(mrand.New(mrand.NewSource(seed)), "test.sum.example")
	if err != nil {
		panic(err)
	}
	vkey = v
	server = sumdb.NewServer(sumdb.NewTestServer(skey, func(path, vers string) ([]byte, error) {
		if b, ok := records[path+"@"+vers]; ok {
			return b, nil
		}
		return nil, fmt.Errorf("no record for %s@%s", path, vers)
	}))
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	enc := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		var r req
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			enc.Encode(map[string]any{"fatal": err.Error()})
			continue
		}
		if r.Hex != "" {
			b, err := hex.DecodeString(r.Hex)
			if err != nil {
				enc.Encode(map[string]any{"fatal": err.Error()})
				continue
			}
			r.Path = string(b)
		}
		out := map[string]any{}
		switch r.Op {
		case "checkpath":
			err := module.CheckPath(r.Path)
			out["ok"], out["err"] = err == nil, errStr(err)
		case "escapepath":
			s, err := module.EscapePath(r.Path)
			out["ok"], out["out"], out["err"] = err == nil, s, errStr(err)
		case "semver":
			out["valid"] = semver.IsValid(r.V)
			out["canonical"] = semver.Canonical(r.V)
		case "canonver":
			out["canonical"] = module.CanonicalVersion(r.V)
			out["pseudo"] = module.IsPseudoVersion(r.V)
		case "split":
			pre, maj, ok := module.SplitPathVersion(r.Path)
			out["prefix"], out["major"], out["ok"] = pre, maj, ok
		case "checkmajor":
			err := module.CheckPathMajor(r.V, r.Path)
			out["ok"], out["err"] = err == nil, errStr(err)
		case "hashzip":
			h, err := dirhash.HashZip(r.File, dirhash.Hash1)
			out["ok"], out["h1"], out["err"] = err == nil, h, errStr(err)
		case "hashfile":
			// h1 of one file named go.mod, as the `/go.mod` line of the checksum database.
			h, err := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return os.Open(r.File) })
			out["ok"], out["h1"], out["err"] = err == nil, h, errStr(err)
		case "checkzip":
			cf, err := modzip.CheckZip(module.Version{Path: r.Module, Version: r.Version}, r.File)
			out["err"] = errStr(err)
			out["valid"], out["omitted"], out["invalid"] = len(cf.Valid), len(cf.Omitted), len(cf.Invalid)
		case "vcszip":
			// A module zip from a git checkout at a revision: what the proxy builds from a tag.
			f, err := os.Create(r.Out)
			if err == nil {
				err = modzip.CreateFromVCS(f, module.Version{Path: r.Module, Version: r.Version}, r.Dir, r.Rev, r.Subdir)
				f.Close()
			}
			out["ok"], out["err"] = err == nil, errStr(err)
		case "parsemodlax":
			// A go.mod read as a dependency's is (modfile.ParseLax): unknown and main-module-only directives ignored.
			f, err := modfile.ParseLax("go.mod", []byte(r.Path), nil)
			out["ok"], out["err"] = err == nil, errStr(err)
			if err == nil {
				if f.Module != nil {
					out["module"] = f.Module.Mod.Path
				}
				var reqs [][]any
				for _, q := range f.Require {
					reqs = append(reqs, []any{q.Mod.Path, q.Mod.Version, q.Indirect})
				}
				out["require"] = reqs
			}
		case "sumdbserve":
			// The body of GET /lookup/<module>@<version> of a checksum database that holds these two hashes.
			if server == nil {
				startServer(r.Seed)
			}
			records[r.Module+"@"+r.Version] = []byte(fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n",
				r.Module, r.Version, r.H1Zip, r.Module, r.Version, r.H1Mod))
			ep, e1 := module.EscapePath(r.Module)
			ev, e2 := module.EscapeVersion(r.Version)
			if e1 != nil || e2 != nil {
				out["ok"], out["err"] = false, errStr(e1)+errStr(e2)
				break
			}
			w := httptest.NewRecorder()
			server.ServeHTTP(w, httptest.NewRequest("GET", "/lookup/"+ep+"@"+ev, nil))
			out["ok"] = w.Code == http.StatusOK
			out["body"] = hex.EncodeToString(w.Body.Bytes())
			out["vkey"] = vkey
		default:
			out["fatal"] = "unknown op " + r.Op
		}
		enc.Encode(out)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
