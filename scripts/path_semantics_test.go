// Path-library checks only: no source fixture is executed and no path is opened.
// Run from the repository root: go test scripts/path_semantics_test.go
package paths_test

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPathSemantics(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok { t.Fatal("cannot locate the path matrix") }
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "tests", "fixtures", "path-api-semantics.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		API    string
		Parts  []string
		Result string
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		var got string
		switch row.API {
		case "go.path.Join":
			got = path.Join(row.Parts...)
			if runtime.GOOS != "windows" && filepath.Join(row.Parts...) != row.Result {
				t.Errorf("filepath.Join(%q): got %q, want %q", row.Parts, filepath.Join(row.Parts...), row.Result)
			}
		case "go.filepath.windows.Join":
			if runtime.GOOS != "windows" {
				continue
			}
			got = filepath.Join(row.Parts...)
		default:
			continue
		}
		if got != row.Result {
			t.Errorf("%s(%q): got %q, want %q", row.API, row.Parts, got, row.Result)
		}
	}
}
