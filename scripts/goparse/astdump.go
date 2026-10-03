// astdump prints the syntax tree go/parser builds for each Go file named on the command line (or read from the
// standard input when none is): one line per node, in the order ast.Inspect visits them, "<Kind> <start> <end>" with
// offsets counted in code points (what Lazaret's engine counts), preceded by a line "== <path>"; a file that does not
// parse prints "!! <first error>" instead of nodes. Comments are not parsed (they are not in Lazaret's tree).
//
// It is the reference Lazaret's Go parser (rust/crates/lazaret-engine/src/goparse) is held to: see
// scripts/goparse/README.md. Standard library only.
package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"unicode/utf8"
)

func main() {
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	args := os.Args[1:]
	if len(args) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			args = append(args, sc.Text())
		}
	}
	for _, path := range args {
		src, err := os.ReadFile(path)
		fmt.Fprintf(out, "== %s\n", path)
		if err != nil {
			fmt.Fprintf(out, "!! %v\n", err)
			continue
		}
		dump(out, src)
	}
}

func dump(out *bufio.Writer, src []byte) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, parser.SkipObjectResolution)
	if err != nil {
		msg := err.Error()
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		fmt.Fprintf(out, "!! %s\n", msg)
		return
	}
	file := fset.File(f.Pos())
	// byte offset -> code point offset
	cp := make([]int32, len(src)+1)
	n := int32(0)
	for i := 0; i <= len(src); {
		cp[i] = n
		if i == len(src) {
			break
		}
		_, w := utf8.DecodeRune(src[i:])
		for k := 1; k < w; k++ {
			cp[i+k] = n
		}
		i += w
		n++
	}
	off := func(p token.Pos) int32 { return cp[file.Offset(p)] }
	ast.Inspect(f, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		name := fmt.Sprintf("%T", node)
		name = strings.TrimPrefix(name, "*ast.")
		fmt.Fprintf(out, "%s %d %d\n", name, off(node.Pos()), off(node.End()))
		return true
	})
}
