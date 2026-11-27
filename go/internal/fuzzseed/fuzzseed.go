// Package fuzzseed seeds fuzz corpora from the test vectors
// (../test-vectors): every hex string and every short text string found in
// the vector files.
package fuzzseed

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Dir returns the test-vectors directory: $SPARROW_VECTORS, or the
// repository's test-vectors directory. (This package imports nothing of the
// module, so that any package's internal tests can use it.)
func Dir() string {
	if d := os.Getenv("SPARROW_VECTORS"); d != "" {
		return d
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "test-vectors")
}

// files returns the vector files with the given base names (all of them,
// scenarios included, when none is given).
func files(names []string) []string {
	if len(names) == 0 {
		top, _ := filepath.Glob(filepath.Join(Dir(), "*.json"))
		sc, _ := filepath.Glob(filepath.Join(Dir(), "scenarios", "*.json"))
		return append(top, sc...)
	}
	var out []string
	for _, n := range names {
		out = append(out, filepath.Join(Dir(), n))
	}
	return out
}

func walk(v any, f func(string)) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(x[k], f)
		}
	case []any:
		for _, e := range x {
			walk(e, f)
		}
	case string:
		f(x)
	}
}

func strings(names []string, keep func(string) ([]byte, bool)) [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	for _, p := range files(names) {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var v any
		if json.Unmarshal(b, &v) != nil {
			continue
		}
		walk(v, func(s string) {
			if seen[s] {
				return
			}
			seen[s] = true
			if b, ok := keep(s); ok {
				out = append(out, b)
			}
		})
	}
	return out
}

// Hex returns the distinct non-empty hex strings of the named vector files
// (all files when none is named), decoded.
func Hex(names ...string) [][]byte {
	return strings(names, func(s string) ([]byte, bool) {
		if len(s) < 2 || len(s)%2 != 0 {
			return nil, false
		}
		b, err := hex.DecodeString(s)
		return b, err == nil
	})
}

// Text returns the distinct strings of at most 200 bytes that are not hex
// in the named vector files (all files when none is named).
func Text(names ...string) []string {
	var out []string
	for _, b := range strings(names, func(s string) ([]byte, bool) {
		if len(s) > 200 {
			return nil, false
		}
		if _, err := hex.DecodeString(s); err == nil && s != "" {
			return nil, false
		}
		return []byte(s), true
	}) {
		out = append(out, string(b))
	}
	return out
}
