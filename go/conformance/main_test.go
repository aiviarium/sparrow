package conformance

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
)

var (
	mu      sync.Mutex
	checked = map[string]bool{}
	files   = map[string]*vectors.File{}
)

// file loads a vector file once.
func file(t *testing.T, name string) *vectors.File {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if f, ok := files[name]; ok {
		return f
	}
	f, err := vectors.Load(name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	files[name] = f
	return f
}

// vector finds a vector by name in any file.
func vector(t *testing.T, name string) vectors.Vector {
	t.Helper()
	for _, fn := range allFiles(t) {
		for _, v := range file(t, fn).Vectors {
			if v.Name == name {
				return v
			}
		}
	}
	t.Fatalf("vector %q not found", name)
	return vectors.Vector{}
}

func allFiles(t *testing.T) []string {
	t.Helper()
	paths, err := vectors.Files()
	if err != nil || len(paths) == 0 {
		t.Fatalf("no vector files in %s: %v", vectors.Dir(), err)
	}
	var out []string
	for _, p := range paths {
		out = append(out, p[len(vectors.Dir())+1:])
	}
	return out
}

func markChecked(name string) {
	mu.Lock()
	checked[name] = true
	mu.Unlock()
}

// each runs fn as a subtest for every vector of the given types in a file
// and records the vectors that passed.
func each(t *testing.T, fileName string, fn func(t *testing.T, v vectors.Vector), types ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, ty := range types {
		want[ty] = true
	}
	for _, v := range file(t, fileName).Vectors {
		if len(types) > 0 && !want[v.Type] {
			continue
		}
		v := v
		if t.Run(v.Name, func(t *testing.T) { fn(t, v) }) {
			markChecked(v.Name)
		}
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	code := m.Run()
	if f := flag.Lookup("test.run"); code == 0 && (f == nil || f.Value.String() == "") {
		code = coverage()
	}
	os.Exit(code)
}

// coverage fails the run if any vector was not checked.
func coverage() int {
	paths, err := vectors.Files()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	total, missing := 0, []string{}
	perFile := []string{}
	for _, p := range paths {
		name := p[len(vectors.Dir())+1:]
		f, err := vectors.Load(name)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		n := 0
		for _, v := range f.Vectors {
			total++
			if checked[v.Name] {
				n++
			} else {
				missing = append(missing, name+": "+v.Name)
			}
		}
		perFile = append(perFile, fmt.Sprintf("%s %d/%d", name, n, len(f.Vectors)))
	}
	sort.Strings(missing)
	fmt.Printf("vector coverage: %d/%d vectors checked and passing (%v)\n", total-len(missing), total, perFile)
	if len(missing) > 0 {
		fmt.Printf("unchecked or failing vectors:\n")
		for _, m := range missing {
			fmt.Println("  " + m)
		}
		return 1
	}
	return 0
}
