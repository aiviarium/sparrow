// Command vectorgen generates the Sparrow test vectors.
//
//	go run . -out ../../test-vectors
//
// Output is deterministic: running it twice gives identical files.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", "../../test-vectors", "output directory")
	flag.Parse()
	files := []struct {
		name  string
		build func() O
	}{
		{"encoding.json", encodingVectors},
		{"framing.json", framingVectors},
		{"handshake.json", handshakeVectors},
		{"calls.json", callVectors},
		{"credit.json", creditVectors},
		{"schema.json", schemaVectors},
		{"signing.json", signingVectors},
		{"status.json", statusVectors},
		{"hub.json", hubVectors},
		{"admin.json", adminVectors},
	}
	must(os.MkdirAll(*out, 0o755))
	for _, f := range files {
		doc := append(o("generator", "tools/vectorgen-go"), f.build()...)
		buf := writeJSON(filepath.Join(*out, f.name), doc)
		var n struct {
			Vectors []json.RawMessage `json:"vectors"`
		}
		must(json.Unmarshal(buf, &n))
		fmt.Printf("%-16s %3d vectors\n", f.name, len(n.Vectors))
	}
	writeScenarios(*out)
}

// writeJSON writes an indented JSON document and returns its bytes.
func writeJSON(path string, doc any) []byte {
	raw, err := marshalNoEscape(doc)
	must(err)
	var buf bytes.Buffer
	must(json.Indent(&buf, raw, "", "  "))
	buf.WriteByte('\n')
	must(os.WriteFile(path, buf.Bytes(), 0o644))
	return buf.Bytes()
}
