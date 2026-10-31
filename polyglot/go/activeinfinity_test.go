package activeinfinity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type manifestCase struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	ContentHash string `json:"content_hash"`
}

type manifest struct {
	Cases []manifestCase `json:"cases"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func wasmPath(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	path := filepath.Join(root, "ffi", "active-infinity-ffi", "target",
		"wasm32-unknown-unknown", "release", "active_infinity_ffi.wasm")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("build the WASM module first: %v", err)
	}
	return path
}

func TestConformance(t *testing.T) {
	ctx := context.Background()
	instance, err := New(ctx, wasmPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close(ctx)

	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "conformance", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases manifest
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, entry := range cases.Cases {
		if entry.Kind != "valid" {
			continue
		}
		image, err := os.ReadFile(filepath.Join(root, entry.Path))
		if err != nil {
			t.Fatal(err)
		}
		if err := instance.Validate(ctx, image); err != nil {
			t.Fatalf("%s: %v", entry.Name, err)
		}
		hash, err := instance.ContentHashHex(ctx, image)
		if err != nil {
			t.Fatalf("%s: %v", entry.Name, err)
		}
		if hash != entry.ContentHash {
			t.Fatalf("%s: hash %s, want %s", entry.Name, hash, entry.ContentHash)
		}
		canonical, err := instance.Reencode(ctx, image)
		if err != nil {
			t.Fatalf("%s: %v", entry.Name, err)
		}
		if entry.Name == "non_canonical" {
			if string(canonical) == string(image) {
				t.Fatalf("%s: expected re-encoding to change bytes", entry.Name)
			}
		} else if string(canonical) != string(image) {
			t.Fatalf("%s: canonical bytes changed", entry.Name)
		}
		checked++
	}
	if checked < 4 {
		t.Fatalf("checked %d vectors", checked)
	}

	first, err := instance.FromActive(ctx, []byte("port = 8080\nname = \"go\"\n"), "go.active")
	if err != nil {
		t.Fatal(err)
	}
	second, err := instance.FromActive(ctx, []byte("port = 8080\nname = \"go\"\n"), "go.active")
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("Active source encoding is not deterministic")
	}
	if err := instance.Validate(ctx, first); err != nil {
		t.Fatal(err)
	}

	full, err := os.ReadFile(filepath.Join(root, "tests", "vectors", "valid", "full.ainf"))
	if err != nil {
		t.Fatal(err)
	}
	jsonText, err := instance.RedactedJSON(ctx, full)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jsonText, "CANARY_SECRET_") {
		t.Fatal("secret canary survived redaction")
	}
	if !json.Valid([]byte(jsonText)) {
		t.Fatal("redacted JSON is not valid JSON")
	}

	if err := instance.Validate(ctx, []byte{0xff, 0xff, 0xff}); err == nil {
		t.Fatal("malformed input was accepted")
	} else if !strings.HasPrefix(err.(*Error).Code, "infinity/") {
		t.Fatalf("unstable code %q", err.(*Error).Code)
	}
}
