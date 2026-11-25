package secfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivate(t *testing.T) {
	dir := t.TempDir()
	f, err := createPrivateTemp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, f.Name()) // Permissions must be correct before any bytes are written.
	if err := os.Remove(f.Name()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "secret.json")
	for _, want := range []string{"first", "second"} {
		if err := WritePrivate(path, []byte(want)); err != nil {
			t.Fatal(err)
		}
		assertPrivate(t, path)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("replacement contents did not match: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file was not removed: %v", err)
	}
}
