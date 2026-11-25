//go:build !windows

package secfile

import (
	"os"
	"testing"
)

func assertPrivate(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("temporary secret has non-owner permissions: %o", st.Mode().Perm())
	}
}
