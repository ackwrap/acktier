package secfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WritePrivate atomically writes secret data to path with strict owner-only OS permissions
// (0600 on Unix/macOS; Protected DACL restricted to SYSTEM, Administrators, and current user SID on Windows).
func WritePrivate(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("secfile: empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, wErr := f.Write(data)
	cErr := f.Close()
	if wErr != nil {
		_ = os.Remove(tmp)
		return wErr
	}
	if cErr != nil {
		_ = os.Remove(tmp)
		return cErr
	}
	if err := restrictFileOwnerOnly(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return restrictFileOwnerOnly(path)
}
