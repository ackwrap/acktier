package secfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WritePrivate replaces a secret file using a temporary file that is private
// from creation. The parent directory must be controlled by the caller.
func WritePrivate(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("secfile: empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := createPrivateTemp(dir)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	return nil
}
