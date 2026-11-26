package secfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsurePrivateDir creates a protected directory or verifies an existing one.
// It never changes permissions on an existing directory.
func EnsurePrivateDir(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := createPrivateDir(path); err != nil && !os.IsExist(err) {
			return err
		}
	}
	return checkPrivatePath(path, true)
}

// CheckPrivateFile checks an existing file without following symlinks.
func CheckPrivateFile(path string) error {
	return checkPrivatePath(path, false)
}

func checkPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("secfile: unexpected file type at %s", path)
	}
	if err := checkPrivatePermissions(path, info); err != nil {
		return fmt.Errorf("secfile: %s: %w", path, err)
	}
	return nil
}
