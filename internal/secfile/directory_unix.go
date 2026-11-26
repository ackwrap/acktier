//go:build !windows

package secfile

import (
	"errors"
	"os"
)

func createPrivateDir(path string) error {
	return os.Mkdir(path, 0o700)
}

func checkPrivatePermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("use a private state directory (0700) and private files (0600)")
	}
	return nil
}
