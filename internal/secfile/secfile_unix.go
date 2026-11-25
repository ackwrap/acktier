//go:build !windows

package secfile

import "os"

func restrictFileOwnerOnly(path string) error {
	return os.Chmod(path, 0o600)
}
