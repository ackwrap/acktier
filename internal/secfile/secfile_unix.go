//go:build !windows

package secfile

import "os"

func createPrivateTemp(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".acktier-*")
}
