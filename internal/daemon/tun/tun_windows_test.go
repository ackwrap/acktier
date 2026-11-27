//go:build windows

package tun

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLoadWintunUsesExecutableDirectory(t *testing.T) {
	dir := t.TempDir()
	dll, err := loadWintun(filepath.Join(dir, "acktierd.exe"))
	if dll != nil {
		_ = dll.Release()
		t.Fatal("loaded Wintun from outside the installation directory")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Path != filepath.Join(dir, "wintun.dll") ||
		!errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		t.Fatalf("missing adjacent DLL returned %v", err)
	}
}
