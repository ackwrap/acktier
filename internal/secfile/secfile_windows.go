//go:build windows

package secfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createPrivateTemp(dir string) (*os.File, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("secfile: query token user: %w", err)
	}
	sidStr := tu.User.Sid.String()
	// Protected DACL (D:P): disable inheritance and grant Full Access ONLY to LocalSystem (SY),
	// Builtin Administrators (BA), and the exact current process owner SID.
	sddl := fmt.Sprintf("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)", sidStr)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("secfile: build security descriptor: %w", err)
	}
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.SecurityDescriptor = sd
	for range 10 {
		var suffix [16]byte
		_, _ = rand.Read(suffix[:])
		path := filepath.Join(dir, ".acktier-"+hex.EncodeToString(suffix[:]))
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "create private file", Path: path, Err: err}
		}
		return os.NewFile(uintptr(h), path), nil
	}
	return nil, fmt.Errorf("secfile: cannot allocate a unique temporary file in %s", dir)
}
