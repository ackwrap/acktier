//go:build windows

package secfile

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func restrictFileOwnerOnly(path string) error {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("secfile: query token user: %w", err)
	}
	sidStr := tu.User.Sid.String()
	// Protected DACL (D:P): disable inheritance and grant Full Access ONLY to LocalSystem (SY),
	// Builtin Administrators (BA), and the exact current process owner SID.
	sddl := fmt.Sprintf("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)", sidStr)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("secfile: build security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("secfile: extract dacl: %w", err)
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}
