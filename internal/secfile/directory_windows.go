//go:build windows

package secfile

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createPrivateDir(path string) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	// Child files, including SQLite journals, must inherit this DACL.
	sddl := fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", tu.User.Sid)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return windows.CreateDirectory(name, &sa)
}

func checkPrivatePermissions(path string, info os.FileInfo) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	allowed := func(sid *windows.SID) bool {
		return sid.Equals(tu.User.Sid) || sid.Equals(system) || sid.Equals(admins)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	notPrivate := errors.New("use a private state directory and files accessible only to the service account, SYSTEM, and Administrators")
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !allowed(owner) {
		return notPrivate
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return notPrivate
	}
	childrenInherit := false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !allowed(sid) {
				return notPrivate
			}
			if ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE != 0 {
				childrenInherit = true
			}
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny-only entry cannot grant additional access.
		default:
			return notPrivate
		}
	}
	if info.IsDir() && !childrenInherit {
		return errors.New("the private directory ACL must also apply to its files")
	}
	return nil
}
