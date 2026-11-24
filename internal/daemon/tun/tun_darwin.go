//go:build darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	utunControlName = "com.apple.net.utun_control"
	ctlIOCGINFO     = 0xc0644e03
	afSysControl    = 2
	sysprotoControl = 2
	utunOptIfname   = 2
)

type ctlInfo struct {
	CtlID   uint32
	CtlName [96]byte
}

type sockaddrCtl struct {
	ScLen      uint8
	ScFamily   uint8
	SsSysaddr  uint16
	ScID       uint32
	ScUnit     uint32
	ScReserved [5]uint32
}

type darwinTUN struct {
	name string
	mtu  int
	file *os.File
}

// CreateOSDevice opens a native macOS kernel utun interface.
func CreateOSDevice(_ string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	fd, err := syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("utun socket: %w (run with sudo)", err)
	}

	var info ctlInfo
	copy(info.CtlName[:], utunControlName)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(ctlIOCGINFO), uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO: %w", errno)
	}

	sc := sockaddrCtl{
		ScLen:     uint8(unsafe.Sizeof(sockaddrCtl{})),
		ScFamily:   syscall.AF_SYSTEM,
		SsSysaddr: afSysControl,
		ScID:      info.CtlID,
		ScUnit:    0, // dynamic utunN assignment
	}
	_, _, errno = syscall.RawSyscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sc)),
		uintptr(sc.ScLen),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("connect utun: %w", errno)
	}

	var ifNameBuf [32]byte
	ifNameLen := uint32(len(ifNameBuf))
	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		sysprotoControl,
		utunOptIfname,
		uintptr(unsafe.Pointer(&ifNameBuf[0])),
		uintptr(unsafe.Pointer(&ifNameLen)),
		0,
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %w", errno)
	}
	actualName := string(ifNameBuf[:ifNameLen-1])
	_ = syscall.SetNonblock(fd, true)

	return &darwinTUN{
		name: actualName,
		mtu:  mtu,
		file: os.NewFile(uintptr(fd), actualName),
	}, nil
}

func (d *darwinTUN) Name() string { return d.name }
func (d *darwinTUN) MTU() int     { return d.mtu }

func (d *darwinTUN) ReadPacket(buf []byte) (int, error) {
	tmp := make([]byte, len(buf)+4)
	n, err := d.file.Read(tmp)
	if err != nil || n <= 4 {
		return 0, err
	}
	copy(buf, tmp[4:n])
	return n - 4, nil
}

func (d *darwinTUN) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	out := make([]byte, len(pkt)+4)
	if (pkt[0] >> 4) == 6 {
		binary.BigEndian.PutUint32(out[0:4], syscall.AF_INET6)
	} else {
		binary.BigEndian.PutUint32(out[0:4], syscall.AF_INET)
	}
	copy(out[4:], pkt)
	_, err := d.file.Write(out)
	return err
}

func (d *darwinTUN) Configure(ipv4 netip.Prefix, ipv6 netip.Prefix, routes []netip.Prefix) error {
	_ = exec.Command("ifconfig", d.name, "mtu", strconv.Itoa(d.mtu), "up").Run()
	if ipv4.IsValid() {
		addr := ipv4.Addr().String()
		if err := exec.Command("ifconfig", d.name, "inet", addr, addr, "up").Run(); err != nil {
			return fmt.Errorf("ifconfig %s: %w", d.name, err)
		}
		_ = exec.Command("route", "-q", "-n", "add", "-inet", ipv4.Masked().String(), "-interface", d.name).Run()
	}
	if ipv6.IsValid() {
		_ = exec.Command("ifconfig", d.name, "inet6", ipv6.String(), "up").Run()
	}
	for _, rt := range routes {
		_ = exec.Command("route", "-q", "-n", "add", "-inet", rt.String(), "-interface", d.name).Run()
	}
	return nil
}

func (d *darwinTUN) Close() error {
	return d.file.Close()
}
