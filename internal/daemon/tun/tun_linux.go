//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	cIFFTUN    = 0x0001
	cIFFNOPI   = 0x1000
	cTUNSETIFF = 0x400454ca
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [22]byte
}

type linuxTUN struct {
	name string
	mtu  int
	file *os.File
}

// CreateOSDevice opens a native Linux /dev/net/tun interface.
func CreateOSDevice(ifName string, mtu int) (Device, error) {
	ifName = interfaceNameOrDefault(ifName)
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (run with sudo/CAP_NET_ADMIN or --tun=memory)", err)
	}

	var req ifReq
	copy(req.Name[:15], ifName)
	req.Flags = cIFFTUN | cIFFNOPI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(cTUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF(%s): %w", ifName, errno)
	}

	actualName := cString(req.Name[:])
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	return &linuxTUN{
		name: actualName,
		mtu:  mtu,
		file: os.NewFile(uintptr(fd), "/dev/net/tun"),
	}, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (d *linuxTUN) Name() string { return d.name }
func (d *linuxTUN) MTU() int     { return d.mtu }

func (d *linuxTUN) ReadPacket(buf []byte) (int, error) {
	return d.file.Read(buf)
}

func (d *linuxTUN) WritePacket(pkt []byte) error {
	_, err := d.file.Write(pkt)
	return err
}

func (d *linuxTUN) Configure(ipv4 netip.Prefix, ipv6 netip.Prefix, routes []netip.Prefix) error {
	_ = exec.Command("ip", "link", "set", "dev", d.name, "mtu", strconv.Itoa(d.mtu), "up").Run()
	if ipv4.IsValid() {
		_ = exec.Command("ip", "-4", "addr", "flush", "dev", d.name).Run()
		if err := exec.Command("ip", "-4", "addr", "add", ipv4.String(), "dev", d.name).Run(); err != nil {
			return fmt.Errorf("configure ipv4 on %s: %w", d.name, err)
		}
	}
	if ipv6.IsValid() {
		_ = exec.Command("ip", "-6", "addr", "replace", ipv6.String(), "dev", d.name).Run()
	}
	for _, rt := range routes {
		_ = exec.Command("ip", "route", "replace", rt.String(), "dev", d.name).Run()
	}
	return nil
}

func (d *linuxTUN) Close() error {
	return d.file.Close()
}
