//go:build windows

package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wintunRingCapacity = 0x400000 // 4 MiB ring buffer
	waitObject0        = 0x00000000
	errorNoMoreItems   = 259
)

type windowsTUN struct {
	name string
	mtu  int

	dll                *windows.DLL
	procCloseAdapter   *windows.Proc
	procEndSession     *windows.Proc
	procReceivePacket  *windows.Proc
	procReleaseReceive *windows.Proc
	procAllocateSend   *windows.Proc
	procSendPacket     *windows.Proc

	adapter   uintptr
	session   uintptr
	readEvent syscall.Handle

	closeOnce sync.Once
	closedCh  chan struct{}
	mu        sync.RWMutex
}

// loadWintun trusts the installation directory containing the running executable.
func loadWintun(executable string) (*windows.DLL, error) {
	if !filepath.IsAbs(executable) {
		return nil, errors.New("Wintun requires an absolute executable path")
	}
	path := filepath.Join(filepath.Dir(executable), "wintun.dll")
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, &os.PathError{Op: "load", Path: path, Err: err}
	}
	return &windows.DLL{Name: path, Handle: handle}, nil
}

// CreateOSDevice dynamically loads wintun.dll and creates an L3 Wintun adapter on Windows.
func CreateOSDevice(ifName string, mtu int) (Device, error) {
	ifName = interfaceNameOrDefault(ifName)
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	nameUTF16, err := syscall.UTF16PtrFromString(ifName)
	if err != nil {
		return nil, fmt.Errorf("invalid Wintun adapter name: %w", err)
	}
	typeUTF16, _ := syscall.UTF16PtrFromString("AckTier")

	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate Wintun installation: %w", err)
	}
	dll, err := loadWintun(executable)
	if err != nil {
		return nil, fmt.Errorf("%w (install trusted wintun.dll next to the executable or run with -tun memory)", err)
	}
	dev := &windowsTUN{name: ifName, mtu: mtu, dll: dll, closedCh: make(chan struct{})}
	ready := false
	defer func() {
		if !ready {
			_ = dev.Close()
		}
	}()

	var procCreateAdapter, procStartSession, procGetReadWaitEvent *windows.Proc
	for _, export := range []struct {
		name string
		proc **windows.Proc
	}{
		{"WintunCreateAdapter", &procCreateAdapter},
		{"WintunStartSession", &procStartSession},
		{"WintunGetReadWaitEvent", &procGetReadWaitEvent},
		{"WintunCloseAdapter", &dev.procCloseAdapter},
		{"WintunEndSession", &dev.procEndSession},
		{"WintunReceivePacket", &dev.procReceivePacket},
		{"WintunReleaseReceivePacket", &dev.procReleaseReceive},
		{"WintunAllocateSendPacket", &dev.procAllocateSend},
		{"WintunSendPacket", &dev.procSendPacket},
	} {
		proc, err := dll.FindProc(export.name)
		if err != nil {
			return nil, fmt.Errorf("resolve Wintun exports: %w", err)
		}
		*export.proc = proc
	}

	adapter, _, err := procCreateAdapter.Call(
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(typeUTF16)),
		0,
	)
	if adapter == 0 {
		return nil, fmt.Errorf("WintunCreateAdapter failed (Administrator privileges required): %w", err)
	}
	dev.adapter = adapter

	session, _, err := procStartSession.Call(adapter, wintunRingCapacity)
	if session == 0 {
		return nil, fmt.Errorf("WintunStartSession failed: %w", err)
	}
	dev.session = session

	ev, _, _ := procGetReadWaitEvent.Call(session)
	dev.readEvent = syscall.Handle(ev)
	ready = true
	return dev, nil
}

func (d *windowsTUN) Name() string { return d.name }
func (d *windowsTUN) MTU() int     { return d.mtu }

func (d *windowsTUN) ReadPacket(buf []byte) (int, error) {
	for {
		select {
		case <-d.closedCh:
			return 0, io.EOF
		default:
		}

		d.mu.RLock()
		if d.session == 0 {
			d.mu.RUnlock()
			return 0, io.EOF
		}
		var pktSize uint32
		ptr, _, callErr := d.procReceivePacket.Call(d.session, uintptr(unsafe.Pointer(&pktSize)))
		if ptr != 0 {
			n := int(pktSize)
			if n <= len(buf) {
				src := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), n)
				copy(buf[:n], src)
			}
			_, _, _ = d.procReleaseReceive.Call(d.session, ptr)
			d.mu.RUnlock()
			if n > len(buf) {
				return 0, errors.New("wintun: packet larger than read buffer")
			}
			return n, nil
		}
		d.mu.RUnlock()

		if errno, ok := callErr.(syscall.Errno); ok && errno != errorNoMoreItems && errno != 0 {
			return 0, fmt.Errorf("WintunReceivePacket: %w", errno)
		}

		// Wait up to 200ms on Wintun kernel event so Close() stays responsive
		_, _ = syscall.WaitForSingleObject(d.readEvent, 200)
	}
}

func (d *windowsTUN) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.session == 0 {
		return io.ErrClosedPipe
	}
	ptr, _, err := d.procAllocateSend.Call(d.session, uintptr(len(pkt)))
	if ptr == 0 {
		return fmt.Errorf("WintunAllocateSendPacket: %w", err)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(pkt))
	copy(dst, pkt)
	_, _, _ = d.procSendPacket.Call(d.session, ptr)
	return nil
}

func (d *windowsTUN) Configure(ipv4 netip.Prefix, ipv6 netip.Prefix, routes []netip.Prefix) error {
	if ipv4.IsValid() {
		mask := net.CIDRMask(ipv4.Bits(), 32)
		maskStr := net.IP(mask).String()
		cmd := exec.Command("netsh", "interface", "ip", "set", "address",
			fmt.Sprintf("name=%s", d.name), "source=static",
			fmt.Sprintf("addr=%s", ipv4.Addr().String()),
			fmt.Sprintf("mask=%s", maskStr), "gateway=none")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh set ipv4: %v (%s)", err, string(out))
		}
	}
	if ipv6.IsValid() {
		_ = exec.Command("netsh", "interface", "ipv6", "set", "address",
			fmt.Sprintf("interface=%s", d.name),
			fmt.Sprintf("address=%s", ipv6.String())).Run()
	}
	for _, rt := range routes {
		_ = exec.Command("netsh", "interface", "ip", "add", "route",
			rt.String(), d.name).Run()
	}
	return nil
}

func (d *windowsTUN) Close() error {
	d.closeOnce.Do(func() {
		close(d.closedCh)
		d.mu.Lock()
		if d.session != 0 {
			_, _, _ = d.procEndSession.Call(d.session)
			d.session = 0
		}
		if d.adapter != 0 {
			_, _, _ = d.procCloseAdapter.Call(d.adapter)
			d.adapter = 0
		}
		_ = d.dll.Release()
		d.mu.Unlock()
	})
	return nil
}
