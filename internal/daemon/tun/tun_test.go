package tun

import "testing"

func TestInterfaceNameOrDefault(t *testing.T) {
	if got := interfaceNameOrDefault(""); got != "acktier" {
		t.Errorf("default system TUN name = %q, want acktier", got)
	}
	const custom = "acktier-lab"
	if got := interfaceNameOrDefault(custom); got != custom {
		t.Errorf("custom system TUN name = %q, want %q", got, custom)
	}
}
