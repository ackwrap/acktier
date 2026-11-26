package filter

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/ackwrap/acktier/internal/daemon/pktutil"
	"github.com/ackwrap/acktier/pkg/types"
)

func TestReplacingPolicyRevokesTrackedReplies(t *testing.T) {
	f := New()
	a := netip.MustParseAddr("100.64.0.1")
	b := netip.MustParseAddr("100.64.0.2")
	allow := []types.FilterRule{{
		Action: types.FilterAccept, IPProto: pktutil.ProtoTCP,
		SrcPrefixes:  []netip.Prefix{netip.PrefixFrom(a, 32)},
		DstPrefixes:  []netip.Prefix{netip.PrefixFrom(b, 32)},
		DstPortStart: 443, DstPortEnd: 443,
	}}
	deny := []types.FilterRule{{Action: types.FilterDrop}}
	out := pktutil.BuildTCPPacket(a, b, 40000, 443, 1, 0, pktutil.TCPFlagSYN, 4096, nil)
	reply := pktutil.BuildTCPPacket(b, a, 443, 40000, 1, 2, pktutil.TCPFlagSYN|pktutil.TCPFlagACK, 4096, nil)
	f.SetRules(allow)
	if !f.AllowOutbound(out) || !f.AllowInbound(reply) || f.AllowOutbound(reply) {
		t.Fatal("return path was not tracked in the correct direction")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				f.AllowOutbound(out)
			}
		})
	}
	f.SetRules(deny)
	wg.Wait()
	if f.AllowInbound(reply) || f.AllowOutbound(out) {
		t.Fatal("replaced policy left an obsolete connection entry")
	}
}
