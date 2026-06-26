package main

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
)

// newDiscardLogger returns a Config with a zerolog logger that discards all output.
func newDiscardLogger() *Config {
	return &Config{
		Logger: zerolog.New(io.Discard),
	}
}

// newDNSQuery builds a minimal DNS query packet for the given domain and type.
func newDNSQuery(domain string, qtype layers.DNSType) *layers.DNS {
	return &layers.DNS{
		QR: false,
		Questions: []layers.DNSQuestion{
			{Name: []byte(domain), Type: qtype},
		},
	}
}

// ─── checkWildcard ───────────────────────────────────────────────────────────

func TestCheckWildcard_ExactMatch(t *testing.T) {
	if !checkWildcard("example.com", "example.com", false) {
		t.Error("expected exact match to return true")
	}
}

func TestCheckWildcard_WildcardSingleLabel(t *testing.T) {
	if !checkWildcard("*.example.com", "foo.example.com", false) {
		t.Error("expected wildcard match to return true")
	}
}

func TestCheckWildcard_WildcardDoesNotMatchSubdomain(t *testing.T) {
	// *.example.com should NOT match foo.bar.example.com (different number of parts)
	if checkWildcard("*.example.com", "foo.bar.example.com", false) {
		t.Error("expected length mismatch to return false")
	}
}

func TestCheckWildcard_WildcardWrongLabel(t *testing.T) {
	// Wildcard matches any single label, but second part must match
	if checkWildcard("*.example.com", "foo.other.com", false) {
		t.Error("expected non-matching label to return false")
	}
}

func TestCheckWildcard_LengthMismatch_Shorter(t *testing.T) {
	if checkWildcard("*.example.com", "example.com", false) {
		t.Error("expected shorter domain to return false")
	}
}

func TestCheckWildcard_LengthMismatch_Longer(t *testing.T) {
	if checkWildcard("example.com", "sub.example.com", false) {
		t.Error("expected longer domain to return false")
	}
}

func TestCheckWildcard_MultipleWildcards(t *testing.T) {
	if !checkWildcard("*.*", "foo.bar", false) {
		t.Error("expected double wildcard to match foo.bar")
	}
}

func TestCheckWildcard_NoMatch(t *testing.T) {
	if checkWildcard("example.com", "other.com", false) {
		t.Error("expected non-matching domain to return false")
	}
}

// ─── checkWildcard greedy ─────────────────────────────────────────────────────

func TestCheckWildcardGreedy_SingleLabelMatch(t *testing.T) {
	if !checkWildcard("*.example.com", "bam.example.com", true) {
		t.Error("expected single-label match to return true")
	}
}

func TestCheckWildcardGreedy_MultiLabelMatch(t *testing.T) {
	if !checkWildcard("*.example.com", "foo.bar.bam.example.com", true) {
		t.Error("expected multi-label match to return true")
	}
}

func TestCheckWildcardGreedy_ZeroLabelMatch(t *testing.T) {
	// * can match zero labels
	if !checkWildcard("*.example.com", "example.com", true) {
		t.Error("expected zero-label match to return true")
	}
}

func TestCheckWildcardGreedy_WildcardEndMatch(t *testing.T) {
	// * can match at the end
	if !checkWildcard("example.*", "example.foo.ca", true) {
		t.Error("expected wildcard end match to return true")
	}
}

func TestCheckWildcardGreedy_WrongSuffix(t *testing.T) {
	if checkWildcard("*.example.com", "example.com.ca", true) {
		t.Error("expected wrong suffix to return false")
	}
}

func TestCheckWildcardGreedy_ExactMatch(t *testing.T) {
	if !checkWildcard("example.com", "example.com", true) {
		t.Error("expected exact match to return true")
	}
}

func TestCheckWildcardGreedy_MiddleWildcard_SingleLabel(t *testing.T) {
	if !checkWildcard("foo.*.example.com", "foo.bar.example.com", true) {
		t.Error("expected middle wildcard single-label match to return true")
	}
}

func TestCheckWildcardGreedy_MiddleWildcard_MultiLabel(t *testing.T) {
	if !checkWildcard("foo.*.example.com", "foo.bar.bam.example.com", true) {
		t.Error("expected middle wildcard multi-label match to return true")
	}
}

func TestCheckWildcardGreedy_MiddleWildcard_ZeroLabel(t *testing.T) {
	// * can match zero labels in middle position too
	if !checkWildcard("foo.*.example.com", "foo.example.com", true) {
		t.Error("expected middle wildcard zero-label match to return true")
	}
}

func TestCheckWildcardGreedy_MiddleWildcard_WrongPrefix(t *testing.T) {
	if checkWildcard("foo.*.example.com", "bar.baz.example.com", true) {
		t.Error("expected wrong prefix to return false")
	}
}

func TestCheckWildcardGreedy_WrongDomain(t *testing.T) {
	if checkWildcard("*.example.com", "foo.other.com", true) {
		t.Error("expected non-matching domain to return false")
	}
}

// ─── filterDns ───────────────────────────────────────────────────────────────

func TestFilterDns_Response_NotFiltered(t *testing.T) {
	cfg := newDiscardLogger()
	req := &layers.DNS{QR: true, Questions: []layers.DNSQuestion{
		{Name: []byte("example.com"), Type: layers.DNSTypeA},
	}}
	if filterDns(req, cfg) {
		t.Error("DNS response (QR=true) should not be filtered")
	}
}

func TestFilterDns_MultipleQuestions_NotFiltered(t *testing.T) {
	cfg := newDiscardLogger()
	req := &layers.DNS{
		QR: false,
		Questions: []layers.DNSQuestion{
			{Name: []byte("a.com"), Type: layers.DNSTypeA},
			{Name: []byte("b.com"), Type: layers.DNSTypeA},
		},
	}
	if filterDns(req, cfg) {
		t.Error("request with multiple questions should not be filtered")
	}
}

func TestFilterDns_NonARecord_NotFiltered(t *testing.T) {
	cfg := newDiscardLogger()
	req := newDNSQuery("example.com", layers.DNSTypeAAAA)
	if filterDns(req, cfg) {
		t.Error("non-A record query should not be filtered")
	}
}

func TestFilterDns_EmptyBlocklistAndSafelist_PassThrough(t *testing.T) {
	cfg := newDiscardLogger()
	req := newDNSQuery("example.com", layers.DNSTypeA)
	if filterDns(req, cfg) {
		t.Error("query with no blocklist/safelist rules should pass through")
	}
}

func TestFilterDns_Blocklist_DomainBlocked(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.BlockList = []string{"evil.com"}
	req := newDNSQuery("evil.com", layers.DNSTypeA)
	if !filterDns(req, cfg) {
		t.Error("domain on blocklist should be filtered")
	}
}

func TestFilterDns_Blocklist_DomainNotBlocked(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.BlockList = []string{"evil.com"}
	req := newDNSQuery("good.com", layers.DNSTypeA)
	if filterDns(req, cfg) {
		t.Error("domain not on blocklist should pass through")
	}
}

func TestFilterDns_Blocklist_WildcardBlocked(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.BlockList = []string{"*.evil.com"}
	req := newDNSQuery("sub.evil.com", layers.DNSTypeA)
	if !filterDns(req, cfg) {
		t.Error("wildcard blocklist domain should be filtered")
	}
}

func TestFilterDns_Safelist_DomainAllowed(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.SafeList = []string{"good.com"}
	req := newDNSQuery("good.com", layers.DNSTypeA)
	// Domain is on safelist → should NOT be filtered
	if filterDns(req, cfg) {
		t.Error("domain on safelist should pass through")
	}
}

func TestFilterDns_Safelist_DomainBlocked(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.SafeList = []string{"good.com"}
	req := newDNSQuery("unlisted.com", layers.DNSTypeA)
	// Safelist is active but domain is not on it → should be filtered
	if !filterDns(req, cfg) {
		t.Error("domain not on safelist should be filtered when safelist is active")
	}
}

func TestFilterDns_Safelist_WildcardAllowed(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.SafeList = []string{"*.safe.com"}
	req := newDNSQuery("api.safe.com", layers.DNSTypeA)
	if filterDns(req, cfg) {
		t.Error("wildcard safelist domain should pass through")
	}
}

func TestFilterDns_Safelist_WildcardBlocked(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.SafeList = []string{"*.safe.com"}
	req := newDNSQuery("api.other.com", layers.DNSTypeA)
	if !filterDns(req, cfg) {
		t.Error("domain not matching safelist wildcard should be filtered")
	}
}

func TestFilterDns_SentinelDomain_Excluded(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.ForwardToSentinel = true
	cfg.LogAnalyticsWorkspaceId = "myworkspace"
	// SafeList intentionally empty — domain still should not be filtered
	cfg.SafeList = []string{"other.com"}
	req := newDNSQuery("myworkspace.ods.opinsights.azure.com", layers.DNSTypeA)
	if filterDns(req, cfg) {
		t.Error("sentinel workspace domain should never be filtered")
	}
}

func TestFilterDns_SentinelDisabled_WorkspaceDomainFiltered(t *testing.T) {
	cfg := newDiscardLogger()
	cfg.ForwardToSentinel = false
	cfg.LogAnalyticsWorkspaceId = "myworkspace"
	cfg.SafeList = []string{"other.com"}
	req := newDNSQuery("myworkspace.ods.opinsights.azure.com", layers.DNSTypeA)
	// ForwardToSentinel is false, domain is not on safelist → should be filtered
	if !filterDns(req, cfg) {
		t.Error("workspace domain should be filtered when ForwardToSentinel is false and not on safelist")
	}
}

func TestFilterDns_Blocklist_SafelistTakesPrecedence(t *testing.T) {
	// When SafeList is active, BlockList is ignored entirely.
	cfg := newDiscardLogger()
	cfg.SafeList = []string{"good.com"}
	cfg.BlockList = []string{"good.com"} // blocklist is irrelevant when safelist is set
	req := newDNSQuery("good.com", layers.DNSTypeA)
	if filterDns(req, cfg) {
		t.Error("safelist should take precedence over blocklist")
	}
}

// helper to build a minimal DNS query with ID
func makeDNSQueryWithID(id uint16, domain string, qtype layers.DNSType) *layers.DNS {
	return &layers.DNS{
		ID:        id,
		QR:        false,
		Questions: []layers.DNSQuestion{{Name: []byte(domain), Type: qtype}},
	}
}

// Test the branch in proxyRequest that returns a filtered DNS response to the client.
func TestProxyRequest_BlockedResponse(t *testing.T) {
	// prepare a UDP listener that will act as the client receiving the response
	recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to create recv socket: %v", err)
	}
	defer recvConn.Close()

	// sender socket used by proxyRequest to write responses
	sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to create send socket: %v", err)
	}
	defer sendConn.Close()

	cfg := &Config{
		Logger:    zerolog.New(io.Discard),
		BlockList: []string{"evil.com"},
	}

	// Build a request that should be filtered
	req := makeDNSQueryWithID(0x1234, "evil.com", layers.DNSTypeA)

	// call the function under test
	proxyRequest(sendConn, recvConn.LocalAddr(), req, cfg)

	// read the response from the recv socket
	_ = recvConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := recvConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	packet := gopacket.NewPacket(buf[:n], layers.LayerTypeDNS, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		t.Fatalf("no DNS layer in response")
	}
	resp := dnsLayer.(*layers.DNS)

	if !resp.QR {
		t.Errorf("expected response QR=true, got false")
	}
	if resp.ID != req.ID {
		t.Errorf("expected response ID %d, got %d", req.ID, resp.ID)
	}
	if resp.ANCount != 0 {
		t.Errorf("expected ANCount 0 for blocked response, got %d", resp.ANCount)
	}
}
