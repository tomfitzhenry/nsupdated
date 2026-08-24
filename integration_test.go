package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/dnsrr"

	"github.com/tomfitzhenry/nsupdated/internal/provider"
	"github.com/tomfitzhenry/nsupdated/internal/rfc2136"
)

// fakeProvider is an in-memory DNSControl DNS service provider: GetZoneRecords
// returns the stored records, and GetZoneRecordsCorrections replaces them.
type fakeProvider struct {
	mu      sync.Mutex
	records models.Records
}

func (f *fakeProvider) GetNameservers(string) ([]*models.Nameserver, error) { return nil, nil }

func (f *fakeProvider) GetZoneRecords(*models.DomainConfig) (models.Records, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records, nil
}

func (f *fakeProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, actual models.Records) ([]*models.Correction, int, error) {
	desired := dc.Records
	return []*models.Correction{{
		Msg: "set zone",
		F: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.records = append(models.Records(nil), desired...)
			return nil
		},
	}}, 0, nil
}

// startStack starts the proxy backed by an in-memory provider, returning the
// proxy's Unix socket path.
func startStack(t *testing.T) (sock string, fake *fakeProvider) {
	t.Helper()

	fake = &fakeProvider{}
	recs := provider.New(fake)

	sock = filepath.Join(t.TempDir(), "nsupdated.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	handler := &rfc2136.Handler{
		Records: recs,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv := &dns.Server{
		Listener:    ln,
		Handler:     dns.HandlerFunc(handler.ServeDNS),
		ReadTimeout: 5 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	t.Cleanup(func() {
		srv.Shutdown(context.Background())
		os.Remove(sock)
	})
	go srv.ListenAndServe()
	return sock, fake
}

func newUpdate(zone string) *dns.Msg {
	u := dns.NewMsg(zone, dns.TypeSOA)
	u.Opcode = dns.OpcodeUpdate
	return u
}

func rr(name string, args ...string) dns.RR {
	line := name + " 300 IN " + strings.Join(args, " ")
	out, err := dns.New(line)
	if err != nil {
		panic(err)
	}
	return out
}

func doUpdate(t *testing.T, sock string, m *dns.Msg) *dns.Msg {
	t.Helper()
	resp, err := dns.Exchange(context.Background(), m, "unix", sock)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return resp
}

func axfr(t *testing.T, sock, zone string) []dns.RR {
	t.Helper()
	c := dns.NewClient()
	m := dns.NewMsg(zone, dns.TypeAXFR)
	env, err := c.TransferIn(context.Background(), m, "unix", sock)
	if err != nil {
		t.Fatalf("transfer in: %v", err)
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			t.Fatalf("transfer: %v", e.Error)
		}
		rrs = append(rrs, e.Answer...)
	}
	return rrs
}

func TestIntegrationAddThenAXFR(t *testing.T) {
	sock, _ := startStack(t)

	u := newUpdate("example.com.")
	u.Ns = []dns.RR{rr("www.example.com.", "A", "1.2.3.4")}
	if resp := doUpdate(t, sock, u); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add rcode = %v, want success", resp.Rcode)
	}

	rrs := axfr(t, sock, "example.com.")
	if len(rrs) < 3 {
		t.Fatalf("axfr returned %d RRs, want at least 3", len(rrs))
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Errorf("axfr must start with SOA, got %T", rrs[0])
	}
	if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
		t.Errorf("axfr must end with SOA, got %T", rrs[len(rrs)-1])
	}
	var found bool
	for _, r := range rrs {
		if a, ok := r.(*dns.A); ok && a.A.Addr.String() == "1.2.3.4" && a.Hdr.Name == "www.example.com." {
			found = true
		}
	}
	if !found {
		t.Errorf("axfr missing added A record: %v", rrs)
	}
}

func TestIntegrationDeleteRRset(t *testing.T) {
	sock, _ := startStack(t)

	add := newUpdate("example.com.")
	add.Ns = []dns.RR{
		rr("www.example.com.", "A", "1.2.3.4"),
		rr("www.example.com.", "A", "5.6.7.8"),
	}
	if resp := doUpdate(t, sock, add); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add rcode = %v", resp.Rcode)
	}

	del := newUpdate("example.com.")
	d := rr("www.example.com.", "A", "1.2.3.4")
	d.Header().Class = dns.ClassANY
	d.Header().TTL = 0
	del.Ns = []dns.RR{d}
	if resp := doUpdate(t, sock, del); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("delete rcode = %v", resp.Rcode)
	}

	rrs := axfr(t, sock, "example.com.")
	for _, r := range rrs {
		if a, ok := r.(*dns.A); ok && a.Hdr.Name == "www.example.com." {
			t.Errorf("axfr still has deleted A record: %v", a)
		}
	}
}

func TestIntegrationDeleteSpecificValue(t *testing.T) {
	sock, _ := startStack(t)

	add := newUpdate("example.com.")
	add.Ns = []dns.RR{
		rr("www.example.com.", "A", "1.2.3.4"),
		rr("www.example.com.", "A", "5.6.7.8"),
	}
	if resp := doUpdate(t, sock, add); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add rcode = %v", resp.Rcode)
	}

	del := newUpdate("example.com.")
	d := rr("www.example.com.", "A", "1.2.3.4")
	d.Header().Class = dns.ClassNONE
	d.Header().TTL = 0
	del.Ns = []dns.RR{d}
	if resp := doUpdate(t, sock, del); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("delete rcode = %v", resp.Rcode)
	}

	rrs := axfr(t, sock, "example.com.")
	var left []string
	for _, r := range rrs {
		if a, ok := r.(*dns.A); ok && a.Hdr.Name == "www.example.com." {
			left = append(left, a.A.Addr.String())
		}
	}
	if len(left) != 1 || left[0] != "5.6.7.8" {
		t.Errorf("expected only 5.6.7.8 to remain, got %v", left)
	}
}

func TestIntegrationPrereqFailure(t *testing.T) {
	sock, _ := startStack(t)

	u := newUpdate("example.com.")
	u.Answer = []dns.RR{rr("www.example.com.", "A", "9.9.9.9")}
	u.Ns = []dns.RR{rr("www.example.com.", "A", "1.2.3.4")}
	if resp := doUpdate(t, sock, u); resp.Rcode != dns.RcodeNXRrset {
		t.Fatalf("rcode = %v, want NXRRSET", resp.Rcode)
	}
}

func TestIntegrationNotZone(t *testing.T) {
	sock, _ := startStack(t)

	u := newUpdate("example.com.")
	u.Ns = []dns.RR{rr("www.other.net.", "A", "1.2.3.4")}
	if resp := doUpdate(t, sock, u); resp.Rcode != dns.RcodeNotZone {
		t.Fatalf("rcode = %v, want NOTZONE", resp.Rcode)
	}
}

func TestIntegrationTTL(t *testing.T) {
	sock, _ := startStack(t)

	u := newUpdate("example.com.")
	txt, err := dns.New(`ttl.example.com. 600 IN TXT "six hundred"`)
	if err != nil {
		t.Fatal(err)
	}
	u.Ns = []dns.RR{txt}
	if resp := doUpdate(t, sock, u); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %v", resp.Rcode)
	}

	rrs := axfr(t, sock, "example.com.")
	for _, r := range rrs {
		if txt, ok := r.(*dns.TXT); ok && txt.Hdr.Name == "ttl.example.com." {
			if txt.Hdr.TTL != 600 {
				t.Errorf("TTL = %d, want 600", txt.Hdr.TTL)
			}
			if got := recordconvTXT(txt); got != "six hundred" {
				t.Errorf("TXT = %q, want %q", got, "six hundred")
			}
		}
	}
}

// recordconvTXT recovers the raw text of a TXT record from its presentation
// form.
func recordconvTXT(txt *dns.TXT) string {
	var parts []string
	for _, s := range txt.Txt {
		parts = append(parts, unescape(s))
	}
	return strings.Join(parts, " ")
}

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		n := i + 1
		if n+2 < len(s) && s[n] >= '0' && s[n] <= '9' && s[n+1] >= '0' && s[n+1] <= '9' && s[n+2] >= '0' && s[n+2] <= '9' {
			b.WriteByte((s[n]-'0')*100 + (s[n+1]-'0')*10 + (s[n+2] - '0'))
			i = n + 2
			continue
		}
		b.WriteByte(s[n])
		i = n
	}
	return b.String()
}

func TestIntegrationSOAQuery(t *testing.T) {
	sock, _ := startStack(t)

	q := dns.NewMsg("example.com.", dns.TypeSOA)
	resp, err := dns.Exchange(context.Background(), q, "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %v", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 SOA answer, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.SOA); !ok {
		t.Errorf("answer = %T, want SOA", resp.Answer[0])
	}
}

func TestIntegrationTXTWithQuotes(t *testing.T) {
	sock, _ := startStack(t)

	u := newUpdate("example.com.")
	u.Ns = []dns.RR{rr("txt.example.com.", "TXT", `"quotes \" backslashes \\000"`)}
	if resp := doUpdate(t, sock, u); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %v: %v", resp.Rcode, resp)
	}

	rrs := axfr(t, sock, "example.com.")
	for _, r := range rrs {
		if txt, ok := r.(*dns.TXT); ok && txt.Hdr.Name == "txt.example.com." {
			if got := recordconvTXT(txt); got != `quotes " backslashes \000` {
				t.Errorf("TXT = %q, want %q", got, `quotes " backslashes \000`)
			}
		}
	}
}

// TestIntegrationAXFRUsesProviderSOA checks that a provider exposing its own
// SOA (like AXFRDDNS) has that SOA transferred, rather than a synthesized one.
func TestIntegrationAXFRUsesProviderSOA(t *testing.T) {
	sock, fake := startStack(t)

	rc := soaRecordConfig(t, 42)
	fake.mu.Lock()
	fake.records = models.Records{rc}
	fake.mu.Unlock()

	rrs := axfr(t, sock, "example.com.")
	first, firstOK := rrs[0].(*dns.SOA)
	last, lastOK := rrs[len(rrs)-1].(*dns.SOA)
	if !firstOK || !lastOK {
		t.Fatalf("transfer must start and end with SOA, got %T and %T", rrs[0], rrs[len(rrs)-1])
	}
	if first.Serial != 42 || last.Serial != 42 {
		t.Errorf("transfer SOA serials = %d and %d, want the provider's 42", first.Serial, last.Serial)
	}
	if first.Ns != "ns1.example.com." {
		t.Errorf("SOA Ns = %q, want the provider's ns1.example.com.", first.Ns)
	}
}

func soaRecordConfig(t *testing.T, serial uint32) *models.RecordConfig {
	t.Helper()
	rr, err := dns.New(fmt.Sprintf("example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. %d 3600 600 604800 3600", serial))
	if err != nil {
		t.Fatal(err)
	}
	dc, err := models.NewDomainConfig("example.com")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := dnsrr.RRv2toRC(dc, rr)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}
