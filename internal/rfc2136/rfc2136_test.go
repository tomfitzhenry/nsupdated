package rfc2136

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// fakeRecords is an in-memory Records implementation.
type fakeRecords struct {
	mu      sync.Mutex
	records []dns.RR

	sets [][]dns.RR
}

func (f *fakeRecords) GetRecords(_ context.Context, _ string) ([]dns.RR, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dns.RR(nil), f.records...), nil
}

func (f *fakeRecords) SetRecords(_ context.Context, _ string, actual, desired []dns.RR) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, desired)
	f.records = append([]dns.RR(nil), desired...)
	return nil
}

// stubResponseWriter captures what the handler writes so tests can unpack it.
type stubResponseWriter struct {
	mu   sync.Mutex
	data []byte
}

func (w *stubResponseWriter) LocalAddr() net.Addr   { return &net.UnixAddr{Name: "@", Net: "unix"} }
func (w *stubResponseWriter) RemoteAddr() net.Addr  { return &net.UnixAddr{Name: "@", Net: "unix"} }
func (w *stubResponseWriter) Conn() net.Conn        { return nil }
func (w *stubResponseWriter) Close() error          { return nil }
func (w *stubResponseWriter) Session() *dns.Session { return nil }
func (w *stubResponseWriter) Hijack()               {}
func (w *stubResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *stubResponseWriter) response(t *testing.T) *dns.Msg {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.data) < 2 {
		t.Fatalf("response too short: %d bytes", len(w.data))
	}
	// Stream responses are prefixed with a 2-byte length.
	var m dns.Msg
	m.Data = w.data[2:]
	if err := m.Unpack(); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return &m
}

func update(t *testing.T, zone string) *dns.Msg {
	t.Helper()
	u := dns.NewMsg(zone, dns.TypeSOA)
	u.Opcode = dns.OpcodeUpdate
	return u
}

func aRR(name, addr string) dns.RR {
	rr, err := dns.New(name + " 300 IN A " + addr)
	if err != nil {
		panic(err)
	}
	return rr
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testHandler(recs *fakeRecords) *Handler {
	return &Handler{
		Records: recs,
		Logger:  discardLogger(),
	}
}

// serve packs the request as the server would and drives the handler.
func serve(t *testing.T, h *Handler, u *dns.Msg) *dns.Msg {
	t.Helper()
	if err := u.Pack(); err != nil {
		t.Fatalf("pack request: %v", err)
	}
	w := &stubResponseWriter{}
	h.ServeDNS(context.Background(), w, u)
	return w.response(t)
}

func TestUpdateAdd(t *testing.T) {
	recs := &fakeRecords{}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Ns = []dns.RR{aRR("www.example.com.", "1.2.3.4")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(recs.records) != 1 {
		t.Fatalf("provider has %d records, want 1", len(recs.records))
	}
	if rr := recs.records[0]; rr.Header().Name != "www.example.com." || rdataOf(rr) != "1.2.3.4" {
		t.Errorf("record = %+v", rr)
	}
}

func TestUpdateAddDuplicateIsNoop(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{aRR("www.example.com.", "1.2.3.4")}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Ns = []dns.RR{aRR("www.example.com.", "1.2.3.4")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(recs.records) != 1 {
		t.Errorf("duplicate add must not change the zone, got %d records", len(recs.records))
	}
}

func TestUpdateDeleteRRset(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{
		aRR("www.example.com.", "1.2.3.4"),
		aRR("www.example.com.", "5.6.7.8"),
	}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	rr := aRR("www.example.com.", "1.2.3.4")
	rr.Header().Class = dns.ClassANY
	rr.Header().TTL = 0
	u.Ns = []dns.RR{rr}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(recs.records) != 0 {
		t.Errorf("expected empty zone, got %d records", len(recs.records))
	}
}

func TestUpdateDeleteName(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{
		aRR("www.example.com.", "1.2.3.4"),
		mustRR(`www.example.com. 300 IN TXT "hello"`),
		aRR("mail.example.com.", "5.6.7.8"),
	}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Ns = []dns.RR{&dns.ANY{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassANY, TTL: 0}}}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(recs.records) != 1 {
		t.Fatalf("expected 1 record left, got %d", len(recs.records))
	}
	if rr := recs.records[0]; rr.Header().Name != "mail.example.com." {
		t.Errorf("remaining record = %+v", rr)
	}
}

func mustRR(line string) dns.RR {
	rr, err := dns.New(line)
	if err != nil {
		panic(err)
	}
	return rr
}

func TestUpdateDeleteSpecificValue(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{
		aRR("www.example.com.", "1.2.3.4"),
		aRR("www.example.com.", "5.6.7.8"),
	}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	rr := aRR("www.example.com.", "1.2.3.4")
	rr.Header().Class = dns.ClassNONE
	rr.Header().TTL = 0
	u.Ns = []dns.RR{rr}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(recs.records) != 1 {
		t.Fatalf("expected 1 record left, got %d", len(recs.records))
	}
	if rdataOf(recs.records[0]) != "5.6.7.8" {
		t.Errorf("remaining record = %+v", recs.records[0])
	}
}

func TestUpdateDeleteAbsentValueIsNoop(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{aRR("www.example.com.", "1.2.3.4")}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	rr := aRR("www.example.com.", "9.9.9.9")
	rr.Header().Class = dns.ClassNONE
	rr.Header().TTL = 0
	u.Ns = []dns.RR{rr}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(recs.records) != 1 {
		t.Errorf("deleting an absent value must not change the zone, got %d records", len(recs.records))
	}
}

func TestUpdatePrereqRRsetExistsValue(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{aRR("www.example.com.", "1.2.3.4")}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Answer = []dns.RR{aRR("www.example.com.", "1.2.3.4")}
	u.Ns = []dns.RR{aRR("mail.example.com.", "5.6.7.8")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
}

func TestUpdatePrereqRRsetExistsValueFails(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{aRR("www.example.com.", "1.2.3.4")}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Answer = []dns.RR{aRR("www.example.com.", "9.9.9.9")}
	u.Ns = []dns.RR{aRR("mail.example.com.", "5.6.7.8")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeNXRrset {
		t.Fatalf("rcode = %v, want NXRRSET", got)
	}
	if len(recs.records) != 1 {
		t.Errorf("failed prereq must not change the zone, got %d records", len(recs.records))
	}
}

func TestUpdatePrereqRRsetDoesNotExist(t *testing.T) {
	recs := &fakeRecords{}
	h := testHandler(recs)

	u := update(t, "example.com.")
	rr := aRR("www.example.com.", "1.2.3.4")
	rr.Header().Class = dns.ClassNONE
	rr.Header().TTL = 0
	u.Answer = []dns.RR{rr}
	u.Ns = []dns.RR{aRR("www.example.com.", "1.2.3.4")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
}

func TestUpdatePrereqNameInUse(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{aRR("www.example.com.", "1.2.3.4")}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Answer = []dns.RR{&dns.ANY{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassANY, TTL: 0}}}
	u.Ns = []dns.RR{aRR("mail.example.com.", "5.6.7.8")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
}

func TestUpdatePrereqNameNotInUseFails(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{aRR("www.example.com.", "1.2.3.4")}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Answer = []dns.RR{&dns.ANY{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassNONE, TTL: 0}}}
	u.Ns = []dns.RR{aRR("mail.example.com.", "5.6.7.8")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeNameError {
		t.Fatalf("rcode = %v, want NXDOMAIN", got)
	}
}

func TestUpdateNotZone(t *testing.T) {
	recs := &fakeRecords{}
	h := testHandler(recs)

	u := update(t, "example.com.")
	u.Ns = []dns.RR{aRR("www.other.net.", "1.2.3.4")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeNotZone {
		t.Fatalf("rcode = %v, want NOTZONE", got)
	}
}

func TestUpdateReplaceValue(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{aRR("www.example.com.", "1.2.3.4")}}
	h := testHandler(recs)

	u := update(t, "example.com.")
	del := aRR("www.example.com.", "1.2.3.4")
	del.Header().Class = dns.ClassNONE
	del.Header().TTL = 0
	u.Ns = []dns.RR{del, aRR("www.example.com.", "5.6.7.8")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(recs.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs.records))
	}
	if rdataOf(recs.records[0]) != "5.6.7.8" {
		t.Errorf("record = %+v", recs.records[0])
	}
}

func TestUpdateServerFailure(t *testing.T) {
	h := &Handler{
		Records: &errRecords{},
		Logger:  discardLogger(),
	}
	u := update(t, "example.com.")
	u.Ns = []dns.RR{aRR("www.example.com.", "1.2.3.4")}

	if got := serve(t, h, u).Rcode; got != dns.RcodeServerFailure {
		t.Fatalf("rcode = %v, want SERVFAIL", got)
	}
}

// errRecords fails every operation.
type errRecords struct{}

func (errRecords) GetRecords(context.Context, string) ([]dns.RR, error) {
	return nil, errBoom
}

func (errRecords) SetRecords(context.Context, string, []dns.RR, []dns.RR) error {
	return errBoom
}

var errBoom = &errType{}

type errType struct{}

func (e *errType) Error() string { return "boom" }

func TestRefuseQuery(t *testing.T) {
	h := testHandler(&fakeRecords{})
	u := dns.NewMsg("example.com.", dns.TypeAAAA)
	if got := serve(t, h, u).Rcode; got != dns.RcodeRefused {
		t.Fatalf("rcode = %v, want REFUSED", got)
	}
}

func TestSOAQuery(t *testing.T) {
	h := testHandler(&fakeRecords{})
	u := dns.NewMsg("example.com.", dns.TypeSOA)
	m := serve(t, h, u)
	if got := m.Rcode; got != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", got)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 SOA answer, got %d", len(m.Answer))
	}
	soa, ok := m.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("answer = %T, want *dns.SOA", m.Answer[0])
	}
	if soa.Hdr.Name != "example.com." {
		t.Errorf("SOA name = %q", soa.Hdr.Name)
	}
	if soa.Ns != "ns.example.com." {
		t.Errorf("SOA Ns = %q", soa.Ns)
	}
}

// gateRecords blocks in GetRecords until release is closed, and tracks the
// maximum number of concurrent GetRecords calls.
type gateRecords struct {
	entered chan struct{}
	release chan struct{}

	inflight atomic.Int32
	max      atomic.Int32
}

func (g *gateRecords) GetRecords(_ context.Context, _ string) ([]dns.RR, error) {
	cur := g.inflight.Add(1)
	defer g.inflight.Add(-1)
	for {
		prev := g.max.Load()
		if cur <= prev || g.max.CompareAndSwap(prev, cur) {
			break
		}
	}
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	return nil, nil
}

func (g *gateRecords) SetRecords(context.Context, string, []dns.RR, []dns.RR) error {
	<-g.release
	return nil
}

// serveUpdateMsg packs and drives an update without asserting, for use from
// goroutines. The message must not be shared with other goroutines: ServeDNS
// unpacks it in place.
func serveUpdateMsg(h *Handler, u *dns.Msg) error {
	if err := u.Pack(); err != nil {
		return err
	}
	w := &stubResponseWriter{}
	h.ServeDNS(context.Background(), w, u)
	w.mu.Lock()
	data := append([]byte(nil), w.data...)
	w.mu.Unlock()
	if len(data) < 2 {
		return nil
	}
	var m dns.Msg
	m.Data = data[2:]
	return m.Unpack()
}

// addUpdate returns a fresh update adding name to zone; each call builds its
// own message.
func addUpdate(zone, name, addr string) *dns.Msg {
	u := dns.NewMsg(zone, dns.TypeSOA)
	u.Opcode = dns.OpcodeUpdate
	u.Ns = []dns.RR{aRR(name, addr)}
	return u
}

func TestUpdatesToSameZoneAreSerialized(t *testing.T) {
	recs := &gateRecords{entered: make(chan struct{}, 1), release: make(chan struct{})}
	h := testHandler(&fakeRecords{})
	h.Records = recs

	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			done <- serveUpdateMsg(h, addUpdate("example.com.", "www.example.com.", "1.2.3.4"))
		}()
	}

	// The first update is blocked inside GetRecords; the second must still be
	// waiting on the zone lock, so GetRecords must never be concurrent.
	select {
	case <-recs.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first update never entered GetRecords")
	}
	if got := recs.max.Load(); got != 1 {
		t.Fatalf("concurrent GetRecords = %d, want 1", got)
	}

	close(recs.release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("update failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("update never completed")
		}
	}
}

func TestUpdatesToDifferentZonesAreConcurrent(t *testing.T) {
	recs := &gateRecords{entered: make(chan struct{}, 2), release: make(chan struct{})}
	h := testHandler(&fakeRecords{})
	h.Records = recs

	u1 := addUpdate("example.com.", "www.example.com.", "1.2.3.4")
	u2 := addUpdate("other.net.", "www.other.net.", "1.2.3.4")

	done := make(chan error, 2)
	go func() { done <- serveUpdateMsg(h, u1) }()
	go func() { done <- serveUpdateMsg(h, u2) }()

	// Both zones are independent, so both updates may be in flight.
	for i := 0; i < 2; i++ {
		select {
		case <-recs.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("an update never entered GetRecords")
		}
	}
	if got := recs.max.Load(); got != 2 {
		t.Fatalf("concurrent GetRecords = %d, want 2", got)
	}

	close(recs.release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("update failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("update never completed")
		}
	}
}

func TestAXFRChunking(t *testing.T) {
	zone := "example.com."
	answer := []dns.RR{synthesizeSOA(zone, nil)}
	for i := 0; i < 3000; i++ {
		answer = append(answer, aRR(fmt.Sprintf("host%d.example.com.", i), "1.2.3.4"))
	}
	answer = append(answer, synthesizeSOA(zone, nil))

	envs := axfrEnvelopes(answer)
	if len(envs) < 2 {
		t.Fatalf("large zone should span multiple envelopes, got %d", len(envs))
	}

	var all []dns.RR
	for i, e := range envs {
		if len(e.Answer) == 0 {
			t.Errorf("envelope %d is empty", i)
		}
		var size int
		for _, rr := range e.Answer {
			size += rr.Len()
			all = append(all, rr)
		}
		if size > 60*1024 {
			t.Errorf("envelope %d is %d bytes, over the 60 KiB message limit", i, size)
		}
	}
	if len(all) != len(answer) {
		t.Fatalf("envelopes hold %d RRs, want %d", len(all), len(answer))
	}
	if _, ok := all[0].(*dns.SOA); !ok {
		t.Errorf("transfer must start with the opening SOA, got %T", all[0])
	}
	if _, ok := all[len(all)-1].(*dns.SOA); !ok {
		t.Errorf("transfer must end with the closing SOA, got %T", all[len(all)-1])
	}
}

func soaRR(t *testing.T, zone string, serial uint32, ns, mbox string) dns.RR {
	t.Helper()
	rr, err := dns.New(fmt.Sprintf("%s 3600 IN SOA %s %s %d 3600 600 604800 3600", zone, ns, mbox, serial))
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func nsRR(zone, ns string) dns.RR {
	rr, err := dns.New(zone + " 3600 IN NS " + ns)
	if err != nil {
		panic(err)
	}
	return rr
}

func TestSOAOrSynthesizedUsesProviderSOA(t *testing.T) {
	zone := "example.com."
	records := []dns.RR{
		soaRR(t, zone, 42, "ns1.example.com.", "hostmaster.example.com."),
		aRR("www.example.com.", "1.2.3.4"),
	}
	soa, rest := soaOrSynthesized(zone, records)
	if soa.Serial != 42 || soa.Header().Name != zone {
		t.Errorf("soa = %+v, want the provider's SOA with serial 42", soa)
	}
	if len(rest) != 1 || rest[0].Header().Name != "www.example.com." {
		t.Errorf("rest = %v, want just the A record", rest)
	}
}

func TestSynthesizedSOAUsesApexNS(t *testing.T) {
	zone := "example.com."
	records := []dns.RR{nsRR(zone, "ns1.example.com."), aRR("www.example.com.", "1.2.3.4")}
	soa, _ := soaOrSynthesized(zone, records)
	if soa.Ns != "ns1.example.com." {
		t.Errorf("Ns = %q, want the apex NS target", soa.Ns)
	}
	if soa.Serial != 1 {
		t.Errorf("serial = %d, want the constant placeholder 1", soa.Serial)
	}
}

func TestSynthesizedSOAFallsBackToNsDotZone(t *testing.T) {
	soa, _ := soaOrSynthesized("example.com.", nil)
	if soa.Ns != "ns.example.com." {
		t.Errorf("Ns = %q, want ns.example.com.", soa.Ns)
	}
}

func TestSOAQueryReturnsProviderSOA(t *testing.T) {
	recs := &fakeRecords{records: []dns.RR{
		soaRR(t, "example.com.", 42, "ns1.example.com.", "hostmaster.example.com."),
	}}
	h := testHandler(recs)
	u := dns.NewMsg("example.com.", dns.TypeSOA)
	m := serve(t, h, u)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %v, want success", m.Rcode)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(m.Answer))
	}
	soa, ok := m.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("answer = %T, want *dns.SOA", m.Answer[0])
	}
	if soa.Serial != 42 {
		t.Errorf("serial = %d, want the provider's 42", soa.Serial)
	}
}
