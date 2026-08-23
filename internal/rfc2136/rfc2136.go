// Package rfc2136 implements the server side of RFC 2136 dynamic updates and
// RFC 5936 zone transfers, backed by a Records provider.
package rfc2136

import (
	"context"
	"hash/fnv"
	"io"
	"log/slog"
	"strings"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Records is the provider interface the handler drives. SetRecords replaces
// the whole zone: it diffs desired against actual and applies the difference.
type Records interface {
	GetRecords(ctx context.Context, zone string) ([]dns.RR, error)
	SetRecords(ctx context.Context, zone string, actual, desired []dns.RR) error
}

// Handler serves RFC 2136 updates and AXFR over a Records provider. It is
// stateless and performs no authentication.
type Handler struct {
	// Records is the provider the handler drives. It is shared across
	// requests; the provider handles its own login and bearer token.
	Records Records
	Logger  *slog.Logger

	// zones serialize updates per zone (see lockZone).
	zones [256]sync.Mutex
}

// lockZone blocks until the zone is free for another update. Each update is a
// whole-zone read-modify-write cycle against the provider, so concurrent
// updates to the same zone would clobber each other. A fixed set of stripes
// bounds memory regardless of how many distinct zones are updated; zones that
// collide on a stripe are serialized, which only costs a little concurrency.
func (h *Handler) lockZone(zone string) {
	h.zones[h.stripe(zone)].Lock()
}

// unlockZone is the inverse of lockZone.
func (h *Handler) unlockZone(zone string) {
	h.zones[h.stripe(zone)].Unlock()
}

// stripe hashes a zone to a lock stripe.
func (h *Handler) stripe(zone string) uint8 {
	f := fnv.New32a()
	f.Write([]byte(zone))
	return uint8(f.Sum32() % uint32(len(h.zones)))
}

func (h *Handler) logf(level slog.Level, msg string, args ...any) {
	if h.Logger != nil {
		h.Logger.Log(context.Background(), level, msg, args...)
	}
}

// ServeDNS implements dns.Handler.
func (h *Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	// The server only unpacks the header and question before invoking the
	// handler; finish the parse so the update/prerequisite sections are
	// available.
	if err := r.Unpack(); err != nil {
		h.logf(slog.LevelError, "unpack request", "err", err)
		m := dnsutil.SetReply(new(dns.Msg), r)
		m.Rcode = dns.RcodeFormatError
		h.reply(w, m)
		return
	}

	var zone, qtype, remote string
	if len(r.Question) > 0 {
		zone = r.Question[0].Header().Name
		qtype = dns.TypeToString[dns.RRToType(r.Question[0])]
	}
	if addr := w.RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	h.logf(slog.LevelDebug, "request",
		"remote", remote,
		"opcode", dns.OpcodeToString[r.Opcode],
		"zone", zone,
		"qtype", qtype,
	)

	switch r.Opcode {
	case dns.OpcodeUpdate:
		h.serveUpdate(ctx, w, r)
	case dns.OpcodeQuery:
		h.serveQuery(ctx, w, r)
	default:
		h.reply(w, refuse(r))
	}
}

func (h *Handler) serveQuery(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		h.reply(w, refuse(r))
		return
	}
	switch dns.RRToType(r.Question[0]) {
	case dns.TypeAXFR:
		h.serveAXFR(ctx, w, r)
	case dns.TypeSOA:
		h.serveSOA(w, r)
	default:
		h.reply(w, refuse(r))
	}
}

func (h *Handler) serveSOA(w dns.ResponseWriter, r *dns.Msg) {
	m := dnsutil.SetReply(new(dns.Msg), r)
	m.Authoritative = true
	m.Answer = []dns.RR{soa(dnsutil.Canonical(r.Question[0].Header().Name))}
	h.reply(w, m)
}

func (h *Handler) serveAXFR(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	zone := dnsutil.Canonical(r.Question[0].Header().Name)
	records, err := h.Records.GetRecords(ctx, zone)
	if err != nil {
		h.logf(slog.LevelError, "axfr get records", "zone", zone, "err", err)
		m := dnsutil.SetReply(new(dns.Msg), r)
		m.Authoritative = true
		m.Rcode = dns.RcodeServerFailure
		h.reply(w, m)
		return
	}

	// RFC 5936 requires the transfer to begin and end with an SOA record.
	s := soa(zone)
	answer := []dns.RR{s}
	for _, rr := range records {
		// The SOA is synthesized; the provider's own SOA is not transferred.
		if dns.RRToType(rr) == dns.TypeSOA {
			continue
		}
		answer = append(answer, rr)
	}
	answer = append(answer, s)

	w.Hijack()
	env := make(chan *dns.Envelope)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer w.Close()
		if err := dns.NewClient().TransferOut(w, r, env); err != nil {
			h.logf(slog.LevelError, "axfr transfer out", "zone", zone, "err", err)
		}
	}()
	env <- &dns.Envelope{Answer: answer}
	close(env)
	wg.Wait()
	h.logf(slog.LevelDebug, "axfr served", "zone", zone, "records", len(records))
}

func (h *Handler) serveUpdate(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	m := dnsutil.SetReply(new(dns.Msg), r)
	m.Authoritative = true

	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		h.reply(w, m)
		return
	}
	q := r.Question[0]
	zone := dnsutil.Canonical(q.Header().Name)
	if q.Header().Class != dns.ClassINET {
		m.Rcode = dns.RcodeRefused
		h.reply(w, m)
		return
	}

	// Updates to the same zone are serialized because each is a whole-zone
	// read-modify-write cycle against the provider.
	h.lockZone(zone)
	defer h.unlockZone(zone)

	provider := h.Records
	current, err := provider.GetRecords(ctx, zone)
	if err != nil {
		h.logf(slog.LevelError, "update get records", "zone", zone, "err", err)
		m.Rcode = dns.RcodeServerFailure
		h.reply(w, m)
		return
	}

	model := newModel(current)

	if rcode := evalPrereqs(zone, model, r.Answer); rcode != dns.RcodeSuccess {
		m.Rcode = rcode
		h.reply(w, m)
		return
	}
	if rcode := applyUpdates(zone, model, r.Ns); rcode != dns.RcodeSuccess {
		m.Rcode = rcode
		h.reply(w, m)
		return
	}
	if err := model.commit(ctx, zone, provider); err != nil {
		h.logf(slog.LevelError, "update commit", "zone", zone, "err", err)
		m.Rcode = dns.RcodeServerFailure
		h.reply(w, m)
		return
	}

	h.reply(w, m)
}

// soa returns the synthesized zone SOA. DNS provider APIs generally never
// expose SOA records, so one is fabricated to satisfy RFC 5936 and clients
// that probe for the SOA first.
func soa(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.Header{Name: zone, Class: dns.ClassINET, TTL: 3600},
		SOA: rdata.SOA{
			Ns:      "ns." + zone,
			Mbox:    "hostmaster." + zone,
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  604800,
			Minttl:  3600,
		},
	}
}

func refuse(r *dns.Msg) *dns.Msg {
	m := dnsutil.SetReply(new(dns.Msg), r)
	m.Authoritative = true
	m.Rcode = dns.RcodeRefused
	return m
}

// reply writes the message to the client. io.Copy routes to Msg.WriteTo, which
// adds the stream length prefix; a failed write just means the client went
// away.
func (h *Handler) reply(w dns.ResponseWriter, m *dns.Msg) {
	if _, err := io.Copy(w, m); err != nil {
		h.logf(slog.LevelDebug, "write response", "err", err)
	}
}

// inZone reports whether name (a fully-qualified name) is within zone.
func inZone(name, zone string) bool {
	name = strings.ToLower(name)
	zone = strings.ToLower(zone)
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// rdataOf returns the RDATA of rr in presentation syntax.
func rdataOf(rr dns.RR) string {
	parts := strings.SplitN(rr.String(), "\t", 5)
	if len(parts) != 5 {
		return ""
	}
	return parts[4]
}

// recKey identifies a record within a zone by its lower-cased name, type, and
// presentation-syntax data.
type recKey struct {
	name string
	typ  string
	data string
}

func keyOf(rr dns.RR) recKey {
	typ := dns.RRToType(rr)
	return recKey{name: strings.ToLower(rr.Header().Name), typ: dns.TypeToString[typ], data: rdataOf(rr)}
}

// model is the zone as a set of records, before (orig) and after (cur) the
// updates of a single message.
type model struct {
	orig map[recKey]dns.RR
	cur  map[recKey]dns.RR
}

func newModel(records []dns.RR) *model {
	orig := make(map[recKey]dns.RR, len(records))
	for _, rr := range records {
		orig[keyOf(rr)] = rr
	}
	cur := make(map[recKey]dns.RR, len(orig))
	for k, v := range orig {
		cur[k] = v
	}
	return &model{orig: orig, cur: cur}
}

func (m *model) hasName(name string) bool {
	name = strings.ToLower(name)
	for k := range m.cur {
		if k.name == name {
			return true
		}
	}
	return false
}

func (m *model) hasRRset(name, typ string) bool {
	name = strings.ToLower(name)
	typ = strings.ToUpper(typ)
	for k := range m.cur {
		if k.name == name && k.typ == typ {
			return true
		}
	}
	return false
}

func (m *model) deleteName(name string) {
	name = strings.ToLower(name)
	for k := range m.cur {
		if k.name == name {
			delete(m.cur, k)
		}
	}
}

func (m *model) deleteRRset(name, typ string) {
	name = strings.ToLower(name)
	typ = strings.ToUpper(typ)
	for k := range m.cur {
		if k.name == name && k.typ == typ {
			delete(m.cur, k)
		}
	}
}

// evalPrereqs checks the prerequisite section (RFC 2136 section 2.4) against
// the pre-update zone, returning the RCODE of the first failure.
func evalPrereqs(zone string, m *model, prereqs []dns.RR) uint16 {
	for _, rr := range prereqs {
		if !inZone(rr.Header().Name, zone) {
			return dns.RcodeNotZone
		}
		name := rr.Header().Name
		typ := dns.RRToType(rr)

		switch rr.Header().Class {
		case dns.ClassINET:
			if !valuePresent(m, rr) {
				return dns.RcodeNXRrset
			}
		case dns.ClassANY:
			switch {
			case typ == dns.TypeANY:
				// Name is in use.
				if !m.hasName(name) {
					return dns.RcodeNameError
				}
			case rrHasData(rr):
				if !valuePresent(m, rr) {
					return dns.RcodeNXRrset
				}
			default:
				// RRset exists (value independent).
				if !m.hasRRset(name, dns.TypeToString[typ]) {
					return dns.RcodeNXRrset
				}
			}
		case dns.ClassNONE:
			if typ == dns.TypeANY {
				// Name is not in use.
				if m.hasName(name) {
					return dns.RcodeNameError
				}
			} else {
				// RRset does not exist.
				if m.hasRRset(name, dns.TypeToString[typ]) {
					return dns.RcodeNXRrset
				}
			}
		default:
			return dns.RcodeFormatError
		}
	}
	return dns.RcodeSuccess
}

// valuePresent reports whether the RRset that rr names exists with the value rr
// carries (RFC 2136 section 2.4.1).
func valuePresent(m *model, rr dns.RR) bool {
	_, ok := m.cur[keyOf(rr)]
	return ok
}

// rrHasData reports whether rr carries resource data.
func rrHasData(rr dns.RR) bool {
	if txt, ok := rr.(*dns.TXT); ok {
		return len(txt.Txt) > 0
	}
	return strings.TrimSpace(rdataOf(rr)) != ""
}

// applyUpdates applies the update section (RFC 2136 section 2.5) to the model,
// returning the RCODE of the first error.
func applyUpdates(zone string, m *model, updates []dns.RR) uint16 {
	for _, rr := range updates {
		if !inZone(rr.Header().Name, zone) {
			return dns.RcodeNotZone
		}
		name := rr.Header().Name
		typ := dns.RRToType(rr)

		switch rr.Header().Class {
		case dns.ClassINET:
			// Add to an RRset.
			if rr.Header().TTL == 0 {
				return dns.RcodeFormatError
			}
			m.cur[keyOf(rr)] = rr
		case dns.ClassNONE:
			// Delete an RR from an RRset.
			if rr.Header().TTL != 0 {
				return dns.RcodeFormatError
			}
			delete(m.cur, keyOf(rr))
		case dns.ClassANY:
			// Delete an RRset, or all RRsets from a name.
			if rr.Header().TTL != 0 {
				return dns.RcodeFormatError
			}
			if typ == dns.TypeANY {
				m.deleteName(name)
			} else {
				m.deleteRRset(name, dns.TypeToString[typ])
			}
		default:
			return dns.RcodeFormatError
		}
	}
	return dns.RcodeSuccess
}

// commit pushes the whole post-update zone to the provider, which diffs it
// against the pre-update zone.
func (m *model) commit(ctx context.Context, zone string, provider Records) error {
	desired := make([]dns.RR, 0, len(m.cur))
	for _, rr := range m.cur {
		desired = append(desired, rr)
	}
	actual := make([]dns.RR, 0, len(m.orig))
	for _, rr := range m.orig {
		actual = append(actual, rr)
	}
	return provider.SetRecords(ctx, zone, actual, desired)
}
