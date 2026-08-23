// Package provider adapts a DNSControl v5 DNS service provider to the
// rfc2136 Records interface. DNSControl's model holds codeberg.org/miekg/dns
// v2 RDATA natively, so conversion is trivial.
package provider

import (
	"context"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/dnsrr"
	"github.com/DNSControl/dnscontrol/v5/pkg/providers"

	_ "github.com/DNSControl/dnscontrol/v5/providers/axfrddns"     // register the provider
	_ "github.com/DNSControl/dnscontrol/v5/providers/mythicbeasts" // register the provider
)

// Records adapts a DNSControl DNSServiceProvider to rfc2136.Records.
type Records struct {
	provider providers.DNSServiceProvider
}

// New wraps an existing DNSControl provider, for tests.
func New(p providers.DNSServiceProvider) *Records {
	return &Records{provider: p}
}

// NewFromCreds returns a Records backed by a fresh provider constructed from a
// provider config map. The type is taken from the config's TYPE field.
func NewFromCreds(config map[string]string) (*Records, error) {
	p, err := providers.CreateDNSProvider("", config, nil)
	if err != nil {
		return nil, err
	}
	return New(p), nil
}

// GetRecords returns the zone's records. The SOA is filtered out: the handler
// synthesizes it, so the provider's own SOA is not transferred.
func (r *Records) GetRecords(ctx context.Context, zone string) ([]dns.RR, error) {
	dc, err := models.NewDomainConfig(strings.TrimSuffix(zone, "."))
	if err != nil {
		return nil, err
	}
	rcs, err := r.provider.GetZoneRecords(dc)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for _, rc := range rcs {
		rr := rc.ToRRv2()
		if dns.RRToType(rr) == dns.TypeSOA {
			continue
		}
		rrs = append(rrs, rr)
	}
	return rrs, nil
}

// SetRecords replaces the zone: DNSControl diffs desired against actual and
// executes the resulting corrections.
func (r *Records) SetRecords(ctx context.Context, zone string, actual, desired []dns.RR) error {
	dc, err := models.NewDomainConfig(strings.TrimSuffix(zone, "."))
	if err != nil {
		return err
	}
	actualRCs, err := toRecordConfigs(dc, actual)
	if err != nil {
		return err
	}
	dc.Records, err = toRecordConfigs(dc, desired)
	if err != nil {
		return err
	}
	corrections, _, err := r.provider.GetZoneRecordsCorrections(dc, actualRCs)
	if err != nil {
		return err
	}
	for _, c := range corrections {
		if err := c.F(); err != nil {
			return err
		}
	}
	return nil
}

func toRecordConfigs(dc *models.DomainConfig, rrs []dns.RR) (models.Records, error) {
	rcs := make(models.Records, 0, len(rrs))
	for _, rr := range rrs {
		rc, err := dnsrr.RRv2toRC(dc, rr)
		if err != nil {
			return nil, err
		}
		rcs = append(rcs, rc)
	}
	return rcs, nil
}
