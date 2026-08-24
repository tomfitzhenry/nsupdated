package provider

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/DNSControl/dnscontrol/v5/models"
	"github.com/DNSControl/dnscontrol/v5/pkg/providers"
)

// fakeProvider is a minimal DNSServiceProvider that records the config its
// initializer received.
type fakeProvider struct {
	config map[string]string
}

func (f *fakeProvider) GetNameservers(string) ([]*models.Nameserver, error) { return nil, nil }
func (f *fakeProvider) GetZoneRecords(*models.DomainConfig) (models.Records, error) {
	return nil, nil
}
func (f *fakeProvider) GetZoneRecordsCorrections(*models.DomainConfig, models.Records) ([]*models.Correction, int, error) {
	return nil, 0, nil
}

var registerFakeOnce sync.Once

// registerFake registers a throwaway provider type, once per process, so the
// test below can prove NewFromCreds resolves TYPE from the config.
func registerFake(t *testing.T) {
	t.Helper()
	registerFakeOnce.Do(func() {
		providers.RegisterDomainServiceProviderType("TESTFAKE", providers.DspFuncs{
			Initializer: func(config map[string]string, _ json.RawMessage) (providers.DNSServiceProvider, error) {
				return &fakeProvider{config: config}, nil
			},
		})
	})
}

func TestNewFromCredsUsesTypeField(t *testing.T) {
	registerFake(t)

	recs, err := NewFromCreds(map[string]string{
		"TYPE":    "TESTFAKE",
		"api-key": "hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}
	fake, ok := recs.provider.(*fakeProvider)
	if !ok {
		t.Fatalf("provider = %T, want *fakeProvider", recs.provider)
	}
	if fake.config["api-key"] != "hunter2" {
		t.Errorf("initializer config = %v, want api-key passed through", fake.config)
	}
}

func TestNewFromCredsRejectsUnknownType(t *testing.T) {
	if _, err := NewFromCreds(map[string]string{"TYPE": "NO-SUCH-PROVIDER"}); err == nil {
		t.Fatal("expected an error for an unknown provider type")
	}
}
