package filtering

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/require"
)

// matchServicesSlow is the reference implementation of matching blocked
// services, which checks every rule of every service.
func matchServicesSlow(host string, svcs []ServiceEntry) (svcName, ruleText string) {
	req := rules.NewRequestForHostname(host)
	for _, s := range svcs {
		for _, r := range s.Rules {
			if r.Match(req) {
				return s.Name, r.Text()
			}
		}
	}

	return "", ""
}

// serviceHosts returns hostnames for testing that the rules of blocked services
// match, including subdomains and the expansions of the wildcards.
func serviceHosts() (hosts []string) {
	for _, s := range blockedServices {
		for _, text := range s.Rules {
			d := strings.TrimPrefix(strings.TrimPrefix(text, "@@"), "||")
			d = strings.TrimPrefix(d, "|")
			d, _, _ = strings.Cut(d, "^")
			d = strings.ReplaceAll(d, "*", "x1")
			hosts = append(hosts, d, "sub."+d, "a+"+d, d+"x")
		}
	}

	return hosts
}

func TestDNSFilter_matchBlockedServicesRules_differential(t *testing.T) {
	InitModule(testutil.ContextWithTimeout(t, testTimeout), testLogger)

	d, _ := newForTest(t, nil, nil)
	t.Cleanup(d.Close)

	hosts := serviceHosts()
	r := rand.New(rand.NewPCG(5, 6))

	for i := range 8 {
		// Block a random subset of the services in a random order.
		ids := make([]string, 0, len(serviceIDs))
		for _, idx := range r.Perm(len(serviceIDs))[:1+r.IntN(len(serviceIDs))] {
			ids = append(ids, serviceIDs[idx])
		}

		setts := &Settings{ProtectionEnabled: true}
		d.ApplyBlockedServicesList(setts, ids)

		for _, host := range hosts {
			wantSvc, wantRule := matchServicesSlow(host, setts.ServicesRules)

			res, err := d.matchBlockedServicesRules(host, 0, setts)
			require.NoError(t, err)

			gotRule := ""
			if len(res.Rules) > 0 {
				gotRule = res.Rules[0].Text
			}

			msg := fmt.Sprintf("iteration %d, host %q", i, host)
			require.Equal(t, wantSvc, res.ServiceName, msg)
			require.Equal(t, wantRule, gotRule, msg)
			require.Equal(t, wantSvc != "", res.IsFiltered, msg)
		}
	}
}

func BenchmarkDNSFilter_matchBlockedServicesRules(b *testing.B) {
	InitModule(b.Context(), testLogger)

	d, _ := newForTest(b, nil, nil)
	b.Cleanup(d.Close)

	setts := &Settings{ProtectionEnabled: true}
	d.ApplyBlockedServicesList(setts, serviceIDs[:min(40, len(serviceIDs))])

	hosts := []string{"cdn12.allowed-example.com", "sub." + setts.ServicesRules[0].Rules[0].Shortcut}

	for _, host := range hosts {
		b.Run(host, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = d.matchBlockedServicesRules(host, 0, setts)
			}
		})
	}
}
