package filtering

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// diffDomains are the domains used to generate rules and requests for the
// differential tests.
var diffDomains = []string{
	"example.org",
	"ads.example.org",
	"a.ads.example.org",
	"tracker.example.net",
	"cdn.example.net",
	"example.net",
	"ad1.example.com",
	"ad22.example.com",
	"www.example.com",
	"example.com",
}

// diffRuleTemplates are the rule templates used for the differential tests.
// "%s" is replaced with a domain from diffDomains.
var diffRuleTemplates = []string{
	"||%s^",
	"@@||%s^",
	"||%s^$important",
	"@@||%s^$important",
	"|%s^",
	"%s",
	"||%s^$dnstype=AAAA",
	"||%s^$dnstype=~A",
	"@@||%s^$dnstype=HTTPS",
	"||%s^$client=192.0.2.1",
	"||%s^$client=~192.0.2.1",
	"@@||%s^$client='laptop'",
	"||%s^$ctag=device_phone",
	"@@||%s^$ctag=~device_phone",
	"||%s^$dnsrewrite=192.0.2.53",
	"||%s^$dnsrewrite=NOERROR;AAAA;2001:db8::53",
	"||%s^$dnsrewrite=NOERROR;CNAME;cname.example.net",
	"||%s^$dnsrewrite=REFUSED",
	"@@||%s^$dnsrewrite",
	"@@||%s^$dnsrewrite=192.0.2.53",
	"||%s^$denyallow=www.example.com",
	"0.0.0.0 %s",
	"127.0.0.1 %s",
	"192.0.2.10 %s",
	"::1 %s",
	"2001:db8::10 %s",
	"/^ad[0-9]+\\./",
	"@@/^www\\./",
	"||%s^$badfilter",
	"||%s^$important,badfilter",
}

// randomRules returns n random rules generated from diffRuleTemplates.  If
// allowBadfilter is false, $badfilter rules are skipped.
func randomRules(r *rand.Rand, n int, allowBadfilter bool) (res []string) {
	for len(res) < n {
		tmpl := diffRuleTemplates[r.IntN(len(diffRuleTemplates))]
		if !allowBadfilter && strings.Contains(tmpl, "badfilter") {
			continue
		}

		if strings.Contains(tmpl, "%s") {
			tmpl = fmt.Sprintf(tmpl, diffDomains[r.IntN(len(diffDomains))])
		}

		res = append(res, tmpl)
	}

	return res
}

// newReferenceFilter returns a filter that compiles all filters into a single
// engine, which is how the custom rules were compiled before they got their
// own engine.
func newReferenceFilter(tb testing.TB, filters []Filter) (d *DNSFilter) {
	tb.Helper()

	d, _ = newForTest(tb, nil, nil)
	tb.Cleanup(d.Close)

	storage, err := newRuleStorage(filters)
	require.NoError(tb, err)

	d.engineLock.Lock()
	defer d.engineLock.Unlock()

	d.rulesStorage, d.filteringEngine = storage, urlfilter.NewDNSEngine(storage)

	return d
}

// diffSettings are the filtering settings used for the differential tests.
var diffSettings = []*Settings{{
	ProtectionEnabled: true,
	FilteringEnabled:  true,
}, {
	ProtectionEnabled: true,
	FilteringEnabled:  true,
	ClientIP:          netip.MustParseAddr("192.0.2.1"),
	ClientName:        "laptop",
}, {
	ProtectionEnabled: true,
	FilteringEnabled:  true,
	ClientIP:          netip.MustParseAddr("192.0.2.2"),
	ClientTags:        []string{"device_phone"},
}}

// diffQTypes are the DNS types used for the differential tests.
var diffQTypes = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeTXT}

func TestDNSFilter_customRules_differential(t *testing.T) {
	const (
		iterations     = 100
		customRulesNum = 8
		listRulesNum   = 25
	)

	r := rand.New(rand.NewPCG(1, 2))
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	hosts := append([]string{"sub.example.org", "deep.a.ads.example.org", "ad7.example.net"}, diffDomains...)

	for i := range iterations {
		custom := randomRules(r, customRulesNum, false)
		filters := []Filter{{
			ID:   rulelist.IDCustom,
			Data: []byte(strings.Join(custom, "\n")),
		}, {
			ID:   1,
			Data: []byte(strings.Join(randomRules(r, listRulesNum, true), "\n")),
		}, {
			ID:   2,
			Data: []byte(strings.Join(randomRules(r, listRulesNum, true), "\n")),
		}}

		ref := newReferenceFilter(t, filters)

		d, _ := newForTest(t, nil, nil)
		require.NoError(t, d.initFiltering(ctx, nil, filters, 0))
		require.NotNil(t, d.customRules, "custom rules must be compiled separately")

		for _, host := range hosts {
			for _, qt := range diffQTypes {
				for si, setts := range diffSettings {
					want, wantErr := ref.matchHost(host, qt, setts)
					got, gotErr := d.matchHost(host, qt, setts)

					msg := fmt.Sprintf(
						"iteration %d, host %q, qtype %s, settings %d\ncustom:\n%s\nlist 1:\n%s\nlist 2:\n%s",
						i,
						host,
						dns.Type(qt),
						si,
						filters[0].Data,
						filters[1].Data,
						filters[2].Data,
					)
					require.Equal(t, wantErr, gotErr, msg)

					require.Equal(t, want, got, msg)
				}
			}
		}

		d.Close()
	}
}

func TestDNSFilter_initFiltering_badfilter(t *testing.T) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	setts := &Settings{
		ProtectionEnabled: true,
		FilteringEnabled:  true,
	}

	filters := []Filter{{
		ID:   rulelist.IDCustom,
		Data: []byte("||ads.example.org^$badfilter\n"),
	}, {
		ID:   1,
		Data: []byte("||ads.example.org^\n0.0.0.0 ads.example.org\n"),
	}}

	d, _ := newForTest(t, nil, nil)
	t.Cleanup(d.Close)

	require.NoError(t, d.initFiltering(ctx, nil, filters, 0))
	assert.Nil(t, d.customRules, "custom $badfilter rules must be compiled with the lists")

	// The custom rule disables the network rule from the list, but the
	// hosts-file style rule still applies.
	res, err := d.matchHost("ads.example.org", dns.TypeA, setts)
	require.NoError(t, err)

	assert.True(t, res.IsFiltered)
	require.Len(t, res.Rules, 1)
	assert.Equal(t, "0.0.0.0 ads.example.org", res.Rules[0].Text)
}

// startUpdatesLoop starts the loop that installs asynchronously compiled
// filters, without registering the HTTP handlers.
func startUpdatesLoop(tb testing.TB, d *DNSFilter) {
	tb.Helper()

	d.filtersInitializerChan = make(chan filtersInitializerParams, 1)
	d.done = make(chan struct{}, 1)

	go d.updatesLoop(testutil.ContextWithTimeout(tb, testTimeout))
}

func TestDNSFilter_SetUserRules(t *testing.T) {
	ctx := testutil.ContextWithTimeout(t, testTimeout)
	setts := &Settings{
		ProtectionEnabled: true,
		FilteringEnabled:  true,
	}

	d, _ := newForTest(t, &Config{}, []Filter{{
		ID:   rulelist.IDCustom,
		Data: nil,
	}, {
		ID:   1,
		Data: []byte("||ads.example.org^\n"),
	}})
	t.Cleanup(d.Close)

	// Make the list filter part of the configuration so that full rebuilds
	// keep it.
	d.conf.Filters = []FilterYAML{{
		Enabled: true,
		Filter:  Filter{ID: 1},
	}}

	startUpdatesLoop(t, d)

	isFiltered := func() (ok bool) {
		res, err := d.matchHost("ads.example.org", dns.TypeA, setts)
		require.NoError(t, err)

		return res.IsFiltered
	}

	// Write the list file, since full rebuilds read it from disk.
	d.conf.DataDir = t.TempDir()
	writeFilterFile(t, d, 1, "||ads.example.org^\n")

	require.True(t, isFiltered())

	t.Run("fast", func(t *testing.T) {
		d.SetUserRules(ctx, []string{"@@||ads.example.org^"})

		// The rules must be installed synchronously.
		assert.False(t, isFiltered())
		assert.NotNil(t, d.customRules)
	})

	t.Run("badfilter", func(t *testing.T) {
		d.SetUserRules(ctx, []string{"||ads.example.org^$badfilter"})

		// Custom $badfilter rules require a full asynchronous rebuild.
		assert.Eventually(t, func() (ok bool) {
			d.engineLock.RLock()
			defer d.engineLock.RUnlock()

			return d.customRules == nil
		}, testTimeout, testTimeout/100)
		assert.False(t, isFiltered())
	})

	t.Run("back_to_separate", func(t *testing.T) {
		d.SetUserRules(ctx, []string{"||other.example.org^"})

		assert.Eventually(t, func() (ok bool) {
			d.engineLock.RLock()
			defer d.engineLock.RUnlock()

			return d.customRules != nil
		}, testTimeout, testTimeout/100)
		assert.True(t, isFiltered())
	})

	t.Run("edit", func(t *testing.T) {
		got, changed := d.EditUserRules(ctx, []string{"@@||ads.example.org^"}, []string{"||other.example.org^"})
		assert.True(t, changed)
		assert.Equal(t, []string{"@@||ads.example.org^"}, got)
		assert.False(t, isFiltered())
	})
}

// writeFilterFile writes the rules of the filter with the given ID to its file.
func writeFilterFile(tb testing.TB, d *DNSFilter, id rules.ListID, text string) {
	tb.Helper()

	flt := &FilterYAML{Filter: Filter{ID: id}}
	path := flt.Path(d.conf.DataDir)
	require.NoError(tb, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(tb, os.WriteFile(path, []byte(text), 0o600))
}

func TestEditRules(t *testing.T) {
	testCases := []struct {
		name        string
		userRules   []string
		add         []string
		remove      []string
		want        []string
		wantChanged bool
	}{{
		name:        "add",
		userRules:   []string{"||a.example^"},
		add:         []string{"@@||b.example^"},
		want:        []string{"||a.example^", "@@||b.example^"},
		wantChanged: true,
	}, {
		name:        "add_existing",
		userRules:   []string{" ||a.example^ "},
		add:         []string{"||a.example^"},
		want:        []string{" ||a.example^ "},
		wantChanged: false,
	}, {
		name:        "add_after_trailing_empty",
		userRules:   []string{"||a.example^", "", " "},
		add:         []string{"||b.example^"},
		want:        []string{"||a.example^", "||b.example^"},
		wantChanged: true,
	}, {
		name:        "remove",
		userRules:   []string{"||a.example^", "! comment", "||a.example^"},
		remove:      []string{"||a.example^"},
		want:        []string{"! comment"},
		wantChanged: true,
	}, {
		name:        "remove_missing",
		userRules:   []string{"||a.example^"},
		remove:      []string{"||b.example^"},
		want:        []string{"||a.example^"},
		wantChanged: false,
	}, {
		name:        "toggle",
		userRules:   []string{"||a.example^$important"},
		add:         []string{"@@||a.example^$important"},
		remove:      []string{"||a.example^$important"},
		want:        []string{"@@||a.example^$important"},
		wantChanged: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := editRules(tc.userRules, tc.add, tc.remove)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantChanged, changed)
		})
	}
}

// newBenchFilter returns a filter with the benchmark blocklists and a few
// custom rules, its filters, and some of the domains blocked by the
// blocklists.
func newBenchFilter(b *testing.B) (d *DNSFilter, filters []Filter, blocked []string) {
	b.Helper()

	paths, blocked := aghtest.BenchBlocklists(b, 20_000*aghtest.BenchScale(b), 1_000)
	require.NotEmpty(b, blocked)

	filters = []Filter{{
		ID:   rulelist.IDCustom,
		Data: []byte("||custom.example^\n@@||allowed.example^\n"),
	}}
	for i, p := range paths {
		filters = append(filters, Filter{
			ID:       rules.ListID(i + 1),
			FilePath: p,
		})
	}

	d, _ = newForTest(b, nil, filters)
	b.Cleanup(d.Close)

	return d, filters, blocked
}

// BenchmarkDNSFilter_SetUserRules measures how long changing the custom rules,
// for example by unblocking a domain from the query log, takes until the change
// takes effect.
func BenchmarkDNSFilter_SetUserRules(b *testing.B) {
	setts := &Settings{
		ProtectionEnabled: true,
		FilteringEnabled:  true,
	}

	b.Run("separate", func(b *testing.B) {
		d, _, blocked := newBenchFilter(b)
		ctx := b.Context()

		rulesSets := [][]string{{"@@||" + blocked[0] + "^$important"}, nil}

		b.ReportAllocs()
		i := 0
		for b.Loop() {
			d.SetUserRules(ctx, rulesSets[i%2])
			i++
		}

		res, err := d.CheckHost(blocked[0], dns.TypeA, setts)
		require.NoError(b, err)

		assert.Equal(b, i%2 == 1, !res.IsFiltered)
	})

	// full_rebuild is how changing the custom rules worked before they got
	// their own engine, and how it still works for custom rules with
	// $badfilter rules.
	b.Run("full_rebuild", func(b *testing.B) {
		d, filters, _ := newBenchFilter(b)
		ctx := b.Context()

		b.ReportAllocs()
		for b.Loop() {
			err := d.initFiltering(ctx, nil, filters, 0)
			require.NoError(b, err)
		}
	})
}

func BenchmarkDNSFilter_CheckHost(b *testing.B) {
	d, _, blocked := newBenchFilter(b)

	setts := &Settings{
		ProtectionEnabled: true,
		FilteringEnabled:  true,
	}

	blockedHosts := make([]string, len(blocked))
	allowedHosts := make([]string, len(blocked))
	for i, host := range blocked {
		blockedHosts[i] = "sub." + host
		allowedHosts[i] = fmt.Sprintf("cdn%d.allowed-example%d.com", i, i%97)
	}

	benchCases := []struct {
		name         string
		hosts        []string
		wantFiltered bool
	}{{
		name:         "blocked",
		hosts:        blockedHosts,
		wantFiltered: true,
	}, {
		name:         "allowed",
		hosts:        allowedHosts,
		wantFiltered: false,
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			var res Result
			var err error

			b.ReportAllocs()
			i := 0
			for b.Loop() {
				res, err = d.CheckHost(bc.hosts[i%len(bc.hosts)], dns.TypeA, setts)
				i++
			}

			require.NoError(b, err)

			assert.Equal(b, bc.wantFiltered, res.IsFiltered)
		})
	}
}
