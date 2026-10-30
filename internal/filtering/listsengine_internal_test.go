package filtering

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDomainRule(t *testing.T) {
	testCases := []struct {
		line       string
		wantDomain string
		wantFlags  uint8
		wantOK     bool
	}{{
		line:       "||example.org^",
		wantDomain: "example.org",
		wantOK:     true,
	}, {
		line:       "@@||example.org^",
		wantDomain: "example.org",
		wantFlags:  domainFlagAllow,
		wantOK:     true,
	}, {
		line:       "||example.org^$important",
		wantDomain: "example.org",
		wantFlags:  domainFlagImportant,
		wantOK:     true,
	}, {
		line:       "@@||sub_1.ex-ample.org^$important",
		wantDomain: "sub_1.ex-ample.org",
		wantFlags:  domainFlagAllow | domainFlagImportant,
		wantOK:     true,
	}, {
		line: "||example.org",
	}, {
		line: "||example.org^|",
	}, {
		line: "|example.org^",
	}, {
		line: "||Example.org^",
	}, {
		line: "||*.example.org^",
	}, {
		line: "||example.org.^",
	}, {
		line: "||.example.org^",
	}, {
		line: "||example..org^",
	}, {
		line: "||192.0.2.1^",
	}, {
		line: "||example.org^$important,client=192.0.2.1",
	}, {
		line: "||example.org^$Important",
	}, {
		line: "||^",
	}, {
		line: "example.org",
	}, {
		line: "0.0.0.0 example.org",
	}}

	for _, tc := range testCases {
		t.Run(tc.line, func(t *testing.T) {
			domain, flags, ok := parseDomainRule([]byte(tc.line))
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantDomain, string(domain))
			assert.Equal(t, tc.wantFlags, flags)
		})
	}
}

// ruleDomains returns all domains passed by [forEachRuleDomain] for hostname.
func ruleDomains(hostname string) (domains []string) {
	forEachRuleDomain(hostname, func(d string) { domains = append(domains, d) })

	return domains
}

func TestForEachRuleDomain(t *testing.T) {
	testCases := []struct {
		hostname string
		want     []string
	}{{
		hostname: "a.b.example.org",
		want:     []string{"a.b.example.org", "b.example.org", "example.org", "org"},
	}, {
		hostname: "a+b.example.org",
		want:     []string{"a"},
	}, {
		hostname: ".example.org",
		want:     []string{"org"},
	}, {
		hostname: "example.org+x.example.net",
		want:     []string{"example.org", "org"},
	}, {
		hostname: "1.2.3.4",
		want:     nil,
	}, {
		hostname: "sub.1.example",
		want:     []string{"sub.1.example", "1.example", "example"},
	}}

	for _, tc := range testCases {
		t.Run(tc.hostname, func(t *testing.T) {
			assert.Equal(t, tc.want, ruleDomains(tc.hostname))
		})
	}
}

// TestForEachRuleDomain_urlfilter checks that [forEachRuleDomain] passes
// exactly the domains d for which package rules matches "||d^" against random
// hostnames, including ones with characters that affect the matching.
func TestForEachRuleDomain_urlfilter(t *testing.T) {
	const alphabet = "ab1-_.+% "

	r := rand.New(rand.NewPCG(3, 4))
	randomHostname := func() (h string) {
		b := make([]byte, 1+r.IntN(12))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}

		return string(b)
	}

	for range 2_000 {
		checkRuleDomains(t, randomHostname())
	}
}

// checkRuleDomains checks that [forEachRuleDomain] passes exactly the domains
// d for which package rules matches "||d^" against hostname.
func checkRuleDomains(t *testing.T, hostname string) {
	t.Helper()

	want := ruleDomains(hostname)

	// Check every substring that can be the domain of a plain domain rule.
	for start := range len(hostname) {
		for end := start + 1; end <= len(hostname); end++ {
			d := hostname[start:end]
			if !isRuleDomain(d) {
				continue
			}

			nr, err := rules.NewNetworkRule("||"+d+"^", 1)
			require.NoError(t, err)

			matched := nr.Match(rules.NewRequestForHostname(hostname))
			assert.Equal(t, matched, slices.Contains(want, d), "hostname %q, domain %q", hostname, d)
		}
	}
}

func TestDomainTable(t *testing.T) {
	b := &domainTableBuilder{}
	for i := range 1_000 {
		require.True(t, b.addRule(fmt.Appendf(nil, "||d%d.example^", i), 0))
	}

	// Add the same domain in another list and with other flags.
	require.True(t, b.addRule([]byte("@@||d1.example^$important"), 1))
	require.False(t, b.addRule([]byte("||d1.example^$client=1.2.3.4"), 1))

	tbl := b.build()
	require.Equal(t, 1_001, tbl.len())

	got := tbl.appendMatches(nil, "d1.example")
	require.Len(t, got, 2)

	assert.ElementsMatch(
		t,
		[]uint32{0, 1},
		[]uint32{tbl.entries[got[0]].listIdx(), tbl.entries[got[1]].listIdx()},
	)
	assert.Empty(t, tbl.appendMatches(nil, "d1000.example"))
	assert.Empty(t, tbl.appendMatches(nil, "example"))
}

func TestDomainTableBuilder_unindexed(t *testing.T) {
	b := &domainTableBuilder{}

	// Package urlfilter ignores later copies of unindexed rules, but not of
	// indexed ones.
	for listIdx := range uint32(2) {
		require.True(t, b.addRule([]byte("||a.io^"), listIdx))
		require.True(t, b.addRule([]byte("||indexed.example^"), listIdx))
	}

	tbl := b.build()

	assert.Len(t, tbl.appendMatches(nil, "a.io"), 1)
	assert.Len(t, tbl.appendMatches(nil, "indexed.example"), 2)
}

// TestListsEngine_realLists compares the engine with and without the plain
// domain rules table on the real blocklists in the directory from the
// AGH_BENCH_LISTS environment variable.
func TestListsEngine_realLists(t *testing.T) {
	if os.Getenv("AGH_BENCH_LISTS") == "" {
		t.Skip("set AGH_BENCH_LISTS to a directory with blocklists to run")
	}

	paths, blocked := aghtest.BenchBlocklists(t, 0, 5_000)

	filters := []Filter{{
		ID:   0,
		Data: []byte("@@||" + blocked[0] + "^$important\n"),
	}}
	for i, p := range paths {
		filters = append(filters, Filter{ID: rules.ListID(len(paths) - i), FilePath: p})
	}

	fast, err := newListsEngine(filters, true)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, fast.Close()) })

	ref, err := newListsEngine(filters, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ref.Close()) })

	hosts := make([]string, 0, len(blocked)*3)
	for i, d := range blocked {
		hosts = append(hosts, d, "sub."+d, fmt.Sprintf("x%d.not-%s", i, filepath.Base(d)))
	}

	matched := 0
	for _, host := range hosts {
		req := &urlfilter.DNSRequest{Hostname: strings.ToLower(host)}
		want, wantOK := ref.MatchRequest(req)
		got, gotOK := fast.MatchRequest(req)

		require.Equal(t, wantOK, gotOK, host)
		if gotOK {
			matched++
		}

		want.NetworkRules = normalizeNetworkRules(want.NetworkRules)
		if want.NetworkRule != nil {
			want.NetworkRule = rules.GetDNSBasicRule(want.NetworkRules)
		}

		require.Equal(t, ruleTexts(want), ruleTexts(got), host)
	}

	t.Logf("compared %d hosts, %d matched", len(hosts), matched)

	// The blocked domains and their subdomains must mostly match.
	assert.Greater(t, matched, len(hosts)/2)
}

// ruleTexts returns the texts and list IDs of the chosen rules in res.
func ruleTexts(res *urlfilter.DNSResult) (texts []string) {
	if res.NetworkRule != nil {
		return []string{fmt.Sprintf("%d %s", res.NetworkRule.GetFilterListID(), res.NetworkRule.Text())}
	}

	for _, hr := range slices.Concat(res.HostRulesV4, res.HostRulesV6) {
		texts = append(texts, fmt.Sprintf("%d %s", hr.GetFilterListID(), hr.Text()))
	}

	return texts
}
