package querylog

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryLog_Search_findClient(t *testing.T) {
	const knownClientID = "client-1"
	const knownClientName = "Known Client 1"
	const unknownClientID = "client-2"

	knownClient := &Client{
		Name: knownClientName,
	}

	findClientCalls := 0
	findClient := func(ids []string) (c *Client, _ error) {
		defer func() { findClientCalls++ }()

		if len(ids) == 0 {
			return nil, nil
		}

		if ids[0] == knownClientID {
			return knownClient, nil
		}

		return nil, nil
	}

	l, err := newQueryLog(Config{
		Logger:            testLogger,
		FindClient:        findClient,
		BaseDir:           t.TempDir(),
		RotationIvl:       timeutil.Day,
		MemSize:           100,
		Enabled:           true,
		FileEnabled:       true,
		AnonymizeClientIP: false,
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return l.Shutdown(ctx)
	})

	q := &dns.Msg{
		Question: []dns.Question{{
			Name: "example.com",
		}},
	}

	l.Add(&AddParams{
		Question: q,
		ClientID: knownClientID,
		ClientIP: net.IP{1, 2, 3, 4},
	})

	// Add the same thing again to test the cache.
	l.Add(&AddParams{
		Question: q,
		ClientID: knownClientID,
		ClientIP: net.IP{1, 2, 3, 4},
	})

	l.Add(&AddParams{
		Question: q,
		ClientID: unknownClientID,
		ClientIP: net.IP{1, 2, 3, 5},
	})

	sp := &searchParams{
		// Add some time to the "current" one to protect against
		// low-resolution timers on some Windows machines.
		//
		// TODO(a.garipov): Use some kind of timeSource interface
		// instead of relying on time.Now() in tests.
		olderThan: time.Now().Add(10 * time.Second),
		limit:     3,
	}
	entries, _ := l.search(ctx, sp)
	assert.Equal(t, 2, findClientCalls)

	require.Len(t, entries, 3)

	assert.Nil(t, entries[0].client)

	gotClient := entries[2].client
	require.NotNil(t, gotClient)

	assert.Equal(t, knownClientName, gotClient.Name)
}

func TestQueryLog_Search_cursor(t *testing.T) {
	l, err := newQueryLog(Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Write the entries to the file, oldest first.  Only the entries with the
	// "match" prefix match the search.
	hosts := []string{
		"h0.example",
		"match1.example",
		"h2.example",
		"h3.example",
		"h4.example",
		"h5.example",
		"h6.example",
		"h7.example",
		"match8.example",
		"h9.example",
	}
	for _, h := range hosts {
		addTestEntry(l, h, testAnswerIPv4, testClientIPv4, filtering.NotFilteredNotFound)
	}
	require.NoError(t, l.flushLogBuffer(ctx))

	all, _ := l.search(ctx, newSearchParams())
	require.Len(t, all, len(hosts))

	// timeOf returns the time of the entry with the given index in hosts.
	timeOf := func(i int) (tm time.Time) {
		return all[len(hosts)-1-i].Time
	}

	newParams := func(olderThan time.Time) (p *searchParams) {
		p = newSearchParams()
		p.limit = 5
		p.maxFileScanEntries = 4
		p.olderThan = olderThan
		p.searchCriteria = []searchCriterion{searchCriTerm("match", false)}

		return p
	}

	// The first page scans h9 to h6 and finds match8.  The cursor must point to
	// the oldest scanned entry, not to match8, so that the next page doesn't
	// scan h7 and h6 again.
	entries, oldest := l.search(ctx, newParams(time.Time{}))
	require.Len(t, entries, 1)
	assert.Equal(t, "match8.example", entries[0].QHost)
	assert.Equal(t, timeOf(6).UnixNano(), oldest.UnixNano())

	// The second page scans h5 to h2.
	entries, oldest = l.search(ctx, newParams(oldest))
	assert.Empty(t, entries)
	assert.Equal(t, timeOf(2).UnixNano(), oldest.UnixNano())

	// The third page scans match1 and h0 and reaches the end of the log.
	entries, oldest = l.search(ctx, newParams(oldest))
	require.Len(t, entries, 1)
	assert.Equal(t, "match1.example", entries[0].QHost)
	assert.True(t, oldest.IsZero())

	t.Run("full_page", func(t *testing.T) {
		p := newParams(time.Time{})
		p.limit = 1
		p.maxFileScanEntries = 0

		entries, oldest = l.search(ctx, p)
		require.Len(t, entries, 1)

		// The page is full, so the next one must start after its last entry.
		assert.Equal(t, timeOf(8).UnixNano(), oldest.UnixNano())
	})
}

// newBenchQueryLog returns a query log with n records in its file.  Counting
// from the newest record, every 40,000th record is for "sparse.example", and
// every other rareEvery-th record is for "rare.example".
func newBenchQueryLog(b *testing.B, n, rareEvery int) (l *queryLog) {
	b.Helper()

	l, err := newQueryLog(Config{
		Logger:      testLogger,
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     b.TempDir(),
	})
	require.NoError(b, err)

	ctx := testutil.ContextWithTimeout(b, testTimeout)

	// Use a real record as the template for the generated ones.
	addTestEntry(l, "template.example", testAnswerIPv4, testClientIPv4, filtering.NotFilteredNotFound)
	require.NoError(b, l.flushLogBuffer(ctx))

	data, err := os.ReadFile(l.logFile)
	require.NoError(b, err)

	tmpl := strings.TrimSpace(string(data))
	tmplTime := readJSONValue(tmpl, `"T":"`)
	require.NotEmpty(b, tmplTime)

	start := time.Now().Add(-time.Duration(n) * time.Millisecond)
	sb := &strings.Builder{}
	for i := range n {
		host := fmt.Sprintf("host%d.example", i%5000)
		switch {
		case (n-i)%40_000 == 0:
			host = "sparse.example"
		case (n-i)%rareEvery == 0:
			host = "rare.example"
		}

		line := strings.Replace(tmpl, "template.example", host, 1)
		line = strings.Replace(line, tmplTime, start.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339Nano), 1)
		sb.WriteString(line)
		sb.WriteByte('\n')
	}

	err = os.WriteFile(l.logFile, []byte(sb.String()), 0o600)
	require.NoError(b, err)

	return l
}

// BenchmarkQueryLog_search measures how long the web interface takes to show a
// page of search results, including the requests it makes for the following
// pages while it has fewer than a page of results.
func BenchmarkQueryLog_search(b *testing.B) {
	const pageSize = 20

	n := 20_000 * aghtest.BenchScale(b)
	l := newBenchQueryLog(b, n, 2_500)
	ctx := b.Context()

	benchCases := []struct {
		name      string
		criterion searchCriterion
	}{{
		name:      "rare_term",
		criterion: searchCriTerm("rare", false),
	}, {
		name:      "sparse_term",
		criterion: searchCriTerm("sparse", false),
	}, {
		name:      "no_match",
		criterion: searchCriTerm("no-such-host", false),
	}, {
		name: "status_no_match",
		criterion: searchCriterion{
			criterionType: ctFilteringStatus,
			value:         filteringStatusBlocked,
		},
	}}

	l.index.build(ctx, l.logger, l.indexPaths(), &l.fileWriteLock)

	for _, indexed := range []bool{false, true} {
		for _, bc := range benchCases {
			b.Run(fmt.Sprintf("%s/indexed=%t", bc.name, indexed), func(b *testing.B) {
				l.index.mu.Lock()
				l.index.ready = indexed
				l.index.mu.Unlock()

				requests := 0

				b.ReportAllocs()
				for b.Loop() {
					requests += searchLikeWebUI(ctx, l, bc.criterion, pageSize)
				}

				b.ReportMetric(float64(requests)/float64(b.N), "requests/op")
			})
		}
	}
}

// searchLikeWebUI searches l the way the web interface does: it requests the
// following pages while it has fewer than pageSize results and the log isn't
// over.  It returns the number of requests.
func searchLikeWebUI(
	ctx context.Context,
	l *queryLog,
	c searchCriterion,
	pageSize int,
) (requests int) {
	found := 0
	var olderThan time.Time
	for {
		p := newSearchParams()
		p.limit = pageSize
		p.olderThan = olderThan
		p.searchCriteria = []searchCriterion{c}

		entries, oldest := l.search(ctx, p)
		requests++
		found += len(entries)
		if found >= pageSize || oldest.IsZero() {
			return requests
		}

		olderThan = oldest
	}
}
