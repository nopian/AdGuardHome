package querylog

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// indexTestClients are the clients of the records in the index tests, by their
// IP address.
var indexTestClients = map[string]*Client{
	"192.0.2.1": {Name: "laptop"},
	"192.0.2.2": {Name: "phone"},
	"192.0.2.3": {Name: "ignored-tv", IgnoreQueryLog: true},
}

// indexTestHosts are the requested domains in the index tests, the first ones
// being the most frequent.
var indexTestHosts = []string{
	"example.org",
	"ads.example.org",
	"cdn.example.net",
	"tracker.example.com",
	"ignored.example",
	"rare.example",
	"xn--e1afmkfd.xn--p1ai",
}

// indexTestReasons are the filtering results of the records in the index tests.
var indexTestReasons = []filtering.Result{{
	Reason: filtering.NotFilteredNotFound,
}, {
	Reason:     filtering.FilteredBlockList,
	IsFiltered: true,
}, {
	Reason: filtering.NotFilteredAllowList,
}, {
	Reason:     filtering.FilteredSafeBrowsing,
	IsFiltered: true,
}, {
	Reason: filtering.RewrittenRule,
}}

// newIndexTestLog returns a query log for the index tests, without records.
func newIndexTestLog(tb testing.TB) (l *queryLog) {
	tb.Helper()

	ignored, err := aghnet.NewIgnoreEngine([]string{"ignored.example"}, true)
	require.NoError(tb, err)

	l, err = newQueryLog(Config{
		Logger:      testLogger,
		Ignored:     ignored,
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     500,
		BaseDir:     tb.TempDir(),
		FindClient: func(ids []string) (c *Client, err error) {
			for _, id := range ids {
				if c = indexTestClients[id]; c != nil {
					return c, nil
				}
			}

			return nil, nil
		},
	})
	require.NoError(tb, err)

	return l
}

// addIndexTestRecords adds n random records to l and writes them to the
// current file.
func addIndexTestRecords(tb testing.TB, l *queryLog, r *rand.Rand, n int) {
	tb.Helper()

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	for i := range n {
		// Make the later hosts rare.
		host := indexTestHosts[min(r.IntN(len(indexTestHosts)), r.IntN(len(indexTestHosts)))]
		if r.IntN(500) == 0 {
			host = fmt.Sprintf("once%d.example", i)
		}

		res := indexTestReasons[r.IntN(len(indexTestReasons))]
		q := &dns.Msg{Question: []dns.Question{{
			Name:   host + ".",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}}}

		clientID := ""
		if r.IntN(4) == 0 {
			clientID = "client-id-1"
		}

		l.Add(&AddParams{
			Question: q,
			Answer:   q,
			Result:   &res,
			ClientID: clientID,
			ClientIP: net.IPv4(192, 0, 2, byte(1+r.IntN(4))),
			Upstream: "upstream",
		})

		if l.buffer.Len() >= 400 {
			require.NoError(tb, l.flushLogBuffer(ctx))
		}
	}

	if l.buffer.Len() > 0 {
		require.NoError(tb, l.flushLogBuffer(ctx))
	}
}

// appendLegacyRecord appends a record with an unusual result, which the index
// can't read quickly, to the current file of l.
func appendLegacyRecord(tb testing.TB, l *queryLog) {
	tb.Helper()

	f, err := os.OpenFile(l.logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	require.NoError(tb, err)

	line := fmt.Sprintf(
		`{"IP":"192.0.2.2","T":%q,"QH":"legacy.example","Result":{"IsFiltered":true,"Reason":"3"}}`+"\n",
		time.Now().Format(time.RFC3339Nano),
	)
	_, err = f.WriteString(line)
	require.NoError(tb, err)
	require.NoError(tb, f.Close())
}

// buildIndex builds the search index of l synchronously.
func buildIndex(tb testing.TB, l *queryLog) {
	tb.Helper()

	l.index.build(testutil.ContextWithTimeout(tb, testTimeout), l.logger, l.indexPaths(), &l.fileWriteLock)
	l.index.mu.RLock()
	defer l.index.mu.RUnlock()

	require.True(tb, l.index.ready)
}

// randomSearchParams returns random search parameters for the index tests.
func randomSearchParams(r *rand.Rand, records []*logEntry) (p *searchParams) {
	p = newSearchParams()
	p.limit = 1 + r.IntN(30)
	p.maxFileScanEntries = 0
	if r.IntN(4) == 0 {
		p.olderThan = records[r.IntN(len(records))].Time
	}

	terms := []string{
		"rare", "example", "ads.example.org", "once", "192.0.2.4", "client-id", "laptop",
		"phone", "ignored", "legacy", "nothing-at-all", "XN--", "ФЫВА",
	}
	statuses := []string{
		filteringStatusAll, filteringStatusFiltered, filteringStatusBlocked,
		filteringStatusBlockedSafebrowsing, filteringStatusWhitelisted,
		filteringStatusRewritten, filteringStatusProcessed,
	}

	if r.IntN(3) != 0 {
		c := searchCriTerm(terms[r.IntN(len(terms))], r.IntN(4) == 0)
		if strings.HasPrefix(c.value, "Ф") {
			c.value, c.asciiVal = "фыва.рф", "xn--80aah4b.xn--p1ai"
		}

		p.searchCriteria = append(p.searchCriteria, c)
	}

	switch r.IntN(3) {
	case 0:
		p.searchCriteria = append(p.searchCriteria, searchCriterion{
			criterionType: ctFilteringStatus,
			value:         statuses[r.IntN(len(statuses))],
		})
	case 1:
		p.searchCriteria = append(p.searchCriteria, searchReason([]string{
			indexTestReasons[r.IntN(len(indexTestReasons))].Reason.String(),
		}))
	}

	return p
}

// searchBoth searches l with p with and without the index and requires the
// same results.
func searchBoth(t *testing.T, l *queryLog, p *searchParams, msg string) {
	t.Helper()

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	l.index.mu.Lock()
	l.index.ready = false
	l.index.mu.Unlock()

	want, wantOldest := l.search(ctx, p)

	l.index.mu.Lock()
	l.index.ready = true
	l.index.mu.Unlock()

	got, gotOldest := l.search(ctx, p)

	require.Equal(t, len(want), len(got), msg)
	for i := range want {
		require.Equal(t, want[i].Time.UnixNano(), got[i].Time.UnixNano(), msg)
		require.Equal(t, want[i].QHost, got[i].QHost, msg)
	}

	require.Equal(t, wantOldest.UnixNano(), gotOldest.UnixNano(), msg)
}

func TestSearchIndex_differential(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	l := newIndexTestLog(t)

	addIndexTestRecords(t, l, r, 4_000)
	appendLegacyRecord(t, l)
	require.NoError(t, l.rotate(testutil.ContextWithTimeout(t, testTimeout)))
	addIndexTestRecords(t, l, r, 3_000)

	buildIndex(t, l)

	// Add records after building the index, so that they are indexed on
	// flush, and keep some in memory.
	addIndexTestRecords(t, l, r, 700)
	for range 50 {
		addTestEntry(l, "memory.example", testAnswerIPv4, testClientIPv4, filtering.NotFilteredNotFound)
	}

	all, _ := l.search(testutil.ContextWithTimeout(t, testTimeout), &searchParams{limit: 100_000})
	// Some of the records are for an ignored domain or client.
	require.Greater(t, len(all), 4_000)

	for i := range 300 {
		p := randomSearchParams(r, all)
		searchBoth(t, l, p, fmt.Sprintf("iteration %d, params %+v", i, p))
	}
}

func TestSearchIndex_lifecycle(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 10))
	l := newIndexTestLog(t)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// An index of no files.
	buildIndex(t, l)

	check := func(t *testing.T) {
		t.Helper()

		for _, term := range []string{"rare", "example", "phone"} {
			p := newSearchParams()
			p.maxFileScanEntries = 0
			p.searchCriteria = []searchCriterion{searchCriTerm(term, false)}
			searchBoth(t, l, p, term)
		}
	}

	t.Run("flush", func(t *testing.T) {
		addIndexTestRecords(t, l, r, 3_000)
		check(t)
	})

	t.Run("rotate", func(t *testing.T) {
		require.NoError(t, l.rotate(ctx))
		addIndexTestRecords(t, l, r, 1_500)
		check(t)
	})

	t.Run("rotate_again", func(t *testing.T) {
		require.NoError(t, l.rotate(ctx))
		check(t)

		// The dictionaries only keep the strings of the remaining file.
		l.index.mu.RLock()
		defer l.index.mu.RUnlock()

		assert.Less(t, len(l.index.domains.strs), 20)
	})

	t.Run("clear", func(t *testing.T) {
		l.clear(ctx)
		check(t)

		addIndexTestRecords(t, l, r, 500)
		check(t)
	})

	t.Run("mismatch", func(t *testing.T) {
		// Change the file behind the index's back.  The next flush must notice
		// it and rebuild the index in the background.
		appendLegacyRecord(t, l)
		addIndexTestRecords(t, l, r, 500)

		require.Eventually(t, func() (ok bool) {
			l.index.mu.RLock()
			defer l.index.mu.RUnlock()

			return l.index.ready && !l.index.building.Load()
		}, 5*time.Second, 10*time.Millisecond)

		check(t)
	})
}

func TestSearchIndex_addRecord_memory(t *testing.T) {
	const (
		domainsNum = 1_000
		padLen     = 128 << 10

		// maxLive is far below the domainsNum*padLen bytes that the index would
		// keep if it kept the lines.
		maxLive = 32 << 20
	)

	pad := strings.Repeat("A", padLen)
	idx := &searchIndex{}
	fi := &fileIndex{}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	var end int64
	for i := range domainsNum {
		line := fmt.Sprintf(`{"IP":"192.0.2.1","QH":"u%d.example","Result":{},"Answer":%q}`, i, pad)
		m := readRecordMeta(line)
		end += int64(len(line) + 1)
		idx.addRecord(fi, &m, end)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	require.Len(t, idx.domains.strs, domainsNum)
	assert.Less(t, int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(maxLive))
	runtime.KeepAlive(idx)
}

func TestSearchIndex_maxEntries(t *testing.T) {
	const maxEntries = 10

	prev := indexMaxEntries
	indexMaxEntries = maxEntries
	t.Cleanup(func() { indexMaxEntries = prev })

	r := rand.New(rand.NewPCG(11, 12))
	l := newIndexTestLog(t)

	// Many records are for unique domains, so the dictionary fills up.
	addIndexTestRecords(t, l, r, 3_000)
	require.NoError(t, l.rotate(testutil.ContextWithTimeout(t, testTimeout)))
	addIndexTestRecords(t, l, r, 2_000)

	buildIndex(t, l)
	addIndexTestRecords(t, l, r, 500)

	func() {
		l.index.mu.RLock()
		defer l.index.mu.RUnlock()

		assert.LessOrEqual(t, len(l.index.domains.strs), maxEntries)
		assert.LessOrEqual(t, len(l.index.clients.strs), maxEntries)
		assert.LessOrEqual(t, len(l.index.pairs.pairs), maxEntries)

		unknown := 0
		for _, fi := range l.index.files {
			for _, blk := range fi.blocks {
				if blk.unknown {
					unknown++
				}
			}
		}

		assert.Positive(t, unknown)
	}()

	all, _ := l.search(testutil.ContextWithTimeout(t, testTimeout), &searchParams{limit: 100_000})
	for i := range 100 {
		p := randomSearchParams(r, all)
		searchBoth(t, l, p, fmt.Sprintf("iteration %d, params %+v", i, p))
	}
}

func TestQuickResult(t *testing.T) {
	testCases := []struct {
		line           string
		wantReason     filtering.Reason
		wantIsFiltered bool
		wantOK         bool
	}{{
		line:       `{"QH":"example.org","Result":{}}`,
		wantReason: filtering.NotFilteredNotFound,
		wantOK:     true,
	}, {
		line:           `{"QH":"example.org","Result":{"IsFiltered":true,"Reason":3}}`,
		wantReason:     filtering.FilteredBlockList,
		wantIsFiltered: true,
		wantOK:         true,
	}, {
		line:       `{"QH":"example.org","Result":{"Reason":9,"Rules":[{"Text":"\"IsFiltered\":true"}]}}`,
		wantReason: filtering.Rewritten,
		wantOK:     true,
	}, {
		line:   `{"QH":"example.org","Result":{"IsFiltered":true,"Rea`,
		wantOK: false,
	}, {
		line:   `{"QH":"example.org","Result":{"Reason":"x"}}`,
		wantOK: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.line, func(t *testing.T) {
			reason, isFiltered, ok := quickResult(tc.line)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantReason, reason)
				assert.Equal(t, tc.wantIsFiltered, isFiltered)
			}
		})
	}
}
