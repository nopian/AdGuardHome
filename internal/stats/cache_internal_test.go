package stats

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ignoredTestClient is the client which statistics aren't shown in the cache
// tests.
const ignoredTestClient = "192.0.2.99"

// addCacheTestEntries adds n random entries to s.
func addCacheTestEntries(s *StatsCtx, r *rand.Rand, n int) {
	for range n {
		// Make the domains with lower numbers more frequent.
		domain := fmt.Sprintf("d%d.example", min(r.IntN(300), r.IntN(300)))
		if r.IntN(10) == 0 {
			domain = "ignored.example"
		}

		client := fmt.Sprintf("192.0.2.%d", min(r.IntN(150), r.IntN(150)))
		if r.IntN(10) == 0 {
			client = ignoredTestClient
		}

		s.Update(&Entry{
			Client: client,
			Domain: domain,
			UpstreamStats: []*proxy.UpstreamStatistics{{
				Address:       fmt.Sprintf("upstream%d.example:53", r.IntN(5)),
				QueryDuration: time.Duration(r.IntN(100_000)) * time.Microsecond,
				IsCached:      r.IntN(5) == 0,
			}},
			Result:         Result(1 + r.IntN(int(resultLast-1))),
			ProcessingTime: time.Duration(r.IntN(100_000)) * time.Microsecond,
		})
	}
}

// requireSameTop requires the top lists to be the same, except for the order
// and the choice of the names with the same value as the last one.
func requireSameTop(t *testing.T, want, got []topAddrsFloat, msg string) {
	t.Helper()

	wantValues, wantAbove := splitTop(want)
	gotValues, gotAbove := splitTop(got)

	require.Equal(t, wantValues, gotValues, msg)
	require.Equal(t, wantAbove, gotAbove, msg)
}

// splitTop returns the values of top as well as its items with values other
// than the last one.
func splitTop(top []topAddrsFloat) (values []float64, above topAddrsFloat) {
	for _, item := range top {
		values = slices.AppendSeq(values, maps.Values(item))
	}

	above = topAddrsFloat{}
	for _, item := range top {
		for name, n := range item {
			if n != values[len(values)-1] {
				above[name] = n
			}
		}
	}

	return values, above
}

// requireSameData requires the statistics from the cache to be the same as the
// ones from the database.
func requireSameData(t *testing.T, s *StatsCtx, limit uint32, msg string) {
	t.Helper()

	units, curID := s.loadUnits(limit)
	require.NotNil(t, units, msg)

	want := s.dataFromUnits(units, curID)
	got, ok := s.dataFromCache(limit)
	require.True(t, ok, msg)

	// The upstreams with the same average time are in a random order.
	requireSameTop(t, want.TopUpstreamsAvgTime, got.TopUpstreamsAvgTime, msg)
	want.TopUpstreamsAvgTime, got.TopUpstreamsAvgTime = nil, nil

	require.Equal(t, want, got, msg)

	// Check the clients for [StatsCtx.TopClientsIP], which includes the ignored
	// ones.
	clients := map[string]uint64{}
	for _, u := range units {
		for _, p := range u.Clients {
			clients[p.Name] += p.Count
		}
	}

	var gotClients map[string]uint64
	ok = s.withCache(limit, func(firstID, curID uint32, cur *unitDB) {
		gotClients = s.cache.clients(firstID, curID, cur)
	})
	require.True(t, ok, msg)

	require.Equal(t, clients, gotClients, msg)
}

// requireConsistentCache requires the running totals and the names of the
// cache of s to match its units.
func requireConsistentCache(t *testing.T, s *StatsCtx, msg string) {
	t.Helper()

	c := s.cache
	c.mu.RLock()
	defer c.mu.RUnlock()

	want := unitTotals{}
	refs := slices.Clone(c.names.refs)
	clear(refs)
	for _, cu := range c.units {
		want.add(cu)
		addRefs(refs, cu)
	}

	for cat, totals := range c.totals {
		// The totals of the removed names are zero.
		wantTotals := want[cat]
		wantTotals = append(wantTotals, make([]uint64, len(totals)-len(wantTotals))...)

		require.Equal(t, wantTotals, totals, "%s: category %d", msg, cat)
	}

	require.Equal(t, refs, c.names.refs, msg)
	require.Len(t, c.names.ids, len(c.names.names)-len(c.names.free), msg)
}

// addRefs counts the references of cu, which may be nil, to the names in refs.
func addRefs(refs []uint32, cu *compactUnit) {
	if cu == nil {
		return
	}

	for _, ncs := range cu.pairs {
		for _, nc := range ncs {
			refs[nc.id]++
		}
	}
}

func TestStatsCtx_dataFromCache(t *testing.T) {
	const limitHours = 48

	ignored, err := aghnet.NewIgnoreEngine([]string{"ignored.example"}, true)
	require.NoError(t, err)

	var unitID atomic.Uint32
	unitID.Store(1_000)

	s := newTestStatsCtx(t, Config{
		UnitID:  unitID.Load,
		Ignored: ignored,
		ShouldCountClient: func(ids []string) (ok bool) {
			return ids[0] != ignoredTestClient
		},
		Limit:   limitHours * time.Hour,
		Enabled: true,
	})
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	r := rand.New(rand.NewPCG(1, 2))
	for i := range 400 {
		addCacheTestEntries(s, r, r.IntN(200))

		switch n := r.IntN(100); {
		case n < 40:
			// Move to the next unit, sometimes skipping units.
			unitID.Add(1 + uint32(r.IntN(2))*uint32(r.IntN(4)))
			_, _ = s.flush()
		case n < 42:
			require.NoError(t, s.clear())
		}

		limit := []uint32{1, 2, 24, limitHours, limitHours, 2 * limitHours}[r.IntN(6)]
		msg := fmt.Sprintf("iteration %d, limit %d", i, limit)
		requireSameData(t, s, limit, msg)
		requireConsistentCache(t, s, msg)
		requireCacheMatchesDB(t, s)
	}

	// The cache must only keep the units within the limit, except for the ones
	// loaded for the larger limits since the last flush.
	unitID.Add(1)
	_, _ = s.flush()

	s.cache.mu.RLock()
	defer s.cache.mu.RUnlock()

	assert.LessOrEqual(t, len(s.cache.units), limitHours)
}

// requireCacheMatchesDB requires the cached units of s to be the same as the
// ones in the database.
func requireCacheMatchesDB(t *testing.T, s *StatsCtx) {
	t.Helper()

	c := s.cache
	c.mu.RLock()
	defer c.mu.RUnlock()

	tx, err := s.db.Load().Begin(false)
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback()) }()

	for id, cu := range c.units {
		require.Equal(t, s.loadUnitFromDB(tx, id), c.expand(cu), "unit %d", id)
	}
}

// expand returns cu, which may be nil, with the names instead of their IDs.
func (c *unitCache) expand(cu *compactUnit) (udb *unitDB) {
	if cu == nil {
		return nil
	}

	pairs := func(cat category) (ps []countPair) {
		for _, nc := range cu.pairs[cat] {
			ps = append(ps, countPair{Name: c.names.names[nc.id], Count: nc.count})
		}

		return ps
	}

	return &unitDB{
		NResult:            cu.nResult,
		Domains:            pairs(catDomains),
		BlockedDomains:     pairs(catBlockedDomains),
		Clients:            pairs(catClients),
		UpstreamsResponses: pairs(catUpstreamsResponses),
		UpstreamsTimeSum:   pairs(catUpstreamsTimeSum),
		NTotal:             cu.nTotal,
		TimeAvg:            cu.timeAvg,
	}
}

// readStatsUntil gets the statistics for limit hours from s until done is
// closed.
func readStatsUntil(s *StatsCtx, limit uint32, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
			_, _ = s.getData(limit)
		}
	}
}

func TestStatsCtx_dataFromCache_concurrent(t *testing.T) {
	var unitID atomic.Uint32
	unitID.Store(1_000)

	s := newTestStatsCtx(t, Config{
		UnitID:  unitID.Load,
		Limit:   24 * time.Hour,
		Enabled: true,
	})
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	done := make(chan struct{})
	wg := &sync.WaitGroup{}
	for i := range 4 {
		wg.Go(func() { readStatsUntil(s, uint32(12*(1+i%3)), done) })
	}

	r := rand.New(rand.NewPCG(3, 4))
	for i := range 300 {
		addCacheTestEntries(s, r, 20)
		if r.IntN(3) == 0 {
			unitID.Add(1)
			_, _ = s.flush()
		}

		if i%100 == 99 {
			require.NoError(t, s.clear())
		}
	}

	close(done)
	wg.Wait()

	requireCacheMatchesDB(t, s)
	requireConsistentCache(t, s, "after concurrent use")
	requireSameData(t, s, 24, "after concurrent use")
}

func TestUnitCache_add(t *testing.T) {
	c := newUnitCache()
	stale := &unitDB{
		NResult: make([]uint64, resultLast),
		Domains: []countPair{{Name: "stale.example", Count: 1}},
	}

	ids, gen := c.missing(10, 12)
	require.Equal(t, []uint32{10, 11}, ids)

	// A flush stores unit 11 and deletes unit 10 after they're read, but before
	// they're added.
	c.set(11, &unitDB{NResult: make([]uint64, resultLast), NTotal: 1})
	c.removeOutside(11, 13)

	assert.False(t, c.add(gen, ids, []*unitDB{stale, nil}))
	assert.NotContains(t, c.units, uint32(10))
	require.NotNil(t, c.units[11])
	assert.Equal(t, uint64(1), c.units[11].nTotal)

	// Only the missing units are added.
	ids, gen = c.missing(11, 13)
	require.Equal(t, []uint32{12}, ids)

	assert.True(t, c.add(gen, []uint32{11, 12}, []*unitDB{nil, stale}))
	assert.NotNil(t, c.units[11])
	assert.NotNil(t, c.units[12])
}

func TestNameTable(t *testing.T) {
	tbl := &nameTable{}

	a := tbl.acquire("a")
	b := tbl.acquire("b")
	assert.Equal(t, a, tbl.acquire("a"))

	tbl.release(a)
	assert.Equal(t, "a", tbl.names[a])

	tbl.release(a)
	assert.Empty(t, tbl.names[a])
	assert.NotContains(t, tbl.ids, "a")

	// The ID of the removed name is reused.
	assert.Equal(t, a, tbl.acquire("c"))
	assert.Equal(t, b, tbl.acquire("b"))
	assert.Len(t, tbl.names, 2)
}
