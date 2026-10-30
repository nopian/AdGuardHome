package stats

import (
	"slices"
	"strings"
	"sync"
)

// unitCache keeps the stored units in a compact form, so that the statistics
// can be computed without reading and decoding them from the database.  The
// stored units never change, so the cache only needs to add the units when
// they are stored and to remove them when they are deleted.  It also keeps the
// running totals of the cached units, so that summing the top lists for the
// configured period doesn't depend on the number of units.
type unitCache struct {
	// units are the cached units by their IDs.  A nil unit means that the unit
	// isn't in the database.
	units map[uint32]*compactUnit

	// names are the domains, clients, and upstreams of the cached units.
	names nameTable

	// totals are the summed counts of the cached units.
	totals unitTotals

	// mu protects all fields.
	mu sync.RWMutex

	// gen is the generation of the cache, which changes every time a unit is
	// stored or removed, so that units read from the database before that
	// aren't added.
	gen uint64
}

// newUnitCache returns a new empty cache.
func newUnitCache() (c *unitCache) {
	return &unitCache{
		units: map[uint32]*compactUnit{},
	}
}

// category is a category of the named counts of a unit.
type category uint8

// category values.
const (
	catDomains category = iota
	catBlockedDomains
	catClients
	catUpstreamsResponses
	catUpstreamsTimeSum

	catNum
)

// compactUnit is a stored unit with interned names.
type compactUnit struct {
	// pairs are the named counts of the unit by their category.
	pairs [catNum][]namedCount

	// nResult is the number of requests by the result's kind.
	nResult []uint64

	// nTotal is the total number of requests.
	nTotal uint64

	// timeAvg is the average of processing times in microseconds.
	timeAvg uint32
}

// counters sets the counters of udb to the ones of cu.  empty is used as the
// result counters if cu is nil.
func (cu *compactUnit) counters(udb *unitDB, empty []uint64) {
	if cu == nil {
		*udb = unitDB{NResult: empty}

		return
	}

	*udb = unitDB{
		NResult: cu.nResult,
		NTotal:  cu.nTotal,
		TimeAvg: cu.timeAvg,
	}
}

// namedCount is a count for an interned name.
type namedCount struct {
	// count is the count.
	count uint64

	// id is the ID of the name in [unitCache.names].
	id uint32
}

// unitTotals are the summed counts of units by the category and the ID of the
// name.
type unitTotals [catNum][]uint64

// add adds the counts of cu, which may be nil, to t.
func (t *unitTotals) add(cu *compactUnit) {
	if cu == nil {
		return
	}

	for cat, ncs := range cu.pairs {
		for _, nc := range ncs {
			if n := int(nc.id) + 1; n > len(t[cat]) {
				t[cat] = append(t[cat], make([]uint64, n-len(t[cat]))...)
			}

			t[cat][nc.id] += nc.count
		}
	}
}

// sub subtracts the counts of cu, which may be nil and must have been added
// before, from t.
func (t *unitTotals) sub(cu *compactUnit) {
	if cu == nil {
		return
	}

	for cat, ncs := range cu.pairs {
		for _, nc := range ncs {
			t[cat][nc.id] -= nc.count
		}
	}
}

// nameTable interns names, counting the references to them, so that unused
// names can be removed.
type nameTable struct {
	// ids are the IDs of the names.
	ids map[string]uint32

	// names are the names by their IDs.  Removed names are empty.
	names []string

	// refs are the numbers of references to the names by their IDs.
	refs []uint32

	// free are the IDs of the removed names, which can be reused.
	free []uint32
}

// acquire returns the ID of name, adding it if necessary, and counts a
// reference to it.
func (t *nameTable) acquire(name string) (id uint32) {
	id, ok := t.ids[name]
	if !ok {
		if t.ids == nil {
			t.ids = map[string]uint32{}
		}

		name = strings.Clone(name)
		if n := len(t.free); n > 0 {
			id, t.free = t.free[n-1], t.free[:n-1]
			t.names[id] = name
		} else {
			id = uint32(len(t.names))
			t.names = append(t.names, name)
			t.refs = append(t.refs, 0)
		}

		t.ids[name] = id
	}

	t.refs[id]++

	return id
}

// release removes a reference to the name with id, removing the name if it's no
// longer used.
func (t *nameTable) release(id uint32) {
	t.refs[id]--
	if t.refs[id] > 0 {
		return
	}

	delete(t.ids, t.names[id])
	t.names[id] = ""
	t.free = append(t.free, id)
}

// compact returns udb with interned names.  c.mu must be locked.
func (c *unitCache) compact(udb *unitDB) (cu *compactUnit) {
	return &compactUnit{
		pairs: [catNum][]namedCount{
			catDomains:            c.namedCounts(udb.Domains),
			catBlockedDomains:     c.namedCounts(udb.BlockedDomains),
			catClients:            c.namedCounts(udb.Clients),
			catUpstreamsResponses: c.namedCounts(udb.UpstreamsResponses),
			catUpstreamsTimeSum:   c.namedCounts(udb.UpstreamsTimeSum),
		},
		nResult: slices.Clone(udb.NResult),
		nTotal:  udb.NTotal,
		timeAvg: udb.TimeAvg,
	}
}

// namedCounts returns pairs with interned names.  c.mu must be locked.
func (c *unitCache) namedCounts(pairs []countPair) (ncs []namedCount) {
	ncs = make([]namedCount, len(pairs))
	for i, p := range pairs {
		ncs[i] = namedCount{count: p.Count, id: c.names.acquire(p.Name)}
	}

	return ncs
}

// releaseUnit removes the references of cu, which may be nil, to the names.
// c.mu must be locked.
func (c *unitCache) releaseUnit(cu *compactUnit) {
	if cu == nil {
		return
	}

	for _, ncs := range cu.pairs {
		for _, nc := range ncs {
			c.names.release(nc.id)
		}
	}
}

// set caches udb as the unit with id, or caches that the unit isn't in the
// database if udb is nil.  It must be called after the unit is stored.
func (c *unitCache) set(id uint32, udb *unitDB) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gen++
	c.setLocked(id, udb)
}

// setLocked is [unitCache.set] with c.mu locked.
func (c *unitCache) setLocked(id uint32, udb *unitDB) {
	var cu *compactUnit
	if udb != nil {
		cu = c.compact(udb)
		c.totals.add(cu)
	}

	c.removeLocked(id)
	c.units[id] = cu
}

// removeLocked removes the unit with id.  c.mu must be locked.
func (c *unitCache) removeLocked(id uint32) {
	cu := c.units[id]
	c.totals.sub(cu)
	c.releaseUnit(cu)
	delete(c.units, id)
}

// removeOutside removes the units with IDs outside of the range from firstID up
// to, but not including, curID.  The range may wrap around.  It must be called
// after the units are deleted.
func (c *unitCache) removeOutside(firstID, curID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gen++
	n := curID - firstID
	for id := range c.units {
		if id-firstID >= n {
			c.removeLocked(id)
		}
	}
}

// reset removes all units.
func (c *unitCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gen++
	c.units = map[uint32]*compactUnit{}
	c.names = nameTable{}
	c.totals = unitTotals{}
}

// missing returns the IDs of the units from firstID up to, but not including,
// curID that aren't cached as well as the current generation of the cache.
func (c *unitCache) missing(firstID, curID uint32) (ids []uint32, gen uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for id := firstID; id != curID; id++ {
		if _, ok := c.units[id]; !ok {
			ids = append(ids, id)
		}
	}

	return ids, c.gen
}

// add caches udbs, which may contain nils, as the units with ids that aren't
// cached yet, unless the generation of the cache has changed since gen.  It
// returns false if the generation has changed.
//
// The cache is updated after the database, so if the units were read after the
// generation was taken, they're either the same as in the database or they will
// be replaced or removed by the next update.
func (c *unitCache) add(gen uint64, ids []uint32, udbs []*unitDB) (ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.gen != gen {
		return false
	}

	for i, id := range ids {
		if _, ok = c.units[id]; !ok {
			c.setLocked(id, udbs[i])
		}
	}

	return true
}

// unitTops are the summed pairs of units, by the category.
type unitTops struct {
	upstreamsResponses topAddrs
	upstreamsTimeSum   topAddrsFloat
	domains            []countPair
	blockedDomains     []countPair
	clients            []countPair
}

// data returns the counters of the cached units with IDs from firstID up to,
// but not including, curID, followed by cur, as well as their summed pairs.
// skipDomain and skipClient return true for the names that must not be in the
// top lists.
func (c *unitCache) data(
	firstID uint32,
	curID uint32,
	cur *unitDB,
	skipDomain func(name string) (ok bool),
	skipClient func(name string) (ok bool),
) (counters []*unitDB, tops *unitTops) {
	// Lock exclusively, since cur is temporarily added to the cache.
	c.mu.Lock()
	defer c.mu.Unlock()

	n := curID - firstID
	counters = make([]*unitDB, 0, n+1)
	udbs := make([]unitDB, n)
	empty := make([]uint64, resultLast)
	for i := range udbs {
		c.units[firstID+uint32(i)].counters(&udbs[i], empty)
		counters = append(counters, &udbs[i])
	}

	counters = append(counters, cur)

	c.withTotals(firstID, curID, cur, func(totals *unitTotals) {
		tops = c.tops(totals, skipDomain, skipClient)
	})

	return counters, tops
}

// clients returns the numbers of requests of the clients in the cached units
// with IDs from firstID up to, but not including, curID and in cur.
func (c *unitCache) clients(firstID, curID uint32, cur *unitDB) (m map[string]uint64) {
	// Lock exclusively, since cur is temporarily added to the cache.
	c.mu.Lock()
	defer c.mu.Unlock()

	c.withTotals(firstID, curID, cur, func(totals *unitTotals) {
		m = c.counts(totals[catClients])
	})

	return m
}

// withTotals calls f with the summed counts of the cached units with IDs from
// firstID up to, but not including, curID and of cur.  c.mu must be locked.
func (c *unitCache) withTotals(firstID, curID uint32, cur *unitDB, f func(totals *unitTotals)) {
	cu := c.compact(cur)
	defer c.releaseUnit(cu)

	// Use the running totals if the cache contains exactly the units in the
	// range, which is the case for the configured period.
	if c.hasExactly(firstID, curID) {
		c.totals.add(cu)
		defer c.totals.sub(cu)

		f(&c.totals)

		return
	}

	totals := &unitTotals{}
	for id := firstID; id != curID; id++ {
		totals.add(c.units[id])
	}

	totals.add(cu)

	f(totals)
}

// hasExactly returns true if the cache contains the units with IDs from firstID
// up to, but not including, curID and no others.  c.mu must be locked.
func (c *unitCache) hasExactly(firstID, curID uint32) (ok bool) {
	if len(c.units) != int(curID-firstID) {
		return false
	}

	for id := firstID; id != curID; id++ {
		if _, ok = c.units[id]; !ok {
			return false
		}
	}

	return true
}

// tops returns the top pairs from totals.  c.mu must be locked.
func (c *unitCache) tops(
	totals *unitTotals,
	skipDomain func(name string) (ok bool),
	skipClient func(name string) (ok bool),
) (tops *unitTops) {
	tops = &unitTops{
		domains:            c.top(totals[catDomains], maxDomains, skipDomain),
		blockedDomains:     c.top(totals[catBlockedDomains], maxDomains, skipDomain),
		clients:            c.top(totals[catClients], maxClients, skipClient),
		upstreamsResponses: c.counts(totals[catUpstreamsResponses]),
		upstreamsTimeSum:   topAddrsFloat{},
	}

	for id, n := range totals[catUpstreamsTimeSum] {
		if n != 0 {
			tops.upstreamsTimeSum[c.names.names[id]] = float64(n)
		}
	}

	return tops
}

// counts returns the non-zero counts in totals by their names.  c.mu must be
// locked.
func (c *unitCache) counts(totals []uint64) (m map[string]uint64) {
	m = map[string]uint64{}
	for id, n := range totals {
		if n != 0 {
			m[c.names.names[id]] = n
		}
	}

	return m
}

// top returns up to maxNum pairs with the highest counts in totals, except for
// the names for which skip returns true, sorted with [countPair.compare].  c.mu
// must be locked.
func (c *unitCache) top(
	totals []uint64,
	maxNum int,
	skip func(name string) (ok bool),
) (pairs []countPair) {
	if maxNum <= 0 {
		return nil
	}

	// Keep the pairs sorted and only insert the ones that make it into the top,
	// which is much faster than sorting all of them, since there are few such
	// pairs.  Only check those for skipping as well.
	pairs = make([]countPair, 0, maxNum+1)
	for id, n := range totals {
		if n == 0 {
			continue
		}

		p := countPair{Name: c.names.names[id], Count: n}
		if len(pairs) == maxNum && p.compare(pairs[maxNum-1]) >= 0 {
			continue
		} else if skip(p.Name) {
			continue
		}

		i, _ := slices.BinarySearchFunc(pairs, p, countPair.compare)
		pairs = slices.Insert(pairs, i, p)
		pairs = pairs[:min(len(pairs), maxNum)]
	}

	return pairs
}
