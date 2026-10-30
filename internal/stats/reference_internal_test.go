package stats

// This file contains the reference implementation of [StatsCtx.getData], which
// reads and sums all units from the database on every request.  It is used to
// test [unitCache].

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// loadUnits returns stored units from the database and current unit ID.
func (s *StatsCtx) loadUnits(limit uint32) (units []*unitDB, curID uint32) {
	db := s.db.Load()
	if db == nil {
		return nil, 0
	}

	// NOTE:  This mutex, when combined with the database transaction, is
	// required to be locked first.
	s.currMu.RLock()
	defer s.currMu.RUnlock()

	// Use writable transaction to ensure any ongoing writable transaction is
	// taken into account.
	tx, err := db.Begin(true)
	if err != nil {
		s.logger.Error("opening transaction", slogutil.KeyError, err)

		return nil, 0
	}
	cur := s.curr

	if cur != nil {
		curID = cur.id
	} else {
		curID = s.unitIDGen()
	}

	// Per-hour units.
	units = make([]*unitDB, 0, limit)
	firstID := curID - limit + 1
	for i := firstID; i != curID; i++ {
		u := s.loadUnitFromDB(tx, i)
		if u == nil {
			u = &unitDB{NResult: make([]uint64, resultLast)}
		}
		units = append(units, u)
	}

	err = finishTxn(tx, false)
	if err != nil {
		s.logger.Error("finishing transaction", slogutil.KeyError, err)
	}

	if cur != nil {
		units = append(units, cur.serialize())
	}

	if unitsLen := len(units); unitsLen != int(limit) {
		// Should not happen.
		panic(fmt.Errorf("loaded %d units when the desired number is %d", unitsLen, limit))
	}

	return units, curID
}

// pairsGetter is a signature for topsCollector argument.
type pairsGetter func(u *unitDB) (pairs []countPair)

// topsCollector collects statistics about highest values from the given *unitDB
// slice using pg to retrieve data.
func topsCollector(units []*unitDB, max int, ignored *aghnet.IgnoreEngine, pg pairsGetter) []map[string]uint64 {
	m := map[string]uint64{}
	for _, u := range units {
		for _, cp := range pg(u) {
			if !ignored.Has(cp.Name) {
				m[cp.Name] += cp.Count
			}
		}
	}
	a2 := convertMapToSlice(m, max)

	return convertTopSlice(a2)
}

// dataFromUnits collects and returns the statistics data.
func (s *StatsCtx) dataFromUnits(units []*unitDB, curID uint32) (resp *StatsResp) {
	topUpstreamsResponses, topUpstreamsAvgTime := topUpstreamsPairs(units)

	resp = &StatsResp{
		TopQueried:            topsCollector(units, maxDomains, s.ignored, func(u *unitDB) (pairs []countPair) { return u.Domains }),
		TopBlocked:            topsCollector(units, maxDomains, s.ignored, func(u *unitDB) (pairs []countPair) { return u.BlockedDomains }),
		TopUpstreamsResponses: topUpstreamsResponses,
		TopUpstreamsAvgTime:   topUpstreamsAvgTime,
		TopClients:            topsCollector(units, maxClients, nil, topClientPairs(s)),
	}

	s.fillCounters(resp, units, curID)

	return resp
}

// topClientPairs returns a pairsGetter for the clients that are counted.
func topClientPairs(s *StatsCtx) (pg pairsGetter) {
	return func(u *unitDB) (clients []countPair) {
		for _, c := range u.Clients {
			if c.Name != "" && !s.shouldCountClient([]string{c.Name}) {
				continue
			}

			clients = append(clients, c)
		}

		return clients
	}
}

// topUpstreamsPairs returns sorted lists of number of total responses and the
// average of processing time for each upstream.
func topUpstreamsPairs(
	units []*unitDB,
) (topUpstreamsResponses []topAddrs, topUpstreamsAvgTime []topAddrsFloat) {
	upstreamsResponses := topAddrs{}
	upstreamsTimeSum := topAddrsFloat{}

	for _, u := range units {
		for _, cp := range u.UpstreamsResponses {
			upstreamsResponses[cp.Name] += cp.Count
		}

		for _, cp := range u.UpstreamsTimeSum {
			upstreamsTimeSum[cp.Name] += float64(cp.Count)
		}
	}

	return topUpstreams(upstreamsResponses, upstreamsTimeSum)
}
