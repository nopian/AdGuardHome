package stats

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnit_Deserialize(t *testing.T) {
	testCases := []struct {
		db   *unitDB
		name string
		want unit
	}{{
		name: "empty",
		want: unit{
			domains:            map[string]uint64{},
			blockedDomains:     map[string]uint64{},
			clients:            map[string]uint64{},
			nResult:            []uint64{0, 0, 0, 0, 0, 0},
			id:                 0,
			nTotal:             0,
			timeSum:            0,
			upstreamsResponses: map[string]uint64{},
			upstreamsTimeSum:   map[string]uint64{},
		},
		db: &unitDB{
			NResult:            []uint64{0, 0, 0, 0, 0, 0},
			Domains:            []countPair{},
			BlockedDomains:     []countPair{},
			Clients:            []countPair{},
			NTotal:             0,
			TimeAvg:            0,
			UpstreamsResponses: []countPair{},
			UpstreamsTimeSum:   []countPair{},
		},
	}, {
		name: "basic",
		want: unit{
			domains: map[string]uint64{
				"example.com": 1,
			},
			blockedDomains: map[string]uint64{
				"example.net": 1,
			},
			clients: map[string]uint64{
				"127.0.0.1": 2,
			},
			nResult: []uint64{0, 1, 1, 0, 0, 0},
			id:      0,
			nTotal:  2,
			timeSum: 246912,
			upstreamsResponses: map[string]uint64{
				"1.2.3.4": 2,
			},
			upstreamsTimeSum: map[string]uint64{
				"1.2.3.4": 246912,
			},
		},
		db: &unitDB{
			NResult: []uint64{0, 1, 1, 0, 0, 0},
			Domains: []countPair{{
				"example.com", 1,
			}},
			BlockedDomains: []countPair{{
				"example.net", 1,
			}},
			Clients: []countPair{{
				"127.0.0.1", 2,
			}},
			NTotal:  2,
			TimeAvg: 123456,
			UpstreamsResponses: []countPair{{
				"1.2.3.4", 2,
			}},
			UpstreamsTimeSum: []countPair{{
				"1.2.3.4", 246912,
			}},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := unit{}
			got.deserialize(tc.db)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestTopUpstreamsPairs(t *testing.T) {
	testCases := []struct {
		db            *unitDB
		name          string
		wantResponses []topAddrs
		wantAvgTime   []topAddrsFloat
	}{{
		name: "empty",
		db: &unitDB{
			NResult:            []uint64{0, 0, 0, 0, 0, 0},
			Domains:            []countPair{},
			BlockedDomains:     []countPair{},
			Clients:            []countPair{},
			NTotal:             0,
			TimeAvg:            0,
			UpstreamsResponses: []countPair{},
			UpstreamsTimeSum:   []countPair{},
		},
		wantResponses: []topAddrs{},
		wantAvgTime:   []topAddrsFloat{},
	}, {
		name: "basic",
		db: &unitDB{
			NResult:        []uint64{0, 0, 0, 0, 0, 0},
			Domains:        []countPair{},
			BlockedDomains: []countPair{},
			Clients:        []countPair{},
			NTotal:         0,
			TimeAvg:        0,
			UpstreamsResponses: []countPair{{
				"1.2.3.4", 2,
			}},
			UpstreamsTimeSum: []countPair{{
				"1.2.3.4", 246912,
			}},
		},
		wantResponses: []topAddrs{{
			"1.2.3.4": 2,
		}},
		wantAvgTime: []topAddrsFloat{{
			"1.2.3.4": 0.123456,
		}},
	}, {
		name: "sorted",
		db: &unitDB{
			NResult:        []uint64{0, 0, 0, 0, 0, 0},
			Domains:        []countPair{},
			BlockedDomains: []countPair{},
			Clients:        []countPair{},
			NTotal:         0,
			TimeAvg:        0,
			UpstreamsResponses: []countPair{
				{"3.3.3.3", 8},
				{"2.2.2.2", 4},
				{"4.4.4.4", 16},
				{"1.1.1.1", 2},
			},
			UpstreamsTimeSum: []countPair{
				{"3.3.3.3", 800_000_000},
				{"2.2.2.2", 40_000_000},
				{"4.4.4.4", 16_000_000_000},
				{"1.1.1.1", 2_000_000},
			},
		},
		wantResponses: []topAddrs{
			{"4.4.4.4": 16},
			{"3.3.3.3": 8},
			{"2.2.2.2": 4},
			{"1.1.1.1": 2},
		},
		wantAvgTime: []topAddrsFloat{
			{"4.4.4.4": 1000},
			{"3.3.3.3": 100},
			{"2.2.2.2": 10},
			{"1.1.1.1": 1},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotResponses, gotAvgTime := topUpstreamsPairs([]*unitDB{tc.db})
			assert.Equal(t, tc.wantResponses, gotResponses)
			assert.Equal(t, tc.wantAvgTime, gotAvgTime)
		})
	}
}

// BenchmarkStatsCtx_getData measures how long the dashboard takes to load the
// statistics for 90 days.
func BenchmarkStatsCtx_getData(b *testing.B) {
	const (
		curID      = 1_000_000
		unitsNum   = 90 * 24
		namesNum   = 20_000
		topPerUnit = 100
	)

	s := newTestStatsCtx(b, Config{
		Limit:  unitsNum * time.Hour,
		UnitID: func() (id uint32) { return curID },
	})
	b.Cleanup(func() { require.NoError(b, s.Close()) })

	// pairs returns the top pairs of a unit with names from a fixed pool.
	pairs := func(prefix string, unit int) (ps []countPair) {
		for i := range topPerUnit {
			ps = append(ps, countPair{
				Name:  fmt.Sprintf("%s%d.example", prefix, (unit*37+i)%namesNum),
				Count: uint64(topPerUnit - i),
			})
		}

		return ps
	}

	tx, err := s.db.Load().Begin(true)
	require.NoError(b, err)

	for u := range unitsNum {
		udb := &unitDB{
			NResult:        []uint64{0, 900, 100, 0, 0, 0},
			Domains:        pairs("d", u),
			BlockedDomains: pairs("b", u),
			Clients:        pairs("c", u),
			NTotal:         1000,
			TimeAvg:        1234,
		}
		require.NoError(b, s.flushUnitToDB(udb, tx, uint32(curID-unitsNum+u)))
	}

	require.NoError(b, tx.Commit())

	var resp *StatsResp
	var ok bool

	b.ReportAllocs()
	for b.Loop() {
		resp, ok = s.getData(unitsNum)
	}

	require.True(b, ok)
	assert.Len(b, resp.TopQueried, maxDomains)
}
