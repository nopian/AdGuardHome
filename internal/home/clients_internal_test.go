package home

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/agh"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClientsContainer is a helper that creates a new clients container for
// tests.
func newClientsContainer(tb testing.TB) (c *clientsContainer) {
	tb.Helper()

	c = &clientsContainer{}

	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	err := c.Init(
		ctx,
		testLogger,
		nil,
		client.EmptyDHCP{},
		nil,
		nil,
		&filtering.Config{
			Logger: testLogger,
		},
		newSignalHandler(testLogger, nil, nil),
		agh.EmptyConfigModifier{},
		aghhttp.EmptyRegistrar{},
	)

	require.NoError(tb, err)

	return c
}

func TestClientsContainer_shouldLogClient(t *testing.T) {
	clients := newClientsContainer(t)
	clients.clientChecker = &testBlockedClientChecker{
		onIsBlockedClient: func(_ netip.Addr, _ string) (blocked bool, rule string) {
			return false, ""
		},
	}

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	ignoring := newPersistentClientWithIDs(t, "ignoring", []string{"192.0.2.1", "ignoring-id"})
	ignoring.IgnoreQueryLog = true
	require.NoError(t, clients.storage.Add(ctx, ignoring))

	logged := newPersistentClientWithIDs(t, "logged", []string{"192.0.2.2", "logged-id"})
	require.NoError(t, clients.storage.Add(ctx, logged))

	zoned := newPersistentClientWithIDs(t, "zoned", []string{"fe80::1%eth0"})
	zoned.IgnoreQueryLog = true
	require.NoError(t, clients.storage.Add(ctx, zoned))

	idsList := [][]string{
		{"192.0.2.1"},
		{"192.0.2.2"},
		{"192.0.2.3"},
		{"fe80::1"},
		{"ignoring-id", "192.0.2.2"},
		{"logged-id", "192.0.2.1"},
		{"unknown-id", "192.0.2.1"},
		{"unknown-id", "192.0.2.3"},
	}

	for _, ids := range idsList {
		c, err := clients.findMultiple(ids)
		require.NoError(t, err)

		want := c == nil || !c.IgnoreQueryLog
		assert.Equal(t, want, clients.shouldLogClient(ids), "ids %q", ids)
	}
}

// BenchmarkClientsContainer_perQuery measures the client lookups that the DNS
// server makes for every query: the filtering settings, the custom upstreams,
// and the query log and statistics settings.
func BenchmarkClientsContainer_perQuery(b *testing.B) {
	const clientsNum = 50

	clients := newClientsContainer(b)
	clients.clientChecker = &testBlockedClientChecker{
		onIsBlockedClient: func(_ netip.Addr, _ string) (blocked bool, rule string) {
			return false, ""
		},
	}

	ctx := testutil.ContextWithTimeout(b, testTimeout)
	for i := range clientsNum {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		c := newPersistentClientWithIDs(b, fmt.Sprintf("client%d", i), []string{ip.String()})
		require.NoError(b, clients.storage.Add(ctx, c))
	}

	// Half of the queries are from unknown clients.
	addrs := make([]netip.Addr, 2*clientsNum)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{192, 0, 2 + byte(i%2), byte(i / 2)})
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for i := 0; pb.Next(); i++ {
			addr := addrs[i%len(addrs)]
			ids := []string{addr.String()}

			setts := &filtering.Settings{}
			clients.storage.ApplyClientFiltering("", addr, setts)
			_ = clients.storage.CustomUpstreamConfig("", addr)
			_ = clients.shouldLogClient(ids)
			_ = clients.shouldCountClient(ids)
		}
	})
}
