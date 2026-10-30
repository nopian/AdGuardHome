package aghtest

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// envBenchScale is the environment variable that sets the factor by which
	// benchmarks scale the size of the data they generate.
	envBenchScale = "AGH_BENCH_SCALE"

	// envBenchLists is the environment variable that sets the directory with
	// real blocklists for benchmarks to use instead of generated ones.
	envBenchLists = "AGH_BENCH_LISTS"
)

// BenchScale returns the factor by which benchmarks scale the size of the data
// they generate.  It is set with the AGH_BENCH_SCALE environment variable and
// is 1 by default, which keeps benchmarks fast enough for CI.
func BenchScale(tb testing.TB) (scale int) {
	tb.Helper()

	v := os.Getenv(envBenchScale)
	if v == "" {
		return 1
	}

	scale, err := strconv.Atoi(v)
	require.NoError(tb, err, envBenchScale)
	require.Positive(tb, scale, envBenchScale)

	return scale
}

// BenchBlocklists returns the paths of the blocklists for benchmarks and up to
// maxDomains domains blocked by them.  If the AGH_BENCH_LISTS environment
// variable is set, the blocklists are the "*.txt" files in that directory.
// Otherwise, it generates a single blocklist with n rules.
func BenchBlocklists(tb testing.TB, n, maxDomains int) (paths, domains []string) {
	tb.Helper()

	dir := os.Getenv(envBenchLists)
	if dir == "" {
		path, generated := GenerateBlocklist(tb, n)

		return []string{path}, generated[:min(maxDomains, len(generated))]
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	require.NoError(tb, err)
	require.NotEmpty(tb, paths, envBenchLists)

	// Take the domains from all lists evenly.
	perList := max(maxDomains/len(paths), 1)
	for _, p := range paths {
		domains = append(domains, readBlockedDomains(tb, p, perList)...)
	}

	return paths, domains
}

// readBlockedDomains returns up to n domains blocked by the "||domain^" rules
// and hosts-file lines from the blocklist at path.
func readBlockedDomains(tb testing.TB, path string, n int) (domains []string) {
	tb.Helper()

	// #nosec G304 G703 -- Trust this path, since it comes from the directory
	// set by the person running the benchmarks.
	f, err := os.Open(path)
	require.NoError(tb, err)
	defer func() { require.NoError(tb, f.Close()) }()

	s := bufio.NewScanner(f)
	for len(domains) < n && s.Scan() {
		if d, ok := blockedDomain(s.Text()); ok {
			domains = append(domains, d)
		}
	}

	require.NoError(tb, s.Err())

	return domains
}

// blockedDomain returns the domain blocked by line if it's a "||domain^" rule
// or a hosts-file line for 0.0.0.0 or 127.0.0.1.
func blockedDomain(line string) (domain string, ok bool) {
	if d, isHosts := strings.CutPrefix(line, "0.0.0.0 "); isHosts {
		domain = strings.TrimSpace(d)
	} else if d, isHosts = strings.CutPrefix(line, "127.0.0.1 "); isHosts {
		domain = strings.TrimSpace(d)
	} else if d, ok = strings.CutPrefix(line, "||"); ok {
		domain, ok = strings.CutSuffix(d, "^")
		if !ok {
			return "", false
		}
	}

	if domain == "" || strings.ContainsAny(domain, "*$/# \t") || !strings.Contains(domain, ".") {
		return "", false
	}

	return domain, true
}

// GenerateBlocklist writes a blocklist with n "||domain^" rules for random
// domains to a temporary file and returns its path and the blocked domains.
// The domains are the same for the same n.
func GenerateBlocklist(tb testing.TB, n int) (path string, domains []string) {
	tb.Helper()

	// #nosec G404 -- Use a deterministic generator so that the generated data
	// is the same in every run.
	r := rand.New(rand.NewPCG(uint64(n), 0))
	tlds := []string{"com", "net", "org", "io", "xyz", "info"}

	sb := &strings.Builder{}
	sb.WriteString("! Title: Generated benchmark blocklist\n")

	domains = make([]string, 0, n)
	for i := range n {
		d := fmt.Sprintf("%s%d.%s", randomLabel(r), i, tlds[r.IntN(len(tlds))])
		if r.IntN(3) == 0 {
			d = randomLabel(r) + "." + d
		}

		domains = append(domains, d)
		_, _ = fmt.Fprintf(sb, "||%s^\n", d)
	}

	path = filepath.Join(tb.TempDir(), "blocklist.txt")
	err := os.WriteFile(path, []byte(sb.String()), 0o600)
	require.NoError(tb, err)

	return path, domains
}

// randomLabel returns a random domain name label of 4 to 11 letters.
func randomLabel(r *rand.Rand) (l string) {
	b := make([]byte, 4+r.IntN(8))
	for i := range b {
		b[i] = byte('a' + r.IntN(26))
	}

	return string(b)
}
