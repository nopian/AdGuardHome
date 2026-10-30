# Performance plan

Goal: make the things people wait for feel instant (searching the query log, unblocking a domain, opening the dashboard) and cut the per-query cost of filtering.  Upstream compatibility is not a constraint.

## Baseline

Measured on a 4-core x86 container with two real HaGeZi blocklists: Ultimate (282k rules) and TIF (1.85M rules).  A Raspberry Pi is roughly 5–10× slower in absolute terms; the ratios should hold.  The benchmarks live next to the code they measure (see Phase 0).

| What | Today | Target | Speed-up |
|---|---|---|---|
| Unblock click (server side) | 0.63 s with 282k rules, 6.1 s with 2.1M | under 10 ms | 60–600× |
| Search for a rare term, 1M log lines | 1.7 s over 21 requests; 9 s for a status filter | 10–20 ms, one request | about 100× |
| Dashboard, 90 days | 180 ms per load | under 2 ms | about 100× |
| Rule matching per query | 20 µs for allowed domains, 79 µs for blocked ones | under 0.5 µs | 40–150× |
| Loading or updating lists | 5.9 s | under 0.3 s, a few ms from a saved compiled copy | 20× and up |
| Memory for the rule engine | 220 MB, doubling during each rebuild | about 50–90 MB | 2–4× |
| Whole query, server CPU | about 38 µs; 51k queries/s (75k with no lists) | about 12 µs | about 3× |

Whole-query DNS latency cannot improve 100×: once matching is fast, most of the time per query is the operating system's network handling.

### Why unblocking is slow

Clicking "Unblock" sends the whole custom-rules text back to the server (`POST /control/filtering/set_rules`).  The server then rebuilds the entire engine from every list (`enableFiltersLocked` → `initFiltering`), re-reading and re-parsing millions of rules, and finishes with a forced garbage collection.  After that, the client device keeps the old blocked answer for another 10 s (the default `blocked_response_ttl`).

### Why matching is slow

urlfilter files rules under every 5-character substring of the domain.  For each query it collects all rules sharing a substring with the hostname and string-compares each one.  But essentially every rule in both lists is a plain `||domain^` rule (282,349 of 282,350 and 1,852,754 of 1,852,755), so a hash lookup per domain level would answer the same question.

### Why searching is slow

The UI asks for 20 results and the server scans at most 50,000 lines per request, so a rare term means a long chain of sequential requests that each reopen files, binary-search to the cursor and rescan the in-memory buffer.  The cursor also rewinds to the last match instead of the last scanned line, so lines get scanned twice.  Status filters skip the cheap pre-check and fully JSON-decode every line.

### Why the dashboard is slow

Every load decodes all hourly records for the configured period (2,160 gob records for 90 days) and re-aggregates them from scratch.

## Phase 0: measurement and safety net

- Committed benchmarks: unblock rebuild, rule matching, 90-day dashboard, a 1M-line search, and a full-server UDP load test.  They use generated data by default; set `AGH_BENCH_LISTS` to a directory of real lists to use those instead.
- A differential checker that runs the reference matcher (one combined engine, the old behavior) and the new matcher on many hostnames and fails on any difference.  Phases 1 and 2 are not safe without it.
- Run the benchmarks on a Raspberry Pi 4 as well, since that is the hardware to optimize for.

### Running the benchmarks

| Benchmark | Package | What it measures |
|---|---|---|
| `BenchmarkDNSFilter_SetUserRules` | `internal/filtering` | Time until a custom-rules change takes effect: `separate` is the new path, `full_rebuild` the old one. |
| `BenchmarkDNSFilter_CheckHost` | `internal/filtering` | Rule matching per query, for blocked and allowed domains. |
| `BenchmarkStatsCtx_getData` | `internal/stats` | Loading 90 days of statistics for the dashboard. |
| `BenchmarkQueryLog_search` | `internal/querylog` | A search as the web interface does it, including the follow-up requests; `requests/op` is the number of requests. |
| `BenchmarkServer_udp` | `internal/dnsforward` | Plain DNS over UDP through the whole server, with the query log and statistics enabled. |

By default, the benchmarks generate small data sets so that they stay fast in CI.  Two environment variables make them realistic:

- `AGH_BENCH_SCALE` multiplies the generated data: 20,000 blocklist rules and 20,000 query log records per unit.  For example, `AGH_BENCH_SCALE=50` gives a 1M-record query log.
- `AGH_BENCH_LISTS` is a directory of real blocklists (`*.txt`) to use instead of the generated one.

```sh
AGH_BENCH_LISTS=/path/to/lists AGH_BENCH_SCALE=50 \
	go test -run '^$' -bench . -benchmem \
	./internal/filtering/ ./internal/stats/ ./internal/querylog/ ./internal/dnsforward/
```

The differential checker is `TestDNSFilter_customRules_differential` in `internal/filtering`.  It compares the separately compiled custom rules against a single combined engine on random rule sets, including `$important`, `$badfilter`, `$client`, `$ctag`, `$dnstype`, `$dnsrewrite`, `$denyallow`, regular expressions and hosts-file rules.

### Phase 1 results

Same machine as the baseline.

| What | Before | After |
|---|---|---|
| Custom-rules change takes effect, 2.1M list rules | 4.74 s, 1.3 GB allocated | 7 µs |
| Custom-rules change takes effect, 20k list rules | 23 ms | 4.5 µs |
| Rule matching per query with custom rules, 2.1M list rules | 9.5 µs allowed, 14 µs blocked | about 1 µs more |
| Search with matches 40k records apart, 1M records | 20 requests, 1.16 s | 16 requests, 1.03 s |
| Real server: unblock request until DNS stops blocking, 2.1M list rules | 5.3 s | 4 ms |
| Real server and web UI: "Unblock" click in the query log until DNS stops blocking | | 46 ms |
| TTL of blocked responses with the default configuration | 10 s | 1 s |

Matching costs about 1 µs more per query when custom rules exist, because urlfilter prepares the request once per engine.  Phase 2 replaces this code.

The real-server numbers come from running the built binaries with both HaGeZi lists and a local upstream, and timing DNS queries from the unblock request (or, for the web UI, from the click in a headless browser) until the domain resolves.

## Phase 1: instant unblock

- Custom rules get their own small engine, separate from the lists.  Changing a custom rule rebuilds only that engine.
- Results from both engines are combined using urlfilter's own priority logic: matching rules from both engines go through urlfilter's selection function, so `$important`, `@@` and `$badfilter` behave exactly as before, including custom rules that override list rules.
- A new endpoint adds or removes individual custom rules, so the UI stops sending the whole text back.  This also fixes lost updates when two tabs edit rules, and a data race: `handleFilteringSetRules` writes `d.conf.UserRules` without the lock that `EnableFilters` reads it under.
- Lower the default blocked-response TTL from 10 s to 1 s, so phones and laptops stop using the cached block soon after an unblock.
- The UI updates immediately and offers an undo, instead of waiting for the server.
- Independent fix: the query log cursor rewind.

## Phase 2: hash-based fast path for list matching

### Phase 2 results

Same machine as the baseline, 2.1M-rule HaGeZi lists unless noted.

| What | Before | After |
|---|---|---|
| Rule matching per query, allowed domain | 9.5 µs | 1.6 µs |
| Rule matching per query, blocked domain | 14 µs | 2.4 µs |
| Rule matching per query, 20k generated rules, allowed / blocked | 1.8 / 3.4 µs | 0.6 / 1.3 µs |
| Compiling the blocklists | 4.7 s | 0.57 s |
| Heap used by the compiled blocklists | about 220 MB | 38 MB |
| Matching 40 blocked services | about 16 µs | 0.3 µs on a match, 1.7 µs otherwise |
| Whole server, plain DNS over UDP | 15.1 µs per query | 11.5 µs per query |

The remaining matching time is mostly memory latency: the table is 36 MB, so a lookup usually misses the CPU caches.  Saving the compiled table to disk turned out unnecessary, since compiling takes half a second.

How it works:

- When a list is compiled, rules of the forms `||d^`, `@@||d^`, `||d^$important`, and `@@||d^$important` go into a hash table grouped into small buckets, about 17 bytes per rule.  All other rules, including hosts-file rules, go into a much smaller urlfilter engine.
- A request checks the table for each domain that `||d^` can match according to the regular expression urlfilter builds for it, including its handling of characters such as `+` and `_` in hostnames.  Matched rules from both parts go through urlfilter's `GetDNSBasicRule`.
- urlfilter ignores later copies of rules it can't index by shortcut, such as `||a.io^`, so the table does the same.

Checks:

- `TestDNSFilter_customRules_differential` compares against a plain urlfilter engine on random rule sets with near-miss rule shapes, short domains, unusual hostnames, list IDs out of order, and custom `$badfilter` rules.  A one-off heavy run made 624,000 comparisons without a difference.
- `TestForEachRuleDomain_urlfilter` compares the candidate domains with urlfilter's own matching for random hostnames.
- `TestListsEngine_realLists`, with `AGH_BENCH_LISTS` set, compares both engines on real lists: the HaGeZi lists, the AdGuard DNS filter, and the StevenBlack hosts file.

- Sort rules into two groups when a list loads.  Plain `||domain^` rules, `@@` and `$important` variants, and `0.0.0.0 host` lines go into compact hash tables.  Everything else (regex, `$client`, `$dnsrewrite`, `$denyallow`, and so on) goes into a small leftover urlfilter engine.
- A lookup checks the hash tables for each domain level of the hostname.  Only on a hit is the matched rule parsed and passed to the same urlfilter selection function as in Phase 1.  Queries that match nothing never parse anything.
- Compile each list once after download and save the result to disk, so startup just loads the compiled copy.  Updating one list rebuilds only the list tables, in the background.
- Blocked services: compile each set of blocked services once and cache it, instead of checking rules one by one on every query.
- The Phase 0 checker must pass on both HaGeZi lists, the AdGuard default list and a hosts-format list before this ships.

## Phase 3: instant query log search

Instead of a new storage format, which would require migrating existing logs, the JSON log files stay as they are and get an in-memory search index (`internal/querylog/searchindex.go`):

- The index splits each file into blocks of 256 records and keeps, for each block, its byte range, its time range, the set of filtering results in it, and the IDs of its domains and clients in shared dictionaries.  It takes about 7 bytes per record.
- A search first matches the term against the dictionaries, which have thousands of entries instead of millions of records, including the client names, and then reads only the blocks that can contain a match.  The records in those blocks go through the same matching code as before, so the results are the same.
- Status and reason filters read the result of a record without decoding it, both in the index and when matching records.
- One request now searches the whole log, limited by a 1-second budget instead of 50,000 records, so the web interface no longer chains requests.
- The index is built in the background at startup and updated when records are written, the log is rotated, or cleared.  Until it's ready, or if a file changes behind its back, searches work as before and the index is rebuilt.
- The new web interface waits 150 ms instead of 500 ms after typing and ignores late results of earlier searches.

Not done: a live stream of new queries, and saving the index to disk.  Building it takes about 1.5 s per million records.

### Phase 3 results

Same machine as the baseline, 1M records (244 MB of JSON).

| Search, as the web interface does it | Before | After |
|---|---|---|
| Rare term, real server over HTTP | 0.81 s, 20 requests | 7 ms, 1 request |
| No matches, real server over HTTP | 0.79 s, 21 requests | 3 ms, 1 request |
| Rare reason (Safe Browsing), real server over HTTP | 0.58 s, 21 requests | 1 ms, 1 request |
| Rare term, benchmark | 111 ms | 4.2 ms |
| Term with matches 40k records apart, benchmark | 0.90 s, 16 requests | 5.1 ms, 1 request |
| No matches, benchmark | 1.12 s, 21 requests | 1.0 ms |
| Status filter without matches, benchmark | 6.1 s (1.38 s with the quick result check) | 0.04 ms |

Checks: `TestSearchIndex_differential` compares searches with and without the index on random parameters (terms, strict terms, statuses, reasons, cursors, limits) over a log with both files, ignored domains and clients, and a record the index can't read; a one-off run of 3,000 searches found no difference.  `TestSearchIndex_lifecycle` covers writing, rotating twice, clearing, and a file changed behind the index's back.

## Phase 4: dashboard

The hourly records stay in the database as they are, and an in-memory cache (`internal/stats/cache.go`) keeps them decoded:

- Each cached hour stores its top lists as pairs of a count and a name ID, with the names interned and reference-counted, so a name used in many hours is stored once.
- The cache keeps running totals per name: an hour is added when it's stored and subtracted when it expires.  A page load for the configured period adds the live current hour to the totals, picks the top 100 of each list, and subtracts the current hour again.  Shorter periods, such as the new web interface's `recent` parameter, sum the cached hours instead, which is still fast.
- The top 100 is picked by inserting into a sorted list of 100 instead of sorting all names, and the ignored domains and clients are only checked for the names that would make it into the list.
- The cache is filled in the background at startup.  Reading hours from the database no longer holds the lock that `StatsCtx.Update` needs on every DNS query, so a page load no longer stalls DNS responses.  A generation counter makes sure that hours read while a flush changes the database aren't cached.
- `StatsCtx.Update` now takes the configuration lock for reading only.  The lock of the current hour is still exclusive, since every query changes its maps.
- `StatsCtx.TopClientsIP`, which picks the clients to resolve at startup, uses the cache too.
- Names with the same count are now ordered by name, both in the stored hours and in the top lists, instead of randomly.

Not done: more accurate top lists.  Each stored hour still keeps only its own top 100, and changing that requires a new storage format.

### Phase 4 results

Same machine as the baseline, 90 days (2,160 hours) with 100 entries in every list of every hour and 60,000 distinct names.

| Dashboard | Before | After |
|---|---|---|
| Real server over HTTP, median | 745 ms | 4.1 ms |
| Real server over HTTP, first load after start | 707 ms | 4.5 ms |
| Longest DNS response while loading the dashboard | 155 ms | 11 ms, at 256 loads per second |
| Benchmark (`BenchmarkStatsCtx_getData`) | 172 ms, 102 MB allocated | 1.0 ms, 0.6 MB allocated |
| Server memory (RSS) after 20 loads | 124 MB | 90 MB |

The cache takes about 20 MB in this worst case and grows with the period and the number of entries per hour; for the default period of one day it's negligible.

Checks: `TestStatsCtx_dataFromCache` compares the cache with the original code, which reads every hour from the database (kept in `reference_internal_test.go`), over random updates, flushes, skipped hours, clears, and periods shorter and longer than the configured one, and checks that the running totals and the reference counts match the cached hours and that every cached hour matches the database.  `TestStatsCtx_dataFromCache_concurrent` does the same after concurrent page loads, and `TestUnitCache_add` covers hours read while a flush changes the database.

## Phase 5: per-query cleanup

- Look up the client once per query and reuse it; today it happens 3–4 times, including a second access-list check.
- Keep filtering settings as a read-only snapshot swapped on config changes instead of building a new settings object under a lock for every query.
- Write query log entries straight into the new storage format, without the JSON step.
- Expected: about 38 µs → 12 µs of server CPU per query.

## UI

- Build on `client_v2`, which currently copies the polling loop (`stores/queryLogs.ts`) and whole-text `set_rules` (`stores/filtering.ts`), so it needs the new API.
- A query log table that only renders visible rows, search as you type with request cancellation, instant block and unblock with undo, a live view, and dashboard counters over SSE.
- Keep the v1 API working until the old UI is gone.

## Risks

- Rule behavior: Phases 1–2 must not change what gets blocked.  Passing matches through urlfilter's own selection function plus the Phase 0 checker keeps this manageable.
- Data migration for the query log and stats.  Fallback: keep the old readers until old data expires.
- To verify in Phase 1: whether responses blocked by checks on the upstream's answer (like CNAME blocking) are cached by dnsproxy.  If so, an unblock also has to clear those cache entries.
