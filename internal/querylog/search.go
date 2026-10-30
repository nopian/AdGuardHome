package querylog

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// client finds the client info, if any, by its ClientID and IP address,
// optionally checking the provided cache.  It will use the IP address
// regardless of if the IP anonymization is enabled now, because the
// anonymization could have been disabled in the past, and client will try to
// find those records as well.
func (l *queryLog) client(clientID, ip string, cache clientCache) (c *Client, err error) {
	cck := clientCacheKey{clientID: clientID, ip: ip}

	var ok bool
	if c, ok = cache[cck]; ok {
		return c, nil
	}

	var ids []string
	if clientID != "" {
		ids = append(ids, clientID)
	}

	if ip != "" {
		ids = append(ids, ip)
	}

	c, err = l.findClient(ids)
	if err != nil {
		return nil, err
	}

	// Cache all results, including negative ones, to prevent excessive and
	// expensive client searching.
	cache[cck] = c

	return c, nil
}

// searchMemory looks up log records which are currently in the in-memory
// buffer.  It optionally uses the client cache, if provided.  It also returns
// the total amount of records in the buffer at the moment of searching.
// l.confMu is expected to be locked.
func (l *queryLog) searchMemory(
	ctx context.Context,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, total int) {
	// Check memory size, as the buffer can contain a single log record.  See
	// [newQueryLog].
	if l.conf.MemSize == 0 {
		return nil, 0
	}

	l.bufferLock.Lock()
	defer l.bufferLock.Unlock()

	l.buffer.ReverseRange(func(entry *logEntry) (cont bool) {
		// A shallow clone is enough, since the only thing that this loop
		// modifies is the client field.
		e := entry.shallowClone()

		var err error
		e.client, err = l.client(e.ClientID, e.IP.String(), cache)
		if err != nil {
			l.logger.ErrorContext(
				ctx,
				"enriching memory record",
				"at", e.Time,
				"client_ip", e.IP,
				"client_id", e.ClientID,
				slogutil.KeyError, err,
			)

			// Go on and try to match anyway.
		}

		if params.match(e) {
			entries = append(entries, e)
		}

		return true
	})

	return entries, int(l.buffer.Len())
}

// search searches log entries in memory buffer and log file using specified
// parameters and returns the list of entries found and the time of the oldest
// entry.  l.confMu is expected to be locked.
func (l *queryLog) search(
	ctx context.Context,
	params *searchParams,
) (entries []*logEntry, oldest time.Time) {
	start := time.Now()

	if params.limit == 0 {
		return []*logEntry{}, time.Time{}
	}

	cache := clientCache{}

	memoryEntries, bufLen := l.searchMemory(ctx, params, cache)
	l.logger.DebugContext(ctx, "got entries from memory", "count", len(memoryEntries))

	fileEntries, oldest, total := l.searchFiles(ctx, params, cache)
	l.logger.DebugContext(ctx, "got entries from files", "count", len(fileEntries))

	total += bufLen

	totalLimit := params.offset + params.limit

	// now let's get a unified collection
	entries = append(memoryEntries, fileEntries...)
	isFull := len(entries) >= totalLimit
	if isFull {
		// remove extra records
		entries = entries[:totalLimit]
	}

	entries, oldest = l.finalizeSearchResults(entries, params, oldest, isFull)

	l.logger.DebugContext(
		ctx,
		"prepared data",
		"count", len(entries),
		"total", total,
		"older_than", params.olderThan,
		"elapsed", time.Since(start),
	)

	return entries, oldest
}

// finalizeSearchResults sorts entries and applies offset trimming, and updates
// the oldest timestamp.  isFull is true if entries were cut at the limit, in
// which case the next page must start after the last returned entry.
// Otherwise, oldest is the time of the oldest scanned record, or zero if the
// whole log has been scanned, so that the next page doesn't scan the same
// records again.  params must not be nil.
func (l *queryLog) finalizeSearchResults(
	entries []*logEntry,
	params *searchParams,
	oldest time.Time,
	isFull bool,
) (res []*logEntry, t time.Time) {
	// Resort entries on start time to partially mitigate query log looking
	// weird on the frontend.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/2293.
	slices.SortStableFunc(entries, func(a, b *logEntry) (res int) {
		return -a.Time.Compare(b.Time)
	})

	if params.offset > 0 {
		if len(entries) > params.offset {
			entries = entries[params.offset:]
		} else {
			return nil, time.Time{}
		}
	}

	if isFull && len(entries) > 0 {
		oldest = entries[len(entries)-1].Time
	}

	return entries, oldest
}

// seekRecord changes the current position to the next record older than the
// provided parameter.
func (r *qLogReader) seekRecord(ctx context.Context, olderThan time.Time) (err error) {
	if olderThan.IsZero() {
		return r.SeekStart()
	}

	err = r.seekTS(ctx, olderThan.UnixNano())
	if err == nil {
		// Read to the next record, because we only need the one that goes
		// after it.
		_, err = r.ReadNext()
	}

	return err
}

// setQLogReader creates a reader with the specified files and sets the
// position to the next record older than the provided parameter.
func (l *queryLog) setQLogReader(
	ctx context.Context,
	olderThan time.Time,
) (qr *qLogReader, err error) {
	files := []string{
		l.logFile + ".1",
		l.logFile,
	}

	r, err := newQLogReader(ctx, l.logger, files)
	if err != nil {
		return nil, fmt.Errorf("opening qlog reader: %w", err)
	}

	err = r.seekRecord(ctx, olderThan)
	if err != nil {
		defer func() { err = errors.WithDeferred(err, r.Close()) }()
		l.logger.DebugContext(ctx, "cannot seek", "older_than", olderThan, slogutil.KeyError, err)

		return nil, nil
	}

	return r, nil
}

// readEntries reads entries from the reader to totalLimit.  By default, we do
// not scan more than maxFileScanEntries at once.  The idea is to make search
// calls faster so that the UI could handle it and show something quicker.
// This behavior can be overridden if maxFileScanEntries is set to 0.
func (l *queryLog) readEntries(
	ctx context.Context,
	r *qLogReader,
	params *searchParams,
	cache clientCache,
	totalLimit int,
) (entries []*logEntry, oldestNano int64, total int) {
	for total < params.maxFileScanEntries || params.maxFileScanEntries <= 0 {
		ent, ts, rErr := l.readNextEntry(ctx, r, params, cache)
		if rErr == io.EOF {
			oldestNano = 0

			break
		} else if rErr != nil {
			l.logger.ErrorContext(ctx, "reading next entry", slogutil.KeyError, rErr)
		}

		// Keep the previous timestamp if the record has none, for example
		// because it couldn't be read.
		oldestNano = cmp.Or(ts, oldestNano)
		total++

		if ent == nil {
			continue
		}

		entries = append(entries, ent)
		if len(entries) == totalLimit {
			break
		}
	}

	return entries, oldestNano, total
}

// searchFiles looks up log records from all log files.  It optionally uses the
// client cache, if provided.  searchFiles does not scan more than
// maxFileScanEntries so callers may need to call it several times to get all
// the results.  oldest and total are the time of the oldest processed entry
// and the total number of processed entries, including discarded ones,
// correspondingly.
func (l *queryLog) searchFiles(
	ctx context.Context,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, oldest time.Time, total int) {
	entries, oldest, total, ok := l.searchFilesIndexed(ctx, params, cache)
	if ok {
		return entries, oldest, total
	}

	r, err := l.setQLogReader(ctx, params.olderThan)
	if err != nil {
		l.logger.ErrorContext(ctx, "searching files", slogutil.KeyError, err)
	}

	if r == nil {
		return entries, oldest, 0
	}

	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			l.logger.ErrorContext(ctx, "closing files", slogutil.KeyError, closeErr)
		}
	}()

	totalLimit := params.offset + params.limit
	entries, oldestNano, total := l.readEntries(ctx, r, params, cache, totalLimit)
	if oldestNano != 0 {
		oldest = time.Unix(0, oldestNano)
	}

	return entries, oldest, total
}

// indexSearchBudget is the time after which a search using the index returns
// the results found so far, if there are fewer than requested, so that the web
// interface can show them and request more.
const indexSearchBudget = 1 * time.Second

// searchFilesIndexed is [queryLog.searchFiles] that uses the search index to
// skip the blocks of records that can't match.  ok is false if the index can't
// be used, in which case the files must be searched without it.  The search is
// limited by [indexSearchBudget] instead of params.maxFileScanEntries, unless
// the latter is zero.
func (l *queryLog) searchFilesIndexed(
	ctx context.Context,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, oldest time.Time, total int, ok bool) {
	s, err := l.index.newSearch(l.indexPaths(), params, func(clientID, ip string) (name string) {
		if c, _ := l.client(clientID, ip, cache); c != nil {
			return c.Name
		}

		return ""
	})
	if err != nil {
		l.logger.ErrorContext(ctx, "searching with index", slogutil.KeyError, err)
	}

	if s == nil {
		return nil, time.Time{}, 0, false
	}

	defer func() {
		if closeErr := s.close(); closeErr != nil {
			l.logger.ErrorContext(ctx, "closing files", slogutil.KeyError, closeErr)
		}
	}()

	entries, oldestNano, total, err := l.readIndexedEntries(ctx, s, params, cache)
	if err != nil {
		l.logger.ErrorContext(ctx, "searching with index; rebuilding", slogutil.KeyError, err)
		l.index.invalidate()
		l.startIndexBuild(ctx)

		return nil, time.Time{}, 0, false
	}

	if oldestNano != 0 {
		oldest = time.Unix(0, oldestNano)
	}

	return entries, oldest, total, true
}

// indexedSearch is the state of a search using the index.
type indexedSearch struct {
	// entries are the matching entries found so far.
	entries []*logEntry

	// oldestNano is the time of the oldest record searched so far.
	oldestNano int64

	// total is the number of records processed so far.
	total int
}

// readIndexedEntries reads the matching entries of the blocks of s, newest
// first, up to params.offset + params.limit.  oldestNano is the time of the
// oldest record searched, or zero if all records have been searched.
func (l *queryLog) readIndexedEntries(
	ctx context.Context,
	s *indexSearch,
	params *searchParams,
	cache clientCache,
) (entries []*logEntry, oldestNano int64, total int, err error) {
	deadline := time.Now().Add(indexSearchBudget)
	st := &indexedSearch{}
	for fileIdx := currentFileIdx; fileIdx >= rotatedFileIdx; fileIdx-- {
		blocks := s.blocks[fileIdx]
		for i := len(blocks) - 1; i >= 0; i-- {
			var done bool
			done, err = l.searchBlock(ctx, s, fileIdx, blocks[i], params, cache, st)
			if err != nil {
				return nil, 0, 0, err
			} else if done || (params.maxFileScanEntries > 0 && time.Now().After(deadline)) {
				return st.entries, st.oldestNano, st.total, nil
			}
		}
	}

	return st.entries, 0, st.total, nil
}

// searchBlock adds the entries matching params from blk of the file with index
// fileIdx to st.  done is true if the limit has been reached.
func (l *queryLog) searchBlock(
	ctx context.Context,
	s *indexSearch,
	fileIdx int,
	blk *indexBlock,
	params *searchParams,
	cache clientCache,
	st *indexedSearch,
) (done bool, err error) {
	if !blk.unknown && !params.olderThan.IsZero() && blk.minTime >= params.olderThan.UnixNano() {
		// All records are newer than the requested ones.
		return false, nil
	}

	if s.mayMatch(blk) {
		var data []byte
		data, err = s.readBlock(fileIdx, blk)
		if err != nil {
			return false, err
		}

		if l.matchBlock(ctx, data, params, cache, st) {
			return true, nil
		}
	}

	// The times of the rejected records aren't read, so continue after the
	// whole block.
	st.oldestNano = cmp.Or(blk.minTime, st.oldestNano)

	return false, nil
}

// matchBlock adds the entries matching params from the records in data, newest
// first, to st, up to params.offset + params.limit.  full is true if the limit
// has been reached.
func (l *queryLog) matchBlock(
	ctx context.Context,
	data []byte,
	params *searchParams,
	cache clientCache,
	st *indexedSearch,
) (full bool) {
	totalLimit := params.offset + params.limit

	// Convert the whole block at once instead of every line separately.
	text := string(data)

	// Skip the final newline.
	end := len(text) - 1
	for end > 0 {
		lineStart := strings.LastIndexByte(text[:end], '\n') + 1
		e, ts := l.matchLine(ctx, text[lineStart:end], params, cache, false)
		st.oldestNano = cmp.Or(ts, st.oldestNano)
		st.total++

		if e != nil {
			st.entries = append(st.entries, e)
			if len(st.entries) == totalLimit {
				return true
			}
		}

		end = lineStart - 1
	}

	return false
}

// quickMatchClientFinder is a wrapper around the usual client finding function
// to make it easier to use with quick matches.
type quickMatchClientFinder struct {
	client func(clientID, ip string, cache clientCache) (c *Client, err error)
	cache  clientCache
}

// findClient is a method that can be used as a quickMatchClientFinder.
func (f quickMatchClientFinder) findClient(
	ctx context.Context,
	logger *slog.Logger,
	clientID string,
	ip string,
) (c *Client) {
	var err error
	c, err = f.client(clientID, ip, f.cache)
	if err != nil {
		logger.ErrorContext(
			ctx,
			"enriching file record for quick search",
			"client_ip", ip,
			"client_id", clientID,
			slogutil.KeyError, err,
		)
	}

	return c
}

// readNextEntry reads the next log entry and checks if it matches the search
// criteria.  It optionally uses the client cache, if provided.  e is nil if
// the entry doesn't match the search criteria.  ts is the timestamp of the
// processed entry.
func (l *queryLog) readNextEntry(
	ctx context.Context,
	r *qLogReader,
	params *searchParams,
	cache clientCache,
) (e *logEntry, ts int64, err error) {
	var line string
	line, err = r.ReadNext()
	if err != nil {
		return nil, 0, err
	}

	e, ts = l.matchLine(ctx, line, params, cache, true)

	return e, ts, nil
}

// matchLine decodes the log record in line and checks if it matches the search
// criteria.  It optionally uses the client cache, if provided.  e is nil if
// the record doesn't match.  ts is the timestamp of the record, or zero if it
// can't be read or if needTS is false and the record is rejected without
// decoding it.
func (l *queryLog) matchLine(
	ctx context.Context,
	line string,
	params *searchParams,
	cache clientCache,
	needTS bool,
) (e *logEntry, ts int64) {
	clientFinder := quickMatchClientFinder{
		client: l.client,
		cache:  cache,
	}

	if !params.quickMatch(ctx, l.logger, line, clientFinder.findClient) {
		if needTS {
			ts = readQLogTimestamp(ctx, l.logger, line)
		}

		return nil, ts
	}

	e = &logEntry{}
	l.decodeLogEntry(ctx, e, line)

	// Set the timestamp before skipping the entry, so that the search can
	// continue after it.
	ts = e.Time.UnixNano()
	if l.isIgnored(e.QHost) {
		return nil, ts
	}

	var err error
	e.client, err = l.client(e.ClientID, e.IP.String(), cache)
	if err != nil {
		l.logger.ErrorContext(
			ctx,
			"enriching file record",
			"at", e.Time,
			"client_ip", e.IP,
			"client_id", e.ClientID,
			slogutil.KeyError, err,
		)

		// Go on and try to match anyway.
	}

	if e.client != nil && e.client.IgnoreQueryLog {
		return nil, ts
	}

	if !params.match(e) {
		return nil, ts
	}

	return e, ts
}
