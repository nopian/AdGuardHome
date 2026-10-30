package querylog

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// indexBlockSize is the maximum number of records in a block of a
// [searchIndex].
const indexBlockSize = 256

// errIndexMismatch is returned when a [searchIndex] doesn't match the files.
const errIndexMismatch errors.Error = "search index doesn't match the files"

// Indexes of the query log files in a [searchIndex].
const (
	rotatedFileIdx = 0
	currentFileIdx = 1
)

// searchIndex is an in-memory index of the query log files.  It splits each
// file into blocks of up to [indexBlockSize] records and keeps the time range,
// the domains, the clients, and the filtering results of each block, so that a
// search can skip the blocks without matching records.
type searchIndex struct {
	// domains are the requested domains.
	domains stringDict

	// clients are the ClientIDs and the IP addresses of the clients.
	clients stringDict

	// pairs are the unique combinations of ClientID and IP address.
	pairs pairDict

	// files are the indexes of the rotated and the current log files.
	files [2]fileIndex

	// mu protects all fields except building.
	mu sync.RWMutex

	// gen is incremented every time the files are rotated or removed, so that
	// a concurrent build can detect it.
	gen uint64

	// ready is true if the index covers both files.
	ready bool

	// building is true while the index is being built.
	building atomic.Bool
}

// fileIndex is the index of a single query log file.
type fileIndex struct {
	// open is the block being filled, or nil.
	open *blockBuilder

	// blocks are the complete blocks, oldest first.  They must not be
	// modified.
	blocks []*indexBlock

	// size is the number of indexed bytes of the file.
	size int64
}

// indexBlock describes consecutive records of a query log file.
type indexBlock struct {
	// domains are the sorted IDs of the requested domains in
	// [searchIndex.domains].
	domains []uint32

	// pairs are the sorted IDs of the clients in [searchIndex.pairs].
	pairs []uint32

	// start is the offset of the first record in the file.
	start int64

	// end is the offset of the byte after the last record in the file.
	end int64

	// minTime is the earliest time of the records, in Unix nanoseconds, or
	// zero if unknown.
	minTime int64

	// maxTime is the latest time of the records, in Unix nanoseconds.
	maxTime int64

	// results is the set of filtering results of the records, see
	// [resultBit].
	results uint64

	// unknown is true if the block contains records which couldn't be read
	// quickly, so it must never be skipped.
	unknown bool
}

// resultBit returns the bit of the filtering result in
// [indexBlock.results].  Reasons outside the range share the last bit.
func resultBit(reason filtering.Reason, isFiltered bool) (bit uint64) {
	i := min(uint64(reason), 31) * 2
	if isFiltered {
		i++
	}

	return 1 << i
}

// blockBuilder collects the records of an [indexBlock].
type blockBuilder struct {
	// domains are the IDs of the domains in the block.
	domains map[uint32]struct{}

	// pairs are the IDs of the clients in the block.
	pairs map[uint32]struct{}

	// block is the block being built.
	block indexBlock

	// count is the number of records in the block.
	count int
}

// newBlockBuilder returns a builder for a block starting at offset start.
func newBlockBuilder(start int64) (b *blockBuilder) {
	return &blockBuilder{
		block: indexBlock{
			start: start,
			end:   start,
		},
		domains: map[uint32]struct{}{},
		pairs:   map[uint32]struct{}{},
	}
}

// build returns the block with the records collected so far.
func (b *blockBuilder) build() (blk *indexBlock) {
	blk = &indexBlock{}
	*blk = b.block
	blk.domains = sortedKeys(b.domains)
	blk.pairs = sortedKeys(b.pairs)

	return blk
}

// sortedKeys returns the sorted keys of m.
func sortedKeys(m map[uint32]struct{}) (keys []uint32) {
	keys = make([]uint32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	slices.Sort(keys)

	return keys
}

// stringDict assigns IDs to strings.
type stringDict struct {
	// ids are the IDs of the strings.
	ids map[string]uint32

	// strs are the strings by their IDs.
	strs []string
}

// id returns the ID of s, adding it if necessary.
func (d *stringDict) id(s string) (id uint32) {
	id, ok := d.ids[s]
	if ok {
		return id
	}

	if d.ids == nil {
		d.ids = map[string]uint32{}
	}

	id = uint32(len(d.strs))
	d.ids[s] = id
	d.strs = append(d.strs, strings.Clone(s))

	return id
}

// clientPair is a combination of a ClientID and an IP address, as their IDs in
// [searchIndex.clients].
type clientPair struct {
	clientID uint32
	ip       uint32
}

// pairDict assigns IDs to client pairs.
type pairDict struct {
	// ids are the IDs of the pairs.
	ids map[clientPair]uint32

	// pairs are the pairs by their IDs.
	pairs []clientPair
}

// id returns the ID of p, adding it if necessary.
func (d *pairDict) id(p clientPair) (id uint32) {
	id, ok := d.ids[p]
	if ok {
		return id
	}

	if d.ids == nil {
		d.ids = map[clientPair]uint32{}
	}

	id = uint32(len(d.pairs))
	d.ids[p] = id
	d.pairs = append(d.pairs, p)

	return id
}

// recordMeta is the data of a query log record that the index keeps.
type recordMeta struct {
	host       string
	clientID   string
	ip         string
	time       int64
	reason     filtering.Reason
	isFiltered bool

	// ok is false if the data couldn't be read quickly.
	ok bool
}

// readRecordMeta reads the indexed data from a query log line, the same way as
// [searchCriterion.quickMatch] does.
func readRecordMeta(line string) (m recordMeta) {
	m.host = readJSONValue(line, `"QH":"`)
	m.ip = readJSONValue(line, `"IP":"`)
	m.clientID = readJSONValue(line, `"CID":"`)
	m.reason, m.isFiltered, m.ok = quickResult(line)

	val := readJSONValue(line, `"T":"`)
	if val == "" {
		val = readJSONValue(line, `"Time":"`)
	}

	t, err := time.Parse(time.RFC3339Nano, val)
	if err == nil {
		m.time = t.UnixNano()
	}

	return m
}

// quickResult returns the filtering reason and whether the request was
// filtered from a query log line, the way they are decoded, without decoding
// the whole line.  ok is false if they can't be determined this way.
func quickResult(line string) (reason filtering.Reason, isFiltered, ok bool) {
	if len(line) < 2 || line[0] != '{' || line[len(line)-1] != '}' {
		// Probably a partially written line, which may not be fully decoded.
		return 0, false, false
	}

	isFiltered = strings.Contains(line, `"IsFiltered":true`)

	code := readJSONNumericValue(line, `"Reason":`)
	if code == "" {
		return filtering.NotFilteredNotFound, isFiltered, !strings.Contains(line, `"Reason":`)
	}

	n, err := strconv.ParseInt(code, 10, 64)
	if err != nil || n < 0 {
		return 0, false, false
	}

	return filtering.Reason(n), isFiltered, true
}

// addRecord adds a record with data m ending at offset end to fi.
func (idx *searchIndex) addRecord(fi *fileIndex, m *recordMeta, end int64) {
	if fi.open == nil {
		fi.open = newBlockBuilder(fi.size)
	}

	b := fi.open
	blk := &b.block
	blk.end = end
	fi.size = end

	if !m.ok || m.time == 0 {
		blk.unknown = true
	}

	if m.time != 0 {
		if blk.minTime == 0 || m.time < blk.minTime {
			blk.minTime = m.time
		}

		blk.maxTime = max(blk.maxTime, m.time)
	}

	blk.results |= resultBit(m.reason, m.isFiltered)
	b.domains[idx.domains.id(m.host)] = struct{}{}
	b.pairs[idx.pairs.id(clientPair{
		clientID: idx.clients.id(m.clientID),
		ip:       idx.clients.id(m.ip),
	})] = struct{}{}

	b.count++
	if b.count == indexBlockSize {
		fi.blocks = append(fi.blocks, b.build())
		fi.open = nil
	}
}

// addLines adds the complete lines from data, which starts at offset start of
// the file, to fi.  It returns the number of bytes added, which excludes an
// incomplete last line.
func (idx *searchIndex) addLines(fi *fileIndex, start int64, data []byte) (n int) {
	for n < len(data) {
		i := slices.Index(data[n:], '\n')
		if i < 0 {
			break
		}

		m := readRecordMeta(string(data[n : n+i]))
		n += i + 1
		idx.addRecord(fi, &m, start+int64(n))
	}

	return n
}

// indexFile adds the records of the file at path to fi, starting at fi.size.
func (idx *searchIndex) indexFile(fi *fileIndex, path string) (err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	defer func() { err = errors.WithDeferred(err, f.Close()) }()

	_, err = f.Seek(fi.size, io.SeekStart)
	if err != nil {
		return fmt.Errorf("seeking: %w", err)
	}

	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, readErr := r.ReadString('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			m := readRecordMeta(line[:len(line)-1])
			idx.addRecord(fi, &m, fi.size+int64(len(line)))
		}

		if readErr == io.EOF {
			return nil
		} else if readErr != nil {
			return readErr
		}
	}
}

// build indexes the query log files at paths, the rotated file first, and
// installs the index.  writeMu must be the lock that guards writing to and
// rotating the files.
func (idx *searchIndex) build(ctx context.Context, l *slog.Logger, paths [2]string, writeMu *sync.Mutex) {
	defer slogutil.RecoverAndLog(ctx, l)

	for {
		start := time.Now()

		idx.mu.RLock()
		gen := idx.gen
		idx.mu.RUnlock()

		built := &searchIndex{}
		err := built.indexFiles(paths)
		if err != nil {
			l.ErrorContext(ctx, "building search index", slogutil.KeyError, err)

			return
		}

		if idx.install(built, gen, paths, writeMu) {
			l.DebugContext(
				ctx,
				"built search index",
				"elapsed", time.Since(start),
				"domains", len(built.domains.strs),
			)

			return
		}

		l.DebugContext(ctx, "files changed while building search index; retrying")
	}
}

// indexFiles indexes both files at paths in idx.
func (idx *searchIndex) indexFiles(paths [2]string) (err error) {
	for i, p := range paths {
		err = idx.indexFile(&idx.files[i], p)
		if err != nil {
			return fmt.Errorf("indexing %q: %w", p, err)
		}
	}

	return nil
}

// install replaces the contents of idx with built if the files haven't been
// rotated or removed since the generation gen.  It indexes the records written
// to the current file in the meantime.
func (idx *searchIndex) install(built *searchIndex, gen uint64, paths [2]string, writeMu *sync.Mutex) (ok bool) {
	writeMu.Lock()
	defer writeMu.Unlock()

	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.gen != gen {
		return false
	}

	err := built.indexFile(&built.files[currentFileIdx], paths[currentFileIdx])
	if err != nil {
		return false
	}

	idx.domains, idx.clients, idx.pairs = built.domains, built.clients, built.pairs
	idx.files = built.files
	idx.ready = true

	return true
}

// appendCurrent indexes data, which has been written to the current file at
// offset start.  It must be called with the write lock held.  ok is false if the
// index doesn't match the file and must be rebuilt.
func (idx *searchIndex) appendCurrent(start int64, data []byte) (ok bool) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if !idx.ready {
		return true
	}

	fi := &idx.files[currentFileIdx]
	if fi.size != start || idx.addLines(fi, start, data) != len(data) {
		idx.ready = false

		return false
	}

	return true
}

// rotate updates the index after the current file has been renamed to the
// rotated one.  It must be called with the write lock held.
func (idx *searchIndex) rotate() {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.gen++
	if !idx.ready {
		return
	}

	idx.files[rotatedFileIdx] = idx.files[currentFileIdx]
	idx.files[currentFileIdx] = fileIndex{}
	idx.compact()
}

// reset updates the index after both files have been removed.  It must be
// called with the write lock held.
func (idx *searchIndex) reset() {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.gen++
	if idx.ready {
		idx.domains, idx.clients, idx.pairs = stringDict{}, stringDict{}, pairDict{}
		idx.files = [2]fileIndex{}
	}
}

// compact removes the strings and pairs that are no longer used by any block
// from the dictionaries.  idx.mu must be locked.
func (idx *searchIndex) compact() {
	fi := &idx.files[rotatedFileIdx]
	if fi.open != nil {
		fi.blocks = append(fi.blocks, fi.open.build())
		fi.open = nil
	}

	var domains, clients stringDict
	var pairs pairDict
	domainIDs := map[uint32]uint32{}
	pairIDs := map[uint32]uint32{}

	newBlocks := make([]*indexBlock, 0, len(fi.blocks))
	for _, blk := range fi.blocks {
		nb := *blk
		nb.domains = remapIDs(blk.domains, domainIDs, func(id uint32) (newID uint32) {
			return domains.id(idx.domains.strs[id])
		})
		nb.pairs = remapIDs(blk.pairs, pairIDs, func(id uint32) (newID uint32) {
			p := idx.pairs.pairs[id]

			return pairs.id(clientPair{
				clientID: clients.id(idx.clients.strs[p.clientID]),
				ip:       clients.id(idx.clients.strs[p.ip]),
			})
		})
		newBlocks = append(newBlocks, &nb)
	}

	fi.blocks = newBlocks
	idx.domains, idx.clients, idx.pairs = domains, clients, pairs
}

// remapIDs returns the sorted new IDs for ids, using and filling cache, and
// calling newID for the IDs that aren't in it.
func remapIDs(ids []uint32, cache map[uint32]uint32, newID func(id uint32) (newID uint32)) (res []uint32) {
	res = make([]uint32, len(ids))
	for i, id := range ids {
		nid, ok := cache[id]
		if !ok {
			nid = newID(id)
			cache[id] = nid
		}

		res[i] = nid
	}

	slices.Sort(res)

	return res
}

// invalidate marks the index as not matching the files.
func (idx *searchIndex) invalidate() {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.ready = false
}

// indexSearch is a search of the query log files using a snapshot of a
// [searchIndex].
type indexSearch struct {
	// files are the opened log files by their index, or nil if missing.
	files [2]*os.File

	// blocks are the blocks of the files by their index, oldest first.
	blocks [2][]*indexBlock

	// matchers return true if a block may contain records matching the
	// search criteria, one per criterion.
	matchers []blockMatcher
}

// blockMatcher returns true if blk may contain matching records.
type blockMatcher func(blk *indexBlock) (ok bool)

// clientNameFunc returns the name of the client with clientID and ip, or an
// empty string.
type clientNameFunc func(clientID, ip string) (name string)

// newSearch returns a search of the files at paths with params, or nil if the
// index isn't ready.  s must be closed after use.
func (idx *searchIndex) newSearch(
	paths [2]string,
	params *searchParams,
	clientName clientNameFunc,
) (s *indexSearch, err error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if !idx.ready {
		return nil, nil
	}

	s = &indexSearch{}
	for i := range idx.files {
		fi := &idx.files[i]
		s.blocks[i] = slices.Clip(fi.blocks)
		if fi.open != nil {
			s.blocks[i] = append(s.blocks[i], fi.open.build())
		}

		if len(s.blocks[i]) == 0 {
			continue
		}

		s.files[i], err = os.Open(paths[i])
		if err != nil {
			s.close()

			return nil, fmt.Errorf("opening %q: %w", paths[i], err)
		}
	}

	for _, c := range params.searchCriteria {
		s.matchers = append(s.matchers, idx.newBlockMatcher(c, clientName))
	}

	return s, nil
}

// close closes the files of s.
func (s *indexSearch) close() (err error) {
	var errs []error
	for _, f := range s.files {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}

	return errors.Join(errs...)
}

// mayMatch returns true if blk may contain records matching all criteria.
func (s *indexSearch) mayMatch(blk *indexBlock) (ok bool) {
	if blk.unknown {
		return true
	}

	for _, m := range s.matchers {
		if !m(blk) {
			return false
		}
	}

	return true
}

// readBlock returns the records of blk of the file with index fileIdx.
func (s *indexSearch) readBlock(fileIdx int, blk *indexBlock) (data []byte, err error) {
	data = make([]byte, blk.end-blk.start)
	_, err = s.files[fileIdx].ReadAt(data, blk.start)
	if err != nil {
		return nil, fmt.Errorf("reading block at %d: %w", blk.start, err)
	}

	if len(data) == 0 || data[0] != '{' || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("block at %d: %w", blk.start, errIndexMismatch)
	}

	return data, nil
}

// newBlockMatcher returns a matcher for criterion c.  idx.mu must be locked
// for reading.
func (idx *searchIndex) newBlockMatcher(c searchCriterion, clientName clientNameFunc) (m blockMatcher) {
	switch c.criterionType {
	case ctTerm:
		return idx.newTermMatcher(c, clientName)
	case ctFilteringStatus, ctReason:
		mask := resultsMask(c)

		return func(blk *indexBlock) (ok bool) { return blk.results&mask != 0 }
	default:
		return func(_ *indexBlock) (ok bool) { return true }
	}
}

// newTermMatcher returns a matcher for the term criterion c, which matches the
// blocks with a domain or a client that [searchCriterion.quickMatch] matches.
// idx.mu must be locked for reading.
func (idx *searchIndex) newTermMatcher(c searchCriterion, clientName clientNameFunc) (m blockMatcher) {
	matchFunc := ctDomainOrClientCaseNonStrict
	if c.strict {
		matchFunc = ctDomainOrClientCaseStrict
	}

	domains := make([]bool, len(idx.domains.strs))
	for id, d := range idx.domains.strs {
		domains[id] = matchFunc(c.value, c.asciiVal, "", "", d, "")
	}

	pairs := make([]bool, len(idx.pairs.pairs))
	for id, p := range idx.pairs.pairs {
		clientID, ip := idx.clients.strs[p.clientID], idx.clients.strs[p.ip]
		pairs[id] = matchFunc(c.value, c.asciiVal, clientID, clientName(clientID, ip), "", ip)
	}

	return func(blk *indexBlock) (ok bool) {
		return slices.ContainsFunc(blk.domains, func(id uint32) (ok bool) { return domains[id] }) ||
			slices.ContainsFunc(blk.pairs, func(id uint32) (ok bool) { return pairs[id] })
	}
}

// resultsMask returns the set of filtering results, see [resultBit], that
// [searchCriterion.match] accepts for the result criterion c.
func resultsMask(c searchCriterion) (mask uint64) {
	// Reasons outside the range share the last bits, so always include them.
	const maxReason = 31
	mask = resultBit(maxReason, false) | resultBit(maxReason, true)

	for r := range filtering.Reason(maxReason) {
		for _, isFiltered := range []bool{false, true} {
			e := &logEntry{Result: filtering.Result{Reason: r, IsFiltered: isFiltered}}
			if c.match(e) {
				mask |= resultBit(r, isFiltered)
			}
		}
	}

	return mask
}
