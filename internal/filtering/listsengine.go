package filtering

import (
	"bufio"
	"bytes"
	"fmt"
	"hash/maphash"
	"io"
	"io/fs"
	"math/bits"
	"os"
	"sync"
	"sync/atomic"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// listsEngine matches DNS requests against filtering-rule lists.  It keeps the
// plain domain rules, like "||example.org^", which make up most blocklists, in
// a compact [domainTable], and the remaining rules in a [urlfilter.DNSEngine].
//
// It produces the same results as a [urlfilter.DNSEngine] containing all the
// rules, except that when plain domain rules match, the matched network rules
// are normalized with [normalizeNetworkRules].
type listsEngine struct {
	// domains contains the plain domain rules.  It is nil if there are none.
	domains *domainTable

	// storage contains the remaining rules.  It must not be nil.
	storage *filterlist.RuleStorage

	// engine matches the remaining rules.  It must not be nil.
	engine *urlfilter.DNSEngine

	// listIDs are the IDs of the filter lists by their index in domains.
	listIDs []rules.ListID

	// parsed are the parsed plain domain rules by their index in domains.  It
	// contains up to [maxParsedDomainRules] rules, since the same blocked
	// domains are usually requested over and over again.
	parsed sync.Map

	// parsedNum is the number of rules in parsed.
	parsedNum atomic.Int64
}

// maxParsedDomainRules is the maximum number of parsed plain domain rules that
// a [listsEngine] keeps.
const maxParsedDomainRules = 100_000

// newListsEngine compiles filters.  If fast is false, all rules are compiled
// into the [urlfilter.DNSEngine], which is only useful for testing.
func newListsEngine(filters []Filter, fast bool) (e *listsEngine, err error) {
	e = &listsEngine{}

	var b *domainTableBuilder
	if fast {
		b = &domainTableBuilder{}
	}

	lists := make([]filterlist.Interface, 0, len(filters))
	for _, f := range filters {
		var rest []byte
		var skip bool
		rest, skip, err = splitFilter(f, b, len(e.listIDs))
		if err != nil {
			return nil, fmt.Errorf("filter %d: %w", f.ID, err)
		} else if skip {
			continue
		}

		e.listIDs = append(e.listIDs, f.ID)
		lists = append(lists, filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             f.ID,
			RulesText:      rest,
			IgnoreCosmetic: true,
		}))
	}

	e.storage, err = filterlist.NewRuleStorage(lists)
	if err != nil {
		return nil, fmt.Errorf("creating rule storage: %w", err)
	}

	e.engine = urlfilter.NewDNSEngine(e.storage)
	e.domains = b.build()

	return e, nil
}

// splitFilter reads the rules of f, adds the plain domain rules to b, if it's
// not nil, as the rules of the list with index listIdx, and returns the other
// rules.  skip is true if f has no rules to read.
func splitFilter(f Filter, b *domainTableBuilder, listIdx int) (rest []byte, skip bool, err error) {
	var r io.Reader
	switch {
	case len(f.Data) != 0:
		r = bytes.NewReader(f.Data)
	case f.FilePath == "":
		return nil, true, nil
	default:
		file, openErr := os.Open(f.FilePath)
		if errors.Is(openErr, fs.ErrNotExist) {
			return nil, true, nil
		} else if openErr != nil {
			return nil, false, fmt.Errorf("opening rule list: %w", openErr)
		}

		defer func() { err = errors.WithDeferred(err, file.Close()) }()

		r = file
	}

	if b != nil && listIdx > maxListIdx {
		return nil, false, fmt.Errorf("too many rule lists: %d", listIdx)
	}

	rest, err = splitRules(bufio.NewReaderSize(r, 64*1024), b, uint32(listIdx))
	if err != nil {
		return nil, false, fmt.Errorf("reading rule list: %w", err)
	}

	return rest, false, nil
}

// splitRules reads the rules from r line by line, the same way that package
// filterlist does, adds the plain domain rules to b, if it's not nil, and
// returns the other lines.
func splitRules(r *bufio.Reader, b *domainTableBuilder, listIdx uint32) (rest []byte, err error) {
	var buf []byte
	for {
		var line []byte
		line, buf, err = readRuleLine(r, buf[:0])
		if b == nil || !b.addRule(bytes.TrimSpace(line), listIdx) {
			rest = appendLine(rest, line)
		}

		if errors.Is(err, io.EOF) {
			return rest, nil
		} else if err != nil {
			return nil, err
		}
	}
}

// appendLine appends line to rest, adding a newline if line doesn't end with
// one.
func appendLine(rest, line []byte) (res []byte) {
	res = append(rest, line...)
	if len(line) > 0 && line[len(line)-1] != '\n' {
		res = append(res, '\n')
	}

	return res
}

// readRuleLine reads the next line from r, including the newline, if any.
// Lines longer than the buffer of r are collected in buf, which is returned for
// reuse.  line is valid until the next call.  err is [io.EOF] if line is the
// last one.
func readRuleLine(r *bufio.Reader, buf []byte) (line, newBuf []byte, err error) {
	for {
		line, err = r.ReadSlice('\n')
		if !errors.Is(err, bufio.ErrBufferFull) {
			break
		}

		buf = append(buf, line...)
	}

	if len(buf) == 0 {
		return line, buf, err
	}

	buf = append(buf, line...)

	return buf, buf, err
}

// RulesCount returns the number of rules in e.
func (e *listsEngine) RulesCount() (n uint64) {
	return e.engine.RulesCount() + uint64(e.domains.len())
}

// Close releases the resources of e.
func (e *listsEngine) Close() (err error) {
	return e.storage.Close()
}

// MatchRequest matches req against the rules in e, the same way as
// [urlfilter.DNSEngine.MatchRequest].
func (e *listsEngine) MatchRequest(req *urlfilter.DNSRequest) (res *urlfilter.DNSResult, matched bool) {
	res = &urlfilter.DNSResult{}
	matched = e.MatchRequestInto(req, res)

	return res, matched
}

// MatchRequestInto matches req against the rules in e and writes the result
// into res, the same way as [urlfilter.DNSEngine.MatchRequestInto].  res must
// be empty.
func (e *listsEngine) MatchRequestInto(req *urlfilter.DNSRequest, res *urlfilter.DNSResult) (matched bool) {
	if e.engine.RulesCount() > 0 {
		matched = e.engine.MatchRequestInto(req, res)
	}

	n := len(res.NetworkRules)
	res.NetworkRules = e.appendDomainRules(res.NetworkRules, req.Hostname)
	if len(res.NetworkRules) == n {
		return matched
	}

	res.NetworkRules = normalizeNetworkRules(res.NetworkRules)
	res.NetworkRule = rules.GetDNSBasicRule(res.NetworkRules)
	if res.NetworkRule == nil {
		// $badfilter rules have disabled all matched rules.  Since plain domain
		// rules are never $badfilter rules, the engine has also found no rule
		// and has already looked up the hosts-file style rules.
		return len(res.HostRulesV4) > 0 || len(res.HostRulesV6) > 0
	}

	res.HostRulesV4, res.HostRulesV6 = nil, nil

	return true
}

// appendDomainRules appends the plain domain rules matching hostname to nrs.
func (e *listsEngine) appendDomainRules(nrs []*rules.NetworkRule, hostname string) (res []*rules.NetworkRule) {
	res = nrs
	if e.domains == nil {
		return res
	}

	var indexes [8]uint32
	forEachRuleDomain(hostname, func(domain string) {
		for _, idx := range e.domains.appendMatches(indexes[:0], domain) {
			if nr := e.domainRule(idx, domain); nr != nil {
				res = append(res, nr)
			}
		}
	})

	return res
}

// domainRule returns the parsed plain domain rule for domain with index idx in
// e.domains.
func (e *listsEngine) domainRule(idx uint32, domain string) (nr *rules.NetworkRule) {
	if v, ok := e.parsed.Load(idx); ok {
		return v.(*rules.NetworkRule)
	}

	de := e.domains.entries[idx]
	nr, err := rules.NewNetworkRule(domainRuleText(domain, de.flags()), e.listIDs[de.listIdx()])
	if err != nil {
		// Shouldn't happen, since package rules parses such rules.
		return nil
	}

	if e.parsedNum.Load() < maxParsedDomainRules {
		if _, loaded := e.parsed.LoadOrStore(idx, nr); !loaded {
			e.parsedNum.Add(1)
		}
	}

	return nr
}

// forEachRuleDomain calls f with every domain d for which the rule "||d^"
// matches hostname according to the regular expression that package rules
// generates for it:
//
//	^(http|https|ws|wss)://([a-z0-9-_.]+\.)?d([^ a-zA-Z0-9.%_-]|$)
//
// That is, d starts at the beginning of hostname, or after a dot preceded by
// at least one character, where all characters before d are letters, digits,
// "-", "_", and ".", and d ends at the end of hostname or before a separator
// character.  Only domains that a plain domain rule can contain are passed to
// f, see [parseDomainRule].
func forEachRuleDomain(hostname string, f func(domain string)) {
	if !isRuleDomain(hostname) {
		forEachRuleDomainSlow(hostname, f)

		return
	}

	// The common case.  Hostname contains no separator characters, and every
	// part of it after a dot is a valid rule domain, since hostname doesn't
	// start with a dot and has no empty labels.
	f(hostname)
	for i := 1; i < len(hostname); i++ {
		if hostname[i] == '.' {
			f(hostname[i+1:])
		}
	}
}

// forEachRuleDomainSlow is the general case of [forEachRuleDomain].
func forEachRuleDomainSlow(hostname string, f func(domain string)) {
	for start := 0; start < len(hostname); start++ {
		isStart, isOver := ruleDomainStart(hostname, start)
		if isOver {
			return
		} else if !isStart {
			continue
		}

		end := start
		for end < len(hostname) && !isSeparatorChar(hostname[end]) {
			end++
		}

		if d := hostname[start:end]; isRuleDomain(d) {
			f(d)
		}
	}
}

// ruleDomainStart returns true if the domain of a "||" rule can start at the
// index start of hostname, see [forEachRuleDomain].  isOver is true if it can't
// start at this or any later index.
func ruleDomainStart(hostname string, start int) (ok, isOver bool) {
	if start == 0 {
		return true, false
	}

	c := hostname[start-1]
	if !isPrefixChar(c) {
		return false, true
	}

	return c == '.' && start >= 2, false
}

// isPrefixChar returns true if c can precede the domain of a "||" rule.
func isPrefixChar(c byte) (ok bool) {
	return isRuleDomainChar(c) || ('A' <= c && c <= 'Z')
}

// isSeparatorChar returns true if c matches the "^" separator of a rule.
func isSeparatorChar(c byte) (ok bool) {
	return !isPrefixChar(c) && c != ' ' && c != '%'
}

// isRuleDomainChar returns true if c can be in the domain of a plain domain
// rule.
func isRuleDomainChar(c byte) (ok bool) {
	return ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.'
}

// isRuleDomain returns true if d can be the domain of a plain domain rule.
// The domain must not start or end with a dot, must not contain empty labels,
// and its last label must contain a letter, so that IP addresses aren't
// included.
func isRuleDomain[T string | []byte](d T) (ok bool) {
	if len(d) == 0 || len(d) > 253 || d[0] == '.' || d[len(d)-1] == '.' {
		return false
	}

	return hasRuleDomainLabels(d)
}

// hasRuleDomainLabels returns true if d, which must not be empty or start with
// a dot, consists of non-empty labels of the characters allowed in plain domain
// rules, and its last label contains a letter.
func hasRuleDomainLabels[T string | []byte](d T) (ok bool) {
	hasLetter := false
	for i := range len(d) {
		c := d[i]
		switch {
		case !isRuleDomainChar(c):
			return false
		case c == '.':
			if d[i-1] == '.' {
				return false
			}

			hasLetter = false
		case 'a' <= c && c <= 'z':
			hasLetter = true
		}
	}

	return hasLetter
}

// Flags of plain domain rules.
const (
	domainFlagAllow     uint8 = 1 << 0
	domainFlagImportant uint8 = 1 << 1
)

const (
	// importantSuffix is the only modifier that plain domain rules can have.
	importantSuffix = "$important"

	// maxListIdx is the maximum index of a list in a [domainTable].
	maxListIdx = 1<<16 - 1
)

// parseDomainRule returns the domain and flags of the rule in line, which must
// have surrounding spaces trimmed, if it's a plain domain rule: "||d^" or
// "@@||d^", optionally followed by "$important".  Package rules parses such
// rules into network rules matching d and its subdomains.
func parseDomainRule(line []byte) (domain []byte, flags uint8, ok bool) {
	rest, isAllow := bytes.CutPrefix(line, []byte("@@"))
	if isAllow {
		flags |= domainFlagAllow
	}

	rest, ok = bytes.CutPrefix(rest, []byte("||"))
	if !ok {
		return nil, 0, false
	}

	rest, isImportant := bytes.CutSuffix(rest, []byte(importantSuffix))
	if isImportant {
		flags |= domainFlagImportant
	}

	rest, ok = bytes.CutSuffix(rest, []byte("^"))
	if !ok || !isRuleDomain(rest) {
		return nil, 0, false
	}

	return rest, flags, true
}

// domainRuleText returns the text of the plain domain rule for domain with
// flags.
func domainRuleText(domain string, flags uint8) (text string) {
	text = "||" + domain + "^"
	if flags&domainFlagAllow != 0 {
		text = "@@" + text
	}

	if flags&domainFlagImportant != 0 {
		text += importantSuffix
	}

	return text
}

// domainEntry is an entry of a [domainTable].
type domainEntry struct {
	// hash is the hash of the domain.
	hash uint64

	// check is the hash of the domain with another seed, which makes false
	// matches practically impossible.
	check uint32

	// meta contains the index of the list in the low 16 bits and the flags of
	// the rule in the next 8 bits.
	meta uint32
}

// listIdx returns the index of the rule's list.
func (de domainEntry) listIdx() (idx uint32) {
	return de.meta & maxListIdx
}

// flags returns the flags of the rule.
func (de domainEntry) flags() (flags uint8) {
	return uint8(de.meta >> 16)
}

// domainTable is a compact, immutable hash table of plain domain rules.  The
// entries are grouped into buckets by the top bits of their hashes, with about
// four entries per bucket on average, so that a lookup reads one or two cache
// lines.
type domainTable struct {
	// buckets are the offsets of the buckets in entries: bucket i spans
	// entries[buckets[i]:buckets[i+1]].
	buckets []uint32

	// entries are the rules, grouped by bucket.
	entries []domainEntry

	// seed is the seed for [domainEntry.hash].
	seed maphash.Seed

	// checkSeed is the seed for [domainEntry.check].
	checkSeed maphash.Seed

	// shift is the shift that turns a hash into a bucket index.
	shift uint
}

// len returns the number of entries in t.  t may be nil.
func (t *domainTable) len() (n int) {
	if t == nil {
		return 0
	}

	return len(t.entries)
}

// appendMatches appends the indexes of the entries for domain to dst.
func (t *domainTable) appendMatches(dst []uint32, domain string) (res []uint32) {
	h := maphash.String(t.seed, domain)
	b := h >> t.shift
	lo, hi := t.buckets[b], t.buckets[b+1]
	if lo == hi {
		return dst
	}

	var check uint32
	checked := false
	for i := lo; i < hi; i++ {
		de := &t.entries[i]
		if de.hash != h {
			continue
		}

		if !checked {
			check, checked = uint32(maphash.String(t.checkSeed, domain)), true
		}

		if de.check == check {
			dst = append(dst, i)
		}
	}

	return dst
}

// domainTableBuilder collects plain domain rules for a [domainTable].
type domainTableBuilder struct {
	// entries are the collected entries.
	entries []domainEntry

	// seed is the seed for [domainEntry.hash].
	seed maphash.Seed

	// checkSeed is the seed for [domainEntry.check].
	checkSeed maphash.Seed

	// seenUnindexed are the texts of the added rules that package urlfilter
	// doesn't index, see [isUnindexedDomain].
	seenUnindexed map[string]struct{}

	// seeded is true if the seeds have been initialized.
	seeded bool
}

// isUnindexedDomain returns true if package urlfilter doesn't index the plain
// domain rule for domain by its shortcut, which is the domain itself.  It
// ignores the rules with the same text as an already added unindexed rule, even
// from other lists.
func isUnindexedDomain(domain []byte) (ok bool) {
	return len(domain) <= 5 || (len(domain) < len("https://")+1 && bytes.HasPrefix(domain, []byte("http")))
}

// addRule adds the rule in line, which must have surrounding spaces trimmed,
// as a rule of the list with index listIdx, if it's a plain domain rule.  It
// returns false if it isn't.
func (b *domainTableBuilder) addRule(line []byte, listIdx uint32) (ok bool) {
	domain, flags, ok := parseDomainRule(line)
	if !ok {
		return false
	}

	if !b.seeded {
		b.seed, b.checkSeed, b.seeded = maphash.MakeSeed(), maphash.MakeSeed(), true
		b.seenUnindexed = map[string]struct{}{}
	}

	if isUnindexedDomain(domain) {
		if _, seen := b.seenUnindexed[string(line)]; seen {
			return true
		}

		b.seenUnindexed[string(line)] = struct{}{}
	}

	b.entries = append(b.entries, domainEntry{
		hash:  maphash.Bytes(b.seed, domain),
		check: uint32(maphash.Bytes(b.checkSeed, domain)),
		meta:  listIdx | uint32(flags)<<16,
	})

	return true
}

// build returns the table with the collected entries, or nil if there are
// none.  b may be nil.
func (b *domainTableBuilder) build() (t *domainTable) {
	if b == nil || len(b.entries) == 0 {
		return nil
	}

	n := len(b.entries)
	bucketBits := uint(bits.Len(uint(n / 4)))
	t = &domainTable{
		buckets:   make([]uint32, 1<<bucketBits+1),
		entries:   make([]domainEntry, n),
		seed:      b.seed,
		checkSeed: b.checkSeed,
		shift:     64 - bucketBits,
	}

	// Place the entries with a counting sort by bucket.
	for _, de := range b.entries {
		t.buckets[de.hash>>t.shift+1]++
	}

	for i := 1; i < len(t.buckets); i++ {
		t.buckets[i] += t.buckets[i-1]
	}

	next := make([]uint32, len(t.buckets)-1)
	copy(next, t.buckets)
	for _, de := range b.entries {
		bkt := de.hash >> t.shift
		t.entries[next[bkt]] = de
		next[bkt]++
	}

	b.entries, b.seenUnindexed = nil, nil

	return t
}
