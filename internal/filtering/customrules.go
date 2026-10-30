package filtering

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/rules"
)

// errStaleCustomRules is returned by [DNSFilter.initFiltering] when the custom
// rules compiled into the new engines are older than the installed ones, so the
// new engines must not be installed.
const errStaleCustomRules errors.Error = "custom rules are stale"

// customRules are the compiled custom filtering rules.  They are kept in an
// engine separate from the blocklists, so that changing them only requires
// recompiling a few rules instead of all the blocklists.
type customRules struct {
	// engine matches the custom rules.  It must not be nil.
	engine *listsEngine

	// hosts are the hosts-file style custom rules by hostname, in the order in
	// which they appear in the rules.  See [customRules.matchWithLists].
	hosts map[string][]*rules.HostRule

	// hasBadfilter is true if the custom rules contain $badfilter rules.  Such
	// rules can disable rules from the blocklists, so they must be compiled
	// together with the blocklists.
	hasBadfilter bool
}

// newCustomRules compiles the custom filtering rules from data.
func newCustomRules(data []byte) (cr *customRules, err error) {
	engine, err := newListsEngine([]Filter{{
		ID:   rulelist.IDCustom,
		Data: data,
	}}, true)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	cr = &customRules{
		engine: engine,
		hosts:  map[string][]*rules.HostRule{},
	}

	// Plain domain rules are neither hosts-file style rules nor $badfilter
	// rules, so only scan the remaining ones.
	scanner := engine.storage.NewRuleStorageScanner()
	for scanner.Scan() {
		r, _ := scanner.Rule()
		switch r := r.(type) {
		case *rules.HostRule:
			for _, h := range r.Hostnames {
				cr.hosts[h] = append(cr.hosts[h], r)
			}
		case *rules.NetworkRule:
			cr.hasBadfilter = cr.hasBadfilter || r.IsOptionEnabled(rules.OptionBadfilter)
		}
	}

	return cr, nil
}

// isEmpty returns true if cr contains no rules.  cr may be nil.
func (cr *customRules) isEmpty() (ok bool) {
	return cr == nil || cr.engine.RulesCount() == 0
}

// close releases the resources of cr.  cr may be nil.
func (cr *customRules) close(ctx context.Context, l *slog.Logger) {
	if cr == nil {
		return
	}

	err := cr.engine.Close()
	if err != nil {
		l.ErrorContext(ctx, "closing custom rules storage", slogutil.KeyError, err)
	}
}

// matchWithLists matches req against the custom rules and the rules in lists,
// producing the same result as a single [urlfilter.DNSEngine] containing both
// the custom rules and the rules from lists, as long as the custom rules don't
// contain $badfilter rules.  The network rules in res are normalized with
// [normalizeNetworkRules].  cr and lists must not be nil.
//
// The network rules from both engines are combined and the resulting rule is
// chosen by [rules.GetDNSBasicRule], the same function that
// [urlfilter.DNSEngine] uses.  When no network rule is chosen, the
// hosts-file style rules are used, with the custom ones first.
func (cr *customRules) matchWithLists(
	lists *listsEngine,
	req *urlfilter.DNSRequest,
) (res *urlfilter.DNSResult, matched bool) {
	res = &urlfilter.DNSResult{}
	cr.engine.MatchRequestInto(req, res)

	// The engine only looks up its hosts-file style rules when its own network
	// rules don't choose a rule.
	customDecided := res.NetworkRule != nil
	customHostsV4, customHostsV6 := res.HostRulesV4, res.HostRulesV6

	listsRes := &urlfilter.DNSResult{}
	lists.MatchRequestInto(req, listsRes)

	res.NetworkRules = normalizeNetworkRules(appendNewUnindexed(res.NetworkRules, listsRes.NetworkRules))
	res.NetworkRule = rules.GetDNSBasicRule(res.NetworkRules)
	if res.NetworkRule != nil {
		res.HostRulesV4, res.HostRulesV6 = nil, nil

		return res, true
	}

	// A $badfilter rule from the lists may have disabled the network rule that
	// the custom engine chose, so it didn't look up its hosts-file style rules.
	//
	// NOTE:  The opposite case, the lists engine choosing a rule disabled by a
	// custom $badfilter rule, cannot happen, because custom rules with
	// $badfilter rules are compiled into the lists engine.
	if customDecided {
		customHostsV4, customHostsV6 = cr.hostRules(req.Hostname)
	}

	res.HostRulesV4 = append(customHostsV4, listsRes.HostRulesV4...)
	res.HostRulesV6 = append(customHostsV6, listsRes.HostRulesV6...)

	return res, len(res.HostRulesV4) > 0 || len(res.HostRulesV6) > 0
}

// appendNewUnindexed appends the rules from lists to custom, except for the
// unindexed rules, see [isUnindexedRule], that have the same text as a rule in
// custom.  A single [urlfilter.DNSEngine] ignores such duplicates.
func appendNewUnindexed(custom, lists []*rules.NetworkRule) (res []*rules.NetworkRule) {
	res = custom
	customLen := len(custom)
	for _, nr := range lists {
		if isUnindexedRule(nr) && slices.ContainsFunc(res[:customLen], func(cnr *rules.NetworkRule) (ok bool) {
			return cnr.Text() == nr.Text()
		}) {
			continue
		}

		res = append(res, nr)
	}

	return res
}

// isUnindexedRule returns true if package urlfilter doesn't index the
// host-level network rule nr by its shortcut, in which case it ignores the
// rules with the same text as an already added one, even from other lists.
// See [isUnindexedDomain].
func isUnindexedRule(nr *rules.NetworkRule) (ok bool) {
	sc := nr.Shortcut
	if len(sc) <= 5 {
		return true
	}

	return slices.ContainsFunc(anyURLShortcuts, func(p anyURLShortcut) (isAny bool) {
		return len(sc) <= p.maxLen && strings.HasPrefix(sc, p.prefix)
	})
}

// anyURLShortcut describes the shortcuts that package urlfilter considers to
// match too many URLs to index them.
type anyURLShortcut struct {
	// prefix is the prefix of such shortcuts.
	prefix string

	// maxLen is the maximum length of such shortcuts.
	maxLen int
}

// anyURLShortcuts are the shortcuts that package urlfilter doesn't index.
var anyURLShortcuts = []anyURLShortcut{
	{prefix: "ws:", maxLen: len("ws://")},
	{prefix: "wss:", maxLen: len("wss://")},
	{prefix: "|ws", maxLen: len("|wss://")},
	{prefix: "http", maxLen: len("https://")},
	{prefix: "|http", maxLen: len("|https://")},
}

// normalizeNetworkRules sorts the matched network rules by the filter list ID,
// so that the custom rules go first, and then by text, and removes the
// duplicates.  Both [rules.GetDNSBasicRule] and the processing of $dnsrewrite
// rules choose the first one of the rules with the same priority, and
// [urlfilter.DNSEngine] can return the same rule several times, depending on
// how its index is laid out.  This makes the result independent of the
// internal state of the engines, which changes whenever any rule is added or
// removed.
func normalizeNetworkRules(nrs []*rules.NetworkRule) (res []*rules.NetworkRule) {
	if len(nrs) < 2 {
		return nrs
	}

	slices.SortStableFunc(nrs, compareNetworkRules)

	return slices.CompactFunc(nrs, func(a, b *rules.NetworkRule) (ok bool) {
		return compareNetworkRules(a, b) == 0
	})
}

// compareNetworkRules compares network rules by the filter list ID and then by
// text.
func compareNetworkRules(a, b *rules.NetworkRule) (res int) {
	return cmp.Or(
		cmp.Compare(a.GetFilterListID(), b.GetFilterListID()),
		strings.Compare(a.Text(), b.Text()),
	)
}

// hostRules returns the hosts-file style custom rules for hostname, split by
// the IP address family.
func (cr *customRules) hostRules(hostname string) (v4, v6 []*rules.HostRule) {
	for _, r := range cr.hosts[hostname] {
		if r.IP.Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}

	return v4, v6
}

// splitCustomFilter returns the filters without the custom filtering rules and
// the custom filtering rules, if filters contain exactly one filter with them.
// Otherwise, it returns filters unchanged and nil.
func splitCustomFilter(filters []Filter) (lists []Filter, custom *Filter) {
	idx := slices.IndexFunc(filters, func(f Filter) (ok bool) { return f.ID == rulelist.IDCustom })
	if idx < 0 || slices.ContainsFunc(filters[idx+1:], func(f Filter) (ok bool) {
		return f.ID == rulelist.IDCustom
	}) {
		return filters, nil
	}

	return slices.Delete(slices.Clone(filters), idx, idx+1), &filters[idx]
}

// SetUserRules sets the custom filtering rules and applies them.
func (d *DNSFilter) SetUserRules(ctx context.Context, userRules []string) {
	func() {
		d.conf.filtersMu.Lock()
		defer d.conf.filtersMu.Unlock()

		d.conf.UserRules = userRules
		d.customGen++
	}()

	d.applyUserRules(ctx)
}

// EditUserRules removes the rules in remove from the custom filtering rules,
// appends the rules from add that aren't already there, and applies the result.
// Rules are compared with surrounding spaces trimmed.  res is the resulting
// list of custom filtering rules, and changed is true if it differs from the
// previous one.
func (d *DNSFilter) EditUserRules(
	ctx context.Context,
	add []string,
	remove []string,
) (res []string, changed bool) {
	func() {
		d.conf.filtersMu.Lock()
		defer d.conf.filtersMu.Unlock()

		d.conf.UserRules, changed = editRules(d.conf.UserRules, add, remove)
		if changed {
			d.customGen++
		}

		res = slices.Clone(d.conf.UserRules)
	}()

	if changed {
		d.applyUserRules(ctx)
	}

	return res, changed
}

// editRules returns userRules without the rules from remove and with the rules
// from add appended unless already present, as well as whether the result
// differs from userRules.  The elements of add and remove must have surrounding
// spaces trimmed.
func editRules(userRules, add, remove []string) (res []string, changed bool) {
	res = make([]string, 0, len(userRules)+len(add))
	for _, r := range userRules {
		if slices.Contains(remove, strings.TrimSpace(r)) {
			changed = true

			continue
		}

		res = append(res, r)
	}

	for _, a := range add {
		if slices.ContainsFunc(res, func(r string) (ok bool) { return strings.TrimSpace(r) == a }) {
			continue
		}

		// Don't add the rule after trailing empty lines.
		for len(res) > 0 && strings.TrimSpace(res[len(res)-1]) == "" {
			res = res[:len(res)-1]
		}

		res = append(res, a)
		changed = true
	}

	return res, changed
}

// applyUserRules compiles the current custom filtering rules and installs them.
// If the custom rules can be kept separate from the blocklists, only the custom
// rules are recompiled, which takes milliseconds.  Otherwise, all filters are
// recompiled asynchronously.
func (d *DNSFilter) applyUserRules(ctx context.Context) {
	var data []byte
	var gen uint64
	func() {
		d.conf.filtersMu.RLock()
		defer d.conf.filtersMu.RUnlock()

		data = []byte(strings.Join(d.conf.UserRules, "\n"))
		gen = d.customGen
	}()

	cr, err := newCustomRules(data)
	switch {
	case err != nil:
		d.logger.ErrorContext(ctx, "compiling custom rules", slogutil.KeyError, err)
	case cr.hasBadfilter:
		d.logger.DebugContext(ctx, "custom rules have $badfilter rules; recompiling all filters")
		cr.close(ctx, d.logger)
	case d.installCustomRules(ctx, cr, gen):
		d.logger.DebugContext(ctx, "installed custom rules", "gen", gen)

		return
	default:
		cr.close(ctx, d.logger)
	}

	d.EnableFilters(true)
}

// installCustomRules installs cr as the custom rules of generation gen.  It
// returns false if the installed engines have the custom rules compiled
// together with the blocklists, in which case all filters must be recompiled.
func (d *DNSFilter) installCustomRules(ctx context.Context, cr *customRules, gen uint64) (ok bool) {
	d.engineLock.Lock()
	defer d.engineLock.Unlock()

	if d.customRules == nil {
		return false
	}

	if gen < d.installedCustomGen {
		// Newer custom rules have been installed concurrently.
		cr.close(ctx, d.logger)

		return true
	}

	d.customRules.close(ctx, d.logger)
	d.customRules, d.installedCustomGen = cr, gen

	return true
}

// engines are the compiled blocklists and allowlists.
type engines struct {
	// block matches the blocklists.  It also contains the custom rules when
	// they aren't compiled separately.
	block *listsEngine

	// allow matches the allowlists.
	allow *listsEngine
}

// close releases the resources of e.
func (e *engines) close(ctx context.Context, l *slog.Logger) {
	for _, le := range []*listsEngine{e.block, e.allow} {
		if le == nil {
			continue
		}

		err := le.Close()
		if err != nil {
			l.ErrorContext(ctx, "closing filtering engine", slogutil.KeyError, err)
		}
	}
}

// installEngines installs the newly compiled engines.  cr are the custom rules
// of generation gen, or nil if the custom rules are compiled into the
// blocklists engine.  It returns [errStaleCustomRules] if the new engines must
// not be installed because they contain stale custom rules, in which case the
// caller must close them and recompile.
func (d *DNSFilter) installEngines(ctx context.Context, e *engines, cr *customRules, gen uint64) (err error) {
	d.engineLock.Lock()
	defer d.engineLock.Unlock()

	if gen < d.installedCustomGen && (cr == nil || d.customRules == nil) {
		return fmt.Errorf("installing generation %d over %d: %w", gen, d.installedCustomGen, errStaleCustomRules)
	}

	d.reset(ctx)
	d.filteringEngine, d.filteringEngineAllow = e.block, e.allow

	if cr != nil && gen < d.installedCustomGen {
		// Newer custom rules have been installed while the blocklists were
		// being compiled, so keep them.
		cr.close(ctx, d.logger)

		return nil
	}

	d.customRules.close(ctx, d.logger)
	d.customRules, d.installedCustomGen = cr, gen

	return nil
}
