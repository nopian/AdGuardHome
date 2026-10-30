import { createStore } from 'solid-js/store';
import { untrack } from 'solid-js';
import {
    filteringStatus,
    filteringSetRules,
    filteringEditRules,
    filteringAddURL,
    filteringRemoveURL,
    filteringSetURL,
    filteringRefresh,
    filteringConfig,
    filteringCheckHost,
} from 'panel/api/generated';
import { addErrorToast, addSuccessToast, createUndoToast } from './toasts';
import type { Filter } from 'panel/helpers/helpers';
import { normalizeFilteringStatus, normalizeRulesTextarea } from 'panel/helpers/helpers';
import intl from 'panel/common/intl';
import type { FilterCheckHostResponse } from 'panel/api/model/filterCheckHostResponse';
import type { FilterSetUrlData } from 'panel/api/model/filterSetUrlData';
import type { FilterRefreshRequest } from 'panel/api/model/filterRefreshRequest';
import type { FilterConfig } from 'panel/api/model/filterConfig';

type FilteringState = {
    isModalOpen: boolean;
    processingFilters: boolean;
    filtersInitialized: boolean;
    processingRules: boolean;
    processingAddFilter: boolean;
    processingRefreshFilters: boolean;
    processingConfigFilter: boolean;
    processingRemoveFilter: boolean;
    processingSetConfig: boolean;
    processingCheck: boolean;
    isFilterAdded: boolean;
    isFilterRemoved: boolean;
    isFilterEdited: boolean;
    filters: Filter[];
    whitelistFilters: Filter[];
    userRules: string;
    interval: number;
    enabled: boolean;
    modalType: string;
    modalFilterUrl: string;
    check: (FilterCheckHostResponse & { hostname?: string }) | Record<string, never>;
};

const initialState: FilteringState = {
    isModalOpen: false,
    processingFilters: false,
    filtersInitialized: false,
    processingRules: false,
    processingAddFilter: false,
    processingRefreshFilters: false,
    processingConfigFilter: false,
    processingRemoveFilter: false,
    processingSetConfig: false,
    processingCheck: false,
    isFilterAdded: false,
    isFilterRemoved: false,
    isFilterEdited: false,
    filters: [],
    whitelistFilters: [],
    userRules: '',
    interval: 24,
    enabled: true,
    modalType: '',
    modalFilterUrl: '',
    check: {},
};

const [state, setState] = createStore<FilteringState>(initialState);

export const getFilteringStatus = async () => {
    setState('processingFilters', true);
    try {
        const data = await filteringStatus();
        setState({
            ...normalizeFilteringStatus(data),
            processingFilters: false,
            filtersInitialized: true,
        });
    } catch (error) {
        addErrorToast({ error });
        setState({ processingFilters: false, filtersInitialized: true });
    }
};

export const setRules = async (rules: string): Promise<boolean> => {
    setState('processingRules', true);
    try {
        const normalizedRules = {
            rules: (normalizeRulesTextarea(rules)?.split('\n') || []).filter(Boolean),
        };
        await filteringSetRules(normalizedRules);
        setState({ userRules: rules, processingRules: false });
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingRules', false);
        return false;
    }
};

const splitByNewLine = (str: string): string[] => str.split('\n').filter(Boolean);

/**
 * Applies the same edit as the edit_rules API to the rules text, so that the
 * result can be shown before the server responds.  Rules are compared with the
 * surrounding spaces trimmed.
 */
export const applyRulesEdit = (rules: string, add: string[], remove: string[]): string => {
    const toRemove = new Set(remove);
    const lines = rules.split('\n').filter((line) => !toRemove.has(line.trim()));

    add.forEach((rule) => {
        if (lines.some((line) => line.trim() === rule)) {
            return;
        }

        while (lines.length > 0 && lines[lines.length - 1].trim() === '') {
            lines.pop();
        }

        lines.push(rule);
    });

    return lines.join('\n');
};

let editRulesSeq = 0;

/**
 * Adds and removes individual custom filtering rules.  Unlike setRules, it
 * doesn't send the other rules, so it can't overwrite changes made elsewhere.
 * The rules are updated locally right away and restored if the request fails.
 */
export const editRules = async (add: string[], remove: string[]): Promise<boolean> => {
    const previousRules = state.userRules || '';
    editRulesSeq += 1;
    const seq = editRulesSeq;

    setState('userRules', applyRulesEdit(previousRules, add, remove));
    try {
        const { rules } = await filteringEditRules({ add, remove });
        if (seq === editRulesSeq) {
            setState('userRules', rules.join('\n'));
        }

        return true;
    } catch (error) {
        if (seq === editRulesSeq) {
            setState('userRules', previousRules);
        }

        addErrorToast({ error });
        return false;
    }
};

/**
 * Adds rule to the custom filtering rules, removing the rules in replace, and
 * shows a notification with an undo action that restores the previous rules.
 */
const addRuleWithUndo = async (rule: string, replace: string[], message: string): Promise<boolean> => {
    const currentRules = splitByNewLine(state.userRules || '').map((r) => r.trim());
    const hadRule = currentRules.includes(rule);
    const toReplace = replace.filter((r) => r !== rule);
    const replaced = toReplace.filter((r) => currentRules.includes(r));

    if (hadRule && replaced.length === 0) {
        return true;
    }

    const didSave = await editRules([rule], toReplace);
    if (!didSave) {
        return false;
    }

    addSuccessToast(
        createUndoToast(message, intl.getMessage('notify_undo'), async () => {
            await editRules(replaced, hadRule ? [] : [rule]);
        }),
    );

    return true;
};

export const blockDomain = async (domain: string): Promise<boolean> => {
    const rule = `||${domain}^$important`;

    return addRuleWithUndo(rule, [`@@${rule}`], intl.getMessage('user_rules_rule_added', { rule }));
};

export const unblockDomain = async (domain: string): Promise<boolean> => {
    const rule = `||${domain}^$important`;
    const desiredRule = `@@${rule}`;

    return addRuleWithUndo(
        desiredRule,
        [rule],
        intl.getMessage('user_rules_rule_added', { rule: desiredRule }),
    );
};

export const blockDomainForClient = async (domain: string, client: string): Promise<boolean> => {
    const rule = `||${domain}^$client=${client}`;

    return addRuleWithUndo(
        rule,
        [`@@${rule}`],
        intl.getMessage('user_rules_rule_added_to_custom_filtering_rules'),
    );
};

export const BLOCK_ACTIONS = {
    BLOCK: 'block' as const,
    UNBLOCK: 'unblock' as const,
};

export type BlockAction = (typeof BLOCK_ACTIONS)[keyof typeof BLOCK_ACTIONS];

export const toggleBlocking = async (
    type: BlockAction,
    domain: string,
    baseRule?: string,
    baseUnblocking?: string,
    matchedRuleToReplace?: string,
): Promise<boolean> => {
    const baseBlockingRule = baseRule || `||${domain}^$important`;
    const baseUnblockingRule = baseUnblocking || `@@${baseBlockingRule}`;
    const desiredRule = type === BLOCK_ACTIONS.BLOCK ? baseBlockingRule : baseUnblockingRule;
    const oppositeRule = type === BLOCK_ACTIONS.BLOCK ? baseUnblockingRule : baseBlockingRule;
    const rulesToReplace = [oppositeRule, matchedRuleToReplace].filter((rule): rule is string =>
        Boolean(rule),
    );

    return addRuleWithUndo(
        desiredRule,
        rulesToReplace,
        intl.getMessage('user_rules_rule_added', { rule: desiredRule }),
    );
};

export const toggleBlockingForClient = (type: BlockAction, domain: string, client: string) => {
    const escapedClientName = client
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/,/g, '\\,')
        .replace(/\|/g, '\\|');
    const baseRule = `||${domain}^$client='${escapedClientName}'`;
    const baseUnblocking = `@@${baseRule}`;

    return toggleBlocking(type, domain, baseRule, baseUnblocking);
};

export const addFilter = async (url: string, name: string, whitelist: boolean) => {
    setState('processingAddFilter', true);
    try {
        await filteringAddURL({ url, name, whitelist });
        setState('processingAddFilter', false);
        setState('isModalOpen', false);
        if (whitelist) {
            addSuccessToast({
                message: intl.getMessage('filter_added_successfully_allowlist', { value: name }),
            });
        } else {
            addSuccessToast({
                message: intl.getMessage('filter_added_successfully', { value: name }),
            });
        }
        await getFilteringStatus();
    } catch (error) {
        addErrorToast({ error });
        setState('processingAddFilter', false);
    }
};

export const removeFilter = async (url: string, whitelist: boolean, name?: string) => {
    setState('processingRemoveFilter', true);
    try {
        await filteringRemoveURL({ url, whitelist });
        setState('processingRemoveFilter', false);
        setState('isModalOpen', false);
        if (whitelist) {
            addSuccessToast({
                message: intl.getMessage('filter_removed_successfully_allowlist', { value: name }),
            });
        } else {
            addSuccessToast({
                message: intl.getMessage('filter_removed_successfully', { value: name }),
            });
        }
        await getFilteringStatus();
    } catch (error) {
        addErrorToast({ error });
        setState('processingRemoveFilter', false);
    }
};

export const toggleFilterStatus = async (
    url: string,
    data: FilterSetUrlData,
    whitelist: boolean,
) => {
    setState('processingConfigFilter', true);
    try {
        await filteringSetURL({ url, data, whitelist });
        setState('processingConfigFilter', false);
        await getFilteringStatus();
    } catch (error) {
        addErrorToast({ error });
        setState('processingConfigFilter', false);
    }
};

export const disableFilter = async (filter: Filter): Promise<boolean> => {
    const data: FilterSetUrlData = {
        enabled: false,
        name: filter.name,
        url: filter.url,
    };
    try {
        await filteringSetURL({ url: filter.url, data, whitelist: false });
        addSuccessToast(
            createUndoToast(
                intl.getMessage('user_rules_filter_was_disabled', {
                    value: filter.name,
                }),
                intl.getMessage('notify_undo'),
                async () => {
                    await filteringSetURL({
                        url: filter.url,
                        data: { ...data, enabled: true },
                        whitelist: false,
                    });
                    await getFilteringStatus();
                },
            ),
        );
        await getFilteringStatus();
        return true;
    } catch (error) {
        addErrorToast({ error });
        return false;
    }
};

export const editFilter = async (url: string, data: FilterSetUrlData, whitelist: boolean) => {
    setState('processingConfigFilter', true);
    try {
        await filteringSetURL({ url, data, whitelist });
        setState({ processingConfigFilter: false, isModalOpen: false });
        addSuccessToast(intl.getMessage('changes_saved_success'));
        await getFilteringStatus();
    } catch (error) {
        addErrorToast({ error });
        setState('processingConfigFilter', false);
    }
};

export const refreshFilters = async (config: FilterRefreshRequest) => {
    setState('processingRefreshFilters', true);
    try {
        const data = await filteringRefresh(config);
        setState('processingRefreshFilters', false);
        const updated = data?.updated ?? 0;
        if (updated > 0) {
            addSuccessToast(intl.getPlural('list_updated', updated));
        } else {
            addSuccessToast(intl.getMessage('all_lists_up_to_date_toast'));
        }
        await getFilteringStatus();
    } catch (error) {
        addErrorToast({ error });
        setState('processingRefreshFilters', false);
    }
};

export const setFiltersConfig = async (config: FilterConfig) => {
    setState('processingSetConfig', true);
    try {
        await filteringConfig(config);
        setState({ ...config, processingSetConfig: false });
    } catch (error) {
        addErrorToast({ error });
        setState('processingSetConfig', false);
    }
};

export const checkHost = async (
    host: string | { name: string; client?: string; qtype?: string },
): Promise<boolean> => {
    setState('processingCheck', true);
    try {
        const data = await filteringCheckHost(typeof host === 'string' ? { name: host } : host);
        const hostname = typeof host === 'string' ? host : host.name;
        setState({
            check: { hostname, ...data },
            processingCheck: false,
        });
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingCheck', false);
        return false;
    }
};

export const addFiltersBatch = async (
    filters: Array<{ url: string; name: string }>,
): Promise<void> => {
    setState('processingAddFilter', true);
    try {
        const results = await Promise.allSettled(
            filters.map(({ url, name }) => filteringAddURL({ url, name, whitelist: false })),
        );

        const successes: Array<{ url: string; name: string }> = [];
        const failures: Array<{ filter: { url: string; name: string }; error: unknown }> = [];

        results.forEach((result, index) => {
            if (result.status === 'fulfilled') {
                successes.push(filters[index]);
            } else {
                failures.push({ filter: filters[index], error: result.reason });
            }
        });

        if (successes.length === 1) {
            addSuccessToast({
                message: intl.getMessage('filter_added_successfully', {
                    value: successes[0].name || successes[0].url,
                }),
            });
        } else if (successes.length > 1) {
            addSuccessToast({
                message: intl.getMessage('filter_added_successfully_more', {
                    value: successes[0].name || successes[0].url,
                    more: String(successes.length - 1),
                }),
            });
        }

        failures.forEach(({ error }) => {
            addErrorToast({ error });
        });

        if (successes.length > 0) {
            await getFilteringStatus();
        }

        setState('processingAddFilter', false);
    } catch (error) {
        addErrorToast({ error });
        setState('processingAddFilter', false);
    }
};

export const toggleFilteringModal = (modalType?: string) => {
    if (modalType) {
        setState({ isModalOpen: !untrack(() => state.isModalOpen), modalType });
    } else {
        setState('isModalOpen', (prev) => !prev);
    }
};

export const setFilterModalUrl = (url: string) => {
    setState('modalFilterUrl', url);
};

export const handleRulesChange = (rules: string) => {
    setState('userRules', rules);
};

export const filteringState = untrack(() => state);
