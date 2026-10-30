import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    applyRulesEdit,
    blockDomain,
    toggleBlocking,
    unblockDomain,
    BLOCK_ACTIONS,
    filteringState,
} from 'panel/stores/filtering';

// serverRules are the custom filtering rules as stored by the mocked server.
let serverRules: string[] = [];

const mocks = vi.hoisted(() => ({
    apiSetRules: vi.fn((params: { rules?: string[] }) => {
        serverRules = params?.rules || [];
        return Promise.resolve(undefined);
    }),
    apiEditRules: vi.fn((params: { add?: string[]; remove?: string[] }) => {
        const remove = new Set(params?.remove || []);
        const rules = serverRules.filter((rule) => !remove.has(rule.trim()));
        (params?.add || []).forEach((rule) => {
            if (!rules.some((r) => r.trim() === rule)) {
                rules.push(rule);
            }
        });
        serverRules = rules;

        return Promise.resolve({ rules: [...rules] });
    }),
    apiGetFilteringStatus: vi.fn(() =>
        Promise.resolve({
            user_rules: serverRules,
            filters: [],
            whitelist_filters: [],
            interval: 24,
            enabled: true,
        }),
    ),
    addSuccessToast: vi.fn(),
    addErrorToast: vi.fn(),
}));

vi.mock('panel/api/generated', () => ({
    filteringSetRules: mocks.apiSetRules,
    filteringEditRules: mocks.apiEditRules,
    filteringStatus: mocks.apiGetFilteringStatus,
}));

vi.mock('panel/stores/toasts', () => ({
    addSuccessToast: mocks.addSuccessToast,
    addErrorToast: mocks.addErrorToast,
    createUndoToast: (message: any, actionLabel: string, onUndo: () => void | Promise<void>) => ({
        message,
        actionLabel,
        undoId: 'test-undo-id',
        onUndo,
    }),
}));

// setInitialRules sets the rules both on the mocked server and in the store.
const setInitialRules = async (rules: string) => {
    const { setRules } = await import('panel/stores/filtering');
    await setRules(rules);
    mocks.apiSetRules.mockClear();
};

// lastUndo returns the undo callback of the last success toast.
const lastUndo = (): (() => Promise<void>) => {
    const { calls } = mocks.addSuccessToast.mock;

    return calls[calls.length - 1][0].onUndo;
};

describe('toggleBlocking', () => {
    beforeEach(async () => {
        serverRules = [];
        mocks.apiEditRules.mockClear();
        mocks.addSuccessToast.mockClear();
        mocks.addErrorToast.mockClear();
        await setInitialRules('');
    });

    it('adds a blocking rule when no rule exists', async () => {
        const result = await toggleBlocking(BLOCK_ACTIONS.BLOCK, 'example.com');

        expect(result).toBe(true);
        expect(mocks.apiEditRules).toHaveBeenCalledWith({
            add: ['||example.com^$important'],
            remove: ['@@||example.com^$important'],
        });
        expect(mocks.apiSetRules).not.toHaveBeenCalled();
        expect(filteringState.userRules).toContain('||example.com^$important');
    });

    it('replaces an allowlist rule with a blocking rule', async () => {
        await setInitialRules('@@||allowed.example^$important\n');

        const result = await toggleBlocking(BLOCK_ACTIONS.BLOCK, 'allowed.example');

        expect(result).toBe(true);
        expect(serverRules).toEqual(['||allowed.example^$important']);
        expect(filteringState.userRules).toBe('||allowed.example^$important');
    });

    it('replaces a blocking rule with an allowlist rule', async () => {
        await setInitialRules('||blocked.example^$important\n');

        const result = await toggleBlocking(BLOCK_ACTIONS.UNBLOCK, 'blocked.example');

        expect(result).toBe(true);
        expect(serverRules).toEqual(['@@||blocked.example^$important']);
        expect(filteringState.userRules).toContain('@@||blocked.example^$important');
    });

    it('does nothing when the rule is already there', async () => {
        await setInitialRules('@@||allowed.example^$important\n');

        const result = await toggleBlocking(BLOCK_ACTIONS.UNBLOCK, 'allowed.example');

        expect(result).toBe(true);
        expect(mocks.apiEditRules).not.toHaveBeenCalled();
        expect(mocks.addSuccessToast).not.toHaveBeenCalled();
    });

    it('keeps rules added elsewhere', async () => {
        await setInitialRules('||blocked.example^$important\n');

        // Another tab adds a rule that this one doesn't know about.
        serverRules.push('||other-tab.example^');

        await unblockDomain('blocked.example');

        expect(serverRules).toEqual(['||other-tab.example^', '@@||blocked.example^$important']);
    });

    it('undoes the change', async () => {
        await setInitialRules('||blocked.example^$important\n! comment\n');

        await unblockDomain('blocked.example');
        expect(serverRules).toEqual(['! comment', '@@||blocked.example^$important']);

        await lastUndo()();

        expect(serverRules).toEqual(['! comment', '||blocked.example^$important']);
        expect(filteringState.userRules).toBe('! comment\n||blocked.example^$important');
    });

    it('restores the rules when the request fails', async () => {
        await setInitialRules('! comment\n');
        mocks.apiEditRules.mockImplementationOnce(() => Promise.reject(new Error('network')));

        const result = await blockDomain('example.com');

        expect(result).toBe(false);
        expect(filteringState.userRules).toBe('! comment\n');
        expect(mocks.addErrorToast).toHaveBeenCalled();
        expect(mocks.addSuccessToast).not.toHaveBeenCalled();
    });

    it('updates the rules before the server responds', async () => {
        let respond: (value: { rules: string[] }) => void = () => {};
        mocks.apiEditRules.mockImplementationOnce(
            () =>
                new Promise((resolve) => {
                    respond = resolve;
                }),
        );

        const pending = blockDomain('example.com');
        expect(filteringState.userRules).toBe('||example.com^$important');

        respond({ rules: ['||example.com^$important'] });
        expect(await pending).toBe(true);
    });
});

describe('applyRulesEdit', () => {
    it('removes and adds rules', () => {
        expect(applyRulesEdit('||a.example^\n ||b.example^ \n', ['||c.example^'], ['||b.example^'])).toBe(
            '||a.example^\n||c.example^',
        );
    });

    it('does not duplicate rules', () => {
        expect(applyRulesEdit('||a.example^', ['||a.example^'], [])).toBe('||a.example^');
    });
});
