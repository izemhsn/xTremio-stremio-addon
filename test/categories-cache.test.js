// getCategories caching: a failed fetch must be retried in ~60s rather than
// pinned for the full 30-minute TTL, and a failing refresh must fall back to
// stale categories rather than replacing them with empty lists.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
// Lets assertSafeOutboundUrl short-circuit so the stubbed fetch is reached
// without a real DNS lookup.
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    getCategories,
    accountCacheKey,
    catCache,
    CACHE_TTL,
    CACHE_FAILURE_TTL
} = require('../index.js');

const CATS = {
    get_live_categories: [{ category_id: '1', category_name: 'News' }],
    get_vod_categories: [{ category_id: '2', category_name: 'Action' }],
    get_series_categories: [{ category_id: '3', category_name: 'Drama' }]
};

const realFetch = global.fetch;
let calls = [];

// `failing` may be true (all fail), false (all succeed), or a Set of action
// names that should fail.
function stubFetch(failing) {
    calls = [];
    global.fetch = async (url) => {
        const action = new URL(url).searchParams.get('action');
        calls.push(action);
        const shouldFail = failing === true || (failing instanceof Set && failing.has(action));
        if (shouldFail) return { ok: false, status: 500, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => CATS[action] || [] };
    };
}

test.after(() => { global.fetch = realFetch; });

function cfgFor(name) {
    return { serverUrl: 'http://127.0.0.1:9', username: name, password: 'p' };
}

// Moves a cached entry back in time so its TTL is expired, without sleeping.
function expireEntry(cfg) {
    const entry = catCache.get(accountCacheKey(cfg));
    assert.ok(entry, 'expected a cached entry to expire');
    entry.ts = Date.now() - entry.ttl - 1000;
}

test('a successful fetch is cached for the full TTL', async () => {
    const cfg = cfgFor('success');
    stubFetch(false);

    const first = await getCategories(cfg);
    assert.deepStrictEqual(first.live, CATS.get_live_categories);
    assert.deepStrictEqual(first.movies, CATS.get_vod_categories);
    assert.deepStrictEqual(first.series, CATS.get_series_categories);
    assert.strictEqual(first.ttl, CACHE_TTL);
    assert.strictEqual(calls.length, 3);

    const second = await getCategories(cfg);
    assert.strictEqual(calls.length, 3, 'second call within TTL must not refetch');
    assert.strictEqual(second, first);
});

test('a total failure is held only for the short failure TTL', async () => {
    const cfg = cfgFor('total-failure');
    stubFetch(true);

    const entry = await getCategories(cfg);
    assert.deepStrictEqual(entry.live, []);
    assert.deepStrictEqual(entry.movies, []);
    assert.deepStrictEqual(entry.series, []);
    assert.strictEqual(entry.ttl, CACHE_FAILURE_TTL, 'failure must not be pinned for 30 minutes');
    assert.ok(CACHE_FAILURE_TTL < CACHE_TTL);
});

test('a failure is still cached briefly, so a down provider is not stampeded', async () => {
    const cfg = cfgFor('no-stampede');
    stubFetch(true);

    await getCategories(cfg);
    assert.strictEqual(calls.length, 3);
    await getCategories(cfg);
    assert.strictEqual(calls.length, 3, 'repeat call inside the failure window must not refetch');
});

test('a failing refresh falls back to stale categories instead of emptying them', async () => {
    const cfg = cfgFor('stale-fallback');
    stubFetch(false);
    const good = await getCategories(cfg);
    assert.deepStrictEqual(good.live, CATS.get_live_categories);

    expireEntry(cfg);
    stubFetch(true);
    const stale = await getCategories(cfg);

    assert.strictEqual(calls.length, 3, 'expired entry should trigger a refresh attempt');
    assert.deepStrictEqual(stale.live, CATS.get_live_categories, 'stale live categories must survive');
    assert.deepStrictEqual(stale.movies, CATS.get_vod_categories);
    assert.deepStrictEqual(stale.series, CATS.get_series_categories);
    assert.strictEqual(stale.ttl, CACHE_FAILURE_TTL, 'should retry soon after serving stale');
});

test('a partial failure also gets the short TTL', async () => {
    const cfg = cfgFor('partial-failure');
    stubFetch(new Set(['get_vod_categories']));

    const entry = await getCategories(cfg);
    assert.deepStrictEqual(entry.live, CATS.get_live_categories, 'the sources that worked are kept');
    assert.deepStrictEqual(entry.movies, [], 'the failed source is empty on a first fetch');
    assert.strictEqual(entry.ttl, CACHE_FAILURE_TTL, 'one failed source must not pin a half-empty manifest');
});

test('a later refresh recovers once the provider is healthy', async () => {
    const cfg = cfgFor('recovery');
    stubFetch(true);
    const failed = await getCategories(cfg);
    assert.deepStrictEqual(failed.live, []);

    expireEntry(cfg);
    stubFetch(false);
    const recovered = await getCategories(cfg);

    assert.deepStrictEqual(recovered.live, CATS.get_live_categories);
    assert.strictEqual(recovered.ttl, CACHE_TTL, 'a clean fetch restores the full TTL');
});

test('cache entries are keyed by credentials, not just server URL', async () => {
    // Two accounts on the same host can see different content.
    const a = { serverUrl: 'http://127.0.0.1:9', username: 'alice', password: 'pw-a' };
    const b = { serverUrl: 'http://127.0.0.1:9', username: 'bob', password: 'pw-b' };
    assert.notStrictEqual(accountCacheKey(a), accountCacheKey(b));

    stubFetch(false);
    await getCategories(a);
    const callsAfterA = calls.length;
    await getCategories(b);
    assert.ok(calls.length > callsAfterA, 'a second account must not reuse the first account cache');
});
