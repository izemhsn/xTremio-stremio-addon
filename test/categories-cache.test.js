// getCategories caching: a failed fetch must be retried in ~60s rather than
// pinned for the full 30-minute TTL, and a failing refresh must fall back to
// stale categories rather than replacing them with empty lists.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
// Lets assertSafeOutboundUrl short-circuit so the stubbed fetch is reached
// without a real DNS lookup.
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const {
    getCategories,
    accountCacheKey,
    catCache,
    CACHE_TTL,
    CACHE_FAILURE_TTL
} = require('./support/internals.js');

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

afterAll(() => { global.fetch = realFetch; });

function cfgFor(name) {
    return { serverUrl: 'http://127.0.0.1:9', username: name, password: 'p' };
}

// Moves a cached entry back in time so its TTL is expired, without sleeping.
function expireEntry(cfg) {
    const entry = catCache.get(accountCacheKey(cfg));
    expect(entry, 'expected a cached entry to expire').toBeTruthy();
    entry.ts = Date.now() - entry.ttl - 1000;
}

test('a successful fetch is cached for the full TTL', async () => {
    const cfg = cfgFor('success');
    stubFetch(false);

    const first = await getCategories(cfg);
    expect(first.live).toStrictEqual(CATS.get_live_categories);
    expect(first.movies).toStrictEqual(CATS.get_vod_categories);
    expect(first.series).toStrictEqual(CATS.get_series_categories);
    expect(first.ttl).toBe(CACHE_TTL);
    expect(calls.length).toBe(3);

    const second = await getCategories(cfg);
    expect(calls.length, 'second call within TTL must not refetch').toBe(3);
    expect(second).toBe(first);
});

test('a total failure is held only for the short failure TTL', async () => {
    const cfg = cfgFor('total-failure');
    stubFetch(true);

    const entry = await getCategories(cfg);
    expect(entry.live).toStrictEqual([]);
    expect(entry.movies).toStrictEqual([]);
    expect(entry.series).toStrictEqual([]);
    expect(entry.ttl, 'failure must not be pinned for 30 minutes').toBe(CACHE_FAILURE_TTL);
    expect(CACHE_FAILURE_TTL).toBeLessThan(CACHE_TTL);
});

test('a failure is still cached briefly, so a down provider is not stampeded', async () => {
    const cfg = cfgFor('no-stampede');
    stubFetch(true);

    await getCategories(cfg);
    expect(calls.length).toBe(3);
    await getCategories(cfg);
    expect(calls.length, 'repeat call inside the failure window must not refetch').toBe(3);
});

test('a failing refresh falls back to stale categories instead of emptying them', async () => {
    const cfg = cfgFor('stale-fallback');
    stubFetch(false);
    const good = await getCategories(cfg);
    expect(good.live).toStrictEqual(CATS.get_live_categories);

    expireEntry(cfg);
    stubFetch(true);
    const stale = await getCategories(cfg);

    expect(calls.length, 'expired entry should trigger a refresh attempt').toBe(3);
    expect(stale.live, 'stale live categories must survive').toStrictEqual(CATS.get_live_categories);
    expect(stale.movies).toStrictEqual(CATS.get_vod_categories);
    expect(stale.series).toStrictEqual(CATS.get_series_categories);
    expect(stale.ttl, 'should retry soon after serving stale').toBe(CACHE_FAILURE_TTL);
});

test('a partial failure also gets the short TTL', async () => {
    const cfg = cfgFor('partial-failure');
    stubFetch(new Set(['get_vod_categories']));

    const entry = await getCategories(cfg);
    expect(entry.live, 'the sources that worked are kept').toStrictEqual(CATS.get_live_categories);
    expect(entry.movies, 'the failed source is empty on a first fetch').toStrictEqual([]);
    expect(entry.ttl, 'one failed source must not pin a half-empty manifest').toBe(CACHE_FAILURE_TTL);
});

test('a later refresh recovers once the provider is healthy', async () => {
    const cfg = cfgFor('recovery');
    stubFetch(true);
    const failed = await getCategories(cfg);
    expect(failed.live).toStrictEqual([]);

    expireEntry(cfg);
    stubFetch(false);
    const recovered = await getCategories(cfg);

    expect(recovered.live).toStrictEqual(CATS.get_live_categories);
    expect(recovered.ttl, 'a clean fetch restores the full TTL').toBe(CACHE_TTL);
});

test('cache entries are keyed by credentials, not just server URL', async () => {
    // Two accounts on the same host can see different content.
    const a = { serverUrl: 'http://127.0.0.1:9', username: 'alice', password: 'pw-a' };
    const b = { serverUrl: 'http://127.0.0.1:9', username: 'bob', password: 'pw-b' };
    expect(accountCacheKey(a)).not.toBe(accountCacheKey(b));

    stubFetch(false);
    await getCategories(a);
    const callsAfterA = calls.length;
    await getCategories(b);
    expect(calls.length, 'a second account must not reuse the first account cache').toBeGreaterThan(callsAfterA);
});

test('one account is one key however its server URL is spelled (audit M1)', () => {
    // Upstream URLs are built from absolute paths, so only the origin reaches the
    // panel; each spelling used to be a separate account with its own relay budget.
    const key = (serverUrl) => accountCacheKey({ serverUrl, username: 'alice', password: 'pw' });
    const canonical = key('http://panel.example.com');
    for (const spelling of [
        'http://PANEL.example.com',
        'http://panel.example.com:80',
        'http://panel.example.com/',
        'http://panel.example.com/x',
        'http://panel.example.com/?x=1',
        'panel.example.com'
    ]) {
        expect(key(spelling), spelling).toBe(canonical);
    }
    // What does reach the panel still separates accounts.
    expect(key('https://panel.example.com')).not.toBe(canonical);
    expect(key('http://panel.example.com:8080')).not.toBe(canonical);
});

test('credentials containing the old separator cannot collide (audit L11)', () => {
    const serverUrl = 'http://panel.example.com';
    expect(accountCacheKey({ serverUrl, username: 'u\np', password: 'q' })).not.toBe(accountCacheKey({ serverUrl, username: 'u', password: 'p\nq' }));
});
