// A series that never returns usable data costs 3 sequential upstream calls
// plus 1.5 s of backoff. Single flight collapses concurrent callers, but every
// *sequential* request used to pay that cost again from scratch.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    getSeriesInfo,
    getCachedSeriesInfo,
    readSeriesInfoEntry,
    seriesInfoCache,
    SERIES_INFO_NEGATIVE_TTL,
    SERIES_INFO_MAX_ATTEMPTS,
    CACHE_TTL
} = require('../index.js');

const realFetch = global.fetch;
let calls = 0;

function cfg() {
    return { serverUrl: 'http://127.0.0.1:9', username: 'u', password: 'p' };
}

// `mode` decides how the provider misbehaves: throwing outright, or answering
// with a well-formed but empty payload that isUsableSeriesInfo rejects.
function stubFetch(mode, payload = null) {
    calls = 0;
    global.fetch = async () => {
        calls++;
        if (mode === 'throw') throw new Error('upstream down');
        if (mode === 'unusable') return { ok: true, status: 200, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => payload };
    };
}

// Ages every cached entry by `ms` so expiry can be tested without sleeping.
function ageCache(ms) {
    for (const entry of seriesInfoCache.values()) entry.ts -= ms;
}

test.beforeEach(() => seriesInfoCache.clear());
test.after(() => { global.fetch = realFetch; });

test('a totally failing series is retried once, then remembered', async () => {
    stubFetch('throw');

    await assert.rejects(() => getSeriesInfo(cfg(), '1'));
    assert.strictEqual(calls, SERIES_INFO_MAX_ATTEMPTS, 'first request pays the full retry cost');

    const before = calls;
    await assert.rejects(() => getSeriesInfo(cfg(), '1'), /upstream down/, 'still throws the same error');
    assert.strictEqual(calls, before, 'the second request made no upstream calls at all');
});

test('an unusable-but-present payload is replayed, not re-thrown', async () => {
    stubFetch('unusable');

    const first = await getSeriesInfo(cfg(), '2');
    assert.deepStrictEqual(first, {}, 'the unusable payload is returned as before');
    assert.strictEqual(calls, SERIES_INFO_MAX_ATTEMPTS);

    const second = await getSeriesInfo(cfg(), '2');
    assert.deepStrictEqual(second, {}, 'the cached replay matches the uncached result');
    assert.strictEqual(calls, SERIES_INFO_MAX_ATTEMPTS, 'no further upstream calls');
});

test('the negative entry expires and the series is retried', async () => {
    stubFetch('throw');
    await assert.rejects(() => getSeriesInfo(cfg(), '3'));
    assert.strictEqual(calls, SERIES_INFO_MAX_ATTEMPTS);

    ageCache(SERIES_INFO_NEGATIVE_TTL + 1);

    await assert.rejects(() => getSeriesInfo(cfg(), '3'));
    assert.strictEqual(calls, SERIES_INFO_MAX_ATTEMPTS * 2, 'it tried again after the TTL lapsed');
});

test('a provider that recovers is picked up once the negative entry expires', async () => {
    stubFetch('throw');
    await assert.rejects(() => getSeriesInfo(cfg(), '4'));

    const good = { info: { name: 'Fixed Show' }, episodes: { 1: [{ id: '7' }] } };
    stubFetch('ok', good);

    // Still inside the negative window: the recovery is not yet visible.
    await assert.rejects(() => getSeriesInfo(cfg(), '4'), 'the remembered failure still stands');
    assert.strictEqual(calls, 0, 'and it cost nothing upstream');

    ageCache(SERIES_INFO_NEGATIVE_TTL + 1);

    assert.deepStrictEqual(await getSeriesInfo(cfg(), '4'), good, 'recovery is picked up');
});

test('a failure is remembered for far less time than a success', () => {
    assert.ok(
        SERIES_INFO_NEGATIVE_TTL < CACHE_TTL,
        'a broken series must not be pinned for the full positive TTL'
    );
});

test('a negative entry is not served as a cache hit to ordinary callers', async () => {
    stubFetch('throw');
    await assert.rejects(() => getSeriesInfo(cfg(), '5'));

    assert.strictEqual(
        getCachedSeriesInfo(cfg(), '5'),
        null,
        'getCachedSeriesInfo reports a miss rather than handing back null data as a hit'
    );

    const entry = readSeriesInfoEntry(cfg(), '5');
    assert.strictEqual(entry.negative, true, 'but the entry is there');
    assert.strictEqual(entry.data, null, 'with no payload to replay');
    assert.match(entry.error, /upstream down/, 'and the original error preserved');
});

test('a successful fetch is cached positively, on the long TTL', async () => {
    const good = { info: { name: 'Good Show' }, episodes: { 1: [{ id: '9' }] } };
    stubFetch('ok', good);

    assert.deepStrictEqual(await getSeriesInfo(cfg(), '6'), good);
    assert.strictEqual(calls, 1, 'a usable answer needs no retries');

    const entry = readSeriesInfoEntry(cfg(), '6');
    assert.strictEqual(entry.negative, undefined, 'not marked negative');
    assert.strictEqual(entry.ttl, CACHE_TTL, 'and held for the full positive TTL');

    await getSeriesInfo(cfg(), '6');
    assert.strictEqual(calls, 1, 'served from cache');
});

// --- C8: a series with a name and nothing to play ---------------------------

test('a series with a name but no episodes is not pinned for the positive TTL', async () => {
    // It used to be cached as a success. The user opened a series page with
    // nothing on it, and every request for the next half hour got that same
    // payload back with no attempt to ask again — off one flaky call.
    const nameOnly = { info: { name: 'Nothing To Play' } };
    stubFetch('ok', nameOnly);

    assert.deepStrictEqual(
        await getSeriesInfo(cfg(), '10'),
        nameOnly,
        'still answered with, so the meta route can render the name'
    );

    const entry = readSeriesInfoEntry(cfg(), '10');
    assert.strictEqual(entry.negative, true);
    assert.strictEqual(entry.ttl, SERIES_INFO_NEGATIVE_TTL, 'remembered for minutes, not half an hour');
});

test('a season holding no episodes is not content either', async () => {
    // `{ 1: [] }` is one season by key count and no episodes by any measure the
    // meta route applies.
    const emptySeason = { info: { name: 'Season Zero' }, episodes: { 1: [] } };
    stubFetch('ok', emptySeason);

    await getSeriesInfo(cfg(), '11');

    assert.strictEqual(readSeriesInfoEntry(cfg(), '11').ttl, SERIES_INFO_NEGATIVE_TTL);
});

test('an episodes-less series is asked again once the short entry lapses', async () => {
    stubFetch('ok', { info: { name: 'Nothing To Play' } });
    await getSeriesInfo(cfg(), '12');
    const spent = calls;
    assert.strictEqual(spent, SERIES_INFO_MAX_ATTEMPTS, 'the retries ran, as for any unusable answer');

    await getSeriesInfo(cfg(), '12');
    assert.strictEqual(calls, spent, 'inside the window the replay costs nothing upstream');

    ageCache(SERIES_INFO_NEGATIVE_TTL + 1);
    const withEpisodes = { info: { name: 'Nothing To Play' }, episodes: { 1: [{ id: '3' }] } };
    stubFetch('ok', withEpisodes);

    assert.deepStrictEqual(await getSeriesInfo(cfg(), '12'), withEpisodes, 'the episodes are picked up');
    assert.strictEqual(readSeriesInfoEntry(cfg(), '12').ttl, CACHE_TTL, 'and now held for the long TTL');
});

test('negative entries live in the same bounded cache, so they cannot pile up', async () => {
    stubFetch('throw');
    await assert.rejects(() => getSeriesInfo(cfg(), '7'));

    assert.strictEqual(seriesInfoCache.size, 1, 'stored in seriesInfoCache, under the same LRU bound');
});
