// A series that never returns usable data costs 3 sequential upstream calls
// plus 1.5 s of backoff. Single flight collapses concurrent callers, but every
// *sequential* request used to pay that cost again from scratch.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const {
    getSeriesInfo,
    getCachedSeriesInfo,
    readSeriesInfoEntry,
    seriesInfoCache,
    SERIES_INFO_NEGATIVE_TTL,
    SERIES_INFO_MAX_ATTEMPTS,
    CACHE_TTL
} = require('./support/internals.js');

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

beforeEach(() => seriesInfoCache.clear());
afterAll(() => { global.fetch = realFetch; });

test('a totally failing series is retried once, then remembered', async () => {
    stubFetch('throw');

    await expect(getSeriesInfo(cfg(), '1')).rejects.toThrow();
    expect(calls, 'first request pays the full retry cost').toBe(SERIES_INFO_MAX_ATTEMPTS);

    const before = calls;
    await expect(getSeriesInfo(cfg(), '1'), 'still throws the same error').rejects.toThrow(/upstream down/);
    expect(calls, 'the second request made no upstream calls at all').toBe(before);
});

test('an unusable-but-present payload is replayed, not re-thrown', async () => {
    stubFetch('unusable');

    const first = await getSeriesInfo(cfg(), '2');
    expect(first, 'the unusable payload is returned as before').toStrictEqual({});
    expect(calls).toBe(SERIES_INFO_MAX_ATTEMPTS);

    const second = await getSeriesInfo(cfg(), '2');
    expect(second, 'the cached replay matches the uncached result').toStrictEqual({});
    expect(calls, 'no further upstream calls').toBe(SERIES_INFO_MAX_ATTEMPTS);
});

test('the negative entry expires and the series is retried', async () => {
    stubFetch('throw');
    await expect(getSeriesInfo(cfg(), '3')).rejects.toThrow();
    expect(calls).toBe(SERIES_INFO_MAX_ATTEMPTS);

    ageCache(SERIES_INFO_NEGATIVE_TTL + 1);

    await expect(getSeriesInfo(cfg(), '3')).rejects.toThrow();
    expect(calls, 'it tried again after the TTL lapsed').toBe(SERIES_INFO_MAX_ATTEMPTS * 2);
});

test('a provider that recovers is picked up once the negative entry expires', async () => {
    stubFetch('throw');
    await expect(getSeriesInfo(cfg(), '4')).rejects.toThrow();

    const good = { info: { name: 'Fixed Show' }, episodes: { 1: [{ id: '7' }] } };
    stubFetch('ok', good);

    // Still inside the negative window: the recovery is not yet visible.
    await expect(getSeriesInfo(cfg(), '4'), 'the remembered failure still stands').rejects.toThrow();
    expect(calls, 'and it cost nothing upstream').toBe(0);

    ageCache(SERIES_INFO_NEGATIVE_TTL + 1);

    expect(await getSeriesInfo(cfg(), '4'), 'recovery is picked up').toStrictEqual(good);
});

test('a failure is remembered for far less time than a success', () => {
    expect(
        SERIES_INFO_NEGATIVE_TTL,
        'a broken series must not be pinned for the full positive TTL'
    ).toBeLessThan(CACHE_TTL);
});

test('a negative entry is not served as a cache hit to ordinary callers', async () => {
    stubFetch('throw');
    await expect(getSeriesInfo(cfg(), '5')).rejects.toThrow();

    expect(
        getCachedSeriesInfo(cfg(), '5'),
        'getCachedSeriesInfo reports a miss rather than handing back null data as a hit'
    ).toBeNull();

    const entry = readSeriesInfoEntry(cfg(), '5');
    expect(entry.negative, 'but the entry is there').toBe(true);
    expect(entry.data, 'with no payload to replay').toBeNull();
    expect(entry.error, 'and the original error preserved').toMatch(/upstream down/);
});

test('a successful fetch is cached positively, on the long TTL', async () => {
    const good = { info: { name: 'Good Show' }, episodes: { 1: [{ id: '9' }] } };
    stubFetch('ok', good);

    expect(await getSeriesInfo(cfg(), '6')).toStrictEqual(good);
    expect(calls, 'a usable answer needs no retries').toBe(1);

    const entry = readSeriesInfoEntry(cfg(), '6');
    expect(entry.negative, 'not marked negative').toBeUndefined();
    expect(entry.ttl, 'and held for the full positive TTL').toBe(CACHE_TTL);

    await getSeriesInfo(cfg(), '6');
    expect(calls, 'served from cache').toBe(1);
});

// --- C8: a series with a name and nothing to play ---------------------------

test('a series with a name but no episodes is not pinned for the positive TTL', async () => {
    // It used to be cached as a success. The user opened a series page with
    // nothing on it, and every request for the next half hour got that same
    // payload back with no attempt to ask again — off one flaky call.
    const nameOnly = { info: { name: 'Nothing To Play' } };
    stubFetch('ok', nameOnly);

    expect(
        await getSeriesInfo(cfg(), '10'),
        'still answered with, so the meta route can render the name'
    ).toStrictEqual(nameOnly);

    const entry = readSeriesInfoEntry(cfg(), '10');
    expect(entry.negative).toBe(true);
    expect(entry.ttl, 'remembered for minutes, not half an hour').toBe(SERIES_INFO_NEGATIVE_TTL);
});

test('a season holding no episodes is not content either', async () => {
    // `{ 1: [] }` is one season by key count and no episodes by any measure the
    // meta route applies.
    const emptySeason = { info: { name: 'Season Zero' }, episodes: { 1: [] } };
    stubFetch('ok', emptySeason);

    await getSeriesInfo(cfg(), '11');

    expect(readSeriesInfoEntry(cfg(), '11').ttl).toBe(SERIES_INFO_NEGATIVE_TTL);
});

test('an episodes-less series is asked again once the short entry lapses', async () => {
    stubFetch('ok', { info: { name: 'Nothing To Play' } });
    await getSeriesInfo(cfg(), '12');
    const spent = calls;
    expect(spent, 'the retries ran, as for any unusable answer').toBe(SERIES_INFO_MAX_ATTEMPTS);

    await getSeriesInfo(cfg(), '12');
    expect(calls, 'inside the window the replay costs nothing upstream').toBe(spent);

    ageCache(SERIES_INFO_NEGATIVE_TTL + 1);
    const withEpisodes = { info: { name: 'Nothing To Play' }, episodes: { 1: [{ id: '3' }] } };
    stubFetch('ok', withEpisodes);

    expect(await getSeriesInfo(cfg(), '12'), 'the episodes are picked up').toStrictEqual(withEpisodes);
    expect(readSeriesInfoEntry(cfg(), '12').ttl, 'and now held for the long TTL').toBe(CACHE_TTL);
});

test('negative entries live in the same bounded cache, so they cannot pile up', async () => {
    stubFetch('throw');
    await expect(getSeriesInfo(cfg(), '7')).rejects.toThrow();

    expect(seriesInfoCache.size, 'stored in seriesInfoCache, under the same LRU bound').toBe(1);
});
