// A provider blip must not blank a catalog for the full TTL.
//
// Xtream panels answer an overloaded `get_vod_streams` with an error object
// rather than a list. That used to be coerced to [] and cached positively for 30
// minutes, so one blip emptied every movie shelf and every movie search until it
// expired, with no retry in between. These tests pin the distinction the fix
// rests on: a payload that is not a list is a failure, while an empty list is a
// legitimate answer worth caching.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const {
    getAllVodStreams,
    vodStreamsCache,
    sweepCaches,
    CACHE_TTL,
    CACHE_FAILURE_TTL,
    CACHE_REFRESH_AHEAD,
    CACHE_STALE_MAX_AGE_MS
} = require('./support/internals.js');

const realFetch = global.fetch;
let calls = 0;

function stubFetch(payloads) {
    calls = 0;
    const queue = [...payloads];
    global.fetch = async () => {
        calls++;
        const next = queue.length > 1 ? queue.shift() : queue[0];
        if (next instanceof Error) throw next;
        return { ok: true, status: 200, json: async () => next };
    };
}

const cfg = { serverUrl: 'http://127.0.0.1:9', username: 'u', password: 'p' };
const LIST = [{ stream_id: '1', name: 'Alpha' }, { stream_id: '2', name: 'Beta' }];

beforeEach(() => { vodStreamsCache.map.clear(); });
afterAll(() => { global.fetch = realFetch; });

// The entry's own key is internal, and there is only ever one in these tests.
function onlyEntry() {
    const [key] = [...vodStreamsCache.map.keys()];
    return vodStreamsCache.map.peek(key);
}

test('a non-list payload is not cached as an empty catalog', async () => {
    stubFetch([{ user_info: { auth: 1 } }, LIST]);

    // The blip surfaces as a rejection, which the catalog route turns into an
    // empty response for that one request.
    await expect(getAllVodStreams(cfg)).rejects.toThrow(/not a list/);
    expect(vodStreamsCache.map.size, 'nothing may be cached from a failed fetch').toBe(0);

    // The very next request retries rather than inheriting the emptiness.
    expect(await getAllVodStreams(cfg)).toStrictEqual(LIST);
    expect(calls).toBe(2);
});

test('the shapes providers actually return on failure all count as failures', async () => {
    for (const payload of [{}, { user_info: {} }, null, 'error', 42]) {
        vodStreamsCache.map.clear();
        stubFetch([payload]);
        await expect(getAllVodStreams(cfg)).rejects.toThrow(/not a list/);
        expect(vodStreamsCache.map.size).toBe(0);
    }
});

test('a genuinely empty account is still cached, and not refetched', async () => {
    // An account with no VOD content is a real answer, not a failure. Retrying
    // it on every request would be the opposite mistake.
    stubFetch([[]]);

    expect(await getAllVodStreams(cfg)).toStrictEqual([]);
    expect(await getAllVodStreams(cfg)).toStrictEqual([]);
    expect(calls, 'an empty list is a hit, not a miss').toBe(1);
});

test('a failed refresh serves the last good list instead of an empty shelf', async () => {
    stubFetch([LIST]);
    expect(await getAllVodStreams(cfg)).toStrictEqual(LIST);
    expect(calls).toBe(1);

    // Age the entry past its TTL so the next call refreshes.
    const entry = onlyEntry();
    const trueTs = entry.ts - (31 * 60 * 1000);
    entry.ts = trueTs;

    stubFetch([new Error('upstream down')]);
    expect(await getAllVodStreams(cfg), 'stale beats empty').toStrictEqual(LIST);
    expect(calls, 'the refresh was attempted').toBe(1);

    // `ts` keeps the data's true age — it is what CACHE_STALE_MAX_AGE_MS is
    // measured against — and only the ttl moved, far enough to schedule the retry.
    const after = onlyEntry();
    expect(after.ts, 'ts must not be re-stamped').toBe(trueTs);
    const servableFor = after.ts + after.ttl - Date.now();
    expect(
        servableFor > 0 && servableFor <= CACHE_FAILURE_TTL,
        `stale window should be at most ${CACHE_FAILURE_TTL}ms, got ${servableFor}`
    ).toBeTruthy();
});

test('a failure with nothing cached rejects rather than inventing an empty list', async () => {
    stubFetch([new Error('upstream down')]);
    await expect(getAllVodStreams(cfg)).rejects.toThrow(/upstream down/);
    expect(vodStreamsCache.map.size).toBe(0);
});

// --- L3 — the sweeper used to undo the stale fallback -----------------------
//
// The stale copy is kept alive by extending its ttl, but `ts` deliberately still
// says how old the data is, and the map was swept on `ts` against the plain
// 30-minute TTL. So the fallback lasted only until the next sweep — between 0
// and CACHE_SWEEP_INTERVAL_MS — and after that an outage produced a hard error
// instead of a slightly old shelf. "Stale beats empty" was true for a few
// minutes at a time.

// Age an entry by rewriting `ts`, the way real time would.
function ageEntryBy(ms) {
    const entry = onlyEntry();
    entry.ts -= ms;
    return entry;
}

test('a sweep leaves the stale copy an outage is being served from', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    ageEntryBy(CACHE_TTL + 1);

    stubFetch([new Error('upstream down')]);
    expect(await getAllVodStreams(cfg), 'stale beats empty').toStrictEqual(LIST);

    // The sweep that used to end it. Its own return value must not count the
    // entry either, or the operator reads a reclaim that did not happen.
    const dropped = sweepCaches(Date.now());
    expect(dropped, 'nothing was reclaimed').toBe(0);
    expect(onlyEntry(), 'the stale copy survived the sweep').toBeTruthy();

    // And it is still served: within the retry window this is a cache hit, so
    // the dead provider is not asked again on every request.
    stubFetch([new Error('still down')]);
    expect(await getAllVodStreams(cfg)).toStrictEqual(LIST);
    expect(calls, 'served from the stale copy without another upstream call').toBe(0);
});

test('an expired list nobody is falling back on is still reclaimed on the normal TTL', async () => {
    // The other half of the rule: only an entry whose ttl was deliberately
    // extended survives. A plain expired list is the largest thing in the cache
    // and must not linger for a day just because catCache's entries may.
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    ageEntryBy(CACHE_TTL + 1);

    expect(sweepCaches(Date.now()), 'reclaimed').toBe(1);
    expect(vodStreamsCache.map.size).toBe(0);
});

test('the stale window is bounded, so a provider that is gone stops being served', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    ageEntryBy(CACHE_STALE_MAX_AGE_MS + 1);

    stubFetch([new Error('upstream down')]);
    await expect(
        getAllVodStreams(cfg),
        'a day-old lineup is not worth serving; the route degrades instead'
    ).rejects.toThrow(/upstream down/);

    // Nothing extended it, so the sweeper can now take it.
    expect(sweepCaches(Date.now())).toBe(1);
    expect(vodStreamsCache.map.size).toBe(0);
});

test('repeated failures extend the stale copy only up to the cap', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    // Just inside the window, with less than one retry interval left in it.
    ageEntryBy(CACHE_STALE_MAX_AGE_MS - Math.round(CACHE_FAILURE_TTL / 2));

    stubFetch([new Error('upstream down')]);
    expect(await getAllVodStreams(cfg)).toStrictEqual(LIST);

    const entry = onlyEntry();
    expect(
        entry.ttl,
        'the extension is clamped, so the copy cannot outlive the cap by repeated retries'
    ).toBe(CACHE_STALE_MAX_AGE_MS);
    expect(
        entry.ts + entry.ttl - Date.now(),
        'and what is left of the window is shorter than a full retry interval'
    ).toBeLessThanOrEqual(CACHE_FAILURE_TTL);
});

// --- refresh-ahead (audit Perf) --------------------------------------------
//
// A cold full list is seconds of work inside the request that happens to arrive
// first — 4.8 s for movies and 2.6 s for series against a real account — and
// every account paid it once per TTL, forever. A request that finds an entry far
// enough through its life now refetches behind itself, so the entry is replaced
// before anyone waits on it.

const keyOf = () => [...vodStreamsCache.map.keys()][0];
const settleRefresh = () => vodStreamsCache.refreshing.get(keyOf());

// Ages the one cached entry so it sits `ms` past its refresh point.
function agePastRefresh(ms = 1000) {
    const entry = onlyEntry();
    entry.ts -= Math.ceil(CACHE_TTL * CACHE_REFRESH_AHEAD) + ms;
    return entry.ts;
}

test('a request past the refresh point is served warm and refetched behind it', async () => {
    stubFetch([LIST]);
    expect(await getAllVodStreams(cfg)).toStrictEqual(LIST);
    const before = agePastRefresh();

    const NEXT = [...LIST, { stream_id: '3', name: 'Gamma' }];
    stubFetch([NEXT]);
    const served = await getAllVodStreams(cfg);
    expect(served, 'the request is answered warm, not made to wait for the refetch').toStrictEqual(LIST);

    const refresh = settleRefresh();
    expect(refresh, 'and a refresh was started behind it').toBeTruthy();
    await refresh;

    const after = onlyEntry();
    expect(after.data, 'which replaced the list').toStrictEqual(NEXT);
    expect(after.ts, 'and re-stamped its age, so the next TTL starts now').toBeGreaterThan(before);
    expect(calls, 'one upstream call, none of it inside a request').toBe(1);
});

test('an entry short of the refresh point is left alone', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);

    // Just inside the point, so this pins the threshold rather than the idea.
    onlyEntry().ts -= Math.floor(CACHE_TTL * CACHE_REFRESH_AHEAD) - 1000;
    stubFetch([LIST]);
    await getAllVodStreams(cfg);

    expect(calls, 'nothing was refetched').toBe(0);
    expect(vodStreamsCache.refreshing.size).toBe(0);
});

test('the stale copy an outage is being served from is never refreshed ahead', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);

    // What L3 leaves behind: ts says the data is old, and the ttl was extended
    // deliberately to keep serving it. The age rule alone would fire here on every
    // single request, which is why the ttl has to be part of the test.
    const entry = onlyEntry();
    entry.ts -= CACHE_TTL;
    entry.ttl = CACHE_TTL + 5 * 60 * 1000;

    stubFetch([LIST]);
    await getAllVodStreams(cfg);

    expect(calls, 'a failing panel is not asked again by every request').toBe(0);
    expect(vodStreamsCache.refreshing.size).toBe(0);
});

test('a failed refresh leaves the warm list exactly as it was, and is not retried at once', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    const before = agePastRefresh();

    stubFetch([new Error('panel down')]);
    expect(await getAllVodStreams(cfg), 'the request never sees the failure').toStrictEqual(LIST);
    // Nothing awaits a refresh, so a rejection here would reach the process.
    await settleRefresh();

    const after = onlyEntry();
    expect(after.data).toStrictEqual(LIST);
    expect(after.ts, 'a failure must not re-stamp the age of old data').toBe(before);
    expect(calls).toBe(1);

    // The cooldown: the next request does not start another attempt.
    stubFetch([new Error('panel down')]);
    expect(await getAllVodStreams(cfg)).toStrictEqual(LIST);
    expect(calls, 'one attempt per failure window, not one per request').toBe(0);
});

test('requests that arrive together share one refresh', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    agePastRefresh();

    stubFetch([LIST]);
    await Promise.all([getAllVodStreams(cfg), getAllVodStreams(cfg), getAllVodStreams(cfg)]);
    expect(vodStreamsCache.refreshing.size, 'three requests, one refresh').toBe(1);

    await settleRefresh();
    expect(calls).toBe(1);
    expect(vodStreamsCache.refreshing.size, 'and it clears itself when it settles').toBe(0);
});
