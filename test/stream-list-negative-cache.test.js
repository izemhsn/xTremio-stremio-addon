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

const test = require('node:test');
const assert = require('node:assert');

const {
    getAllVodStreams,
    vodStreamsCache,
    sweepCaches,
    CACHE_TTL,
    CACHE_FAILURE_TTL,
    CACHE_STALE_MAX_AGE_MS
} = require('../index.js');

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

test.beforeEach(() => { vodStreamsCache.map.clear(); });
test.after(() => { global.fetch = realFetch; });

// The entry's own key is internal, and there is only ever one in these tests.
function onlyEntry() {
    const [key] = [...vodStreamsCache.map.keys()];
    return vodStreamsCache.map.peek(key);
}

test('a non-list payload is not cached as an empty catalog', async () => {
    stubFetch([{ user_info: { auth: 1 } }, LIST]);

    // The blip surfaces as a rejection, which the catalog route turns into an
    // empty response for that one request.
    await assert.rejects(() => getAllVodStreams(cfg), /not a list/);
    assert.equal(vodStreamsCache.map.size, 0, 'nothing may be cached from a failed fetch');

    // The very next request retries rather than inheriting the emptiness.
    assert.deepEqual(await getAllVodStreams(cfg), LIST);
    assert.equal(calls, 2);
});

test('the shapes providers actually return on failure all count as failures', async () => {
    for (const payload of [{}, { user_info: {} }, null, 'error', 42]) {
        vodStreamsCache.map.clear();
        stubFetch([payload]);
        await assert.rejects(() => getAllVodStreams(cfg), /not a list/);
        assert.equal(vodStreamsCache.map.size, 0);
    }
});

test('a genuinely empty account is still cached, and not refetched', async () => {
    // An account with no VOD content is a real answer, not a failure. Retrying
    // it on every request would be the opposite mistake.
    stubFetch([[]]);

    assert.deepEqual(await getAllVodStreams(cfg), []);
    assert.deepEqual(await getAllVodStreams(cfg), []);
    assert.equal(calls, 1, 'an empty list is a hit, not a miss');
});

test('a failed refresh serves the last good list instead of an empty shelf', async () => {
    stubFetch([LIST]);
    assert.deepEqual(await getAllVodStreams(cfg), LIST);
    assert.equal(calls, 1);

    // Age the entry past its TTL so the next call refreshes.
    const entry = onlyEntry();
    const trueTs = entry.ts - (31 * 60 * 1000);
    entry.ts = trueTs;

    stubFetch([new Error('upstream down')]);
    assert.deepEqual(await getAllVodStreams(cfg), LIST, 'stale beats empty');
    assert.equal(calls, 1, 'the refresh was attempted');

    // `ts` keeps the data's true age — it is what CACHE_STALE_MAX_AGE_MS is
    // measured against — and only the ttl moved, far enough to schedule the retry.
    const after = onlyEntry();
    assert.equal(after.ts, trueTs, 'ts must not be re-stamped');
    const servableFor = after.ts + after.ttl - Date.now();
    assert.ok(
        servableFor > 0 && servableFor <= CACHE_FAILURE_TTL,
        `stale window should be at most ${CACHE_FAILURE_TTL}ms, got ${servableFor}`
    );
});

test('a failure with nothing cached rejects rather than inventing an empty list', async () => {
    stubFetch([new Error('upstream down')]);
    await assert.rejects(() => getAllVodStreams(cfg), /upstream down/);
    assert.equal(vodStreamsCache.map.size, 0);
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
    assert.deepEqual(await getAllVodStreams(cfg), LIST, 'stale beats empty');

    // The sweep that used to end it. Its own return value must not count the
    // entry either, or the operator reads a reclaim that did not happen.
    const dropped = sweepCaches(Date.now());
    assert.equal(dropped, 0, 'nothing was reclaimed');
    assert.ok(onlyEntry(), 'the stale copy survived the sweep');

    // And it is still served: within the retry window this is a cache hit, so
    // the dead provider is not asked again on every request.
    stubFetch([new Error('still down')]);
    assert.deepEqual(await getAllVodStreams(cfg), LIST);
    assert.equal(calls, 0, 'served from the stale copy without another upstream call');
});

test('an expired list nobody is falling back on is still reclaimed on the normal TTL', async () => {
    // The other half of the rule: only an entry whose ttl was deliberately
    // extended survives. A plain expired list is the largest thing in the cache
    // and must not linger for a day just because catCache's entries may.
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    ageEntryBy(CACHE_TTL + 1);

    assert.equal(sweepCaches(Date.now()), 1, 'reclaimed');
    assert.equal(vodStreamsCache.map.size, 0);
});

test('the stale window is bounded, so a provider that is gone stops being served', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    ageEntryBy(CACHE_STALE_MAX_AGE_MS + 1);

    stubFetch([new Error('upstream down')]);
    await assert.rejects(
        () => getAllVodStreams(cfg),
        /upstream down/,
        'a day-old lineup is not worth serving; the route degrades instead'
    );

    // Nothing extended it, so the sweeper can now take it.
    assert.equal(sweepCaches(Date.now()), 1);
    assert.equal(vodStreamsCache.map.size, 0);
});

test('repeated failures extend the stale copy only up to the cap', async () => {
    stubFetch([LIST]);
    await getAllVodStreams(cfg);
    // Just inside the window, with less than one retry interval left in it.
    ageEntryBy(CACHE_STALE_MAX_AGE_MS - Math.round(CACHE_FAILURE_TTL / 2));

    stubFetch([new Error('upstream down')]);
    assert.deepEqual(await getAllVodStreams(cfg), LIST);

    const entry = onlyEntry();
    assert.equal(
        entry.ttl, CACHE_STALE_MAX_AGE_MS,
        'the extension is clamped, so the copy cannot outlive the cap by repeated retries'
    );
    assert.ok(
        entry.ts + entry.ttl - Date.now() <= CACHE_FAILURE_TTL,
        'and what is left of the window is shorter than a full retry interval'
    );
});
