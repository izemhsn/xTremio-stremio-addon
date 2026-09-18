// Concurrent misses for the same data must collapse into one upstream call.
// Stremio opens many catalog requests in parallel on install; without this,
// each one independently pulls the full multi-megabyte stream list.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    createSingleFlight,
    getCategories,
    getAllVodStreams,
    getAllSeriesStreams,
    getAllLiveStreams,
    vodStreamsCache
} = require('../index.js');

const realFetch = global.fetch;
let calls = [];

// Resolves only when release() is called, so several callers are guaranteed to
// be waiting on the same in-flight request at once.
function gatedFetch({ fail = false, payload = [{ stream_id: '1', name: 'X' }] } = {}) {
    calls = [];
    let release;
    const gate = new Promise(r => { release = r; });
    global.fetch = async (url) => {
        calls.push(new URL(url).searchParams.get('action'));
        await gate;
        if (fail) throw new Error('upstream down');
        return { ok: true, status: 200, json: async () => payload };
    };
    return () => release();
}

test.after(() => { global.fetch = realFetch; });

function cfgFor(name) {
    return { serverUrl: 'http://127.0.0.1:9', username: name, password: 'p' };
}

test('createSingleFlight collapses concurrent calls and releases after settle', async () => {
    const singleFlight = createSingleFlight();
    let runs = 0;
    let release;
    const gate = new Promise(r => { release = r; });
    const fn = async () => { runs++; await gate; return 'value'; };

    const all = Promise.all([
        singleFlight('k', fn),
        singleFlight('k', fn),
        singleFlight('k', fn)
    ]);
    release();
    assert.deepStrictEqual(await all, ['value', 'value', 'value']);
    assert.strictEqual(runs, 1, 'three concurrent callers must run the work once');

    // Once settled the key is free again, so a later call re-runs.
    assert.strictEqual(await singleFlight('k', async () => 'second'), 'second');
    assert.strictEqual(runs, 1);
});

test('createSingleFlight keys are independent', async () => {
    const singleFlight = createSingleFlight();
    let runs = 0;
    const fn = async () => { runs++; return runs; };
    await Promise.all([singleFlight('a', fn), singleFlight('b', fn)]);
    assert.strictEqual(runs, 2);
});

test('a rejection is shared, then the key is freed for a retry', async () => {
    const singleFlight = createSingleFlight();
    let runs = 0;
    const boom = async () => { runs++; throw new Error('nope'); };

    const results = await Promise.allSettled([singleFlight('k', boom), singleFlight('k', boom)]);
    assert.ok(results.every(r => r.status === 'rejected'));
    assert.strictEqual(runs, 1, 'both callers share the one failed attempt');

    // A failure must not be sticky: the next caller gets a fresh attempt.
    assert.strictEqual(await singleFlight('k', async () => 'ok'), 'ok');
});

test('a synchronous throw inside the worker still rejects and frees the key', async () => {
    const singleFlight = createSingleFlight();
    await assert.rejects(() => singleFlight('k', () => { throw new Error('sync'); }), /sync/);
    assert.strictEqual(await singleFlight('k', async () => 'recovered'), 'recovered');
});

test('concurrent getAllVodStreams issues one upstream call, not N', async () => {
    const cfg = cfgFor('vod-stampede');
    const release = gatedFetch();

    const all = Promise.all([
        getAllVodStreams(cfg), getAllVodStreams(cfg),
        getAllVodStreams(cfg), getAllVodStreams(cfg), getAllVodStreams(cfg)
    ]);
    release();
    const results = await all;

    assert.strictEqual(calls.length, 1, `expected 1 upstream call, got ${calls.length}`);
    assert.strictEqual(calls[0], 'get_vod_streams');
    // Every caller gets the same data.
    results.forEach(r => assert.deepStrictEqual(r, results[0]));
});

test('the warm cache still short-circuits after a flight completes', async () => {
    const cfg = cfgFor('vod-warm');
    const release = gatedFetch();
    const first = getAllVodStreams(cfg);
    release();
    await first;
    assert.strictEqual(calls.length, 1);

    await getAllVodStreams(cfg);
    assert.strictEqual(calls.length, 1, 'a cached read must not refetch');
});

test('each stream list has its own flight', async () => {
    const cfg = cfgFor('separate-lists');
    const release = gatedFetch();

    const all = Promise.all([
        getAllVodStreams(cfg), getAllSeriesStreams(cfg), getAllLiveStreams(cfg)
    ]);
    release();
    await all;

    assert.deepStrictEqual(
        [...calls].sort(),
        ['get_live_streams', 'get_series', 'get_vod_streams']
    );
});

test('different accounts are not collapsed into one flight', async () => {
    const release = gatedFetch();
    const all = Promise.all([
        getAllVodStreams(cfgFor('acct-a')),
        getAllVodStreams(cfgFor('acct-b'))
    ]);
    release();
    await all;
    assert.strictEqual(calls.length, 2, 'separate accounts must each fetch');
});

test('concurrent getCategories issues 3 upstream calls, not 3 per caller', async () => {
    const cfg = cfgFor('cats-stampede');
    const release = gatedFetch({ payload: [{ category_id: '1', category_name: 'News' }] });

    const all = Promise.all([
        getCategories(cfg), getCategories(cfg), getCategories(cfg), getCategories(cfg)
    ]);
    release();
    const results = await all;

    assert.strictEqual(calls.length, 3, `expected 3 upstream calls, got ${calls.length}`);
    results.forEach(r => assert.strictEqual(r, results[0], 'all callers share one entry'));
});

// Bounded: if the re-check regresses this waits on a gate that never opens,
// so fail in 2s rather than hanging the run.
test('the worker re-checks the cache before fetching', { timeout: 2000 }, async () => {
    // load() checks the cache synchronously, then schedules the worker on a
    // microtask. A flight that finished in that gap should be picked up rather
    // than refetched, so populate the cache in exactly that window.
    const cfg = cfgFor('recheck');
    const preset = [{ stream_id: '99', name: 'from another flight' }];
    gatedFetch();

    const inFlight = getAllVodStreams(cfg);
    vodStreamsCache.set(cfg, preset);

    assert.deepStrictEqual(await inFlight, preset);
    assert.strictEqual(calls.length, 0, 'must not fetch when the cache went warm mid-flight');
});

test('a failed flight does not poison the next attempt', async () => {
    const cfg = cfgFor('recover-after-fail');
    let release = gatedFetch({ fail: true });
    const failed = Promise.all([getAllVodStreams(cfg), getAllVodStreams(cfg)]);
    release();
    await assert.rejects(() => failed);
    assert.strictEqual(calls.length, 1);

    release = gatedFetch();
    const retry = getAllVodStreams(cfg);
    release();
    assert.ok(Array.isArray(await retry), 'a retry after failure must succeed');
    assert.strictEqual(calls.length, 1);
});
