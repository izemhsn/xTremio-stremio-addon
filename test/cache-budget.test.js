// R2, and the half of S4 that outlives a single response: the caches had no memory
// bound between them.
//
// Each cache was bounded on its own, and four of them by entry count alone — a
// hundred per-category lists at 7 MB each is 700 MB inside CACHE_MAX_CATEGORY_LISTS,
// and an instance serving a few large providers could reach 1-1.5 GB inside every
// configured limit. The one cache weighed in bytes weighed the wrong thing,
// serialized text, so a hostile [{},{},…] list fit its budget at a twentieth of its
// real size and was kept for half an hour.
//
// MAX_UPSTREAM_MB is lowered for this file so a hostile body can be driven end to
// end without building megabytes of it: what decides the refusal is the ratio
// between a body and what it parses to, not the absolute size.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.MAX_UPSTREAM_MB = '1';

const {
    app,
    encodeConfig,
    BoundedMap,
    CacheBudget,
    CACHE_BUDGET,
    CACHE_MAX_BYTES,
    weighJson,
    catCache,
    seriesInfoCache,
    vodInfoCache,
    categoryStreamsCache,
    vodStreamsCache,
    liveStreamsCache,
    seriesStreamsCache,
    getSeriesInfo,
    readSeriesInfoEntry
} = require('./support/internals.js');

const realFetch = global.fetch;
const entry = (bytes, extra = {}) => ({ data: null, bytes, ...extra });

function captureWarnings(fn) {
    const logged = [];
    const realWarn = console.warn;
    console.warn = (msg) => logged.push(String(msg));
    try {
        fn();
    } finally {
        console.warn = realWarn;
    }
    return logged;
}

// --- the shared budget itself ------------------------------------------------

test('one budget evicts across caches, oldest first', () => {
    const budget = new CacheBudget(1000);
    const a = new BoundedMap({ maxEntries: 100, ledger: budget });
    const b = new BoundedMap({ maxEntries: 100, ledger: budget });
    a.set('a1', entry(400));
    b.set('b1', entry(400));
    expect(budget.totalBytes).toBe(800);

    b.set('b2', entry(400));
    expect(a.has('a1'), 'the oldest entry went, though it lived in the other cache').toBeFalsy();
    expect(b.has('b1') && b.has('b2')).toBeTruthy();
    expect(budget.totalBytes).toBe(800);
    expect(a.totalBytes, "and that cache's own total followed").toBe(0);
});

test('a read in any cache counts as use', () => {
    const budget = new CacheBudget(1000);
    const a = new BoundedMap({ maxEntries: 100, ledger: budget });
    const b = new BoundedMap({ maxEntries: 100, ledger: budget });
    a.set('a1', entry(400));
    b.set('b1', entry(400));
    a.get('a1');

    b.set('b2', entry(400));
    expect(a.has('a1'), 'read after b1 was written, so b1 is now the older of the two').toBeTruthy();
    expect(b.has('b1')).toBeFalsy();
});

test('an entry larger than the whole shared budget is not cached, and says what to raise', () => {
    // Kept, it would evict every other cache's entries — every other account's
    // data — and still not fit.
    const budget = new CacheBudget(1000);
    const map = new BoundedMap({ maxEntries: 100, ledger: budget });
    const other = new BoundedMap({ maxEntries: 100, ledger: budget });
    other.set('keep', entry(500));
    map.set('k', entry(100));

    const logged = captureWarnings(() => map.set('k', entry(5000)));

    expect(map.has('k'), 'neither the oversized value nor the one it was replacing').toBeFalsy();
    expect(other.has('keep'), 'and nothing was evicted to make room it could never have had').toBeTruthy();
    expect(budget.totalBytes).toBe(500);
    expect(logged.join('\n')).toMatch(/raise CACHE_MAX_MB/);
});

test("the per-cache rule still keeps one entry over that cache's own budget", () => {
    // Over this cache's budget but inside the shared one: refetching it on every
    // request would be worse than holding it.
    const budget = new CacheBudget(10000);
    const map = new BoundedMap({ maxEntries: 10, maxBytes: 1000, ledger: budget });
    map.set('big', entry(5000));
    expect(map.has('big')).toBeTruthy();
    expect(budget.totalBytes).toBe(5000);
});

test('the shared total tracks replacement, sweeping, clearing and deletion', () => {
    // If it drifts, the budget silently becomes either useless or a cache that
    // evicts everything.
    const budget = new CacheBudget(10 ** 9);
    const a = new BoundedMap({ maxEntries: 10, maxAgeMs: 1000, ledger: budget });
    const b = new BoundedMap({ maxEntries: 10, ledger: budget });
    a.set('x', entry(100, { ts: Date.now() }));
    a.set('old', entry(200, { ts: Date.now() - 5000 }));
    b.set('y', entry(300));
    expect(budget.totalBytes).toBe(600);

    a.set('x', entry(50, { ts: Date.now() }));
    expect(budget.totalBytes, 'replacing an entry replaces its weight').toBe(550);

    expect(a.sweep()).toBe(1);
    expect(budget.totalBytes, 'a swept entry leaves the shared total too').toBe(350);

    b.clear();
    expect(budget.totalBytes, 'clearing one cache releases its own share and nothing else').toBe(50);

    a.delete('x');
    expect(budget.totalBytes).toBe(0);
    expect(budget.order.size).toBe(0);
});

test('a weight mutated after an entry was added cannot make the total drift', () => {
    const budget = new CacheBudget(10 ** 9);
    const map = new BoundedMap({ maxEntries: 10, ledger: budget });
    const e = entry(100);
    map.set('k', e);
    e.bytes = 999;
    map.delete('k');
    expect(budget.totalBytes).toBe(0);
});

// --- the production wiring ---------------------------------------------------

test('every data cache is charged to the one production budget', () => {
    expect(CACHE_BUDGET.maxBytes).toBe(CACHE_MAX_BYTES);
    const caches = {
        catCache,
        seriesInfoCache,
        vodInfoCache: vodInfoCache.map,
        categoryStreamsCache: categoryStreamsCache.map,
        vodStreamsCache: vodStreamsCache.map,
        liveStreamsCache: liveStreamsCache.map,
        seriesStreamsCache: seriesStreamsCache.map
    };
    for (const [name, map] of Object.entries(caches)) {
        expect(map.ledger, `${name} is not under CACHE_MAX_MB`).toBe(CACHE_BUDGET);
    }
});

test('many small accounts do not evict each other: bytes decide, not the account count', () => {
    // Audit R3. Four accounts per kind was the default, so a fifth evicted a list that
    // fitted the budget easily, and the refetch meant parsing it again on the thread
    // that relays video.
    vodStreamsCache.map.clear();
    for (let i = 0; i < 12; i++) {
        vodStreamsCache.set({ serverUrl: 'http://panel.test', username: `user${i}`, password: 'p' }, [{ stream_id: i, name: `M${i}` }]);
    }
    expect(vodStreamsCache.map.size).toBe(12);
    vodStreamsCache.map.clear();
});

test('a live stream list evicted by the shared budget names the shared knob', () => {
    // Raising the per-kind budget does nothing when the shared one is the tight one.
    const logged = captureWarnings(() => {
        vodStreamsCache.map.onEvict('k', { ts: Date.now(), bytes: 5 * 1024 * 1024 }, 'global budget');
    });
    expect(logged.length).toBe(1);
    expect(logged[0]).toMatch(/raise CACHE_MAX_MB/);
    expect(logged[0]).not.toMatch(/CACHE_MAX_STREAM_MB/);
});

// --- through the real paths ----------------------------------------------------

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);

let server;
let base;

beforeAll(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
});

beforeEach(() => {
    global.fetch = realFetch;
    catCache.clear();
    seriesInfoCache.clear();
    vodInfoCache.map.clear();
    categoryStreamsCache.map.clear();
    vodStreamsCache.map.clear();
    liveStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
});

// Real Response objects, so readJsonCapped streams and weighs them exactly as it
// does a provider's.
const jsonResponse = (text) => new Response(text, { headers: { 'content-type': 'application/json' } });

test('the caches that counted entries alone now store a weight', async () => {
    const items = Array.from({ length: 300 }, (_, i) => ({ stream_id: i, name: `Movie ${i}`, category_id: 20 }));
    await categoryStreamsCache.load('weight-test-category', async () => items);
    expect(
        categoryStreamsCache.map.peek('weight-test-category').bytes,
        'per-category list'
    ).toBeGreaterThan(1000);

    await vodInfoCache.load('weight-test-vod', async () => ({ info: { name: 'A Movie', plot: 'x'.repeat(500) } }));
    expect(vodInfoCache.map.peek('weight-test-vod').bytes, 'movie info').toBeGreaterThan(250);

    const seriesCfg = { serverUrl: 'http://127.0.0.1:9', username: 'u', password: 'p' };
    global.fetch = async () => jsonResponse(JSON.stringify({ info: { name: 'Show' }, episodes: { 1: [{ id: '1' }] } }));
    await getSeriesInfo(seriesCfg, '77');
    expect(readSeriesInfoEntry(seriesCfg, '77').bytes, 'series info').toBeGreaterThan(0);

    global.fetch = async () => jsonResponse(JSON.stringify([{ category_id: '1', category_name: 'Action' }]));
    const res = await realFetch(`${base}/${CFG}/manifest.json`);
    expect(res.status).toBe(200);
    const [categories] = [...catCache.values()];
    expect(categories && categories.bytes > 0, 'categories').toBeTruthy();
});

test('a hostile list from the provider is refused before it reaches any cache', async () => {
    // ~300 KB of [{},{},…]: inside the 1 MB byte cap, estimated at over 6 MB parsed
    // against the 2 MB allowed for it.
    const hostile = '[' + new Array(100000).fill('{}').join(',') + ']';
    let served = 0;
    global.fetch = async (url) => {
        if (new URL(url).searchParams.get('action') === 'get_vod_streams') {
            served++;
            return jsonResponse(hostile);
        }
        return jsonResponse('[]');
    };

    const res = await realFetch(`${base}/${CFG}/catalog/XT-Movies/xtremio_search_movies/${encodeURIComponent('search=a')}.json`);
    const body = await res.json();

    expect(served, 'the provider was asked').toBeGreaterThanOrEqual(1);
    expect(body.metas, 'the shelf degrades quietly, as for any upstream failure').toStrictEqual([]);
    expect(vodStreamsCache.map.size, 'nothing from it was cached').toBe(0);
});

test('a real list is cached with the weight it was read with, not a sample', async () => {
    const items = Array.from({ length: 1000 }, (_, i) => ({
        stream_id: i, name: `Movie ${i}`, category_id: '20', stream_icon: `http://img.test/${i}.jpg`
    }));
    const text = JSON.stringify(items);
    global.fetch = async (url) => (
        new URL(url).searchParams.get('action') === 'get_vod_streams' ? jsonResponse(text) : jsonResponse('[]')
    );

    const res = await realFetch(`${base}/${CFG}/catalog/XT-Movies/xtremio_search_movies/${encodeURIComponent('search=Movie')}.json`);
    expect(res.status).toBe(200);

    const [cached] = [...vodStreamsCache.map.values()];
    expect(cached, 'the list was cached').toBeTruthy();
    expect(cached.data.length).toBe(1000);
    expect(cached.bytes, 'weighed from every byte of the body it arrived as').toBe(Math.round(weighJson(text)));
});
