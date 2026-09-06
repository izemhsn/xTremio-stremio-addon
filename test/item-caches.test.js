// M-3 — two upstream paths had neither caching nor single-flight.
//
//   get_vod_info was called once by the meta route and again by the stream
//   route for the same movie, and re-opening that movie paid both calls again.
//
//   The per-category catalog fetch that selectCatalogGenre falls back to when
//   the full list is cold was uncached, so paginating a genre re-pulled the
//   whole category from upstream on every page — and a cold cache is exactly
//   when Stremio's parallel catalog requests arrive.
//
// Measured against the real account before the fix: three consecutive loads of
// one genre took 1288 / 2460 / 1172 ms with no warm path, and re-opening one
// movie still cost 839 ms + 748 ms.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    createKeyedCache,
    getVodInfo,
    getCategoryStreams,
    vodInfoCache,
    categoryStreamsCache,
    catCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    sweepCaches,
    CACHE_TTL
} = require('../index.js');

const realFetch = global.fetch;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);
const OTHER = { serverUrl: 'http://provider.test:8080', username: 'bob', password: 'other' };

const MOVIES = [
    { stream_id: 101, name: 'Alpha', category_id: 20, added: 100 },
    { stream_id: 102, name: 'Bravo', category_id: 20, added: 100 }
];

// Every upstream call is recorded as "action" or "action:category_id", so a
// test can assert on exactly which calls were made, not merely how many.
let calls = [];

function stubProvider({ gated = false } = {}) {
    calls = [];
    let release = () => {};
    const gate = gated ? new Promise(r => { release = r; }) : null;

    global.fetch = async (url) => {
        const u = new URL(url);
        const action = u.searchParams.get('action');
        const scoped = u.searchParams.get('category_id');
        calls.push(scoped ? `${action}:${scoped}` : action);
        if (gate) await gate;

        let data = [];
        if (action === 'get_vod_categories') data = [{ category_id: 20, category_name: 'Action' }];
        else if (action === 'get_live_categories' || action === 'get_series_categories') data = [];
        else if (action === 'get_vod_streams') data = MOVIES;
        else if (action === 'get_vod_info') {
            data = {
                info: { name: `Movie ${u.searchParams.get('vod_id')}` },
                movie_data: { container_extension: 'mp4' }
            };
        }
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
    return release;
}

function clearCaches() {
    catCache.clear();
    vodInfoCache.map.clear();
    categoryStreamsCache.map.clear();
    vodStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
    liveStreamsCache.map.clear();
}

const countOf = (prefix) => calls.filter(c => c === prefix || c.startsWith(`${prefix}:`)).length;

let server;
let base;

test.before(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
});

test.beforeEach(() => { clearCaches(); stubProvider(); });

// --- get_vod_info ----------------------------------------------------------

test('repeated getVodInfo calls hit upstream once', async () => {
    const first = await getVodInfo(CFG_ARGS, '101');
    await getVodInfo(CFG_ARGS, '101');
    const third = await getVodInfo(CFG_ARGS, '101');

    assert.equal(countOf('get_vod_info'), 1, 'sequential calls must not refetch');
    assert.deepEqual(third, first);
});

test('concurrent getVodInfo calls collapse into one', async () => {
    const release = stubProvider({ gated: true });
    const all = Promise.all([
        getVodInfo(CFG_ARGS, '101'),
        getVodInfo(CFG_ARGS, '101'),
        getVodInfo(CFG_ARGS, '101'),
        getVodInfo(CFG_ARGS, '101'),
        getVodInfo(CFG_ARGS, '101')
    ]);
    release();
    const results = await all;

    assert.equal(countOf('get_vod_info'), 1, 'five concurrent callers, one upstream call');
    for (const r of results) assert.deepEqual(r, results[0]);
});

test('different movies and different accounts are cached separately', async () => {
    await getVodInfo(CFG_ARGS, '101');
    await getVodInfo(CFG_ARGS, '102');
    assert.equal(countOf('get_vod_info'), 2, 'a second movie is a separate entry');

    // Two accounts on the same host can see different content, so a shared key
    // would serve one user's metadata to the other.
    await getVodInfo(OTHER, '101');
    assert.equal(countOf('get_vod_info'), 3, 'accounts must not share an entry');
});

test('opening a movie costs one get_vod_info, not two', async () => {
    // The finding in one assertion: meta and stream both need the payload.
    await realFetch(`${base}/${CFG}/meta/XT-Movies/xtremio_movie_101.json`);
    await realFetch(`${base}/${CFG}/stream/XT-Movies/xtremio_movie_101.json`);
    assert.equal(countOf('get_vod_info'), 1, 'meta + stream must share one call');

    // And re-opening it is free until the TTL lapses.
    await realFetch(`${base}/${CFG}/meta/XT-Movies/xtremio_movie_101.json`);
    await realFetch(`${base}/${CFG}/stream/XT-Movies/xtremio_movie_101.json`);
    assert.equal(countOf('get_vod_info'), 1, 'reopening the same movie must not refetch');
});

test('the routes still return what they returned before', async () => {
    // Caching must not change the payloads — only how many calls produce them.
    const meta = await (await realFetch(`${base}/${CFG}/meta/XT-Movies/xtremio_movie_101.json`)).json();
    assert.equal(meta.meta.id, 'xtremio_movie_101');
    assert.equal(meta.meta.name, 'Movie 101');

    const stream = await (await realFetch(`${base}/${CFG}/stream/XT-Movies/xtremio_movie_101.json`)).json();
    assert.match(stream.streams[0].url, /\/proxy\/movie\/101\.mp4$/);
});

// --- the per-category fetch ------------------------------------------------

test('repeated per-category fetches hit upstream once', async () => {
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20');
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20');
    assert.equal(countOf('get_vod_streams'), 1);

    // A different category is a different key, and so is a different account.
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '21');
    await getCategoryStreams(OTHER, 'get_vod_streams', '20');
    assert.equal(countOf('get_vod_streams'), 3);
});

test('concurrent per-category fetches collapse into one', async () => {
    const release = stubProvider({ gated: true });
    const all = Promise.all(
        Array.from({ length: 6 }, () => getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20'))
    );
    release();
    await all;
    assert.equal(countOf('get_vod_streams'), 1, 'six concurrent callers, one upstream call');
});

test('paginating a genre no longer refetches the category', async () => {
    // The measured symptom: four sequential page loads, cold full list, cost
    // four upstream calls. The category list is fetched once now.
    const url = (skip) =>
        `${base}/${CFG}/catalog/XT-Movies/xtremio_movies_new/${encodeURIComponent(`genre=Action&skip=${skip}`)}.json`;

    for (const skip of [0, 100, 200, 0]) {
        const res = await realFetch(url(skip));
        assert.equal(res.status, 200);
    }
    assert.equal(countOf('get_vod_streams'), 1, 'one category fetch across four page loads');
    assert.equal(countOf('get_vod_categories'), 1, 'categories are cached too');
});

test('a warm full list is still preferred over the per-category cache', async () => {
    // The full list is the better source when it is there; the per-category
    // path exists only for a cold cache, and must not start shadowing it.
    vodStreamsCache.set(CFG_ARGS, MOVIES);
    const res = await realFetch(
        `${base}/${CFG}/catalog/XT-Movies/xtremio_movies_new/${encodeURIComponent('genre=Action')}.json`
    );
    const body = await res.json();

    assert.equal(body.metas.length, 2);
    assert.equal(countOf('get_vod_streams'), 0, 'a warm full list must not trigger a category fetch');
});

// --- the cache primitive ---------------------------------------------------

test('createKeyedCache bounds entries and expires by TTL', async () => {
    const cache = createKeyedCache({ maxEntries: 3, ttl: 50 });
    for (const key of ['a', 'b', 'c', 'd']) await cache.load(key, async () => key);

    assert.equal(cache.map.size, 3, 'the bound is enforced');
    assert.equal(cache.get('a'), null, 'the least recently used entry was evicted');
    assert.equal(cache.get('d'), 'd');

    await new Promise(r => setTimeout(r, 60));
    assert.equal(cache.get('d'), null, 'a lapsed entry is not served');

    let runs = 0;
    await cache.load('d', async () => { runs++; return 'refetched'; });
    assert.equal(runs, 1, 'a lapsed entry is refetched');
});

test('createKeyedCache treats a null payload as a hit, not a miss', async () => {
    // Providers do return null for an unknown id. Caching that as "no entry"
    // would send every subsequent caller back upstream for the same null.
    const cache = createKeyedCache({ maxEntries: 4 });
    let runs = 0;
    const fetcher = async () => { runs++; return null; };

    assert.equal(await cache.load('k', fetcher), null);
    assert.equal(await cache.load('k', fetcher), null);
    assert.equal(runs, 1);
});

test('a failed fetch is not cached', async () => {
    const cache = createKeyedCache({ maxEntries: 4 });
    let runs = 0;
    await assert.rejects(() => cache.load('k', async () => { runs++; throw new Error('upstream down'); }));
    assert.equal(await cache.load('k', async () => { runs++; return 'ok'; }), 'ok');
    assert.equal(runs, 2, 'the next caller must retry rather than inherit the failure');
});

test('the sweeper reaches both new caches', async () => {
    // A cache the sweeper does not know about only reclaims memory when
    // something new arrives, which for an idle instance is never.
    await getVodInfo(CFG_ARGS, '101');
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20');
    assert.equal(vodInfoCache.map.size, 1);
    assert.equal(categoryStreamsCache.map.size, 1);

    const dropped = sweepCaches(Date.now() + CACHE_TTL + 1);
    assert.ok(dropped >= 2, `expected both entries swept, dropped ${dropped}`);
    assert.equal(vodInfoCache.map.size, 0);
    assert.equal(categoryStreamsCache.map.size, 0);
});
