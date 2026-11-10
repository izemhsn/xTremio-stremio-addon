// M-3 — two upstream paths had neither caching nor single-flight.
//
//   get_vod_info was called once by the meta route and again by the stream
//   route for the same movie, and re-opening that movie paid both calls again.
//
//   The per-category catalog fetch that selectCatalogSource falls back to when
//   the full list is cold was uncached, so paginating a genre re-pulled the
//   whole category from upstream on every page — and a cold cache is exactly
//   when Stremio's parallel catalog requests arrive.
//
// Measured against the real account before the fix: three consecutive loads of
// one genre took 1288 / 2460 / 1172 ms with no warm path, and re-opening one
// movie still cost 839 ms + 748 ms.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

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
} = require('./support/internals.js');

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
        } else if (action === 'get_series_info') {
            data = {
                info: { name: `Series ${u.searchParams.get('series_id')}` },
                episodes: { 1: [{ id: '501', episode_num: 1, container_extension: 'mkv' }] }
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

beforeAll(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
});

beforeEach(() => { clearCaches(); stubProvider(); });

// --- get_vod_info ----------------------------------------------------------

test('repeated getVodInfo calls hit upstream once', async () => {
    const first = await getVodInfo(CFG_ARGS, '101');
    await getVodInfo(CFG_ARGS, '101');
    const third = await getVodInfo(CFG_ARGS, '101');

    expect(countOf('get_vod_info'), 'sequential calls must not refetch').toBe(1);
    expect(third).toStrictEqual(first);
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

    expect(countOf('get_vod_info'), 'five concurrent callers, one upstream call').toBe(1);
    for (const r of results) expect(r).toStrictEqual(results[0]);
});

test('different movies and different accounts are cached separately', async () => {
    await getVodInfo(CFG_ARGS, '101');
    await getVodInfo(CFG_ARGS, '102');
    expect(countOf('get_vod_info'), 'a second movie is a separate entry').toBe(2);

    // Two accounts on the same host can see different content, so a shared key
    // would serve one user's metadata to the other.
    await getVodInfo(OTHER, '101');
    expect(countOf('get_vod_info'), 'accounts must not share an entry').toBe(3);
});

test('opening a movie costs one get_vod_info, not two', async () => {
    // The finding in one assertion: meta and stream both need the payload.
    await realFetch(`${base}/${CFG}/meta/XT-Movies/xtremio_movie_101.json`);
    await realFetch(`${base}/${CFG}/stream/XT-Movies/xtremio_movie_101.json`);
    expect(countOf('get_vod_info'), 'meta + stream must share one call').toBe(1);

    // And re-opening it is free until the TTL lapses.
    await realFetch(`${base}/${CFG}/meta/XT-Movies/xtremio_movie_101.json`);
    await realFetch(`${base}/${CFG}/stream/XT-Movies/xtremio_movie_101.json`);
    expect(countOf('get_vod_info'), 'reopening the same movie must not refetch').toBe(1);
});

test('the routes still return what they returned before', async () => {
    // Caching must not change the payloads — only how many calls produce them.
    const meta = await (await realFetch(`${base}/${CFG}/meta/XT-Movies/xtremio_movie_101.json`)).json();
    expect(meta.meta.id).toBe('xtremio_movie_101');
    expect(meta.meta.name).toBe('Movie 101');

    const stream = await (await realFetch(`${base}/${CFG}/stream/XT-Movies/xtremio_movie_101.json`)).json();
    expect(stream.streams[0].url).toMatch(/\/proxy\/movie\/101\.mp4$/);
});

// --- L-14: a successful stream answer is cacheable --------------------------

test('movie and episode stream answers carry cache hints, as the live one does', async () => {
    // L-1 made no-store the route's default and relied on withCacheHints to
    // replace it wherever a request succeeds. The movie and episode branches never
    // called it, so every open of a title re-asked for a proxy URL that does not
    // change.
    for (const path of [
        '/stream/XT-Movies/xtremio_movie_101.json',
        '/stream/series/xtremio_episode_900:1:501.json',
        '/stream/Live%20TV/xtremio_live_7.json'
    ]) {
        const res = await realFetch(`${base}/${CFG}${path}`);
        const body = await res.json();
        expect(body.streams.length, `${path} served no stream`).toBeGreaterThan(0);
        expect(body.cacheMaxAge, `${path} lost its cacheMaxAge`).toBe(3600);
        expect(res.headers.get('cache-control'), path).toBe('private, max-age=3600');
    }

    // A failure is still never cacheable.
    const bad = await realFetch(`${base}/${CFG}/stream/XT-Movies/xtremio_movie_abc.json`);
    expect(bad.headers.get('cache-control')).toBe('no-store');
});

// --- the per-category fetch ------------------------------------------------

test('repeated per-category fetches hit upstream once', async () => {
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20');
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20');
    expect(countOf('get_vod_streams')).toBe(1);

    // A different category is a different key, and so is a different account.
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '21');
    await getCategoryStreams(OTHER, 'get_vod_streams', '20');
    expect(countOf('get_vod_streams')).toBe(3);
});

test('concurrent per-category fetches collapse into one', async () => {
    const release = stubProvider({ gated: true });
    const all = Promise.all(
        Array.from({ length: 6 }, () => getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20'))
    );
    release();
    await all;
    expect(countOf('get_vod_streams'), 'six concurrent callers, one upstream call').toBe(1);
});

test('paginating a genre no longer refetches the category', async () => {
    // The measured symptom: four sequential page loads, cold full list, cost
    // four upstream calls. The category list is fetched once now.
    const url = (skip) =>
        `${base}/${CFG}/catalog/XT-Movies/xtremio_movies_new/${encodeURIComponent(`genre=Action&skip=${skip}`)}.json`;

    for (const skip of [0, 100, 200, 0]) {
        const res = await realFetch(url(skip));
        expect(res.status).toBe(200);
    }
    expect(countOf('get_vod_streams'), 'one category fetch across four page loads').toBe(1);
    expect(countOf('get_vod_categories'), 'categories are cached too').toBe(1);
});

test('a warm full list is still preferred over the per-category cache', async () => {
    // The full list is the better source when it is there; the per-category
    // path exists only for a cold cache, and must not start shadowing it.
    vodStreamsCache.set(CFG_ARGS, MOVIES);
    const res = await realFetch(
        `${base}/${CFG}/catalog/XT-Movies/xtremio_movies_new/${encodeURIComponent('genre=Action')}.json`
    );
    const body = await res.json();

    expect(body.metas.length).toBe(2);
    expect(countOf('get_vod_streams'), 'a warm full list must not trigger a category fetch').toBe(0);
});

// --- the cache primitive ---------------------------------------------------

test('createKeyedCache bounds entries and expires by TTL', async () => {
    const cache = createKeyedCache({ maxEntries: 3, ttl: 50 });
    for (const key of ['a', 'b', 'c', 'd']) await cache.load(key, async () => key);

    expect(cache.map.size, 'the bound is enforced').toBe(3);
    expect(cache.get('a'), 'the least recently used entry was evicted').toBeNull();
    expect(cache.get('d')).toBe('d');

    await new Promise(r => setTimeout(r, 60));
    expect(cache.get('d'), 'a lapsed entry is not served').toBeNull();

    let runs = 0;
    await cache.load('d', async () => { runs++; return 'refetched'; });
    expect(runs, 'a lapsed entry is refetched').toBe(1);
});

test('createKeyedCache treats a null payload as a hit, not a miss', async () => {
    // Providers do return null for an unknown id. Caching that as "no entry"
    // would send every subsequent caller back upstream for the same null.
    const cache = createKeyedCache({ maxEntries: 4 });
    let runs = 0;
    const fetcher = async () => { runs++; return null; };

    expect(await cache.load('k', fetcher)).toBeNull();
    expect(await cache.load('k', fetcher)).toBeNull();
    expect(runs).toBe(1);
});

test('a failed fetch is not cached', async () => {
    const cache = createKeyedCache({ maxEntries: 4 });
    let runs = 0;
    await expect(cache.load('k', async () => { runs++; throw new Error('upstream down'); })).rejects.toThrow();
    expect(await cache.load('k', async () => { runs++; return 'ok'; })).toBe('ok');
    expect(runs, 'the next caller must retry rather than inherit the failure').toBe(2);
});

test('the sweeper reaches both new caches', async () => {
    // A cache the sweeper does not know about only reclaims memory when
    // something new arrives, which for an idle instance is never.
    await getVodInfo(CFG_ARGS, '101');
    await getCategoryStreams(CFG_ARGS, 'get_vod_streams', '20');
    expect(vodInfoCache.map.size).toBe(1);
    expect(categoryStreamsCache.map.size).toBe(1);

    const dropped = sweepCaches(Date.now() + CACHE_TTL + 1);
    expect(dropped, `expected both entries swept, dropped ${dropped}`).toBeGreaterThanOrEqual(2);
    expect(vodInfoCache.map.size).toBe(0);
    expect(categoryStreamsCache.map.size).toBe(0);
});
