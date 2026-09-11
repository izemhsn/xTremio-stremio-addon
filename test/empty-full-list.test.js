// A provider can answer a list call with an empty list that it later fills.
//
// Measured against a real account: four movie genres returned 1, 0, 500 and 500
// items. One movie search then cached the unscoped get_vod_streams answer — an
// empty list — and every movie shelf came back empty, with a cacheable success
// header, for the list's whole 30-minute TTL. Any cached array counted as a warm
// full list, and `[]` is truthy. A later load of the same account got a populated
// full list, and an empty answer from a category_id call that had served 500
// items before: the empty answers were transient, and came from both endpoints.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    getAllVodStreams,
    catCache,
    categoryStreamsCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    CACHE_TTL,
    CACHE_FAILURE_TTL
} = require('../index.js');

const realFetch = global.fetch;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);

const MOVIES = [
    { stream_id: 101, name: 'Alpha', category_id: 20, added: 100 },
    { stream_id: 102, name: 'Bravo', category_id: 20, added: 200 },
    { stream_id: 201, name: 'Cartoon', category_id: 21, added: 300 }
];
const LIVE = [{ stream_id: 301, name: 'News One', category_id: 10 }];

// What the unscoped calls answer. Scoped calls always answer from the fixtures.
let fullMovies = MOVIES;
let fullLive = LIVE;
// Category ids whose scoped call answers with an empty list.
const emptyScoped = new Set();

// Every upstream call, as "action" or "action:category_id".
let calls = [];

function stubProvider() {
    calls = [];
    global.fetch = async (url) => {
        const u = new URL(url);
        const action = u.searchParams.get('action');
        const scoped = u.searchParams.get('category_id');
        calls.push(scoped ? `${action}:${scoped}` : action);

        const inCategory = list => list.filter(s => String(s.category_id) === scoped);
        let data = [];
        if (action === 'get_vod_categories') {
            data = [{ category_id: 20, category_name: 'Action' }, { category_id: 21, category_name: 'Kids' }];
        } else if (action === 'get_live_categories') {
            data = [{ category_id: 10, category_name: 'News' }];
        } else if (action === 'get_vod_streams') {
            data = scoped ? (emptyScoped.has(scoped) ? [] : inCategory(MOVIES)) : fullMovies;
        } else if (action === 'get_live_streams') {
            data = scoped ? inCategory(LIVE) : fullLive;
        }
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => [...data] };
    };
}

function clearCaches() {
    catCache.clear();
    categoryStreamsCache.map.clear();
    vodStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
    liveStreamsCache.map.clear();
}

const countOf = call => calls.filter(c => c === call).length;
const idsOf = body => body.metas.map(m => m.id);

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

test.beforeEach(() => {
    fullMovies = MOVIES;
    fullLive = LIVE;
    emptyScoped.clear();
    clearCaches();
    stubProvider();
});

// realFetch, not the global: stubProvider replaces the same global the test
// client would otherwise use to reach the server.
async function getCatalog(type, id, extra) {
    const res = await realFetch(
        `${base}/${CFG}/catalog/${encodeURIComponent(type)}/${id}/${encodeURIComponent(extra)}.json`
    );
    return { headers: res.headers, body: await res.json() };
}

test('a cached empty full list does not blank a genre shelf', async () => {
    fullMovies = [];

    const cold = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Action');
    assert.deepEqual(idsOf(cold.body), ['xtremio_movie_102', 'xtremio_movie_101']);

    const search = await getCatalog('XT-Movies', 'xtremio_search_movies', 'search=a');
    assert.deepEqual(search.body.metas, [], 'the provider gave search nothing to search');
    assert.equal(countOf('get_vod_streams'), 1, 'the search should have cached the empty full list');

    const warm = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Action');
    assert.deepEqual(idsOf(warm.body), idsOf(cold.body), 'the cached empty list blanked the shelf');
    assert.equal(countOf('get_vod_streams:20'), 1, 'the shelf should reuse the cached category list');
});

test('a full list serves the categories it covers, and only those', async () => {
    // A full list missing one category must not blank that category either, and
    // must still be the source for the ones it does cover.
    fullMovies = MOVIES.filter(s => s.category_id === 20);
    await getAllVodStreams(CFG_ARGS);

    const action = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Action');
    const kids = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Kids');

    assert.deepEqual(idsOf(action.body), ['xtremio_movie_102', 'xtremio_movie_101']);
    assert.deepEqual(idsOf(kids.body), ['xtremio_movie_201']);
    assert.equal(countOf('get_vod_streams:20'), 0, 'a covered category must not trigger a category fetch');
    assert.equal(countOf('get_vod_streams:21'), 1);
});

test('an empty full list is cached briefly, a populated one for the full TTL', async () => {
    fullMovies = [];
    assert.deepEqual(await getAllVodStreams(CFG_ARGS), []);
    assert.deepEqual(await getAllVodStreams(CFG_ARGS), []);
    assert.equal(countOf('get_vod_streams'), 1, 'still a hit for requests that arrive together');

    const [key] = [...vodStreamsCache.map.keys()];
    assert.equal(vodStreamsCache.map.peek(key).ttl, CACHE_FAILURE_TTL);

    // Past that window it is asked again, and a populated answer replaces it.
    vodStreamsCache.map.peek(key).ts -= CACHE_FAILURE_TTL + 1;
    fullMovies = MOVIES;
    assert.equal((await getAllVodStreams(CFG_ARGS)).length, MOVIES.length);
    assert.equal(countOf('get_vod_streams'), 2);
    assert.equal(vodStreamsCache.map.peek(key).ttl, CACHE_TTL);
});

test('an empty live list falls back to the per-category fetch too', async () => {
    fullLive = [];
    const { body } = await getCatalog('Live TV', 'xtremio_live', 'genre=News');
    assert.deepEqual(idsOf(body), ['xtremio_live_301']);
    assert.equal(countOf('get_live_streams:10'), 1);
});

test('an empty per-category answer is asked again within a minute', async () => {
    // No warm full list here, so nothing else can fill the shelf.
    emptyScoped.add('21');
    const first = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Kids');
    assert.deepEqual(first.body.metas, []);

    const key = [...categoryStreamsCache.map.keys()].find(k => k.endsWith('\n21'));
    assert.equal(categoryStreamsCache.map.peek(key).ttl, CACHE_FAILURE_TTL);

    categoryStreamsCache.map.peek(key).ts -= CACHE_FAILURE_TTL + 1;
    emptyScoped.delete('21');
    const second = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Kids');
    assert.deepEqual(idsOf(second.body), ['xtremio_movie_201']);
    assert.equal(countOf('get_vod_streams:21'), 2);
});

test('a populated per-category answer is still held for the full TTL', async () => {
    await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Kids');
    const key = [...categoryStreamsCache.map.keys()].find(k => k.endsWith('\n21'));
    assert.equal(categoryStreamsCache.map.peek(key).ttl, CACHE_TTL);
});

test('an empty page is never cacheable by the client', async () => {
    // The server retries an empty answer within a minute; a client holding the
    // blank page for 300 s plus 600 s stale would outlast that recovery.
    emptyScoped.add('21');
    const shelf = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Kids');
    assert.deepEqual(shelf.body, { metas: [] });
    assert.equal(shelf.headers.get('cache-control'), 'no-store');

    const search = await getCatalog('XT-Movies', 'xtremio_search_movies', 'search=zzz');
    assert.deepEqual(search.body, { metas: [] });
    assert.equal(search.headers.get('cache-control'), 'no-store');

    // A page with items keeps its hints.
    const full = await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Action');
    assert.match(full.headers.get('cache-control'), /max-age=300/);
});
