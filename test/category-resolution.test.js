// C3 and C4 — how a genre becomes a shelf.
//
// C3: the manifest offers each category name once, so two categories called
// "Action" are one genre to the user. The shelf resolved that name to the first of
// them alone, and the second one's titles could not be reached from anywhere.
//
// C4: served from the cached full list, a shelf matched items on `category_id`
// alone, while the per-category upstream call also returns items filed under the
// category through `category_ids`. A multi-category item was on its shelf while the
// cache was cold and missing from it once a search had warmed the full list.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    catCache,
    categoryStreamsCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache
} = require('../index.js');

const realFetch = global.fetch;
const CFG = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' });

const CATEGORIES = {
    get_vod_categories: [
        { category_id: 20, category_name: 'Action' },
        { category_id: 21, category_name: 'Action' },
        { category_id: 22, category_name: 'Kids' },
        { category_id: 30, category_name: 'Drama' }
    ],
    get_live_categories: [
        { category_id: 10, category_name: 'News' },
        { category_id: 11, category_name: 'News' },
        { category_id: 12, category_name: 'Sport' }
    ],
    get_series_categories: []
};

// The full lists, as the unscoped calls answer.
const MOVIES = [
    { stream_id: 101, name: 'Alpha', category_id: 20, added: 500 },
    { stream_id: 102, name: 'Bravo', category_id: 21, added: 400 },
    // Filed under both Action categories.
    { stream_id: 105, name: 'Echo', category_id: 20, category_ids: [20, 21], added: 300 },
    // Drama first, and Kids through category_ids.
    { stream_id: 103, name: 'Charlie', category_id: 30, category_ids: [30, 22], added: 200 },
    { stream_id: 104, name: 'Delta', category_id: 22, added: 100 }
];
const LIVE = [
    { stream_id: 301, name: 'News One', category_id: 10 },
    { stream_id: 302, name: 'News Two', category_id: 11 },
    { stream_id: 303, name: 'News Three', category_name: 'News' },
    { stream_id: 304, name: 'Sport And News', category_id: 12, category_ids: [12, 11] }
];

// What a category_id call answers: every item filed under that category, through
// either field — which is what a real panel returns, and so what the warm path has
// to agree with.
function inCategory(list, id) {
    return list.filter(s => String(s.category_id) === id || (s.category_ids || []).map(String).includes(id));
}

let calls = [];
function stubProvider() {
    calls = [];
    global.fetch = async (url) => {
        const u = new URL(url);
        const action = u.searchParams.get('action');
        const scoped = u.searchParams.get('category_id');
        calls.push(scoped ? `${action}:${scoped}` : action);
        let data = [];
        if (CATEGORIES[action]) data = CATEGORIES[action];
        else if (action === 'get_vod_streams') data = scoped ? inCategory(MOVIES, scoped) : MOVIES;
        else if (action === 'get_live_streams') data = scoped ? inCategory(LIVE, scoped) : LIVE;
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => JSON.parse(JSON.stringify(data)) };
    };
}

function clearCaches() {
    catCache.clear();
    categoryStreamsCache.map.clear();
    vodStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
    liveStreamsCache.map.clear();
}

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
    clearCaches();
    stubProvider();
});

async function shelf(type, catalogId, extra) {
    const res = await realFetch(`${base}/${CFG}/catalog/${encodeURIComponent(type)}/${catalogId}/${encodeURIComponent(extra)}.json`);
    return (await res.json()).metas.map(m => m.id).sort();
}

const movies = (...ids) => ids.map(i => `xtremio_movie_${i}`).sort();
const channels = (...ids) => ids.map(i => `xtremio_live_${i}`).sort();

// Fills the full movie list the way a real user does: by searching.
async function warmMovies() {
    await shelf('XT-Movies', 'xtremio_search_movies', 'search=a');
    assert.ok(vodStreamsCache.map.size > 0, 'the full list is cached');
    calls = [];
}

// --- C3: a name shared by several categories -----------------------------------

test('the manifest still offers a shared category name once', async () => {
    const manifest = await (await realFetch(`${base}/${CFG}/manifest.json`)).json();
    const catalog = manifest.catalogs.find(c => c.id === 'xtremio_movies_new');
    const options = catalog.extra.find(e => e.name === 'genre').options;
    assert.deepEqual(options.filter(g => g === 'Action'), ['Action']);
});

test('a shared name shows every category that has it, with a cold cache', async () => {
    // It resolved to category 20 alone, so Bravo — filed only under 21 — could not be
    // reached from anywhere.
    assert.deepEqual(await shelf('XT-Movies', 'xtremio_movies_new', 'genre=Action'), movies(101, 102, 105));
    assert.deepEqual(
        calls.filter(c => c.startsWith('get_vod_streams:')).sort(),
        ['get_vod_streams:20', 'get_vod_streams:21'],
        'each category was asked for'
    );
});

test('a shared name shows every category that has it, with a warm full list', async () => {
    await warmMovies();
    assert.deepEqual(await shelf('XT-Movies', 'xtremio_movies_new', 'genre=Action'), movies(101, 102, 105));
    assert.deepEqual(calls.filter(c => c.startsWith('get_vod_streams')), [], 'served from the warm list');
});

test('an item in both categories of a shared name appears once', async () => {
    // Echo is in category 20's list and in 21's; the merge must not show it twice.
    const ids = await shelf('XT-Movies', 'xtremio_movies_new', 'genre=Action');
    assert.equal(ids.filter(id => id === 'xtremio_movie_105').length, 1);
});

// --- C4: an item filed under several categories -------------------------------

test('an item filed under several categories is on each shelf, warm or cold', async () => {
    // Charlie's category_id is Drama; Kids reaches it only through category_ids.
    const cold = await shelf('XT-Movies', 'xtremio_movies_new', 'genre=Kids');

    clearCaches();
    stubProvider();
    await warmMovies();
    const warm = await shelf('XT-Movies', 'xtremio_movies_new', 'genre=Kids');

    assert.deepEqual(cold, movies(103, 104));
    assert.deepEqual(warm, cold, 'what a shelf shows no longer depends on whether a search filled the cache');
});

test('an item is still on the shelf of its own category_id', async () => {
    await warmMovies();
    assert.deepEqual(await shelf('XT-Movies', 'xtremio_movies_new', 'genre=Drama'), movies(103));
});

// --- live: ids, category_ids and names together --------------------------------

test('live resolves a shared name to every category, by id, category_ids or name', async () => {
    const manifest = await (await realFetch(`${base}/${CFG}/manifest.json`)).json();
    const liveCatalog = manifest.catalogs.find(c => c.type === 'Live TV' && c.extra.some(e => e.name === 'genre'));

    // 301 and 302 by the two News ids; 303 by name, having no id at all; 304 by
    // category_ids, since its own category_id is Sport.
    assert.deepEqual(await shelf('Live TV', liveCatalog.id, 'genre=News'), channels(301, 302, 303, 304));
    assert.deepEqual(await shelf('Live TV', liveCatalog.id, 'genre=Sport'), channels(304));
});
