// C1 — one numerically-titled movie broke search for the whole account.
//
// Panels that encode their JSON with PHP's JSON_NUMERIC_CHECK send titles like
// 1917 and 300 as JSON numbers. filterByName called `s.name.toLowerCase()` on
// every item, so a single one of those threw, and the catalog route's catch
// answered `{ metas: [] }` — not just for that title, but for every search the
// account ever made. Nothing about the shelf said why.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const {
    app,
    encodeConfig,
    filterByName,
    titleOf,
    toCatalogMetas,
    catCache,
    categoryStreamsCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    vodInfoCache
} = require('./support/internals.js');

const realFetch = global.fetch;

const CFG = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' });

// The numeric titles are what a JSON_NUMERIC_CHECK panel actually sends: no
// quotes, so they arrive as numbers.
const MOVIES = [
    { stream_id: 101, name: 'The Thing', category_id: 20, added: 100 },
    { stream_id: 102, name: 1917, category_id: 20, added: 200 },
    { stream_id: 103, name: 300, category_id: 20, added: 300 },
    { stream_id: 104, name: 'Alien', category_id: 20, added: 400 }
];

function stubProvider() {
    global.fetch = async (url) => {
        const u = new URL(url);
        const action = u.searchParams.get('action');
        let data = [];
        if (action === 'get_vod_categories') {
            data = [{ category_id: 20, category_name: 'Action' }];
        } else if (action === 'get_vod_streams') {
            data = MOVIES;
        } else if (action === 'get_vod_info') {
            data = { info: { name: 1917, plot: 'A long walk' }, movie_data: { container_extension: 'mkv' } };
        }
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
}

function clearCaches() {
    catCache.clear();
    categoryStreamsCache.map.clear();
    vodStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
    liveStreamsCache.map.clear();
    vodInfoCache.map.clear();
}

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
    clearCaches();
    stubProvider();
});

// --- the unit itself -------------------------------------------------------

test('a numeric title does not throw out of filterByName', () => {
    const found = filterByName(MOVIES, 'ali');
    expect(found.map(s => s.stream_id)).toStrictEqual([104]);
});

test('a numeric title is searchable by its digits', () => {
    expect(filterByName(MOVIES, '19').map(s => s.stream_id)).toStrictEqual([102]);
    expect(filterByName(MOVIES, '300').map(s => s.stream_id)).toStrictEqual([103]);
});

test('titleOf takes strings and numbers, and nothing else', () => {
    expect(titleOf('Alien')).toBe('Alien');
    expect(titleOf(1917)).toBe('1917');
    expect(titleOf(0)).toBe('0');
    // Not titles: the callers all have a fallback, and "[object Object]" on a
    // shelf is worse than using it.
    for (const value of [undefined, null, {}, [], NaN, Infinity, true]) {
        expect(titleOf(value), `titleOf(${JSON.stringify(value) ?? String(value)})`).toBe('');
    }
});

test('a catalog meta carries its title as a string', () => {
    const metas = toCatalogMetas(MOVIES, {
        idPrefix: 'xtremio_movie_',
        idField: 'stream_id',
        metaType: 'XT-Movies',
        posterField: 'stream_icon',
        posterShape: 'poster'
    });
    const numeric = metas.find(m => m.id === 'xtremio_movie_102');

    expect(numeric.name, 'a number would be a type violation in the SDK').toBe('1917');
    expect(typeof numeric.name).toBe('string');
});

// --- what the account actually saw -----------------------------------------

const getJson = async (path) => (await realFetch(`${base}/${CFG}${path}`)).json();

test('one numeric title does not empty every search on the account', async () => {
    // The finding. "ali" matches Alien and nothing else, but the throw happened
    // while filtering, so the route answered with an empty shelf instead.
    const body = await getJson(`/catalog/XT-Movies/xtremio_search_movies/${encodeURIComponent('search=ali')}.json`);

    expect(body.metas.map(m => m.id)).toStrictEqual(['xtremio_movie_104']);
});

test('searching for the numeric title finds it', async () => {
    const body = await getJson(`/catalog/XT-Movies/xtremio_search_movies/${encodeURIComponent('search=1917')}.json`);

    expect(body.metas.map(m => m.id)).toStrictEqual(['xtremio_movie_102']);
    expect(body.metas[0].name).toBe('1917');
});

test('a browse shelf renders a numeric title as a string', async () => {
    const body = await getJson(`/catalog/XT-Movies/xtremio_movies_new/${encodeURIComponent('genre=Action')}.json`);

    const names = body.metas.map(m => m.name);
    expect(names, 'newest first').toStrictEqual(['Alien', '300', '1917', 'The Thing']);
    for (const name of names) expect(typeof name).toBe('string');
});

test('a meta response names a numeric-titled movie as a string', async () => {
    const body = await getJson('/meta/XT-Movies/xtremio_movie_102.json');

    expect(body.meta.name).toBe('1917');
    expect(typeof body.meta.name).toBe('string');
});
