// M-2 — when the category calls failed, the manifest advertised seven catalogs
// each declaring `genre` with `isRequired: true` and an empty option list.
//
// There is no value a client can supply for that, so those shelves cannot be
// opened at all — worse than the plain catalogs the code was supposed to
// degrade into. The `catch` that built those plain catalogs was unreachable:
// getCategories cannot reject, because refreshCategories resolves through
// Promise.allSettled and always returns an entry (stale lists if it has them,
// empty ones otherwise). So the try always succeeded, with empty arrays.
//
// Both README.md and CLAUDE.md documented that fallback as if it happened.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    getManifest,
    getCategories,
    encodeConfig,
    catCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    categoryStreamsCache
} = require('../index.js');

const realFetch = global.fetch;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);

const MOVIES = [
    { stream_id: 101, name: 'Alpha', category_id: 20, added: 100 },
    { stream_id: 102, name: 'Bravo', category_id: 21, added: 101 }
];

// `working` names the category actions that succeed; every other one rejects.
function stubProvider({ working = ['live', 'vod', 'series'] } = {}) {
    global.fetch = async (url) => {
        const u = new URL(url);
        const action = u.searchParams.get('action');
        const kind = /^get_(live|vod|series)_categories$/.exec(action)?.[1];

        if (kind && !working.includes(kind)) throw new Error(`${action} is down`);

        let data = [];
        if (action === 'get_live_categories') data = [{ category_id: 10, category_name: 'News' }];
        else if (action === 'get_vod_categories') data = [{ category_id: 20, category_name: 'Action' }];
        else if (action === 'get_series_categories') data = [{ category_id: 30, category_name: 'Comedy' }];
        else if (action === 'get_vod_streams') data = MOVIES;

        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
}

function clearCaches() {
    catCache.clear();
    vodStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
    liveStreamsCache.map.clear();
    categoryStreamsCache.map.clear();
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

test.beforeEach(() => clearCaches());

const genreOf = (catalog) => (catalog.extra || []).find(e => e.name === 'genre');
const GENRE_CATALOGS = [
    'xtremio_live',
    'xtremio_movies_popular', 'xtremio_movies_new', 'xtremio_movies_featured',
    'xtremio_series_popular', 'xtremio_series_new', 'xtremio_series_featured'
];

// --- the finding -----------------------------------------------------------

test('no catalog ever declares a required genre with nothing to choose', () => {
    // The invariant, stated once: an empty option list and isRequired together
    // is a shelf no client can open, whatever produced it.
    const check = (manifest, label) => {
        for (const catalog of manifest.catalogs) {
            const genre = genreOf(catalog);
            if (!genre) continue;
            assert.ok(
                genre.options?.length > 0,
                `${label}: ${catalog.id} offers a genre with no options`
            );
        }
    };
    return (async () => {
        for (const working of [[], ['vod'], ['live', 'series'], ['live', 'vod', 'series']]) {
            clearCaches();
            stubProvider({ working });
            check(await getManifest('http://addon.test', CFG_ARGS), `working=[${working}]`);
        }
    })();
});

test('total category failure still advertises all nine catalogs, without genres', async () => {
    stubProvider({ working: [] });
    const manifest = await getManifest('http://addon.test', CFG_ARGS);

    assert.equal(manifest.catalogs.length, 9, 'the catalogs themselves must not disappear');
    for (const id of GENRE_CATALOGS) {
        const catalog = manifest.catalogs.find(c => c.id === id);
        assert.ok(catalog, `${id} is missing`);
        assert.equal(genreOf(catalog), undefined, `${id} still offers a genre`);
        // skip and search survive: paginating and searching do not need a genre,
        // and dropping them would take working features away with the broken one.
        assert.deepEqual((catalog.extra || []).map(e => e.name), ['skip', 'search'], id);
    }
});

test('the two search catalogs are unaffected either way', async () => {
    for (const working of [[], ['live', 'vod', 'series']]) {
        clearCaches();
        stubProvider({ working });
        const manifest = await getManifest('http://addon.test', CFG_ARGS);

        for (const id of ['xtremio_search_movies', 'xtremio_search_series']) {
            const catalog = manifest.catalogs.find(c => c.id === id);
            // `skip` too: Stremio sends only declared extras, so without it a
            // search could never reach its second page.
            assert.deepEqual(catalog.extra, [{ name: 'search', isRequired: true }, { name: 'skip' }],
                `${id} working=[${working}]`);
            assert.deepEqual(catalog.searchProperties, ['name']);
        }
    }
});

test('a partial failure degrades only the kinds that failed', async () => {
    // The case the old all-or-nothing catch could not express at all.
    stubProvider({ working: ['vod'] });
    const manifest = await getManifest('http://addon.test', CFG_ARGS);

    for (const id of ['xtremio_movies_popular', 'xtremio_movies_new', 'xtremio_movies_featured']) {
        assert.deepEqual(genreOf(manifest.catalogs.find(c => c.id === id))?.options, ['Action'], id);
    }
    for (const id of ['xtremio_live', 'xtremio_series_popular']) {
        assert.equal(genreOf(manifest.catalogs.find(c => c.id === id)), undefined, id);
    }
});

test('a healthy provider is unchanged', async () => {
    stubProvider();
    const manifest = await getManifest('http://addon.test', CFG_ARGS);

    assert.equal(manifest.catalogs.length, 9);
    assert.deepEqual(genreOf(manifest.catalogs.find(c => c.id === 'xtremio_live')), {
        name: 'genre', options: ['News'], isRequired: true
    });
    assert.deepEqual(
        (manifest.catalogs.find(c => c.id === 'xtremio_movies_new').extra || []).map(e => e.name),
        ['genre', 'skip', 'search']
    );
});

test('the manifest keeps its catalog order', async () => {
    // Stremio renders shelves in this order, so a refactor that reshuffles them
    // silently rearranges the user's home screen.
    stubProvider();
    const manifest = await getManifest('http://addon.test', CFG_ARGS);
    assert.deepEqual(manifest.catalogs.map(c => c.id), [
        ...GENRE_CATALOGS, 'xtremio_search_movies', 'xtremio_search_series'
    ]);
    assert.deepEqual(manifest.catalogs.map(c => c.type), [
        'Live TV', 'XT-Movies', 'XT-Movies', 'XT-Movies',
        'XT-Series', 'XT-Series', 'XT-Series', 'XT-Movies', 'XT-Series'
    ]);
});

// --- why the dead catch was dead -------------------------------------------

test('getCategories resolves even when every upstream call fails', async () => {
    // The premise of the whole finding. If this ever starts rejecting, the
    // manifest's catch stops being belt-and-braces and the empty-list path
    // above stops being the degraded one.
    stubProvider({ working: [] });
    const cats = await getCategories(CFG_ARGS);
    assert.deepEqual(cats.live, []);
    assert.deepEqual(cats.movies, []);
    assert.deepEqual(cats.series, []);
});

// --- and the shelf actually opens ------------------------------------------

test('a genre-less catalog serves the full list rather than an empty shelf', async () => {
    // Dropping the genre only helps if the catalog then works. With no
    // categories there is nothing for a genre to resolve to, so the whole list
    // is the honest answer — the same one search already uses.
    stubProvider({ working: [] });
    const res = await realFetch(`${base}/${CFG}/catalog/XT-Movies/xtremio_movies_new/skip=0.json`);
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.deepEqual(body.metas.map(m => m.id), ['xtremio_movie_102', 'xtremio_movie_101']);
});

test('search still works on a degraded catalog', async () => {
    stubProvider({ working: [] });
    const res = await realFetch(
        `${base}/${CFG}/catalog/XT-Movies/xtremio_movies_new/${encodeURIComponent('search=alpha')}.json`
    );
    const body = await res.json();
    assert.deepEqual(body.metas.map(m => m.name), ['Alpha']);
});
