// The catalog route used to be three near-identical branches plus two search
// branches — about 130 of 175 lines duplicated. They are now one table-driven
// path over CATALOG_KINDS.
//
// The refactor also closes audit L3: per-genre catalogs read from the warm
// full-list cache when there is one and a per-category fetch when there is not.
// Those two sources produce items in different orders, and the old comparators
// were not total, so tied sort keys made the page you got depend on cache state.
// Every comparator now ends in the item id.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    decodeConfig,
    parseCatalogId,
    CATALOG_KINDS,
    FEATURED_PERIOD_MS,
    featuredEpoch,
    catalogComparator,
    filterByName,
    toCatalogMetas,
    getManifest,
    catCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    getAllVodStreams,
    getAllSeriesStreams
} = require('../index.js');

const realFetch = global.fetch;

const DAY_MS = 86400000;
// One featured shuffle lasts this long. Read from the module rather than written
// out here, so lengthening the period does not silently leave these tests
// asserting against a boundary that has moved.
const PERIOD_MS = FEATURED_PERIOD_MS;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);

const CATS = {
    live: [{ category_id: 10, category_name: 'News' }],
    movies: [{ category_id: 20, category_name: 'Action' }],
    series: [{ category_id: 30, category_name: 'Comedy' }]
};

// Every item in a category shares one `added` / `rating` / `last_modified`, so the
// comparators are decided entirely by the tiebreaker. That is what makes the
// cold-vs-warm comparison below meaningful.
const MOVIES = [
    { stream_id: 101, name: 'Alpha', stream_icon: 'a.png', category_id: 20, added: 100, rating: 5 },
    { stream_id: 102, name: 'Bravo', stream_icon: 'b.png', category_id: 20, added: 100, rating: 5 },
    { stream_id: 103, name: 'Charlie', category_id: 20, added: 100, rating: 5 }
];
const SERIES = [
    { series_id: 201, name: 'Sierra', cover: 's.png', category_id: 30, last_modified: 100, rating: 5 },
    { series_id: 202, name: 'Tango', cover: 't.png', category_id: 30, last_modified: 100, rating: 5 }
];
const LIVE = [
    { stream_id: 301, name: 'News One', stream_icon: 'n1.png', category_id: 10 },
    { stream_id: 302, name: 'News Two', category_name: 'News' },   // category_name only
    { stream_id: 303, name: 'Orphan' }                             // neither
];

// A per-category fetch deliberately answers in the opposite order to the full
// list. Real providers offer no ordering guarantee across the two endpoints, and
// without that difference this test could not tell the sources apart.
function stubProvider() {
    global.fetch = async (url) => {
        const u = new URL(url);
        const action = u.searchParams.get('action');
        const scoped = u.searchParams.get('category_id');
        let data = [];
        if (action === 'get_live_categories') data = CATS.live;
        else if (action === 'get_vod_categories') data = CATS.movies;
        else if (action === 'get_series_categories') data = CATS.series;
        else if (action === 'get_live_streams') data = LIVE;
        else if (action === 'get_vod_streams') data = scoped ? [...MOVIES].reverse() : MOVIES;
        else if (action === 'get_series') data = scoped ? [...SERIES].reverse() : SERIES;
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
}

function clearCaches() {
    catCache.clear();
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

// realFetch, not the global: stubProvider replaces the same global the test
// client would otherwise use to reach the server.
async function getCatalog(type, id, extra) {
    const path = extra
        ? `${base}/${CFG}/catalog/${encodeURIComponent(type)}/${id}/${encodeURIComponent(extra)}.json`
        : `${base}/${CFG}/catalog/${encodeURIComponent(type)}/${id}.json`;
    const res = await realFetch(path);
    return { status: res.status, headers: res.headers, body: await res.json() };
}

// --- the table ------------------------------------------------------------

test('parseCatalogId routes every catalog the manifest declares', () => {
    assert.deepEqual(parseCatalogId('xtremio_live'), { kind: 'live', variant: null, search: false });
    assert.deepEqual(parseCatalogId('xtremio_movies_new'), { kind: 'movies', variant: 'new', search: false });
    assert.deepEqual(parseCatalogId('xtremio_series_featured'), { kind: 'series', variant: 'featured', search: false });
    assert.deepEqual(parseCatalogId('xtremio_search_movies'), { kind: 'movies', variant: null, search: true });
    assert.deepEqual(parseCatalogId('xtremio_search_series'), { kind: 'series', variant: null, search: true });
    assert.equal(parseCatalogId('nope'), null);
});

test('every catalog the manifest declares is routable, and vice versa', async () => {
    // The table and the manifest are separate declarations of the same set; this
    // is what stops one drifting from the other.
    const manifest = await getManifest({ ...CFG_ARGS });
    const declared = manifest.catalogs.map(c => c.id);
    assert.ok(declared.length >= 9, `expected the full catalog list, got ${declared.length}`);
    for (const id of declared) {
        const route = parseCatalogId(id);
        assert.ok(route, `manifest declares ${id} but parseCatalogId does not route it`);
        assert.ok(CATALOG_KINDS[route.kind], `${id} routes to unknown kind ${route.kind}`);
    }
});

test('each kind agrees with the manifest on its id prefix and meta type', async () => {
    const manifest = await getManifest(null);
    for (const [name, kind] of Object.entries(CATALOG_KINDS)) {
        assert.ok(manifest.idPrefixes.includes(kind.idPrefix), `${name}: ${kind.idPrefix} missing from idPrefixes`);
        assert.ok(manifest.types.includes(kind.metaType), `${name}: ${kind.metaType} missing from types`);
    }
});

test('the manifest version is the package version', async () => {
    // It used to be a second hand-maintained copy of the same string.
    const manifest = await getManifest(null);
    assert.equal(manifest.version, require('../package.json').version);
});

test('toCatalogMetas maps each kind onto its own fields', () => {
    assert.deepEqual(toCatalogMetas([MOVIES[0]], CATALOG_KINDS.movies), [{
        id: 'xtremio_movie_101', type: 'XT-Movies', name: 'Alpha', poster: 'a.png', posterShape: 'poster'
    }]);
    assert.deepEqual(toCatalogMetas([SERIES[0]], CATALOG_KINDS.series), [{
        id: 'xtremio_series_201', type: 'series', name: 'Sierra', poster: 's.png', posterShape: 'poster'
    }]);
    assert.deepEqual(toCatalogMetas([LIVE[0]], CATALOG_KINDS.live), [{
        id: 'xtremio_live_301', type: 'Live TV', name: 'News One', poster: 'n1.png', posterShape: 'square'
    }]);
    // A missing poster field must be absent, not the empty string — Stremio
    // renders an empty poster as a broken image.
    assert.equal(toCatalogMetas([MOVIES[2]], CATALOG_KINDS.movies)[0].poster, undefined);
});

test('filterByName is a no-op without a search term', () => {
    assert.equal(filterByName(MOVIES, undefined), MOVIES);
    assert.deepEqual(filterByName(MOVIES, 'alph').map(s => s.stream_id), [101]);
    // Items with no name must not throw the whole catalog away.
    assert.deepEqual(filterByName([{ stream_id: 1 }, { stream_id: 2, name: 'Hit' }], 'hit').map(s => s.stream_id), [2]);
});

// --- L3: the comparators are total ----------------------------------------

test('every comparator breaks ties by id, in each direction', () => {
    for (const kindName of ['movies', 'series']) {
        const kind = CATALOG_KINDS[kindName];
        const idField = kind.idField;
        const low = { [idField]: 1, rating: 5, added: 100, last_modified: 100 };
        const high = { [idField]: 2, rating: 5, added: 100, last_modified: 100 };
        for (const variant of ['new', 'popular', 'featured']) {
            const cmp = catalogComparator(kind, variant);
            assert.ok(cmp, `${kindName}/${variant} must have a comparator`);
            assert.ok(cmp(low, high) !== 0, `${kindName}/${variant} leaves tied items unordered`);
            // Antisymmetry: without it, sort order still depends on input order.
            assert.equal(Math.sign(cmp(low, high)), -Math.sign(cmp(high, low)),
                `${kindName}/${variant} comparator is not antisymmetric`);
        }
    }
});

test('the featured shuffle is injective, so it is already a total order', () => {
    // The `|| byId` tail on the featured comparator is unreachable for real ids:
    // 2654435761 is odd, so multiplying by it is a bijection modulo 2^31 and two
    // distinct ids cannot hash equal. It is kept for uniformity with the other
    // comparators. This test asserts the property the tail would otherwise have to
    // provide — that featured is already total over a realistic id range. It is
    // deliberately not a test of the multiplier: collisions need ids about 2^27
    // apart even for an even multiplier, so no tractable range would show that.
    // Checked across a spread of days, not just today: the hash mixes the day
    // seed in, so a property that held only for the current date would be a test
    // that starts failing on some future morning.
    const t0 = Date.UTC(2026, 0, 1);
    for (const kindName of ['movies', 'series']) {
        const kind = CATALOG_KINDS[kindName];
        for (const day of [0, 1, 2, 37, 365, 3650]) {
            const cmp = catalogComparator(kind, 'featured', t0 + day * DAY_MS);
            const seen = new Set();
            for (let id = 1; id <= 5000; id++) {
                const item = { [kind.idField]: id };
                // Position in a total order is unique iff nothing compares equal to it.
                const key = String(cmp(item, { [kind.idField]: 0 }));
                assert.ok(!seen.has(key), `${kindName} day+${day}: id ${id} collides with an earlier id`);
                seen.add(key);
            }
        }
    }
});

test('the featured shuffle actually varies from period to period', () => {
    // The seed used to be *added* after the multiply. Adding a constant is
    // order-preserving except for the one item that wraps 2^31, so "featured"
    // was a fixed permutation — measured byte-identical at day+1, +30, +365 and
    // +3650 against a real account. Nothing in the suite pinned variation, which
    // is exactly why it survived. This is that missing half.
    const t0 = Date.UTC(2026, 0, 1);
    const kind = CATALOG_KINDS.movies;
    const items = Array.from({ length: 2000 }, (_, i) => ({ [kind.idField]: i + 1 }));
    const orderAt = t => [...items]
        .sort(catalogComparator(kind, 'featured', t))
        .map(s => s[kind.idField]);

    const base = orderAt(t0);
    for (const periods of [1, 2, 8, 52, 520]) {
        const later = orderAt(t0 + periods * PERIOD_MS);
        const held = later.filter((x, i) => x === base[i]).length;
        // The bug this guards left every single position in place. A real
        // reshuffle leaves almost none: measured across these offsets the counts
        // are 0 except at period+1, which keeps 22 of 2000 (1.1%) because the seed
        // is XORed into ids that only occupy eleven bits, so adjacent seeds share
        // structure. 5% sits well clear of that and still fails loudly at 100%.
        assert.ok(
            held < items.length / 20,
            `period+${periods} kept ${held}/${items.length} positions — the shuffle is not varying`
        );
    }
});

test('the featured shuffle holds still within a period', () => {
    // The other half of the intent, and the reason it is seeded at all:
    // paginating a shelf must not reshuffle underneath the user.
    const kind = CATALOG_KINDS.series;
    const items = Array.from({ length: 500 }, (_, i) => ({ [kind.idField]: i + 1 }));
    const orderAt = t => [...items]
        .sort(catalogComparator(kind, 'featured', t))
        .map(s => s[kind.idField]);

    // Anchored on a boundary, so "within" means what it says whatever the period
    // is; Date.UTC(2026, 5, 15) is not one once the period is longer than a day.
    const periodStart = Math.floor(Date.UTC(2026, 5, 15) / PERIOD_MS) * PERIOD_MS;
    const first = orderAt(periodStart);
    for (const offset of [1, 1000, 3600000, DAY_MS, PERIOD_MS - 1]) {
        assert.deepEqual(orderAt(periodStart + offset), first, `order changed ${offset}ms into the same period`);
    }
});

// L14 — the order changed at UTC midnight. Stremio holds catalog pages for
// max-age 300 with stale-while-revalidate 600, so for up to fifteen minutes after
// a boundary a shelf could be paginated across two different orders. A longer
// period does not remove the boundary — nothing stateless can, since the client
// holds pages this server has already forgotten — it makes it rare.
test('one featured order lasts much longer than a client caches a page (L14)', () => {
    const STREMIO_PAGE_STALENESS_MS = (300 + 600) * 1000;
    assert.ok(PERIOD_MS > 6 * DAY_MS, `a featured order lasts only ${PERIOD_MS}ms`);
    assert.ok(PERIOD_MS / STREMIO_PAGE_STALENESS_MS > 500,
        'the window where two orders can be mixed is not small against the period');

    // And the comparator and the memo key read the same function, so a sorted
    // view cannot outlive the seed it was built from. Computing the period in two
    // places is what made that a thing that had to be kept in agreement by hand.
    // Anchored on a boundary, or `t + PERIOD_MS - 1` lands in the next period and
    // the test asserts the opposite of what it means.
    const t = Math.floor(Date.UTC(2026, 5, 15) / PERIOD_MS) * PERIOD_MS;
    assert.equal(featuredEpoch(t), Math.floor(t / PERIOD_MS));
    assert.equal(featuredEpoch(t), featuredEpoch(t + PERIOD_MS - 1));
    assert.notEqual(featuredEpoch(t), featuredEpoch(t + PERIOD_MS));
});

test('an unknown variant sorts not at all, preserving upstream order', () => {
    assert.equal(catalogComparator(CATALOG_KINDS.movies, 'bogus'), null);
    assert.equal(catalogComparator(CATALOG_KINDS.live, null), null);
    // Live has no recency field, so `new` must not invent one.
    assert.equal(catalogComparator(CATALOG_KINDS.live, 'new'), null);
});

test('a catalog returns the same page cold or warm, even with tied sort keys', async () => {
    // The regression this guards is L3 itself: before the fix, these two loops
    // disagreed on 22 of the responses in a wider sweep.
    for (const [type, id] of [
        ['XT-Movies', 'xtremio_movies_new'],
        ['XT-Movies', 'xtremio_movies_popular'],
        ['XT-Movies', 'xtremio_movies_featured'],
        ['XT-Series', 'xtremio_series_new'],
        ['XT-Series', 'xtremio_series_popular'],
        ['XT-Series', 'xtremio_series_featured']
    ]) {
        for (const extra of [null, 'skip=1', 'genre=Action', 'genre=Comedy']) {
            stubProvider();
            clearCaches();
            const cold = await getCatalog(type, id, extra);

            stubProvider();
            clearCaches();
            const cfg = decodeConfig(CFG);
            await getAllVodStreams(cfg);       // populate the full-list caches
            await getAllSeriesStreams(cfg);
            const warm = await getCatalog(type, id, extra);

            assert.deepEqual(cold, warm, `${id} ${extra || '(no extra)'} differs by cache state`);
        }
    }
});

// --- behaviour the branches used to hold individually ----------------------

test('a warm full-list cache serves per-genre catalogs without another fetch', async () => {
    // This is the optimization the dual-source design exists for: once the full
    // list is cached, a genre shelf is an in-memory filter rather than a fresh
    // upstream call. Nothing else in the suite would notice if it stopped working,
    // because the *output* is identical either way — only the call count differs.
    stubProvider();
    clearCaches();
    const cfg = decodeConfig(CFG);
    await getAllVodStreams(cfg);
    await getAllSeriesStreams(cfg);

    const stubbed = global.fetch;
    let streamFetches = 0;
    global.fetch = (url, ...rest) => {
        const action = new URL(url).searchParams.get('action');
        if (action === 'get_vod_streams' || action === 'get_series') streamFetches++;
        return stubbed(url, ...rest);
    };

    await getCatalog('XT-Movies', 'xtremio_movies_new', 'genre=Action');
    await getCatalog('XT-Series', 'xtremio_series_new', 'genre=Comedy');
    assert.equal(streamFetches, 0, 'a warm full list must not trigger a per-category fetch');
});

test('live matches on category_id or category_name, and drops items with neither', async () => {
    // get_live_streams items may carry category_id, category_name, or neither —
    // the one place a kind needs its own matching rule.
    stubProvider();
    clearCaches();
    const { body } = await getCatalog('Live TV', 'xtremio_live', 'genre=News');
    assert.deepEqual(body.metas.map(m => m.id), ['xtremio_live_301', 'xtremio_live_302']);
});

test('an unresolvable genre returns empty rather than the first category', async () => {
    stubProvider();
    clearCaches();
    for (const [type, id] of [['XT-Movies', 'xtremio_movies_new'], ['Live TV', 'xtremio_live']]) {
        const { body } = await getCatalog(type, id, 'genre=Nonexistent');
        assert.deepEqual(body.metas, [], `${id} must not fall back to another genre`);
    }
});

test('no genre falls back to the first category', async () => {
    stubProvider();
    clearCaches();
    const { body } = await getCatalog('XT-Movies', 'xtremio_movies_new');
    assert.equal(body.metas.length, MOVIES.length);
});

test('search catalogs need a term and search the whole account', async () => {
    stubProvider();
    clearCaches();
    // No term: the catalog is empty rather than dumping every title.
    assert.deepEqual((await getCatalog('XT-Movies', 'xtremio_search_movies')).body.metas, []);

    const hit = await getCatalog('XT-Movies', 'xtremio_search_movies', 'search=brav');
    assert.deepEqual(hit.body.metas.map(m => m.id), ['xtremio_movie_102']);

    const series = await getCatalog('XT-Series', 'xtremio_search_series', 'search=tango');
    assert.deepEqual(series.body.metas.map(m => m.id), ['xtremio_series_202']);
});

test('a negative skip cannot page backwards into the list tail', async () => {
    // Audit L1: an unclamped skip reached slice(skip, skip + PAGE_SIZE) with a
    // negative start and returned the tail. The magnitude has to be smaller than
    // the list for that to show — slice(-50, 50) on three items still yields all
    // three, so a large negative value would pass either way.
    stubProvider();
    clearCaches();
    const negative = await getCatalog('XT-Movies', 'xtremio_movies_new', 'skip=-2');
    const zero = await getCatalog('XT-Movies', 'xtremio_movies_new', 'skip=0');
    assert.equal(zero.body.metas.length, MOVIES.length);
    assert.deepEqual(negative.body.metas, zero.body.metas);
});

test('an unknown catalog id returns empty without calling upstream', async () => {
    stubProvider();
    clearCaches();
    let calls = 0;
    const stubbed = global.fetch;
    global.fetch = (...a) => { calls++; return stubbed(...a); };
    const { status, body } = await getCatalog('XT-Movies', 'xtremio_not_a_catalog');
    assert.equal(status, 200);
    assert.deepEqual(body, { metas: [] });
    assert.equal(calls, 0);
});

test('caching hints are attached to every catalog response', async () => {
    stubProvider();
    clearCaches();
    for (const [type, id, extra] of [
        ['Live TV', 'xtremio_live', 'genre=News'],
        ['XT-Movies', 'xtremio_movies_new', null],
        ['XT-Series', 'xtremio_search_series', 'search=tango']
    ]) {
        const { body, headers } = await getCatalog(type, id, extra);
        assert.equal(body.cacheMaxAge, 300, `${id} lost its cacheMaxAge`);
        assert.equal(body.staleRevalidate, 600, `${id} lost its staleRevalidate`);

        // The body fields describe a Cache-Control header that this server has to
        // send itself. stremio-addon-sdk derives one from them; a hand-rolled
        // server that emits only the fields gives the client nothing to act on.
        const cc = headers.get('cache-control');
        assert.ok(cc, `${id} sent no Cache-Control`);
        assert.match(cc, /max-age=300/, `${id}: header disagrees with cacheMaxAge`);
        assert.match(cc, /stale-while-revalidate=600/, `${id}: header disagrees with staleRevalidate`);
        // Account-specific content behind a bearer token in the path.
        assert.match(cc, /private/, `${id} must not be marked public`);
    }
});

test('a degraded response is never cacheable', async () => {
    // Every early return in these routes is an empty shelf or a null meta caused
    // by a failure. Heuristic caching of one would pin a transient fault, which
    // is the same mistake as caching an empty upstream list.
    stubProvider();
    clearCaches();

    const cases = [
        ['XT-Movies', 'xtremio_series_new', null],        // type/id mismatch
        ['XT-Movies', 'no_such_catalog', null],           // unknown id
        ['XT-Movies', 'xtremio_search_movies', 'skip=0']  // search with no term
    ];
    for (const [type, id, extra] of cases) {
        const { headers, body } = await getCatalog(type, id, extra);
        assert.deepEqual(body.metas, [], `${id} should have degraded to an empty shelf`);
        assert.equal(headers.get('cache-control'), 'no-store', `${id} left a degraded answer cacheable`);
    }
});

test('search results are ordered, so pagination survives a refetch', async () => {
    // A search catalog has no variant, so it used to get no comparator at all and
    // was served in whatever order upstream produced. That is stable only while
    // one cached list survives: across a TTL refetch, an upstream reordering
    // moves the page boundaries and the reader sees an item twice or not at all.
    stubProvider();
    clearCaches();
    const first = await getCatalog('XT-Series', 'xtremio_search_series', 'search=a');

    // Same account, list refetched and handed back in the opposite order — which
    // is exactly what a provider is free to do across the 30-minute TTL.
    clearCaches();
    const reversedProvider = global.fetch;
    global.fetch = async (url) => {
        const res = await reversedProvider(url);
        const json = await res.json();
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => Array.isArray(json) ? [...json].reverse() : json };
    };
    const second = await getCatalog('XT-Series', 'xtremio_search_series', 'search=a');

    assert.deepEqual(
        second.body.metas.map(m => m.id),
        first.body.metas.map(m => m.id),
        'the same search returned a different order after a refetch'
    );
});
