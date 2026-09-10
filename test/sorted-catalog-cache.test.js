// Audit L-3: `[...items].sort(comparator)` ran on every catalog request, copying
// and sorting up to 50,000 records to keep the 100 the page asked for. Measured
// on a 50k list: 1.7 ms for `new`, 10.7 ms for `popular`, 16.5 ms for `featured`
// — and Stremio fires several catalog requests in parallel on install, so a
// shelf load was 50-100 ms of blocking work on the thread that also relays
// video.
//
// The sorted view is now memoised. What this file pins is not the speed but the
// *invalidation*: a memo over data that can be refetched underneath it is only
// as good as the moment it stops being used, and the rule here is identity — the
// entry is reused only while the array it was derived from is still the array
// the list cache hands back.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    CATALOG_KINDS,
    parseCatalogId,
    catalogComparator,
    sortedCatalogItems,
    sortedCatalogCache,
    sweepCaches,
    catCache,
    categoryStreamsCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    CACHE_TTL,
    CACHE_MAX_SORTED_CATALOGS
} = require('../index.js');

const realFetch = global.fetch;
const DAY_MS = 86400000;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const OTHER_ARGS = { ...CFG_ARGS, password: 'different' };
const CFG = encodeConfig(CFG_ARGS);

const MOVIE_KIND = CATALOG_KINDS.movies;

// Distinct `added` values, so `new` is decided by the field rather than by the
// id tiebreaker — otherwise a memo hit and a fresh sort would be
// indistinguishable from a sort that simply preserved input order.
function movies(n) {
    return Array.from({ length: n }, (_, i) => ({
        stream_id: 100 + i,
        name: `Movie ${String(i).padStart(3, '0')}`,
        category_id: 20,
        added: 1000 + i,
        rating: (i % 5) + 1
    }));
}

function sortedOf(route, items, opts = {}) {
    const { cfg = CFG_ARGS, genre = null, source = items, now } = opts;
    return sortedCatalogItems(cfg, MOVIE_KIND, route, genre, { items, source }, now);
}

test.beforeEach(() => sortedCatalogCache.clear());

// --- memoisation ----------------------------------------------------------

test('the same shelf, asked twice, is sorted once', () => {
    const route = parseCatalogId('xtremio_movies_new');
    const items = movies(50);

    const first = sortedOf(route, items);
    const second = sortedOf(route, items);

    // Identity, not deepEqual: a second sort would produce an equal array, so
    // only reference equality distinguishes a memo hit from a repeat of the work.
    assert.strictEqual(second, first, 'the second request re-sorted the list');
    assert.equal(sortedCatalogCache.size, 1);
});

test('the memoised order is the order the sort produces', () => {
    const route = parseCatalogId('xtremio_movies_popular');
    const items = movies(40);
    const expected = [...items].sort(catalogComparator(MOVIE_KIND, 'popular'));

    assert.deepStrictEqual(sortedOf(route, items).map(s => s.stream_id), expected.map(s => s.stream_id));
    // And again, from the cache this time.
    assert.deepStrictEqual(sortedOf(route, items).map(s => s.stream_id), expected.map(s => s.stream_id));
});

test('the source list is never mutated', () => {
    const route = parseCatalogId('xtremio_movies_new');
    const items = movies(20);
    const before = items.map(s => s.stream_id);
    sortedOf(route, items);
    assert.deepStrictEqual(items.map(s => s.stream_id), before, 'sorted in place');
});

// --- invalidation ---------------------------------------------------------

test('a refetched list invalidates the sorted view in the same instant', () => {
    const route = parseCatalogId('xtremio_movies_new');
    const items = movies(10);
    const first = sortedOf(route, items);

    // What a TTL refetch produces: an equal list in a new array. The old view is
    // still an accurate sort of *an* old list, which is exactly the trap — only
    // identity catches it.
    const refetched = movies(10).concat({
        stream_id: 999, name: 'Brand New', category_id: 20, added: 9999, rating: 5
    });
    const second = sortedOf(route, refetched);

    assert.notStrictEqual(second, first);
    assert.equal(second[0].stream_id, 999, 'the newest item from the refetched list should lead');
    assert.equal(sortedCatalogCache.size, 1, 'the stale entry should be replaced, not accumulated');
});

test('an equal-but-different array is not treated as the same source', () => {
    const route = parseCatalogId('xtremio_movies_new');
    const items = movies(10);
    const clone = movies(10);

    const first = sortedOf(route, items);
    const second = sortedOf(route, clone);
    assert.notStrictEqual(second, first, 'reused a view derived from a different array');
    assert.deepStrictEqual(second.map(s => s.stream_id), first.map(s => s.stream_id));
});

// --- key separation -------------------------------------------------------

test('every coordinate of the key separates two shelves', () => {
    const items = movies(30);
    const now = Date.UTC(2026, 0, 1, 12);
    const newRoute = parseCatalogId('xtremio_movies_new');
    const featured = parseCatalogId('xtremio_movies_featured');
    const search = parseCatalogId('xtremio_search_movies');

    const base = sortedOf(newRoute, items, { now });
    const byVariant = sortedOf(featured, items, { now });
    const byGenre = sortedOf(newRoute, items, { genre: 'Action', now });
    const byAccount = sortedOf(newRoute, items, { cfg: OTHER_ARGS, now });
    const byDay = sortedOf(featured, items, { now: now + DAY_MS });

    // A search shelf and a genre-less browse shelf share account, kind, variant
    // and an empty genre — but a genre-less browse shelf falls back to the first
    // category while search spans everything, so they are different arrays under
    // otherwise identical coordinates and must not share an entry.
    const bySearch = sortedOf(search, items, { now });

    for (const [label, other] of [
        ['variant', byVariant], ['genre', byGenre], ['account', byAccount], ['search', bySearch]
    ]) {
        assert.notStrictEqual(other, base, `${label} did not separate the entries`);
    }
    assert.notStrictEqual(byDay, byVariant, 'the day did not separate the featured entries');
    assert.equal(sortedCatalogCache.size, 6);
});

test("the featured shuffle still changes with the day, through the cache", () => {
    const route = parseCatalogId('xtremio_movies_featured');
    const items = movies(300);
    const t0 = Date.UTC(2026, 5, 1, 9);

    const today = sortedOf(route, items, { now: t0 }).map(s => s.stream_id);
    const tomorrow = sortedOf(route, items, { now: t0 + DAY_MS }).map(s => s.stream_id);

    // Same day, same source: the memo must hold the order still while paginating.
    assert.deepStrictEqual(sortedOf(route, items, { now: t0 + 3600_000 }).map(s => s.stream_id), today);

    // A handful of items land on the same index by coincidence in any
    // permutation — the expected number of fixed points is 1 whatever the list
    // size — so the assertion is that the order is substantially different, not
    // that nothing coincides.
    let held = 0;
    for (let i = 0; i < today.length; i++) if (today[i] === tomorrow[i]) held++;
    assert.ok(held < today.length * 0.1, `a day later, ${held}/${today.length} items held their position`);
});

// --- shelves with no comparator -------------------------------------------

test('an unsorted shelf is passed through and caches nothing', () => {
    // Live has no recency field and its catalog id carries no variant, so
    // catalogComparator returns null. Caching an array that was never sorted
    // would spend memory to remember the identity function.
    const route = parseCatalogId('xtremio_live');
    const items = [{ stream_id: 3 }, { stream_id: 1 }];
    const out = sortedCatalogItems(CFG_ARGS, CATALOG_KINDS.live, route, null, { items, source: items });

    assert.strictEqual(out, items);
    assert.equal(sortedCatalogCache.size, 0);
});

// --- bounds ---------------------------------------------------------------

test('the cache is bounded and swept like every other cache', () => {
    const route = parseCatalogId('xtremio_movies_new');
    const items = movies(5);
    for (let i = 0; i < CACHE_MAX_SORTED_CATALOGS + 10; i++) {
        sortedOf(route, items, { genre: `Genre ${i}` });
    }
    assert.ok(sortedCatalogCache.size <= CACHE_MAX_SORTED_CATALOGS,
        `held ${sortedCatalogCache.size} entries against a bound of ${CACHE_MAX_SORTED_CATALOGS}`);

    // An entry pins the whole list it was sorted from, so an instance whose users
    // have gone away must not hold one until something new arrives.
    sweepCaches(Date.now() + CACHE_TTL + 1);
    assert.equal(sortedCatalogCache.size, 0, 'sortedCatalogCache is missing from sweepCaches');
});

// --- through the route ----------------------------------------------------

const CATS = {
    live: [],
    movies: [{ category_id: 20, category_name: 'Action' }],
    series: [{ category_id: 30, category_name: 'Comedy' }]
};

let provided = movies(250);

function stubProvider() {
    global.fetch = async (url) => {
        const u = new URL(url);
        const action = u.searchParams.get('action');
        let data = [];
        if (action === 'get_vod_categories') data = CATS.movies;
        else if (action === 'get_series_categories') data = CATS.series;
        else if (action === 'get_live_categories') data = CATS.live;
        else if (action === 'get_vod_streams') data = provided;
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
}

function clearCaches() {
    catCache.clear();
    // The genre fallback path fetches per category, and that cache is as capable
    // of carrying a previous test's list into this one as the full-list cache is.
    categoryStreamsCache.map.clear();
    vodStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
    liveStreamsCache.map.clear();
    sortedCatalogCache.clear();
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

async function getCatalog(id, extra) {
    const path = extra
        ? `${base}/${CFG}/catalog/XT-Movies/${id}/${encodeURIComponent(extra)}.json`
        : `${base}/${CFG}/catalog/XT-Movies/${id}.json`;
    return (await realFetch(path)).json();
}

test('paginating a shelf sorts once and pages consistently', async () => {
    stubProvider();
    clearCaches();
    provided = movies(250);

    const page1 = await getCatalog('xtremio_movies_new', 'skip=0');
    const page2 = await getCatalog('xtremio_movies_new', 'skip=100');
    const page3 = await getCatalog('xtremio_movies_new', 'skip=200');

    assert.equal(page1.metas.length, 100);
    assert.equal(page3.metas.length, 50);

    const ids = [...page1.metas, ...page2.metas, ...page3.metas].map(m => m.id);
    assert.equal(new Set(ids).size, 250, 'the three pages overlap or drop items');

    // Newest first, across the page boundaries as well as within a page.
    const added = ids.map(id => Number(id.replace('xtremio_movie_', '')));
    assert.deepStrictEqual(added, [...added].sort((a, b) => b - a));

    // One sorted view for the shelf, reused by all three pages.
    assert.equal(sortedCatalogCache.size, 1);
});

test('search is filtered from the sorted list and returns the same items as before', async () => {
    stubProvider();
    clearCaches();
    provided = movies(250);

    // The route now sorts and then filters, where it used to filter and then
    // sort. The two commute for a total order, and this is the assertion that
    // says so on real route output rather than in the abstract.
    const searched = await getCatalog('xtremio_search_movies', 'search=Movie 01');
    const expected = movies(250)
        .filter(s => s.name.toLowerCase().includes('movie 01'))
        .sort(catalogComparator(MOVIE_KIND, 'new'))
        .map(s => `xtremio_movie_${s.stream_id}`);

    assert.ok(expected.length > 1, 'the fixture should match more than one title');
    assert.deepStrictEqual(searched.metas.map(m => m.id), expected);
});

test('a genre shelf and the search shelf do not serve each other', async () => {
    stubProvider();
    clearCaches();
    provided = movies(250);

    const genreShelf = await getCatalog('xtremio_movies_new', 'genre=Action');
    const searchShelf = await getCatalog('xtremio_search_movies', 'search=Movie');

    assert.equal(genreShelf.metas.length, 100);
    assert.equal(searchShelf.metas.length, 100);
    assert.equal(sortedCatalogCache.size, 2, 'the two shelves shared one entry');
});

test('a list refetched after its TTL is served, not the memoised old order', async () => {
    stubProvider();
    clearCaches();
    provided = movies(10);

    const before = await getCatalog('xtremio_movies_new', 'skip=0');
    assert.equal(before.metas.length, 10);

    // The provider gains a title and the lists behind the shelf expire — both of
    // them, because a genre-less shelf resolves to the first category and is
    // served from the per-category cache when the full list is cold. The sorted
    // view is deliberately *not* cleared: identity is what has to catch this, and
    // if it does not, the new title is invisible for the life of the memo.
    provided = movies(10).concat({
        stream_id: 999, name: 'Newest', category_id: 20, added: 99999, rating: 5
    });
    vodStreamsCache.map.clear();
    categoryStreamsCache.map.clear();

    const after = await getCatalog('xtremio_movies_new', 'skip=0');
    assert.equal(after.metas.length, 11);
    assert.equal(after.metas[0].id, 'xtremio_movie_999', 'served a sorted view of the old list');
});
