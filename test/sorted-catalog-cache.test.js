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
//
// Audit M-5 and L-11 then corrected the memo's lifetime and its key. Views live
// in a WeakMap keyed by the list they were sorted from, so they cannot keep an
// evicted list alive, and under one list they are keyed by what
// selectCatalogSource selected rather than by the genre string a client sent.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');
const v8 = require('node:v8');
const vm = require('node:vm');

const {
    app,
    encodeConfig,
    accountCacheKey,
    CATALOG_KINDS,
    parseCatalogId,
    catalogComparator,
    sortedCatalogItems,
    sortedCatalogViews,
    catCache,
    categoryStreamsCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache
} = require('../index.js');

// A view's lifetime is the whole of M-5, and only a collection can show it. The
// flag is set at runtime so `npm test` needs no node options; a context created
// after it is set gets the `gc` global.
v8.setFlagsFromString('--expose-gc');
const gc = vm.runInNewContext('gc');

const realFetch = global.fetch;
const DAY_MS = 86400000;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
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
    const { source = items, selection = 'all', now } = opts;
    return sortedCatalogItems(MOVIE_KIND, route, { items, source, selection }, now);
}

// The keys of the views held for one source list, in insertion order.
function viewKeys(source) {
    const entry = sortedCatalogViews.get(source);
    return entry ? [...entry.views.keys()] : [];
}

// True once `ref`'s target has been collected. A WeakRef holds its target until
// the end of the job that created or dereferenced it, so each collection has to
// run on a later turn.
async function collected(ref) {
    for (let i = 0; i < 10; i++) {
        await new Promise(resolve => setImmediate(resolve));
        gc();
        if (ref.deref() === undefined) return true;
    }
    return false;
}

// --- memoisation ----------------------------------------------------------

test('the same shelf, asked twice, is sorted once', () => {
    const route = parseCatalogId('xtremio_movies_new');
    const items = movies(50);

    const first = sortedOf(route, items);
    const second = sortedOf(route, items);

    // Identity, not deepEqual: a second sort would produce an equal array, so
    // only reference equality distinguishes a memo hit from a repeat of the work.
    assert.strictEqual(second, first, 'the second request re-sorted the list');
    assert.deepStrictEqual(viewKeys(items), ['new\nall']);
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
    assert.deepStrictEqual(viewKeys(refetched), ['new\nall']);
});

test('an equal-but-different array is not treated as the same source', () => {
    // This is also what separates two accounts: every list cache is keyed by
    // account, so two accounts' lists are two arrays even when their contents
    // agree.
    const route = parseCatalogId('xtremio_movies_new');
    const items = movies(10);
    const clone = movies(10);

    const first = sortedOf(route, items);
    const second = sortedOf(route, clone);
    assert.notStrictEqual(second, first, 'reused a view derived from a different array');
    assert.deepStrictEqual(second.map(s => s.stream_id), first.map(s => s.stream_id));
});

// --- key separation -------------------------------------------------------

test('variant and selection separate views over one source; search does not', () => {
    const items = movies(30);
    const now = Date.UTC(2026, 0, 1, 12);
    const newRoute = parseCatalogId('xtremio_movies_new');
    const popular = parseCatalogId('xtremio_movies_popular');
    const search = parseCatalogId('xtremio_search_movies');

    const base = sortedOf(newRoute, items, { now });
    const byVariant = sortedOf(popular, items, { now });
    const bySelection = sortedOf(newRoute, items.filter(s => s.rating === 1), {
        source: items, selection: 'category:20', now
    });
    assert.notStrictEqual(byVariant, base, 'the variant did not separate the views');
    assert.notStrictEqual(bySelection, base, 'the selection did not separate the views');
    assert.equal(bySelection.length, 6, 'a category view was served the whole list');

    // Search over the full list is sorted `new`, which is exactly the view the
    // no-categories shelf already holds — one sort, not two.
    assert.strictEqual(sortedOf(search, items, { now }), base);

    assert.deepStrictEqual(viewKeys(items), ['new\nall', 'popular\nall', 'new\ncategory:20']);
});

test("a new day drops the previous day's views", () => {
    const items = movies(30);
    const t0 = Date.UTC(2026, 0, 1, 12);
    sortedOf(parseCatalogId('xtremio_movies_featured'), items, { now: t0 });
    sortedOf(parseCatalogId('xtremio_movies_new'), items, { now: t0 });
    assert.equal(viewKeys(items).length, 2);

    // A list can stay cached across midnight; yesterday's featured order must not
    // stay with it.
    sortedOf(parseCatalogId('xtremio_movies_featured'), items, { now: t0 + DAY_MS });
    assert.deepStrictEqual(viewKeys(items), ['featured\nall']);
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
    const out = sortedCatalogItems(CATALOG_KINDS.live, route, { items, source: items, selection: 'all' });

    assert.strictEqual(out, items);
    assert.equal(sortedCatalogViews.has(items), false);
});

// --- lifetime (M-5) -------------------------------------------------------

test('a view does not keep the list it was sorted from alive', async () => {
    // The memo used to hold `source` in an entry of its own, so a list the stream
    // cache evicted stayed reachable for as long as its view did.
    const route = parseCatalogId('xtremio_movies_new');
    let list = movies(1000);
    const listRef = new WeakRef(list);
    const viewRef = new WeakRef(sortedOf(route, list));
    list = null;

    assert.ok(await collected(listRef), 'the sorted view kept its source list reachable');
    assert.ok(await collected(viewRef), 'the view outlived the list it was sorted from');
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
        const categoryId = u.searchParams.get('category_id');
        let data = [];
        if (action === 'get_vod_categories') data = CATS.movies;
        else if (action === 'get_series_categories') data = CATS.series;
        else if (action === 'get_live_categories') data = CATS.live;
        else if (action === 'get_vod_streams') {
            data = categoryId ? provided.filter(s => String(s.category_id) === categoryId) : provided;
        }
        // A fresh array per response, as a parsed body is. Handing back `provided`
        // itself would let this module hold the cached list, and the eviction
        // test below could never see it collected.
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => [...data] };
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
}

function cachedCategoryList(categoryId) {
    return categoryStreamsCache.get(`${accountCacheKey(CFG_ARGS)}\n${MOVIE_KIND.categoryAction}\n${categoryId}`);
}

const idsOf = shelf => shelf.metas.map(m => Number(m.id.replace('xtremio_movie_', '')));

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

    // One sorted view for the shelf, reused by all three pages. The full list is
    // cold, so the genre-less shelf was served from its first category's list.
    assert.deepStrictEqual(viewKeys(cachedCategoryList(20)), ['new\ncategory:20']);
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
    // Odd ids go to a category the account does not list, so a genre shelf and a
    // search select visibly different items.
    provided = movies(250).map(s => (s.stream_id % 2 ? { ...s, category_id: 21 } : s));
    const isEven = id => id % 2 === 0;

    // Search first, so the genre shelf is filtered from the same warm full list:
    // one source, and only the selection tells the two views apart.
    const warmSearch = await getCatalog('xtremio_search_movies', 'search=Movie');
    const warmGenre = await getCatalog('xtremio_movies_new', 'genre=Action');
    assert.ok(!idsOf(warmSearch).every(isEven), 'search should span both categories');
    assert.ok(idsOf(warmGenre).every(isEven), 'the genre shelf was served the search view');
    assert.deepStrictEqual(viewKeys(vodStreamsCache.get(CFG_ARGS)), ['new\nall', 'new\ncategory:20']);

    // And the other way round, where the genre shelf comes from a per-category
    // fetch and the two views sit on different sources.
    clearCaches();
    const coldGenre = await getCatalog('xtremio_movies_new', 'genre=Action');
    const coldSearch = await getCatalog('xtremio_search_movies', 'search=Movie');
    assert.ok(idsOf(coldGenre).every(isEven), 'the genre shelf was served the search view');
    assert.ok(!idsOf(coldSearch).every(isEven), 'search was served the genre view');
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
    // view is deliberately *not* touched: identity is what has to catch this, and
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

// --- L-11: the key is what was selected, not what was asked for -----------

test('a genre that search ignores does not mint a view per distinct string', async () => {
    stubProvider();
    clearCaches();
    provided = movies(250);

    // What the audit reproduced: 64 searches, each with a different ignored genre,
    // filled a cache every account shared with sorts of one list.
    for (let i = 0; i < 20; i++) {
        const page = await getCatalog('xtremio_search_movies', `search=Movie&genre=ignored-${i}`);
        assert.equal(page.metas.length, 100);
    }
    assert.deepStrictEqual(viewKeys(vodStreamsCache.get(CFG_ARGS)), ['new\nall']);
});

test('a kind with no categories holds one view whatever genre is sent, shared with search', async () => {
    const listed = CATS.movies;
    CATS.movies = [];
    try {
        stubProvider();
        clearCaches();
        provided = movies(250);

        // The degraded shelf serves the full list for any genre, advertised or not.
        for (const extra of ['genre=Action', 'genre=anything-at-all', `genre=${'x'.repeat(40)}`]) {
            const page = await getCatalog('xtremio_movies_new', extra);
            assert.equal(page.metas.length, 100, `${extra} should serve the full list`);
        }
        assert.equal((await getCatalog('xtremio_movies_new')).metas.length, 100);
        assert.equal((await getCatalog('xtremio_search_movies', 'search=Movie')).metas.length, 100);

        assert.deepStrictEqual(viewKeys(vodStreamsCache.get(CFG_ARGS)), ['new\nall']);
    } finally {
        CATS.movies = listed;
    }
});

// --- M-5 through the route ------------------------------------------------

test('evicting a stream list releases it, sorted views and all', async () => {
    stubProvider();
    clearCaches();
    provided = movies(2000);

    await getCatalog('xtremio_search_movies', 'search=Movie');
    await getCatalog('xtremio_movies_popular', 'genre=Action');
    const listRef = new WeakRef(vodStreamsCache.get(CFG_ARGS));
    assert.deepStrictEqual(viewKeys(listRef.deref()), ['new\nall', 'popular\ncategory:20']);

    // What the stream cache does to stay within CACHE_MAX_STREAM_MB.
    vodStreamsCache.map.clear();
    assert.ok(await collected(listRef),
        'an evicted list stayed reachable — the stream cache bound no longer bounds memory');
});
