// The three catalog kinds, and how a genre resolves to a set of items.
//
// The kinds differ only in the fields in this table. Everything else — genre
// resolution, the search filter, sorting, pagination and the meta shape — is one
// code path, so a change to any of it cannot apply to movies and quietly miss
// series. Adding a fourth kind means adding a row, not another branch.
//
// This is where the catalog meets the panel: the table names the loaders and the
// list caches, which is why it is here and not in shelf.js, and why shelf.js takes
// the `kind` it needs as an argument instead.
const { accountCacheKey } = require('../cache/layers.js');
const {
    getCategories,
    getCategoryStreams,
    getAllLiveStreams,
    getAllVodStreams,
    getAllSeriesStreams,
    liveStreamsCache,
    vodStreamsCache,
    seriesStreamsCache
} = require('../xtream/data.js');
const {
    parseCatalogId,
    inCategories,
    hasCategoryIds,
    uniqueById,
    cachedCatalogSelection,
    rememberCatalogSelection,
    VIEW_KEY_SEP
} = require('./shelf.js');

const CATALOG_KINDS = {
    live: {
        catalogTypes: ['Live TV'],
        categoryKey: 'live',
        loadAll: getAllLiveStreams,
        listCache: liveStreamsCache,
        // get_live_streams items may carry category_id, category_name, or neither,
        // so live also matches on the category name.
        matchCategoryName: true,
        // Live always loads the full list first; this is only for a category that
        // list has nothing for (see selectCatalogSource).
        categoryAction: 'get_live_streams',
        idField: 'stream_id',
        idPrefix: 'xtremio_live_',
        metaType: 'Live TV',
        posterField: 'stream_icon',
        posterShape: 'square',
        recencyField: null
    },
    movies: {
        catalogTypes: ['XT-Movies'],
        categoryKey: 'movies',
        loadAll: getAllVodStreams,
        listCache: vodStreamsCache,
        categoryAction: 'get_vod_streams',
        idField: 'stream_id',
        idPrefix: 'xtremio_movie_',
        metaType: 'XT-Movies',
        posterField: 'stream_icon',
        posterShape: 'poster',
        recencyField: 'added'
    },
    series: {
        // Declared under XT-Series in the manifest, but the metas are `series`
        // because that is the built-in type that gives episodes their UI.
        catalogTypes: ['XT-Series', 'series'],
        categoryKey: 'series',
        loadAll: getAllSeriesStreams,
        listCache: seriesStreamsCache,
        categoryAction: 'get_series',
        idField: 'series_id',
        idPrefix: 'xtremio_series_',
        metaType: 'series',
        posterField: 'cover',
        posterShape: 'poster',
        recencyField: 'last_modified'
    }
};
function catalogTypesFor(id) {
    const route = parseCatalogId(id);
    return route ? CATALOG_KINDS[route.kind].catalogTypes : null;
}

// "no categories" is a fact about an account and a kind, but selectCatalogSource
// runs on every catalog request, so an account whose category calls are failing
// wrote the same line for every shelf the client opened — dozens per refresh, and
// the interesting lines around them scrolled away (audit L6). Once per account and
// kind per interval says exactly as much. Bounded and evicted oldest-first,
// because the accounts come from install URLs rather than from configuration:
// dropping an entry only re-arms its warning, which is the safe direction.
const DEGRADED_CATALOG_LOG_INTERVAL_MS = 10 * 60 * 1000;
const DEGRADED_CATALOG_LOG_MAX = 1000;
const degradedCatalogLogged = new Map();

function noteDegradedCatalog(cfg, categoryKey, now = Date.now()) {
    const key = JSON.stringify([accountCacheKey(cfg), categoryKey]);
    const last = degradedCatalogLogged.get(key);
    if (last !== undefined && now - last < DEGRADED_CATALOG_LOG_INTERVAL_MS) return false;
    // Re-inserting moves the key to the end, so the eviction below is least
    // recently warned rather than first ever seen.
    degradedCatalogLogged.delete(key);
    if (degradedCatalogLogged.size >= DEGRADED_CATALOG_LOG_MAX) {
        degradedCatalogLogged.delete(degradedCatalogLogged.keys().next().value);
    }
    degradedCatalogLogged.set(key, now);
    console.warn(`[catalog] no ${categoryKey} categories for this account; serving the full list`);
    return true;
}

// The filters below are the expensive half of a genre shelf, and their result
// depends only on the source list and the selection — so it is remembered under
// the selection and consulted before the filter runs. A remembered selection is
// also proof that the filter found items, which settles the "has items" question
// below: an empty result is never remembered (audit Perf).
async function selectCatalogSource(cfg, kind, genre, now = Date.now()) {
    const cats = await getCategories(cfg);
    const categories = cats[kind.categoryKey] || [];

    // No categories at all — the degraded case the manifest reflects by dropping
    // the genre extra. Without this the shelf is empty either way, because there
    // is no category for the genre to resolve to; the full list is the honest
    // answer, and it is the same list search already uses.
    if (!categories.length) {
        noteDegradedCatalog(cfg, kind.categoryKey);
        const all = await kind.loadAll(cfg);
        return { items: all, source: all, selection: 'all' };
    }
    // Stremio marks genre required, but a bare catalog request still falls back
    // to the first category rather than showing an empty shelf.
    const selectedGenre = genre || (categories[0] && categories[0].category_name);
    // Every category with that name, not the first (audit C3): the manifest offers
    // each name once.
    const ids = [...new Set(categories
        .filter(c => c.category_name === selectedGenre)
        .map(c => String(c.category_id)))];
    if (!ids.length) return null;
    const idSet = new Set(ids);

    // Unambiguous for any ids, and exactly the old `category:<id>` for one numeric id.
    const selection = `category:${ids.map(encodeURIComponent).sort().join(',')}`;

    // A warm full list serves a genre only when it has items for it; otherwise the
    // category is asked directly. Real providers have answered each of the two
    // calls with a transient empty list while the other worked.
    if (kind.matchCategoryName) {
        const genreLower = String(selectedGenre || '').toLowerCase();
        const all = await kind.loadAll(cfg);
        // The name takes part in the filter below, so it takes part in the selection.
        const scoped = `${selection}${VIEW_KEY_SEP}${genreLower}`;
        const remembered = cachedCatalogSelection(all, scoped, now);
        if (remembered) return { items: remembered, source: all, selection: scoped };
        // An item with any category id is matched by id; only one with none at all
        // falls back to its category name.
        const items = all.filter(s => (hasCategoryIds(s)
            ? inCategories(s, idSet)
            : Boolean(genreLower) && String(s.category_name || '').toLowerCase() === genreLower));
        if (items.length) {
            return { items: rememberCatalogSelection(all, scoped, items, now), source: all, selection: scoped };
        }
    } else {
        // Reuse the warm full list when there is one; otherwise a per-category
        // fetch beats pulling 10-50 MB just to filter it down.
        const fullList = kind.listCache.get(cfg);
        if (fullList) {
            const remembered = cachedCatalogSelection(fullList, selection, now);
            if (remembered) return { items: remembered, source: fullList, selection };
            const items = fullList.filter(s => inCategories(s, idSet));
            if (items.length) {
                return { items: rememberCatalogSelection(fullList, selection, items, now), source: fullList, selection };
            }
        }
    }

    // One cached per-category list is its own identity token. Several are merged into
    // a fresh array, whose sorted view is computed per request and collected with it.
    const lists = await Promise.all(ids.map(id => getCategoryStreams(cfg, kind.categoryAction, id)));
    if (lists.length === 1) return { items: lists[0], source: lists[0], selection };
    const merged = uniqueById(lists.flat(), kind.idField);
    return { items: merged, source: merged, selection };
}

module.exports = {
    CATALOG_KINDS,
    catalogTypesFor,
    DEGRADED_CATALOG_LOG_INTERVAL_MS,
    DEGRADED_CATALOG_LOG_MAX,
    degradedCatalogLogged,
    noteDegradedCatalog,
    selectCatalogSource
};
