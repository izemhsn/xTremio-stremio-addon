// Turning a cached list into one page of a shelf: parsing a catalog id, ordering,
// filtering, and the memo that keeps a shelf from being re-sorted per page.
//
// The memo's correctness rests on identity, not on a clock. A view is keyed by
// the array it was sorted from, in a WeakMap, so a refetch invalidates it in the
// same instant and an evicted list takes its views with it — there is no second
// TTL that could disagree with the list's own. Nothing stored in a view may hold
// a strong reference back to its list, which is why selectCatalogSource passes the
// cached array a genre shelf was filtered *from* as the token rather than the
// filtered result.
//
// CATALOG_KINDS stays in index.js: it names the loaders and the list caches, so it
// belongs with them rather than here. Everything in this file takes the `kind` it
// needs as an argument.
const { titleOf } = require('../helpers.js');

// Sorted catalog views, so paginating a shelf does not re-sort the whole list per
// page. A WeakMap keyed by the cached array a view was sorted from: a refetch
// invalidates it at once, and an evicted list takes its views with it. Nothing in a
// view may hold a strong reference back to its list. Each source maps to
// `{ day, views }`; see sortedCatalogItems.
const sortedCatalogViews = new WeakMap();

// The separator inside view and selection keys. A newline, because no variant
// and no category id can contain one, so two fields cannot shift into one.
const VIEW_KEY_SEP = '\n';


// Which kind a catalog id belongs to, and which variant. Catalog ids overlap item
// id prefixes (`xtremio_series_new`), so item ids go through typeMatchesId instead.
// Variants are an allowlist: an unknown one must be rejected, not served unsorted.
const CATALOG_VARIANTS = new Set(['new', 'popular', 'featured']);

function parseCatalogId(id) {
    const str = String(id || '');
    if (str === 'xtremio_live') return { kind: 'live', variant: null, search: false };
    if (str === 'xtremio_search_movies') return { kind: 'movies', variant: null, search: true };
    if (str === 'xtremio_search_series') return { kind: 'series', variant: null, search: true };
    for (const kind of ['movies', 'series']) {
        const prefix = `xtremio_${kind}_`;
        if (!str.startsWith(prefix)) continue;
        const variant = str.slice(prefix.length);
        return CATALOG_VARIANTS.has(variant) ? { kind, variant, search: false } : null;
    }
    return null;
}


// How long one featured order lasts. Seeded on a period rather than on the clock
// so the shuffle holds still while a client pages through it — but a day was too
// short (audit L14): Stremio caches catalog pages (max-age 300,
// stale-while-revalidate 600), so for up to fifteen minutes either side of a
// boundary a paginated shelf could mix two orders. A week cuts the number of
// boundaries by 52 without making the shelf feel fixed. It does not remove the
// boundary — nothing stateless can, since the client holds pages this server has
// already forgotten — it makes it rare.
const FEATURED_PERIOD_MS = 7 * 86400000;

// The one place the period is turned into a seed. The comparator and the memo key
// must read the same function: they used to compute `Math.floor(now / 86400000)`
// separately, which is two things that have to agree and no way to notice when
// they stop — a sorted view would outlive the seed it was built from.
function featuredEpoch(now) {
    return Math.floor(now / FEATURED_PERIOD_MS);
}

// Every comparator ends in the item id, making each sort a total order, so a page
// does not depend on which source served the list (audit L3). `now` is a parameter
// only for testing the featured shuffle across periods.
function catalogComparator(kind, variant, now = Date.now()) {
    const idOf = s => parseInt(s[kind.idField]) || 0;
    const byId = (a, b) => idOf(a) - idOf(b);

    if (variant === 'new' && kind.recencyField) {
        return (a, b) => ((parseInt(b[kind.recencyField]) || 0) - (parseInt(a[kind.recencyField]) || 0)) || byId(a, b);
    }
    if (variant === 'popular') {
        return (a, b) => ((parseFloat(b.rating) || 0) - (parseFloat(a.rating) || 0)) || byId(a, b);
    }
    if (variant === 'featured') {
        // Seeded on the period, so the shuffle holds still while paginating. The
        // seed must enter *before* the multiply: added after, it preserves order
        // and the shuffle never changed.
        const periodSeed = featuredEpoch(now);
        // Spread the seed across the word so consecutive periods differ widely.
        const dayKey = Math.imul(periodSeed, 0x9e3779b1);
        // XOR then an odd multiplier: a bijection modulo 2^31, so distinct ids
        // cannot collide.
        const hash = s => (Math.imul(idOf(s) ^ dayKey, 2654435761) & 0x7fffffff);
        return (a, b) => (hash(a) - hash(b)) || byId(a, b);
    }
    return null;
}

// `limit` stops the scan once that many matches are found: the route needs one
// page, and a common word would otherwise lowercase and test every title.
function filterByName(items, search, limit = Infinity) {
    if (!search) return items;
    const q = search.toLowerCase();
    const found = [];
    for (const s of items) {
        if (found.length >= limit) break;
        if (titleOf(s.name).toLowerCase().includes(q)) found.push(s);
    }
    return found;
}

function toCatalogMetas(items, kind) {
    return items.map(s => ({
        id: `${kind.idPrefix}${s[kind.idField]}`,
        type: kind.metaType,
        // An item with no title omits the key rather than sending ''.
        name: titleOf(s.name) || undefined,
        poster: s[kind.posterField] || undefined,
        posterShape: kind.posterShape
    }));
}

// Which categories an item is filed under: `category_id`, plus `category_ids` on
// many panels. Both count, so a warm full list matches what the per-category call
// returns (audit C4).
function hasCategoryIds(item) {
    return (item.category_id != null && item.category_id !== '')
        || (Array.isArray(item.category_ids) && item.category_ids.length > 0);
}

function inCategories(item, ids) {
    if (item.category_id != null && item.category_id !== '' && ids.has(String(item.category_id))) return true;
    return Array.isArray(item.category_ids) && item.category_ids.some(id => ids.has(String(id)));
}

// Items merged from several category lists, each once, first occurrence kept: an
// item filed under two categories of the same name is in both of their lists.
function uniqueById(items, idField) {
    const seen = new Set();
    return items.filter((item) => {
        const id = String(item?.[idField]);
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    });
}


// Search sorts as `new`, so its pages stay stable across refetches.
function catalogVariant(route) {
    return route.search ? 'new' : route.variant;
}

// Under one source, a sorted view is keyed by variant and by `selection` — never
// by the request's genre string, which would be an unbounded key space. Account
// and kind are implied by the source. `variant` never contains a newline, so the
// selection cannot shift into it.
function catalogViewKey(route, selection) {
    return `${catalogVariant(route)}${VIEW_KEY_SEP}${selection}`;
}

// A list that stays cached across a period boundary must not keep the previous
// period's views alongside the new ones. featuredEpoch is the same function the
// comparator seeds from, so the two cannot disagree about when the order changed.

// This period's memo for `source`, or null when there is none and `create` is
// false. `views` holds sorted orders, keyed by variant and selection; `selections`
// holds the filtered arrays those orders were computed from, keyed by selection
// alone — two key spaces that must not share a map, since a selection can itself
// contain the separator. A filtered selection does not depend on the period, but
// it costs one filter to let both live and die together.
function catalogMemoFor(source, epoch, create) {
    let entry = sortedCatalogViews.get(source);
    if (!entry || entry.epoch !== epoch) {
        if (!create) return null;
        entry = { epoch, views: new Map(), selections: new Map() };
        sortedCatalogViews.set(source, entry);
    }
    return entry;
}

// The items a genre shelf resolved to last time, or null — consulted *before* the
// filter that would produce them, and creating nothing. Filtering is the expensive
// half of a genre shelf and its result depends only on the source and the
// selection, so only the sort was being saved while the filter ran on every page
// (audit Perf). Keyed apart from the sorted views because it outlives all of them:
// three variants over one selection share one filtered array.
function cachedCatalogSelection(source, selection, now = Date.now()) {
    const memo = catalogMemoFor(source, featuredEpoch(now), false);
    return (memo && memo.selections.get(selection)) || null;
}

// Remembers a filtered selection and returns it, so a call site can do both in the
// expression that returns. Only ever called with the result of a filter, so it
// cannot store the source array back into its own memo.
function rememberCatalogSelection(source, selection, items, now = Date.now()) {
    catalogMemoFor(source, featuredEpoch(now), true).selections.set(selection, items);
    return items;
}

// The sorted view of one shelf, memoised against the identity of the list it was
// derived from (see sortedCatalogViews). Returns `items` untouched when the
// variant has no comparator — the live shelf and any unsorted kind — since there
// is no order to remember; the filter that produced those items is remembered
// separately, above.
function sortedCatalogItems(kind, route, { items, source, selection }, now = Date.now()) {
    const comparator = catalogComparator(kind, catalogVariant(route), now);
    if (!comparator) return items;

    const views = catalogMemoFor(source, featuredEpoch(now), true).views;
    const key = catalogViewKey(route, selection);
    const hit = views.get(key);
    if (hit) return hit;

    const sorted = [...items].sort(comparator);
    views.set(key, sorted);
    return sorted;
}

module.exports = {
    sortedCatalogViews,
    VIEW_KEY_SEP,
    CATALOG_VARIANTS,
    parseCatalogId,
    FEATURED_PERIOD_MS,
    featuredEpoch,
    catalogComparator,
    filterByName,
    toCatalogMetas,
    hasCategoryIds,
    inCategories,
    uniqueById,
    catalogVariant,
    catalogViewKey,
    catalogMemoFor,
    cachedCatalogSelection,
    rememberCatalogSelection,
    sortedCatalogItems
};
