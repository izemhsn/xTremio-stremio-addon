// The manifest Stremio installs against.
//
// Built per account, because the genre lists come from that account's categories.
// When a kind's categories fail — which is what getCategories returns rather than
// rejecting — that catalog is emitted with `skip` alone and no `genre` extra: a
// required `genre` with an empty `options` leaves Stremio with no value it can
// supply, and the shelf cannot be opened at all.
//
// The genre catalogs never declare `search`, degraded or not. Stremio queries
// every catalog whose only required extra is search, so a degraded manifest that
// kept it added seven duplicate search rows beside the two real ones (audit M3).
const { getCategories } = require('./xtream/data.js');

const ADDON_ID = 'org.xtremio.addon';
// Read rather than restated, so a release cannot bump one and not the other.
const ADDON_VERSION = require('../package.json').version;

async function getManifest(cfg = null) {
    const catalogs = [];

    if (cfg) {
        // getCategories cannot reject — refreshCategories resolves through
        // Promise.allSettled and always returns an entry, serving stale or empty
        // lists on failure — so this catch is belt and braces rather than the
        // degraded path. It used to push a second, hand-maintained copy of the
        // catalog list that could never be reached. The real degraded case is an
        // *empty* category list, which genreExtra handles below.
        let cats = { live: [], movies: [], series: [] };
        try {
            cats = await getCategories(cfg);
        } catch (e) {
            console.error('[manifest] categories unavailable:', e.message);
        }

        const genresOf = (key) =>
            [...new Set((cats[key] || []).map(c => c.category_name).filter(Boolean))];

        // A genre is only offered when there is something to pick. Stremio reads
        // `isRequired: true` as "the client must supply one of these options",
        // so a required genre with an empty list is a catalog nobody can open —
        // strictly worse than the plain catalog it was meant to degrade into.
        // No `search`: Stremio searches every catalog whose only required extra is
        // search, so a degraded manifest put all seven shelves into search beside
        // the two search catalogs — duplicate rows, each rescanning the lists
        // (audit M3). With a required genre it was unreachable anyway.
        const genreExtra = (genres) => (genres.length
            ? [{ name: 'genre', options: genres, isRequired: true }, { name: 'skip' }]
            : [{ name: 'skip' }]);

        // One row per catalog, so the rule cannot apply to some and miss others
        // — which is how the empty-options bug survived in the first place:
        // seven copies of the same `extra` literal.
        const genreCatalogs = [
            ['Live TV', 'xtremio_live', 'Live TV', 'live'],
            ['XT-Movies', 'xtremio_movies_popular', 'Popular', 'movies'],
            ['XT-Movies', 'xtremio_movies_new', 'New', 'movies'],
            ['XT-Movies', 'xtremio_movies_featured', 'Featured', 'movies'],
            ['XT-Series', 'xtremio_series_popular', 'Popular', 'series'],
            ['XT-Series', 'xtremio_series_new', 'New', 'series'],
            ['XT-Series', 'xtremio_series_featured', 'Featured', 'series']
        ];

        const searchCatalogs = [
            ['XT-Movies', 'xtremio_search_movies', 'Search Movies'],
            ['XT-Series', 'xtremio_search_series', 'Search Series']
        ];

        catalogs.push(
            ...genreCatalogs.map(([type, id, name, key]) => ({
                type,
                id,
                name,
                extra: genreExtra(genresOf(key))
            })),
            ...searchCatalogs.map(([type, id, name]) => ({
                type,
                id,
                name,
                // Stremio sends only the extras a catalog declares, so without
                // `skip` a search never asks for page two.
                extra: [{ name: 'search', isRequired: true }, { name: 'skip' }],
                // Not an SDK field, so no client reads it; kept as documentation
                // that filterByName matches on `name` only.
                searchProperties: ['name']
            }))
        );
    }

    return {
        id: ADDON_ID,
        version: ADDON_VERSION,
        name: 'xTremio',
        description: 'xTremio addon for Stremio',
        resources: ['catalog', 'meta', 'stream'],
        types: ['Live TV', 'XT-Movies', 'XT-Series', 'series'],
        catalogs,
        idPrefixes: ['xtremio_live_', 'xtremio_movie_', 'xtremio_series_', 'xtremio_episode_'],
        // No `config` field. The Stremio spec defines it as an array of field
        // descriptors, and this addon used to emit `{ url }` — an object where a
        // client following the spec expects a list. Clients ignore it today, but
        // one that starts honouring it would be handed the wrong type, and it
        // buys nothing: `behaviorHints.configurable` is what routes the user to
        // /configure, and that already works.
        behaviorHints: {
            configurable: true,
            configurationRequired: !cfg
        }
    };
}

module.exports = { getManifest, ADDON_ID, ADDON_VERSION };
