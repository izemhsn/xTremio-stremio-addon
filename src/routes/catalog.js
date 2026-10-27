// GET /:config/catalog/:type/:id.json
// GET /:config/catalog/:type/:id/:extra.json
//
// One page (PAGE_SIZE items) of a shelf: Live TV, a movie or series shelf
// (popular / new / featured, filtered by genre), or a search.
//
// The flow is: decode the account -> work out which catalog was asked for ->
// load the items (from cache when possible) -> sort -> filter by search term ->
// cut out one page -> turn each item into a Stremio "meta preview".
const express = require('express');

const { decodeConfig } = require('../config-token.js');
const { CATALOG_KINDS, catalogTypesFor, selectCatalogSource } = require('../catalog/kinds.js');
const {
    parseCatalogId,
    filterByName,
    toCatalogMetas,
    sortedCatalogItems
} = require('../catalog/shelf.js');
const { parseExtra, rawExtraSegment, PAGE_SIZE, withCacheHints } = require('./extras.js');
const { logRouteError } = require('./errors.js');

const router = express.Router();

router.get(['/:config/catalog/:type/:id.json', '/:config/catalog/:type/:id/:extra.json'], async (req, res) => {
    // Every early return below is an empty answer caused by a failure, and a
    // client caching one would pin a temporary fault. So "do not cache" is the
    // default, and withCacheHints overwrites it on the paths that succeeded.
    // The meta and stream routes follow the same rule.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ metas: [] });

    const { id, type } = req.params;

    const types = catalogTypesFor(id);
    if (!types) return res.json({ metas: [] });
    if (!types.includes(type)) {
        // Both values come straight from the path. JSON.stringify escapes any
        // newline in them, so a caller cannot forge a log line of its own.
        console.warn(`[catalog] type/id mismatch: type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);
        return res.json({ metas: [] });
    }

    const route = parseCatalogId(id);
    const kind = CATALOG_KINDS[route.kind];

    try {
        const extra = parseExtra(rawExtraSegment(req));
        const skip = Math.max(0, parseInt(extra.skip) || 0);
        // One clock for the whole request: the sorted view depends on the
        // featured period, and reading the clock twice could land either side of
        // a period boundary.
        const now = Date.now();

        let selected;
        if (route.search) {
            // Global search: one full-list fetch per account (cached), then an
            // in-memory filter. This is what makes search cheap.
            if (!extra.search) return res.json({ metas: [] });
            const all = await kind.loadAll(cfg);
            selected = { items: all, source: all, selection: 'all' };
        } else {
            selected = await selectCatalogSource(cfg, kind, extra.genre, now);
            if (!selected) return res.json({ metas: [] });
        }

        // Sort first, then filter by the search term. The sorted list is
        // remembered between pages, and sorting before filtering means that
        // remembered list does not depend on the search term. The filter stops
        // as soon as it has enough matches for this page.
        const items = filterByName(
            sortedCatalogItems(kind, route, selected, now),
            extra.search,
            skip + PAGE_SIZE
        );

        const metas = toCatalogMetas(items.slice(skip, skip + PAGE_SIZE), kind);
        // An empty page stays no-store: empty lists are often temporary.
        if (!metas.length) return res.json({ metas });
        return res.json({ metas, ...withCacheHints(res, 300, 600) });
    } catch (e) {
        logRouteError('catalog', e);
        res.json({ metas: [] });
    }
});

module.exports = { router };
