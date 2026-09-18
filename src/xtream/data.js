// The data this addon reads from a panel, and the caches in front of it.
//
// One upstream call per kind per account, then everything else is filtering in
// memory — which is what makes global search cheap and why these caches are the
// largest thing the process holds. Each is charged to CACHE_BUDGET and registers
// itself for the sweep.
//
// The cache instances live with the calls they front rather than in
// src/cache/layers.js, which holds only the primitives and knows nothing about
// Xtream.
const { causeSuffix } = require('../helpers.js');
const { BoundedMap } = require('../cache/bounded-map.js');
const { estimateBytes } = require('../upstream/read-capped.js');
const { xtremioGet, getStreams, LOG_REQUESTS } = require('./client.js');
const {
    CACHE_TTL,
    CACHE_FAILURE_TTL,
    CACHE_STALE_MAX_AGE_MS,
    CACHE_MAX_ACCOUNTS,
    CACHE_MAX_SERIES_INFO,
    CACHE_MAX_VOD_INFO,
    CACHE_MAX_CATEGORY_LISTS,
    CACHE_BUDGET,
    accountCacheKey,
    registerSweepable,
    createSingleFlight,
    createStreamListCache,
    createKeyedCache
} = require('../cache/layers.js');

// Categories per account. maxAgeMs is the 24-hour stale window rather than
// CACHE_TTL, because getCategories serves a stale copy through an outage and the
// sweep must not reclaim what it is still answering from.
const catCache = registerSweepable(new BoundedMap({
    maxEntries: CACHE_MAX_ACCOUNTS,
    maxAgeMs: CACHE_STALE_MAX_AGE_MS,
    ledger: CACHE_BUDGET
}));

const categoriesSingleFlight = createSingleFlight();

function getCategories(cfg) {
    const key = accountCacheKey(cfg);
    // Kept even once expired: stale categories beat empty ones if a refresh fails.
    const cached = catCache.get(key);
    if (cached && cached.ts > Date.now() - cached.ttl) return Promise.resolve(cached);
    return categoriesSingleFlight(key, () => refreshCategories(cfg, key));
}

async function refreshCategories(cfg, key) {
    const cached = catCache.get(key);
    // A concurrent flight may have refreshed it while we queued.
    if (cached && cached.ts > Date.now() - cached.ttl) return cached;

    const results = await Promise.allSettled([
        xtremioGet(cfg, 'get_live_categories'),
        xtremioGet(cfg, 'get_vod_categories'),
        xtremioGet(cfg, 'get_series_categories')
    ]);
    const pick = (r, stale) => (r.status === 'fulfilled' && Array.isArray(r.value)) ? r.value : (stale || []);
    results.forEach((r, i) => {
        if (r.status === 'rejected') {
            console.error(`[getCategories] source ${i} failed:`, r.reason?.message || r.reason);
        }
    });

    const failed = results.some(r => r.status !== 'fulfilled' || !Array.isArray(r.value));
    const entry = {
        live: pick(results[0], cached?.live),
        movies: pick(results[1], cached?.movies),
        series: pick(results[2], cached?.series),
        ts: Date.now(),
        ttl: failed ? CACHE_FAILURE_TTL : CACHE_TTL
    };
    // Weighed by its three lists. A failed refresh reuses the stale arrays, but the
    // entry it writes replaces the one that held them, so they are never counted
    // twice.
    entry.bytes = estimateBytes(entry.live) + estimateBytes(entry.movies) + estimateBytes(entry.series);
    if (failed) {
        console.warn(`[getCategories] partial or total failure; serving ${cached ? 'stale' : 'empty'} data, retrying in ${CACHE_FAILURE_TTL / 1000}s`);
    }
    catCache.set(key, entry);
    return entry;
}

const liveStreamsCache = createStreamListCache();
const vodStreamsCache = createStreamListCache();
const seriesStreamsCache = createStreamListCache();


// stream_id -> item for a cached live or movie list, so opening a channel or
// falling back from get_vod_info is a lookup rather than a scan. Keyed by the
// list's identity, like sortedCatalogViews, so a refetch invalidates it and an
// evicted list takes its index with it.
const streamIdIndexes = new WeakMap();

function findStreamById(list, streamId) {
    let index = streamIdIndexes.get(list);
    if (!index) {
        index = new Map();
        for (const item of list) {
            const id = String(item?.stream_id);
            if (!index.has(id)) index.set(id, item);
        }
        streamIdIndexes.set(list, index);
    }
    return index.get(String(streamId)) || null;
}

function getAllVodStreams(cfg) {
    return vodStreamsCache.load(cfg, () => getStreams(cfg, 'get_vod_streams'));
}

function getAllSeriesStreams(cfg) {
    return seriesStreamsCache.load(cfg, () => getStreams(cfg, 'get_series'));
}

function getAllLiveStreams(cfg) {
    return liveStreamsCache.load(cfg, () => getStreams(cfg, 'get_live_streams'));
}

// The per-category fetch selectCatalogSource falls back to when the full list is
// cold, cached and single-flighted. An empty category is asked again within a
// minute, since real providers return those transiently.
const categoryStreamsCache = createKeyedCache({
    maxEntries: CACHE_MAX_CATEGORY_LISTS,
    ledger: CACHE_BUDGET,
    ttlFor: list => (list.length ? CACHE_TTL : CACHE_FAILURE_TTL)
});

function categoryStreamsCacheKey(cfg, action, categoryId) {
    return `${accountCacheKey(cfg)}\n${action}\n${categoryId}`;
}

function getCategoryStreams(cfg, action, categoryId) {
    return categoryStreamsCache.load(
        categoryStreamsCacheKey(cfg, action, categoryId),
        () => getStreams(cfg, action, { category_id: categoryId })
    );
}

function parseYear(s) {
    if (!s) return undefined;
    const m = String(s).match(/\d{4}/);
    return m ? parseInt(m[0]) : undefined;
}

// Whether a payload is worth *answering* with: a name or episodes. It must mirror
// the meta route's `hasContent` exactly, or the disagreement gets cached. What may
// be cached for the full TTL is the stricter hasSeriesEpisodes.
function isUsableSeriesInfo(info) {
    if (!info || typeof info !== 'object') return false;
    const hasName = info.info && typeof info.info === 'object' && info.info.name;
    return Boolean(hasName || hasSeriesEpisodes(info));
}

// Whether a payload may be cached for the full TTL: at least one non-empty season.
// get_series_info is flaky enough that an episodes-less answer is likelier a bad
// call, so one is still returned but kept only for SERIES_INFO_NEGATIVE_TTL.
function hasSeriesEpisodes(info) {
    if (!info || typeof info !== 'object') return false;
    const eps = info.episodes;
    if (!eps || typeof eps !== 'object') return false;
    return Object.values(eps).some(list => Array.isArray(list) && list.length > 0);
}

const SERIES_INFO_MAX_ATTEMPTS = 3;
const SERIES_INFO_BACKOFF_MS = 500;

// A series that never returns usable data costs 3 upstream calls plus backoff per
// request, so the failure is remembered briefly — longer than CACHE_FAILURE_TTL,
// far shorter than the positive TTL.
const SERIES_INFO_NEGATIVE_TTL = Math.max(1000, Number(process.env.SERIES_INFO_NEGATIVE_TTL_MS) || 5 * 60 * 1000);

const seriesInfoCache = registerSweepable(new BoundedMap({
    maxEntries: CACHE_MAX_SERIES_INFO,
    maxAgeMs: CACHE_TTL,
    ledger: CACHE_BUDGET
}));

function seriesInfoCacheKey(cfg, seriesId) {
    return `${accountCacheKey(cfg)}\n${seriesId}`;
}

// Entries carry their own ttl (as catCache's do) because a remembered failure
// must expire far sooner than a good payload.
function readSeriesInfoEntry(cfg, seriesId) {
    const entry = seriesInfoCache.get(seriesInfoCacheKey(cfg, seriesId));
    if (!entry) return null;
    const ttl = typeof entry.ttl === 'number' ? entry.ttl : CACHE_TTL;
    return entry.ts > Date.now() - ttl ? entry : null;
}

function getCachedSeriesInfo(cfg, seriesId) {
    const entry = readSeriesInfoEntry(cfg, seriesId);
    // Only a good payload is a "hit" here; negative entries are replayed by
    // fetchSeriesInfo, which knows how to reproduce the original outcome.
    return entry && !entry.negative ? entry.data : null;
}

function setCachedSeriesInfo(cfg, seriesId, data) {
    seriesInfoCache.set(seriesInfoCacheKey(cfg, seriesId), {
        data,
        ts: Date.now(),
        ttl: CACHE_TTL,
        bytes: estimateBytes(data)
    });
}

// Remembers *how* the series failed, so a cached failure reproduces exactly what
// an uncached one would have returned: an unusable-but-present payload is
// replayed, and a total failure re-throws.
function setNegativeSeriesInfo(cfg, seriesId, { data, error }) {
    seriesInfoCache.set(seriesInfoCacheKey(cfg, seriesId), {
        data,
        error,
        negative: true,
        ts: Date.now(),
        ttl: SERIES_INFO_NEGATIVE_TTL,
        bytes: estimateBytes(data)
    });
}

const seriesInfoSingleFlight = createSingleFlight();

// Opening a series fires meta and stream requests that both land here, and a
// miss costs up to 3 upstream attempts with backoff — worth deduplicating.
function getSeriesInfo(cfg, seriesId) {
    const hit = getCachedSeriesInfo(cfg, seriesId);
    if (hit) return Promise.resolve(hit);
    return seriesInfoSingleFlight(
        seriesInfoCacheKey(cfg, seriesId),
        () => fetchSeriesInfo(cfg, seriesId)
    );
}

async function fetchSeriesInfo(cfg, seriesId) {
    const cached = readSeriesInfoEntry(cfg, seriesId);
    if (cached) {
        if (!cached.negative) return cached.data;
        if (LOG_REQUESTS) console.log(`[getSeriesInfo] series ${seriesId} failed recently; skipping ${SERIES_INFO_MAX_ATTEMPTS} retries`);
        if (cached.data !== null) return cached.data;
        throw new Error(cached.error);
    }

    let lastInfo = null;
    let lastError = null;
    for (let attempt = 1; attempt <= SERIES_INFO_MAX_ATTEMPTS; attempt++) {
        try {
            const info = await xtremioGet(cfg, 'get_series_info', { series_id: seriesId }, { timeoutMs: 8000 });
            if (hasSeriesEpisodes(info)) {
                setCachedSeriesInfo(cfg, seriesId, info);
                return info;
            }
            lastInfo = info;
            const shape = isUsableSeriesInfo(info) ? 'a series with no episodes' : 'unusable data';
            console.warn(`[getSeriesInfo] attempt ${attempt}/${SERIES_INFO_MAX_ATTEMPTS} for series ${seriesId} returned ${shape}`);
        } catch (e) {
            lastError = e;
            console.warn(`[getSeriesInfo] attempt ${attempt}/${SERIES_INFO_MAX_ATTEMPTS} for series ${seriesId} failed: ${e.message}${causeSuffix(e)}`);
        }
        if (attempt < SERIES_INFO_MAX_ATTEMPTS) {
            await new Promise(r => setTimeout(r, SERIES_INFO_BACKOFF_MS * attempt));
        }
    }
    const failure = lastError || new Error(`get_series_info failed for series ${seriesId}`);

    setNegativeSeriesInfo(cfg, seriesId, {
        data: lastInfo,
        error: failure.message
    });

    if (lastInfo !== null) return lastInfo;
    throw failure;
}

// Movie details, needed by both the meta and stream routes. No retries or negative
// cache: get_vod_info is not flaky the way get_series_info is.
const vodInfoCache = createKeyedCache({ maxEntries: CACHE_MAX_VOD_INFO, ledger: CACHE_BUDGET });

function vodInfoCacheKey(cfg, vodId) {
    return `${accountCacheKey(cfg)}\n${vodId}`;
}

// A name or movie data, or the payload is not cached (a nonexistent id otherwise
// became a movie called "Unknown"). Some panels put the fields at the root.
function isUsableVodInfo(payload) {
    const isObject = v => Boolean(v) && typeof v === 'object' && !Array.isArray(v);
    if (!isObject(payload)) return false;
    const movie = isObject(payload.info) ? payload.info : payload;
    const named = Boolean(movie.name || movie.o_name);
    const data = payload.movie_data;
    const playable = isObject(data) && Boolean(data.stream_id || data.container_extension);
    return named || playable;
}

function getVodInfo(cfg, vodId) {
    return vodInfoCache.load(vodInfoCacheKey(cfg, vodId), async () => {
        const info = await xtremioGet(cfg, 'get_vod_info', { vod_id: vodId });
        // Thrown rather than returned because rejections are not cached, so a
        // movie the provider fills in later is picked up on the next request.
        if (!isUsableVodInfo(info)) throw new Error(`get_vod_info returned no usable data for movie ${vodId}`);
        return info;
    });
}

// This movie's item in the warm full list, or null. Never fetches: it is the
// fallback for when get_vod_info fails, and a cold list costs seconds. The item
// usually names the container, which is all the stream route needs (audit M2).
function warmVodItem(cfg, vodId) {
    const list = vodStreamsCache.get(cfg);
    return Array.isArray(list) ? findStreamById(list, vodId) : null;
}

module.exports = {
    catCache,
    getCategories,
    refreshCategories,
    liveStreamsCache,
    vodStreamsCache,
    seriesStreamsCache,
    streamIdIndexes,
    findStreamById,
    getAllVodStreams,
    getAllSeriesStreams,
    getAllLiveStreams,
    categoryStreamsCache,
    categoryStreamsCacheKey,
    getCategoryStreams,
    parseYear,
    isUsableSeriesInfo,
    hasSeriesEpisodes,
    SERIES_INFO_MAX_ATTEMPTS,
    SERIES_INFO_BACKOFF_MS,
    SERIES_INFO_NEGATIVE_TTL,
    seriesInfoCache,
    seriesInfoCacheKey,
    readSeriesInfoEntry,
    getCachedSeriesInfo,
    setCachedSeriesInfo,
    setNegativeSeriesInfo,
    getSeriesInfo,
    fetchSeriesInfo,
    vodInfoCache,
    vodInfoCacheKey,
    isUsableVodInfo,
    getVodInfo,
    warmVodItem
};
