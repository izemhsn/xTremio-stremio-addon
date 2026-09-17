// One call to an Xtream panel.
//
// Everything above this — the caches, the catalog, the routes — goes through
// xtremioGet, and it is the only place that knows what a panel call costs: three
// deadlines that bound three different failures, a byte and shape cap on the body,
// and the SSRF guard on the URL.
//
// LOG_REQUESTS is read here rather than passed in because it is a logging switch,
// not behaviour, and threading it through every caller would be the more confusing
// of the two.
const { buildXtremioApiUrl } = require('../helpers.js');
const { safeFetch } = require('../net/safe-fetch.js');
const { readJsonCapped, MAX_UPSTREAM_BYTES } = require('../upstream/read-capped.js');
const { CACHE_FAILURE_TTL } = require('../cache/layers.js');

const LOG_REQUESTS = process.env.LOG_REQUESTS === 'true';


// Three deadlines for one upstream call (audit R5): headers, an idle deadline every
// chunk resets so a slow but moving download completes, and an overall one so a
// trickle cannot hold the request open indefinitely.
const UPSTREAM_HEADER_TIMEOUT_MS = Math.max(100, Number(process.env.UPSTREAM_HEADER_TIMEOUT_MS) || 15000);
const UPSTREAM_IDLE_TIMEOUT_MS = Math.max(100, Number(process.env.UPSTREAM_IDLE_TIMEOUT_MS) || 15000);
const UPSTREAM_BODY_TIMEOUT_MS = Math.max(100, Number(process.env.UPSTREAM_BODY_TIMEOUT_MS) || 5 * 60 * 1000);

async function xtremioGet(cfg, action, params = {}, { timeoutMs = UPSTREAM_HEADER_TIMEOUT_MS } = {}) {
    const url = buildXtremioApiUrl(cfg, action, params);
    const controller = new AbortController();
    let expired = null;
    const expire = (waitingFor, ms) => setTimeout(() => {
        expired = { waitingFor, ms };
        controller.abort();
    }, ms);
    let phaseTimer = expire('headers', timeoutMs);
    const overallTimer = expire('the whole response', UPSTREAM_BODY_TIMEOUT_MS);
    try {
        const res = await safeFetch(url, { signal: controller.signal });
        clearTimeout(phaseTimer);
        if (!res.ok) throw new Error(`xtremio ${action} failed: HTTP ${res.status}`);
        const resetIdle = () => {
            clearTimeout(phaseTimer);
            phaseTimer = expire('the next chunk', UPSTREAM_IDLE_TIMEOUT_MS);
        };
        resetIdle();
        const data = await readJsonCapped(res, `xtremio ${action}`, MAX_UPSTREAM_BYTES, { onChunk: resetIdle });

        if (LOG_REQUESTS) console.log(`[xtremioGet] ${action} (${Array.isArray(data) ? data.length : '?'} items)`);

        return data;
    } catch (e) {
        // Name the deadline that fired: "aborted" alone does not tell a stalled panel
        // from a slow one, and the fix for each is a different setting.
        if (expired) {
            throw new Error(`xtremio ${action} timed out waiting for ${expired.waitingFor} after ${expired.ms} ms`, { cause: e });
        }
        throw e;
    } finally {
        clearTimeout(phaseTimer);
        clearTimeout(overallTimer);
    }
}

// A payload that is not an array is a provider failure, not an empty catalog.
// Throwing keeps it out of the cache, since rejections are not cached.
async function getStreams(cfg, action, params = {}) {
    const data = await xtremioGet(cfg, action, params);
    if (!Array.isArray(data)) {
        throw new Error(`${action} returned ${data === null ? 'null' : typeof data}, not a list`);
    }
    // Without this the symptom is a search that finds nothing and no trace of why.
    if (!data.length && params.category_id === undefined) {
        console.warn(
            `[getStreams] ${action} returned an empty list; retrying in ${CACHE_FAILURE_TTL / 1000}s. ` +
            'Genre shelves use per-category fetches meanwhile, but search has nothing to search.'
        );
    }
    return data;
}

module.exports = {
    UPSTREAM_HEADER_TIMEOUT_MS,
    UPSTREAM_IDLE_TIMEOUT_MS,
    UPSTREAM_BODY_TIMEOUT_MS,
    LOG_REQUESTS,
    xtremioGet,
    getStreams
};
