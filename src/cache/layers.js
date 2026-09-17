// The cache layers built on BoundedMap: the TTLs, the shared byte budget, and the
// three cache-aside primitives.
//
// createKeyedCache is the plain one — cache-aside plus single-flight — and is what
// a new cache should use. createStreamListCache predates it and carries the extra
// behaviour the full lists need: a stale-on-failure fallback that survives an
// outage, and refresh-ahead so no request pays for a cold list. The bespoke form
// is kept because that behaviour is load-bearing, not because it is older.
//
// Every entry is charged to one CacheBudget, CACHE_BUDGET, because the per-cache
// bounds were set independently and together did not add up to any figure of
// memory. A new data cache must pass `ledger: CACHE_BUDGET` and weigh its entries,
// or it sits outside CACHE_MAX_MB.
const { BoundedMap, CacheBudget } = require('./bounded-map.js');
const { estimateBytes } = require('../upstream/read-capped.js');
const { normalizeUrl } = require('../helpers.js');

// Every map the periodic sweep should visit.
//
// This used to be a list written out by hand inside sweepCaches, naming all eight
// caches. Two things were wrong with that. A new cache that nobody added to it
// only reclaimed memory when something else was written to the same map, which is
// a leak that looks like nothing; and the sweep therefore had to be able to see
// every cache instance, which is one of the things that kept them all in the same
// file. Registering at the point of construction fixes both.
//
// registerSweepable returns what it was given so that it wraps the construction
// rather than following it — `const c = registerSweepable(new BoundedMap(…))`
// cannot be half-done the way a separate call can. createKeyedCache and
// createStreamListCache register themselves, so only a raw BoundedMap used as a
// live cache needs the wrapper. Deliberately not tied to `ledger`, which looks
// like the same set and is not: hlsOriginVetCache is swept but holds promises
// about hostnames rather than bytes, so it is charged to no budget.
const sweepables = new Set();

function registerSweepable(map) {
    sweepables.add(map);
    return map;
}

// Total entries reclaimed. Each map decides what "expired" means for its own
// entries — see BoundedMap.sweep, which reclaims on the longer of the map's
// maxAgeMs and the entry's own ttl.
function sweepRegistered(now = Date.now()) {
    let dropped = 0;
    for (const map of sweepables) dropped += map.sweep(now);
    return dropped;
}

// All in-memory caches share the same TTL.
const CACHE_TTL = 30 * 60 * 1000;

// A category fetch that partly or wholly failed must not be held for the full
// TTL: one transient upstream blip would otherwise leave the user with empty
// catalogs and an empty genre list for 30 minutes, with no way to force a
// refresh. Retry those soon instead.
const CACHE_FAILURE_TTL = 60 * 1000;

// How far through an entry's life a request starts refetching it behind the
// scenes instead of leaving the next request to pay for it. A cold full list is
// seconds of work inside a request — 4.8 s for movies and 2.6 s for series
// against a real account — and every account paid that once per TTL. A fifth of
// the TTL left to fetch in is ample for a list that takes seconds.
const CACHE_REFRESH_AHEAD = 0.8;

// Keys must include credentials so two users on the same Xtream host don't
// share cached catalogs/streams (different accounts can see different content).
// Keyed by the panel's origin, not the URL as typed: every upstream URL is built
// from an absolute path, so `http://PANEL.x:80/a?b` reaches the same account as
// `http://panel.x`, and keying on the spelling gave one account a fresh relay
// budget and a second copy of its lists per variant (audit M1). JSON rather than
// a separator, which a username or password could contain (audit L11).
function accountCacheKey(cfg) {
    let server = cfg.serverUrl;
    try {
        server = new URL(normalizeUrl(cfg.serverUrl)).origin;
    } catch {
        // Unparseable: no request can reach it either, so the raw string is as good a key.
    }
    return JSON.stringify([server, cfg.username, cfg.password]);
}


// Category lists are small (a few KB per account), so the bound here is about
// account count, not bytes.
const CACHE_MAX_ACCOUNTS = Math.max(1, Number(process.env.CACHE_MAX_ACCOUNTS) || 100);

// How many accounts' full stream lists to hold, per kind. Memory is bounded in
// bytes, so this only stops many tiny entries accumulating; a low count was a churn
// cliff (audit R3). A worker-thread parse was measured and is worse: structured
// clone deserializes on the main thread anyway.
const CACHE_MAX_STREAM_ACCOUNTS = Math.max(1, Number(process.env.CACHE_MAX_STREAM_ACCOUNTS) || 64);

// Stream list budget *per kind*, in estimated heap (see estimateBytes).
const CACHE_MAX_STREAM_BYTES = Math.max(1, Number(process.env.CACHE_MAX_STREAM_MB) || 64) * 1024 * 1024;

// One entry per series *per account* — the only dimension that grows without
// bound for a single user just browsing.
const CACHE_MAX_SERIES_INFO = Math.max(1, Number(process.env.CACHE_MAX_SERIES_INFO) || 500);

// Same dimension for movies. A vod_info payload is a single item's metadata —
// kilobytes, not megabytes — so this bound is about entry count, not size.
const CACHE_MAX_VOD_INFO = Math.max(1, Number(process.env.CACHE_MAX_VOD_INFO) || 500);

// Per-category stream lists: one entry per category per account.
const CACHE_MAX_CATEGORY_LISTS = Math.max(1, Number(process.env.CACHE_MAX_CATEGORY_LISTS) || 100);

// The shared ceiling across every data cache; see CacheBudget. 256 MB is three
// 64 MB stream budgets plus room for the small caches.
const CACHE_MAX_BYTES = Math.max(1, Number(process.env.CACHE_MAX_MB) || 256) * 1024 * 1024;
const CACHE_BUDGET = new CacheBudget(CACHE_MAX_BYTES);

// getCategories intentionally serves expired categories when a refresh fails
// (stale beats empty — see CACHE_FAILURE_TTL), so age-sweeping catCache on the
// normal TTL would destroy that fallback. This hard age only reclaims accounts
// that have genuinely stopped being used.
const CACHE_STALE_MAX_AGE_MS = 24 * 60 * 60 * 1000;


// Deduplicates concurrent misses for the same key. Stremio opens many catalog
// requests in parallel on install, and without this each one fires its own
// multi-megabyte upstream fetch for a list the others are already loading.
function createSingleFlight() {
    const pending = new Map();
    return function singleFlight(key, fn) {
        const existing = pending.get(key);
        if (existing) return existing;
        // Errors are not cached: the entry is dropped either way, so the next
        // caller retries rather than inheriting a stale rejection.
        const promise = Promise.resolve().then(fn).finally(() => pending.delete(key));
        pending.set(key, promise);
        return promise;
    };
}

// Stream list caches - populated on first fetch, reused for catalogs, search and meta
function createStreamListCache() {
    // Swept on the normal TTL, not on CACHE_STALE_MAX_AGE_MS like catCache:
    // these are by far the largest entries, so reclaiming an abandoned one
    // matters most. The one entry that must outlive that is the stale copy an
    // outage is being served from, and it says so itself by carrying a longer
    // ttl, which sweep() honours (audit L3).
    const map = registerSweepable(new BoundedMap({
        maxEntries: CACHE_MAX_STREAM_ACCOUNTS,
        maxAgeMs: CACHE_TTL,
        maxBytes: CACHE_MAX_STREAM_BYTES,
        ledger: CACHE_BUDGET,
        // Evicting an unexpired list means the bounds are too tight for the load;
        // the advice names the bound that did it.
        onEvict(key, entry, reason) {
            // Against the entry's own ttl, so evicting the stale copy an outage
            // is being served from still reports — that is when the bounds bite
            // hardest and when losing the list hurts most.
            const inUseFor = Math.max(CACHE_TTL, entry?.ttl || 0);
            if (entry && entry.ts > Date.now() - inUseFor) {
                const knob = reason === 'global budget'
                    ? 'CACHE_MAX_MB'
                    : 'CACHE_MAX_STREAM_ACCOUNTS or CACHE_MAX_STREAM_MB';
                console.warn(
                    `[cache] evicted a live stream list on ${reason} ` +
                    `(${Math.round((entry.bytes || 0) / 1024 / 1024)} MB); ` +
                    `raise ${knob} if this repeats`
                );
            }
        }
    }));
    const singleFlight = createSingleFlight();
    // Background refreshes in flight, keyed like the cache itself. Its own map
    // rather than the single-flight above: that one is also what a cold miss joins,
    // and a miss must keep its stale-on-failure fallback, which it would lose by
    // inheriting a refresh's rejection. The two can therefore both be in flight for
    // one account — only in the window where a refresh outlives the fifth of the
    // TTL it was given, and only ever two calls, never more.
    const refreshing = new Map();

    // Whether a warm entry is old enough to be worth refreshing behind the request
    // that found it. Only a full-strength entry qualifies: a shorter ttl marks
    // either an empty list or the stale copy an outage is being served from (audit
    // L3), and refreshing those would mean fetching on nearly every request rather
    // than once per TTL. The cooldown bounds it the other way — one attempt per
    // CACHE_FAILURE_TTL whatever the outcome, so a panel that has started failing
    // is not asked again by every request that arrives.
    const shouldRefreshAhead = (entry, now) => Boolean(entry)
        && entry.ttl === CACHE_TTL
        && !(entry.refreshedAt && now - entry.refreshedAt < CACHE_FAILURE_TTL)
        && now - entry.ts >= CACHE_TTL * CACHE_REFRESH_AHEAD;

    return {
        map,
        refreshing,
        get(cfg) {
            const cached = map.get(accountCacheKey(cfg));
            // Per-entry ttl: a stale entry being served through an outage carries
            // a short one, so it is retried in a minute rather than in half an hour.
            if (cached && cached.ts > Date.now() - (cached.ttl || CACHE_TTL)) return cached.data;
            return null;
        },
        set(cfg, items) {
            // An empty list is also something real providers return transiently, so
            // it is held for CACHE_FAILURE_TTL rather than the full TTL.
            map.set(accountCacheKey(cfg), {
                data: items,
                ts: Date.now(),
                ttl: items.length ? CACHE_TTL : CACHE_FAILURE_TTL,
                bytes: estimateBytes(items)
            });
        },
        // Refetches an entry that is still warm but far enough through its life that
        // the next request would have paid for it — measured at 4.8 s for a movie
        // list and 2.6 s for a series list, once per TTL per account, inside the
        // request that happened to arrive first (audit Perf). Nothing awaits this,
        // so it can only ever make a later request faster; a failure is swallowed
        // and leaves the warm entry exactly as it was, to be retried inline once it
        // really does expire. Triggered by a request and never by a timer, so a list
        // nobody is asking for is never refreshed and simply ages out.
        refreshAhead(cfg, fetcher, now = Date.now()) {
            const key = accountCacheKey(cfg);
            const entry = map.peek(key);
            if (!shouldRefreshAhead(entry, now)) return null;
            const existing = refreshing.get(key);
            if (existing) return existing;

            entry.refreshedAt = now;
            const promise = Promise.resolve()
                .then(fetcher)
                .then((items) => { this.set(cfg, items); return items; })
                .catch((e) => {
                    // Never rethrown: no caller is waiting, and an unhandled
                    // rejection exits the process.
                    console.warn(
                        `[cache] background refresh failed (${e.message}); ` +
                        'the warm list stands until it expires'
                    );
                    return null;
                })
                .finally(() => { if (refreshing.get(key) === promise) refreshing.delete(key); });
            refreshing.set(key, promise);
            return promise;
        },
        // Cache-aside read: serves a warm entry, otherwise runs `fetcher` once
        // no matter how many callers arrive while it is in flight.
        load(cfg, fetcher) {
            const cached = this.get(cfg);
            if (cached) {
                this.refreshAhead(cfg, fetcher);
                return Promise.resolve(cached);
            }
            const key = accountCacheKey(cfg);
            return singleFlight(key, async () => {
                // Re-check: a concurrent flight may have populated it already.
                const warm = this.get(cfg);
                if (warm) return warm;
                try {
                    const items = await fetcher();
                    this.set(cfg, items);
                    return items;
                } catch (e) {
                    // A stale list beats an empty shelf, for as long as the copy is
                    // worth serving. `ts` is never re-stamped, so it keeps saying how
                    // old the data really is; only the ttl moves, and only far enough
                    // to schedule the next retry. Past CACHE_STALE_MAX_AGE_MS — the
                    // same window catCache gives its own stale fallback — the copy is
                    // abandoned and the failure is answered as one, so a provider that
                    // is gone for good does not leave a day-old lineup on the shelf.
                    const stale = map.get(key);
                    if (!stale || !Array.isArray(stale.data) || !stale.data.length) throw e;
                    const age = Date.now() - stale.ts;
                    if (age >= CACHE_STALE_MAX_AGE_MS) throw e;
                    stale.ttl = Math.min(age + CACHE_FAILURE_TTL, CACHE_STALE_MAX_AGE_MS);
                    console.warn(
                        `[cache] upstream list failed (${e.message}); serving ${stale.data.length} ` +
                        `stale items, retrying in ${CACHE_FAILURE_TTL / 1000}s`
                    );
                    return stale.data;
                }
            });
        }
    };
}

// Cache-aside read with single-flight over a BoundedMap of `{ data, ts }` — the
// plain case; the older caches keep bespoke forms for their extra behaviour.
// `ttlFor(data)` shortens one entry's lifetime, capped at `ttl`. `ledger` weighs
// each entry and charges it to that CacheBudget.
function createKeyedCache({ maxEntries, ttl = CACHE_TTL, ttlFor = null, ledger = null }) {
    const map = registerSweepable(new BoundedMap({ maxEntries, maxAgeMs: ttl, ledger }));
    const singleFlight = createSingleFlight();
    // Returns the entry, not the value: a legitimately null payload must still
    // read as a hit rather than sending every caller back upstream.
    const liveEntry = (key) => {
        const entry = map.get(key);
        return entry && entry.ts > Date.now() - (entry.ttl ?? ttl) ? entry : null;
    };
    return {
        map,
        get(key) {
            const entry = liveEntry(key);
            return entry ? entry.data : null;
        },
        load(key, fetcher) {
            const hit = liveEntry(key);
            if (hit) return Promise.resolve(hit.data);
            return singleFlight(key, async () => {
                // Re-check: a concurrent flight may have populated it already.
                const warm = liveEntry(key);
                if (warm) return warm.data;
                const data = await fetcher();
                map.set(key, {
                    data,
                    ts: Date.now(),
                    ttl: ttlFor ? Math.min(ttl, ttlFor(data)) : ttl,
                    ...(ledger ? { bytes: estimateBytes(data) } : {})
                });
                return data;
            });
        }
    };
}

module.exports = {
    CACHE_TTL,
    CACHE_FAILURE_TTL,
    CACHE_REFRESH_AHEAD,
    CACHE_MAX_ACCOUNTS,
    CACHE_MAX_STREAM_ACCOUNTS,
    CACHE_MAX_STREAM_BYTES,
    CACHE_MAX_SERIES_INFO,
    CACHE_MAX_VOD_INFO,
    CACHE_MAX_CATEGORY_LISTS,
    CACHE_MAX_BYTES,
    CACHE_BUDGET,
    CACHE_STALE_MAX_AGE_MS,
    accountCacheKey,
    registerSweepable,
    sweepRegistered,
    createSingleFlight,
    createStreamListCache,
    createKeyedCache
};
