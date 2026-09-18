const express = require('express');
const crypto = require('crypto');
// Event-loop delay for /health. Native, and its timer does not hold the process
// open, so it does not interfere with a graceful shutdown.
const { monitorEventLoopDelay } = require('node:perf_hooks');

// The address tables the SSRF guard refuses. Pure, and the one part of the guard
// with a test file of its own, so it is the first thing to leave index.js.
const { isPrivateIp } = require('./src/net/private-ip.js');

// Entry-count and byte bounds, and the one LRU order they all share.
const { BoundedMap, CacheBudget } = require('./src/cache/bounded-map.js');

// Which panels this instance will serve, and how a host is named.
const {
    hostnameOf,
    parseHostList,
    panelHostAllowed,
    ALLOWED_PANEL_HOSTS
} = require('./src/panel-allowlist.js');

// The install-token crypto and the CONFIG_SECRET policy. Required here, near the
// top, because its keys are derived from the environment at load time.
const {
    CONFIG_TOKEN_VERSION,
    CONFIG_SECRET,
    CONFIG_SECRET_MIN_BYTES,
    IS_PRODUCTION,
    SCRYPT_PARAMS,
    deriveConfigKey,
    deriveConfigKeys,
    UNDECODABLE_REPORT_INTERVAL_MS,
    undecodableTokens,
    noteUndecodableToken,
    configSecretProblems,
    enforceConfigSecretPolicy,
    validateConfig,
    signTokenBody,
    encodeConfig,
    sealConfig,
    decodeConfig
} = require('./src/config-token.js');

// Signing, encrypting and rewriting playlists. No DNS and no Express: the mapper
// that vets a target before signing is built here and passed in.
const {
    HLS_SIGNATURE_TTL_MS,
    MAX_PLAYLIST_BYTES,
    signHlsTarget,
    encodeHlsTarget,
    decodeHlsTarget,
    looksLikePlaylist,
    hlsTargetExt,
    rewriteHlsPlaylist
} = require('./src/hls/playlist.js');

// HTML escaping, and the /configure page that depends on it.
const { escapeHtml } = require('./src/html.js');
const { renderConfigPage } = require('./src/pages/configure.js');
const { renderLandingPage } = require('./src/pages/landing.js');

// Pure value helpers — URL and id shapes, and the coercions that make a
// provider's untyped JSON safe to render.
const {
    causeSuffix,
    asString,
    normalizeUrl,
    buildUrl,
    buildXtremioApiUrl,
    isNumericId,
    getPrefixedNumericId,
    parseEpisodeId,
    typeMatchesId,
    statedContainerExt,
    normalizeContainerExt,
    isNotWebReady,
    toIsoDate,
    titleOf,
    ratingOf,
    splitList,
    youtubeTrailers,
    pickBackdrop
} = require('./src/helpers.js');

// The SSRF guard and the DNS pin that makes it binding. Every outbound request
// for a user-supplied URL goes through safeFetch; never call bare fetch.
const {
    DNS_TIMEOUT_MS,
    DNS_PIN_TTL_MS,
    DNS_SERVERS,
    parseDnsServers,
    makeDnsResolver,
    dnsFallback,
    dnsPins,
    resolveHostAddresses,
    pinResolvedAddresses,
    pinnedLookup,
    PINNED_DISPATCHER,
    warnOnUndiciMismatch,
    assertSafeOutboundUrl,
    discardBody,
    safeFetch
} = require('./src/net/safe-fetch.js');

// Reading an upstream body under a byte cap and a parsed-shape cap, and the
// weighing the caches charge against CACHE_MAX_MB.
const {
    MAX_UPSTREAM_BYTES,
    MAX_PARSED_TO_BODY_RATIO,
    readJsonCapped,
    estimateBytes,
    weighJson
} = require('./src/upstream/read-capped.js');

// The cache TTLs, the shared byte budget, and the cache-aside primitives. The
// cache instances themselves stay below, beside the upstream calls they front.
const {
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
    sweepCaches,
    startCacheSweeper,
    createSingleFlight,
    createKeyedCache
} = require('./src/cache/layers.js');

// Reading a catalog request's `extra` segment, and the cache hints on the answer.
const {
    parseExtra,
    rawExtraSegment,
    PAGE_SIZE,
    withCacheHints
} = require('./src/routes/extras.js');

// Ordering, filtering and paginating a shelf, and the identity-keyed memo that
// keeps a list from being re-sorted per page. CATALOG_KINDS stays below, with the
// loaders and list caches it names.
const {
    sortedCatalogViews,
    parseCatalogId,
    FEATURED_PERIOD_MS,
    featuredEpoch,
    catalogComparator,
    filterByName,
    toCatalogMetas,
    catalogViewKey,
    cachedCatalogSelection,
    rememberCatalogSelection,
    sortedCatalogItems
} = require('./src/catalog/shelf.js');

// One call to an Xtream panel: the three upstream deadlines, the body caps and
// the SSRF guard, in one place.
const {
    UPSTREAM_HEADER_TIMEOUT_MS,
    UPSTREAM_IDLE_TIMEOUT_MS,
    UPSTREAM_BODY_TIMEOUT_MS,
    LOG_REQUESTS,
    xtremioGet
} = require('./src/xtream/client.js');

// What this addon reads from a panel, and the caches in front of it. The cache
// instances live with the calls they front, not with the primitives.
const {
    catCache,
    getCategories,
    liveStreamsCache,
    vodStreamsCache,
    seriesStreamsCache,
    findStreamById,
    getAllVodStreams,
    getAllSeriesStreams,
    getAllLiveStreams,
    categoryStreamsCache,
    getCategoryStreams,
    parseYear,
    isUsableSeriesInfo,
    SERIES_INFO_MAX_ATTEMPTS,
    SERIES_INFO_NEGATIVE_TTL,
    seriesInfoCache,
    readSeriesInfoEntry,
    getCachedSeriesInfo,
    setCachedSeriesInfo,
    setNegativeSeriesInfo,
    getSeriesInfo,
    fetchSeriesInfo,
    vodInfoCache,
    isUsableVodInfo,
    getVodInfo,
    warmVodItem
} = require('./src/xtream/data.js');

// The three catalog kinds and how a genre resolves to items. The table names the
// loaders and the list caches, so it sits between the catalog and the panel.
const {
    CATALOG_KINDS,
    catalogTypesFor,
    DEGRADED_CATALOG_LOG_INTERVAL_MS,
    degradedCatalogLogged,
    noteDegradedCatalog,
    selectCatalogSource
} = require('./src/catalog/kinds.js');

// The manifest Stremio installs against, built per account from its categories.
const { getManifest } = require('./src/manifest.js');

// Who a request is from and what URL this server is reachable at — both read
// through TRUST_PROXY, because both come from headers a client can set.
const {
    PORT,
    HOST,
    PUBLIC_URL,
    SAFE_HOST,
    TRUST_PROXY_HOPS,
    forwardedValue,
    getBaseUrl,
    clientKey,
    addressBucket
} = require('./src/routes/request.js');

// Relaying provider bytes to the player: the shared relay, the HLS target mapper,
// and the three concurrency caps. Both proxy routes go through it.
const {
    PROXY_HEADER_TIMEOUT_MS,
    PLAYLIST_BODY_TIMEOUT_MS,
    MAX_PLAYLIST_ORIGINS,
    PLAYLIST_REWRITE_TIMEOUT_MS,
    HLS_ORIGIN_VET_TTL_MS,
    hlsOriginVetCache,
    hlsPrefixVerdict,
    sniffPlaylistStart,
    setRelayHeaders,
    normalizeAcceptRanges,
    relayUpstream,
    panelOrigin,
    hlsTargetOrigins,
    makeHlsProxyMapper,
    HLS_TARGET_ALLOWED_HOSTS,
    PROXY_MAX_CONCURRENT_PER_TOKEN,
    PROXY_MAX_CONCURRENT_PER_CLIENT,
    PROXY_MAX_CONCURRENT_TOTAL,
    proxyInFlight,
    proxyInFlightByClient,
    proxyRelays,
    acquireProxySlot,
    rejectOverCap
} = require('./src/proxy/relay.js');

// Whether a panel exists and the credentials work there, and what to tell the
// user when the connection was downgraded on the way.
const {
    CONFIGURE_TIMEOUT_MS,
    CONFIGURE_PROBE_TIMEOUT_MS,
    schemeOf,
    describeDowngrade,
    serverInfoOrigin,
    validateXtremioCredentials
} = require('./src/configure/validate.js');

// Starting and stopping cleanly: the ordered socket timeouts, the drain flag
// /health reports, and the shutdown handler.
const {
    SHUTDOWN_TIMEOUT_MS,
    KEEPALIVE_TIMEOUT_MS,
    HEADERS_TIMEOUT_MS,
    REQUEST_TIMEOUT_MS,
    isShuttingDown,
    setShuttingDown,
    applyServerTimeouts,
    createShutdownHandler
} = require('./src/lifecycle.js');

const app = express();
// Free stack fingerprinting for anyone who can reach the port.
app.disable('x-powered-by');
// Mounted on POST /configure alone rather than app-wide: it is the only route
// that reads a form, and as a global middleware a POST to any other path — a
// catalog URL, say — had up to 100 KB of body parsed before the 404 that was
// always coming. The only form is three flat string fields, so extended parsing
// (qs) is off: it would build nested objects and arrays that asString then has to
// defend against.
const parseConfigureForm = express.urlencoded({ extended: false, limit: '8kb' });

// The Stremio addon protocol is called cross-origin by web.stremio.com, so its
// JSON resources genuinely need a wildcard. Nothing else here does: /configure
// handles plaintext credentials, and the landing page and health probe are read
// by people and orchestrators, not by scripts on other origins.
const CORS_PATH = /^\/(?:[^/]+\/)?(?:manifest\.json|catalog\/|meta\/|stream\/)/;

// The byte proxy is deliberately excluded. CORS is not what stops someone
// spending your bandwidth — a plain <video src> or a server-side fetch needs no
// CORS at all, so the token is the only real gate. Set PROXY_CORS=true if a
// player turns out to need it (an MSE-based one, or a crossorigin video element).
const PROXY_CORS = process.env.PROXY_CORS === 'true';
const PROXY_PATH = /^\/[^/]+\/proxy\//;

function corsApplies(path) {
    if (PROXY_PATH.test(path)) return PROXY_CORS;
    return CORS_PATH.test(path);
}

app.use((req, res, next) => {
    if (!corsApplies(req.path)) return next();
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});


// The other half of that policy, for the other thing a deployment can get wrong
// silently. SAFE_HOST below only checks the *shape* of the host an install link
// is built from, so with PUBLIC_URL unset any hostname an attacker controls and
// points at this instance mints install links carrying that hostname — and
// whoever controls it can repoint its DNS later and collect the config tokens
// users installed (audit L7). Warned rather than refused: a single-host
// deployment behind a proxy that sets Host correctly is legitimate, but in
// production it should be a deliberate choice rather than the default.
function warnOnUnpinnedBaseUrl({ publicUrl = PUBLIC_URL, production = IS_PRODUCTION, log = console } = {}) {
    if (publicUrl || !production) return false;
    log.warn(
        '[security] PUBLIC_URL is not set, so install links are built from the request Host. ' +
        'A hostname an attacker controls, pointed at this instance, mints install URLs carrying ' +
        'that hostname, and repointing its DNS later collects the config tokens users installed. ' +
        "Set PUBLIC_URL to this addon's own public address."
    );
    return true;
}


app.get('/manifest.json', async (req, res) => {
    res.json(await getManifest(null));
});

app.get('/:config/manifest.json', async (req, res) => {
    const cfg = decodeConfig(req.params.config);
    res.json(await getManifest(cfg));
});

// The configure page echoes a submitted password and embeds the install token, so
// it is kept out of caches and Referer headers, and cannot be framed (it is a
// clickjacking target). The CSP is a backstop behind escapeHtml: nothing external
// loads, scripts run only under a per-response nonce (so no inline on* handlers),
// and style-src keeps 'unsafe-inline' for the style="…" attributes. Returns the
// nonce, which the caller must pass to renderConfigPage.
function setPrivateHeaders(res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');

    const nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader('Content-Security-Policy', [
        "default-src 'none'",
        `script-src 'nonce-${nonce}'`,
        "style-src 'unsafe-inline'",
        // form-action does not fall back to default-src, so the page's own POST
        // has to be allowed explicitly or the form silently stops submitting.
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'"
    ].join('; '));
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return nonce;
}

// POST /configure makes an outbound request to a host the caller chooses, with
// credentials the caller chooses, before any authentication. Unmetered, that
// makes the instance a port scanner and a credential-stuffing relay running on
// this server's IP. A handful of attempts per minute is far more than a human
// configuring an addon needs.
const CONFIGURE_RATE_LIMIT = Math.max(1, Number(process.env.CONFIGURE_RATE_LIMIT) || 10);
const CONFIGURE_RATE_WINDOW_MS = Math.max(1000, Number(process.env.CONFIGURE_RATE_WINDOW_MS) || 60 * 1000);
// Bounded; once full, the oldest bucket makes room rather than letting new clients
// through untracked.
const CONFIGURE_RATE_MAX_CLIENTS = 10000;
const configureAttempts = new Map();


// Fixed window: on the first hit of a window the count resets. Sweeping expired
// entries on each call keeps the map proportional to *active* clients. A bucket is
// only ever inserted at the start of its window, and the window is fixed, so
// insertion order is expiry order and the sweep stops at the first live bucket;
// one that expired out of order is replaced when its client next arrives.
function rateLimitConfigure(req) {
    const now = Date.now();
    for (const [key, entry] of configureAttempts) {
        if (entry.resetAt > now) break;
        configureAttempts.delete(key);
    }

    const key = clientKey(req);
    let entry = configureAttempts.get(key);
    if (entry && entry.resetAt <= now) {
        configureAttempts.delete(key);
        entry = undefined;
    }
    if (!entry) {
        while (configureAttempts.size >= CONFIGURE_RATE_MAX_CLIENTS) {
            configureAttempts.delete(configureAttempts.keys().next().value);
        }
        configureAttempts.set(key, { count: 1, resetAt: now + CONFIGURE_RATE_WINDOW_MS });
        return { allowed: true, retryAfter: 0 };
    }

    entry.count += 1;
    if (entry.count > CONFIGURE_RATE_LIMIT) {
        return { allowed: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    return { allowed: true, retryAfter: 0 };
}

// Prefill comes from an encrypted `config` token only, and never includes the
// password: the token is the install URL Stremio syncs, and decrypting its password
// into the page would hand whoever holds that URL a working provider credential.
function sendConfigurePage(req, res, token) {
    const nonce = setPrivateHeaders(res);
    const existing = decodeConfig(token) || {};
    res.send(renderConfigPage({
        serverUrl: existing.serverUrl || '',
        username: existing.username || '',
        baseUrl: getBaseUrl(req),
        nonce
    }));
}

app.get('/configure', (req, res) => sendConfigurePage(req, res, req.query.config));

// Stremio's Configure button on an installed addon swaps manifest.json for
// `configure` in the transport URL, so it lands here and not on /configure. An
// undecodable token renders the empty form, as the bare route does. The form
// names /configure as its action because a bare POST from this path would go to
// /<token>/configure, which has no handler.
app.get('/:config/configure', (req, res) => sendConfigurePage(req, res, req.params.config));

app.post('/configure', parseConfigureForm, async (req, res) => {
    const nonce = setPrivateHeaders(res);
    // req.body may be undefined, and its fields are not guaranteed to be strings.
    const body = req.body || {};
    const rawServerUrl = asString(body.serverUrl).trim().replace(/\/+$/, '');
    const username = asString(body.username);
    const password = asString(body.password);
    const render = (status, serverUrl = rawServerUrl) => res.send(renderConfigPage({
        serverUrl,
        username,
        password,
        status,
        baseUrl: getBaseUrl(req),
        nonce
    }));
    const fail = (error) => render({ valid: false, error });

    const limit = rateLimitConfigure(req);
    if (!limit.allowed) {
        res.status(429);
        res.setHeader('Retry-After', String(limit.retryAfter));
        return fail(`Too many attempts. Try again in ${limit.retryAfter} second${limit.retryAfter === 1 ? '' : 's'}.`);
    }

    // Normally prevented by `required`, but a direct POST still gets told which
    // field is missing.
    const missing = [
        !rawServerUrl && 'server URL',
        !username && 'username',
        !password && 'password'
    ].filter(Boolean);
    if (missing.length) {
        const named = missing.length === 1
            ? missing[0]
            : `${missing.slice(0, -1).join(', ')} and ${missing[missing.length - 1]}`;
        return fail(`Please enter your ${named}.`);
    }

    // Before any request is made to the host: the credential check is itself an
    // outbound fetch to a URL the caller chose. The reply does not list the hosts
    // that are allowed — whether to publish that is the operator's decision.
    if (!panelHostAllowed(rawServerUrl)) {
        console.warn(
            `[configure] refused ${JSON.stringify(hostnameOf(rawServerUrl) || rawServerUrl.slice(0, 100))}: ` +
            'not in ALLOWED_PANEL_HOSTS'
        );
        return fail('This instance only accepts accounts from specific providers, and that server is not one of them.');
    }

    try {
        const validation = await validateXtremioCredentials(rawServerUrl, username, password);
        render(validation, validation.valid
            ? (validation.resolvedUrl || normalizeUrl(rawServerUrl))
            : rawServerUrl);
    } catch (e) {
        // validateXtremioCredentials is meant to answer, not throw — every
        // provider and network failure is already a { valid: false } result. So
        // anything arriving here is a bug in this server, and it used to be
        // swallowed: a malformed server URL threw while the catch inside was
        // logging, and the operator saw nothing at all (audit F2).
        logRouteError('configure', e);
        fail('Something went wrong. Please try again.');
    }
});

// Route failures are answered quietly, so the log is where a bug has to look
// different from a provider outage (audit R6): a programming error keeps its stack,
// provider and network failures stay one line.

function isProgrammingError(e) {
    if (e instanceof ReferenceError || e instanceof RangeError) return true;
    // fetch reports a network failure as TypeError('fetch failed') with a cause.
    return e instanceof TypeError && !e.cause && e.message !== 'fetch failed';
}

function logRouteError(route, e) {
    if (isProgrammingError(e)) console.error(`[${route}] unexpected error: ${e.stack}`);
    else console.error(`[${route}] Error:`, e?.message);
}

app.get(['/:config/catalog/:type/:id.json', '/:config/catalog/:type/:id/:extra.json'], async (req, res) => {
    // Degraded answers are the default, in this route and in meta and stream:
    // every early return is an empty answer produced by a failure, and a client
    // applying heuristic caching to one would pin a transient fault.
    // withCacheHints overwrites this on the paths that succeeded.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ metas: [] });

    const { id, type } = req.params;

    // Through catalogTypesFor, not a copy of it, so the tested check is the one
    // that runs.
    const types = catalogTypesFor(id);
    if (!types) return res.json({ metas: [] });
    if (!types.includes(type)) {
        // Quoted, here and in meta and stream: both values come straight from the
        // path, and a %0A in :type let a caller write its own log line (audit L1).
        // JSON.stringify escapes the newline and makes the boundaries visible.
        console.warn(`[catalog] type/id mismatch: type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);
        return res.json({ metas: [] });
    }

    const route = parseCatalogId(id);
    const kind = CATALOG_KINDS[route.kind];

    try {
        const extra = parseExtra(rawExtraSegment(req));
        const skip = Math.max(0, parseInt(extra.skip) || 0);
        // One clock for the whole request: the selection memo and the sorted view
        // are both scoped to the featured period, and reading it twice could fall
        // either side of a period boundary.
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

        // Search sorts too (as `new`), so pages stay stable across refetches. The
        // sort runs before the search filter: for a total order the two commute,
        // and this way the memoised view does not depend on the search term. The
        // filter stops once it has this page's worth of matches.
        const items = filterByName(
            sortedCatalogItems(kind, route, selected, now),
            extra.search,
            skip + PAGE_SIZE
        );

        const metas = toCatalogMetas(items.slice(skip, skip + PAGE_SIZE), kind);
        // An empty page stays no-store: empty lists are often transient.
        if (!metas.length) return res.json({ metas });
        return res.json({ metas, ...withCacheHints(res, 300, 600) });
    } catch (e) {
        logRouteError('catalog', e);
        res.json({ metas: [] });
    }
});

app.get('/:config/meta/:type/:id.json', async (req, res) => {
    // Degraded answers are the default; see the catalog route.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ meta: null });
    const { id, type } = req.params;
    if (LOG_REQUESTS) console.log(`[meta] type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);

    if (!typeMatchesId(type, id)) {
        console.warn(`[meta] type/id mismatch: type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);
        return res.status(404).json({ meta: null });
    }

    try {
        if (id.startsWith('xtremio_live_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_live_');
            if (!streamId) return res.status(400).json({ meta: null });
            const s = findStreamById(await getAllLiveStreams(cfg), streamId);

            if (!s) return res.json({ meta: null });
            const meta = {
                id: `xtremio_live_${s.stream_id}`,
                type: 'Live TV',
                name: titleOf(s.name) || undefined,
                poster: s.stream_icon || undefined,
                posterShape: 'square',
                genres: s.category_name ? [s.category_name] : [],
                description: titleOf(s.name) || undefined
            };
            return res.json({ meta, ...withCacheHints(res, 300) });
        }

        if (id.startsWith('xtremio_movie_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_movie_');
            if (!streamId) return res.status(400).json({ meta: null });
            let info;
            try {
                info = await getVodInfo(cfg, streamId);
            } catch (e) {
                // A movie the catalog lists is still worth a page when its details
                // fail: name and poster from the list, served no-store so the full
                // meta replaces it once get_vod_info answers (audit M2).
                const item = isProgrammingError(e) ? null : warmVodItem(cfg, streamId);
                if (!item) throw e;
                console.warn(`[meta] get_vod_info failed for movie ${streamId} (${e.message}); serving the catalog item`);
                return res.json({
                    meta: {
                        id: `xtremio_movie_${streamId}`,
                        type: 'XT-Movies',
                        name: titleOf(item.name) || 'Unknown',
                        poster: item.stream_icon || undefined,
                        posterShape: 'poster',
                        imdbRating: ratingOf(item.rating)
                    }
                });
            }
            const movie = info?.info ?? info ?? {};
            const cast = splitList(movie.cast);
            const backdrop = pickBackdrop(movie.backdrop_path);

            const meta = {
                id: `xtremio_movie_${streamId}`,
                type: 'XT-Movies',
                name: titleOf(movie.name || movie.o_name || info?.movie_data?.name) || 'Unknown',
                poster: movie.cover_big || movie.movie_image || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: movie.plot || movie.description || undefined,
                releaseInfo: movie.releasedate ? String(movie.releasedate) : undefined,
                genres: splitList(movie.genre),
                runtime: movie.duration ? String(movie.duration) + ' min' : (movie.episode_run_time ? String(movie.episode_run_time) + ' min' : undefined),
                director: splitList(movie.director),
                cast,
                imdbRating: ratingOf(movie.rating),
                year: parseYear(movie.releasedate),
                country: movie.country || undefined,
                trailers: youtubeTrailers(movie.youtube_trailer)
            };
            return res.json({ meta, ...withCacheHints(res, 86400) });
        }

        if (id.startsWith('xtremio_series_')) {
            const seriesId = getPrefixedNumericId(id, 'xtremio_series_');
            if (!seriesId) return res.status(400).json({ meta: null });
            let info = null;
            try {
                info = await getSeriesInfo(cfg, seriesId);
            } catch (e) {
                console.warn(`[meta] getSeriesInfo(${seriesId}) failed after retries: ${e.message}${causeSuffix(e)}`);
            }
            const series = info?.info ?? info ?? {};

            const videos = [];
            const episodes = info?.episodes ?? {};
            let skippedEpisodes = 0;
            for (const [seasonNum, eps] of Object.entries(episodes)) {
                if (!Array.isArray(eps)) continue;
                // parseEpisodeId requires all three components to be numeric, so an
                // episode built from a non-numeric season key or episode id would
                // render in the UI and then 400 on play. Drop it here instead.
                if (!isNumericId(seasonNum)) {
                    skippedEpisodes += eps.length;
                    continue;
                }
                for (const ep of eps) {
                    if (!isNumericId(ep?.id)) {
                        skippedEpisodes++;
                        continue;
                    }
                    // Episode 0 is real (specials, pilots); only a value that
                    // will not parse falls back to 1.
                    const parsedEpisode = parseInt(ep.episode_num);
                    const episodeNum = Number.isInteger(parsedEpisode) ? parsedEpisode : 1;
                    videos.push({
                        id: `xtremio_episode_${seriesId}:${seasonNum}:${ep.id}`,
                        // Built from the resolved number, so a missing episode_num
                        // reads "Episode 1" rather than "Episode undefined".
                        title: titleOf(ep.title) || `Episode ${episodeNum}`,
                        season: parseInt(seasonNum),
                        episode: episodeNum,
                        // Omitted, never epoch-defaulted: Stremio renders any date.
                        released: toIsoDate(ep.info?.releasedate) || undefined,
                        overview: ep.info?.plot || undefined,
                        thumbnail: ep.info?.movie_image || undefined
                    });
                }
            }
            if (skippedEpisodes) {
                console.warn(`[meta] series ${seriesId}: skipped ${skippedEpisodes} episode(s) with non-numeric season/episode ids`);
            }

            const hasContent = Boolean(series.name || videos.length);
            if (!hasContent) {
                console.warn(`[meta] no usable data for series ${seriesId}`);
                return res.json({ meta: null });
            }

            const cast = splitList(series.cast);
            const backdrop = pickBackdrop(series.backdrop_path);

            const meta = {
                id: `xtremio_series_${seriesId}`,
                type: 'series',
                name: titleOf(series.name) || 'Unknown',
                poster: series.cover || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: series.plot || undefined,
                releaseInfo: series.releaseDate ? String(series.releaseDate) : undefined,
                genres: splitList(series.genre),
                runtime: series.episode_run_time ? String(series.episode_run_time) + ' min' : undefined,
                director: splitList(series.director),
                cast,
                imdbRating: ratingOf(series.rating),
                year: parseYear(series.releaseDate),
                videos
            };
            return res.json({ meta, ...withCacheHints(res, 3600) });
        }

        res.json({ meta: null });
    } catch (e) {
        logRouteError('meta', e);
        res.json({ meta: null });
    }
});

app.get('/:config/stream/:type/:id.json', async (req, res) => {
    // Degraded answers are the default; see the catalog route.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ streams: [] });
    const { id, type } = req.params;
    if (LOG_REQUESTS) console.log(`[stream] type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);

    if (!typeMatchesId(type, id)) {
        console.warn(`[stream] type/id mismatch: type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);
        return res.status(404).json({ streams: [] });
    }

    try {
        // No credentials are read here any more: every stream this route hands
        // out is a proxy URL on this server, and the proxy is what holds them.

        // --- Handle xTremio's own IDs ---
        if (id.startsWith('xtremio_live_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_live_');
            if (!streamId) return res.status(400).json({ streams: [] });
            // Live is proxied too, because its upstream URL embeds the
            // credentials (audit M9).
            const proxyBase = `${getBaseUrl(req)}/${req.params.config}/proxy/live/${streamId}`;
            const variants = [
                { ext: 'm3u8', title: 'HLS' },
                { ext: 'ts', title: 'MPEG-TS' }
            ];
            return res.json({
                streams: variants.map(({ ext, title }) => {
                    const url = `${proxyBase}.${ext}`;
                    return {
                        url,
                        title,
                        behaviorHints: {
                            notWebReady: isNotWebReady(url, ext),
                            bingeGroup: `xtremio-live-${ext}`
                        }
                    };
                }),
                ...withCacheHints(res, 3600)
            });
        }

        if (id.startsWith('xtremio_movie_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_movie_');
            if (!streamId) return res.status(400).json({ streams: [] });
            // The stream needs only the container, and the warm full list usually
            // names it, so a failed or container-less get_vod_info no longer means
            // "No streams" for a file the proxy would serve (audit M2).
            let info = null;
            try {
                info = await getVodInfo(cfg, streamId);
            } catch (e) {
                if (isProgrammingError(e) || !warmVodItem(cfg, streamId)) throw e;
                console.warn(`[stream] get_vod_info failed for movie ${streamId} (${e.message}); using the catalog item's container`);
            }
            let rawExt = info?.movie_data?.container_extension;
            let fromList = false;
            if (statedContainerExt(rawExt) === null) {
                const listExt = warmVodItem(cfg, streamId)?.container_extension;
                if (statedContainerExt(listExt) !== null) {
                    rawExt = listExt;
                    fromList = true;
                }
            }
            const ext = normalizeContainerExt(rawExt);
            const extStated = statedContainerExt(rawExt) !== null;
            const proxyUrl = `${getBaseUrl(req)}/${req.params.config}/proxy/movie/${streamId}.${ext}`;
            // Cacheable, since the proxy URL is stable — but only when get_vod_info
            // named the container, not when mp4 was guessed or the list stood in.
            return res.json({
                streams: [
                    {
                        url: proxyUrl,
                        title: '▶ Play',
                        behaviorHints: {
                            notWebReady: isNotWebReady(proxyUrl, ext),
                            bingeGroup: `xtremio-movie-${ext}`
                        }
                    }
                ],
                ...(extStated && !fromList && info ? withCacheHints(res, 3600) : {})
            });
        }

        if (id.startsWith('xtremio_episode_')) {
            // Format: xtremio_episode_{seriesId}:{season}:{episodeId}
            const parsed = parseEpisodeId(id);
            if (!parsed) return res.status(400).json({ streams: [] });
            const { seriesId, seasonNum, episodeId } = parsed;

            const findEpisode = (data) => {
                const eps = (data?.episodes ?? {})[seasonNum];
                return Array.isArray(eps) ? eps.find(e => String(e.id) === episodeId) || null : null;
            };

            const info = await getSeriesInfo(cfg, seriesId);
            const rawExt = findEpisode(info)?.container_extension;
            // Not cached when guessed, for the same reason as the movie branch.
            const extStated = statedContainerExt(rawExt) !== null;
            if (!extStated) {
                console.warn(`[stream] episode ${episodeId} is missing from series ${seriesId} info or names no container; defaulting to mp4`);
            }
            const ext = normalizeContainerExt(rawExt);

            const proxyUrl = `${getBaseUrl(req)}/${req.params.config}/proxy/series/${episodeId}.${ext}`;
            return res.json({
                streams: [
                    {
                        url: proxyUrl,
                        title: '▶ Play',
                        behaviorHints: {
                            notWebReady: isNotWebReady(proxyUrl, ext),
                            bingeGroup: `xtremio-series-${seriesId}-${ext}`
                        }
                    }
                ],
                ...(extStated ? withCacheHints(res, 3600) : {})
            });
        }

        res.json({ streams: [] });
    } catch (e) {
        logRouteError('stream', e);
        res.json({ streams: [] });
    }
});


app.all('/:config/proxy/:kind/:file', async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).end('method not allowed');
    }
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.status(401).end('unauthorized');

    const { kind, file } = req.params;
    if (!['movie', 'series', 'live'].includes(kind)) {
        return res.status(400).end('bad kind');
    }
    const match = /^([^./]+)\.([A-Za-z0-9]+)$/.exec(file);
    if (!match) return res.status(400).end('bad file');
    const [, streamId, ext] = match;
    if (!isNumericId(streamId)) return res.status(400).end('bad stream id');

    // A token minted before server_info was validated can hold a server URL that
    // does not parse. Node puts the rejected input on the TypeError, and here that
    // input is this path — username and password included — so the failure is
    // answered on the spot rather than thrown to the terminal handler's log.
    let serverUrl;
    let upstreamUrl;
    try {
        serverUrl = normalizeUrl(cfg.serverUrl);
        upstreamUrl = new URL(
            `/${kind}/${encodeURIComponent(cfg.username)}/${encodeURIComponent(cfg.password)}/${streamId}.${ext}`,
            serverUrl
        ).toString();
    } catch {
        console.warn('[proxy] the configured server URL does not parse; the account needs reconfiguring');
        return res.status(502).end('bad upstream');
    }

    // Taken only once the request is known to be a relay, so a malformed one is
    // answered for what it is rather than 429'd by an account at its cap.
    const refused = acquireProxySlot(cfg, req, res);
    if (refused) return rejectOverCap(res, refused);

    const base = getBaseUrl(req);
    await relayUpstream(req, res, {
        upstreamUrl,
        label: `${kind}/${streamId}.${ext}`,
        ext,
        rewriteFor: (finalUrl, contentType) => {
            if (!looksLikePlaylist(ext, contentType)) return null;
            return makeHlsProxyMapper(
                base,
                req.params.config,
                hlsTargetOrigins(serverUrl, upstreamUrl, finalUrl)
            );
        }
    });
});

// Sub-resources of a proxied playlist: variant playlists, segments and keys.
// Reached only through URLs this server generated and signed, so the target is
// not caller-chosen despite being carried in the query string. A nested
// playlist is rewritten in turn, which is what makes master playlists work.
app.all('/:config/proxy/hls', async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).end('method not allowed');
    }
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.status(401).end('unauthorized');

    // Bound to this config token: a signature minted for another account's
    // playlist does not verify here, even though the keys are shared by every
    // account on this instance.
    const target = decodeHlsTarget(req.query.u, req.query.s, req.query.e, req.params.config);
    if (!target) return res.status(400).end('bad target');

    const refused = acquireProxySlot(cfg, req, res);
    if (refused) return rejectOverCap(res, refused);

    const upstreamUrl = target.url;
    // What the playlist said this target was, or what its path says. Content
    // type alone used to decide it here, which missed every variant playlist a
    // provider labelled text/plain: the body was then relayed untouched, with
    // the credential-bearing URIs the rewrite exists to remove still in it.
    // Supplying the extension also withholds Range, so the response cannot come
    // back a 206 that skips the rewrite.
    const ext = hlsTargetExt(target);

    const base = getBaseUrl(req);
    await relayUpstream(req, res, {
        upstreamUrl,
        label: 'hls sub-resource',
        ext,
        rewriteFor: (finalUrl, contentType) => {
            if (!looksLikePlaylist(ext, contentType)) return null;
            // A nested playlist keeps the same rule. `upstreamUrl` is included as
            // well as `finalUrl` because a variant playlist that redirects may
            // still name its segments back on the host it was fetched from.
            return makeHlsProxyMapper(
                base,
                req.params.config,
                hlsTargetOrigins(panelOrigin(cfg), upstreamUrl, finalUrl)
            );
        }
    });
});

// The page itself is in src/pages/landing.js; it is static, so the route is just
// the send.
app.get('/', (req, res) => res.send(renderLandingPage()));

// --- Server lifecycle ---
// The socket timeouts, the drain flag and the shutdown handler are in
// src/lifecycle.js; the bootstrap that uses them is at the end of this file.

// Liveness alone says only that the process is running, which on this server is
// nearly always true and nearly never the question: the thread that answers
// /health is the thread that parses tens of MB of catalog and relays video, so
// the way this instance fails is by being too busy to answer anything in time.
// Event-loop delay is the one number that says so.
//
// The histogram is reset on every read, so each probe reports the window since
// the last one — which is what a readiness check is asking. Two consequences:
// concurrent probes split the window between them, and a long gap between probes
// widens it. Both are acceptable for a load balancer polling on a fixed interval,
// and neither can hide a stall, since the peak stays the peak of whatever window
// it lands in.
const eventLoopDelay = monitorEventLoopDelay({ resolution: 10 });
eventLoopDelay.enable();

// Deliberately far above anything healthy. Idle delay is the platform's timer
// granularity — measured at 15.6 ms on Windows — and a 25 MB catalog parse, the
// largest block this server does on purpose, is 128 ms. A second is nothing a
// working instance reaches, which is the point: readiness that flaps under load
// pulls a busy-but-working instance out of the pool and moves its traffic onto
// the others, and that is how one slow instance becomes an outage.
const HEALTH_MAX_EVENT_LOOP_LAG_MS = 1000;

app.get('/health', (req, res) => {
    // Reporting unhealthy while draining is the point: it takes this instance out
    // of the load balancer pool before the process actually goes away, instead of
    // letting it keep receiving requests it is about to drop.
    const draining = isShuttingDown();
    // An empty window — two probes close enough together that the histogram's
    // timer has not fired between them — reports `mean` as NaN, which JSON writes
    // as null. Nothing was measured, so the honest reading is 0; reporting null
    // would make a probe that arrived early look like a broken metric. Rounded
    // because this is a measurement, not an identity, and a full float of
    // nanoseconds in a probe response invites false precision.
    const ms = (ns) => (Number.isFinite(ns) ? Math.round((ns / 1e6) * 10) / 10 : 0);
    const lagMs = ms(eventLoopDelay.max);
    const meanLagMs = ms(eventLoopDelay.mean);
    eventLoopDelay.reset();

    const stalled = lagMs > HEALTH_MAX_EVENT_LOOP_LAG_MS;
    const status = draining ? 'shutting_down' : (stalled ? 'stalled' : 'ok');
    res.status(draining || stalled ? 503 : 200)
        .set('Cache-Control', 'no-store')
        .json({
            status,
            uptime: process.uptime(),
            eventLoopLagMs: lagMs,
            eventLoopLagMeanMs: meanLagMs
        });
});

// A path begins with the config token, which is a bearer credential: it
// decrypts to the account's password. Logging one would put working install
// URLs in the log file, so the first segment is dropped when it is long enough
// to be a token rather than a route name.
//
// The path is not the only place a token appears, though — /configure takes one
// as a query parameter — so the two halves are redacted separately. One greedy
// run of non-slash characters read straight through the `?` (audit L13), which
// both missed tokens and destroyed paths depending only on where the first slash
// fell: `/a/b?config=<token>` was logged whole, while `/configure?config=<token>`
// came out as `/<config>`, naming no route at all.
function redactConfigInPath(path) {
    const raw = String(path);
    const cut = raw.indexOf('?');
    const pathname = cut === -1 ? raw : raw.slice(0, cut);
    const query = cut === -1 ? '' : raw.slice(cut);
    return pathname.replace(/^\/[^/]{24,}/, '/<config>')
        + query.replace(/([?&]config=)[^&]*/gi, '$1<config>');
}

// Unknown paths, so Express's default HTML 404 (which names the method and the
// path) never reaches a client.
app.use((req, res) => {
    res.status(404).type('text/plain').end('not found');
});

// Terminal error handler: Express's default writes stacks into responses. A
// malformed percent-escape throws a URIError out of the router before any handler
// runs, so only this can catch it. Registered last; the four parameters are what
// mark it as an error handler.
function terminalErrorHandler(err, req, res, next) {
    // A URIError from decodeParam means the client sent a bad path, not that
    // the server broke; anything carrying its own status (body-parser and
    // friends) is trusted to have set a sensible one — but only inside the
    // error range, since res.status() will send whatever it is given.
    const claimed = Number(err?.status || err?.statusCode);
    const status = err instanceof URIError
        ? 400
        : (claimed >= 400 && claimed <= 599 ? claimed : 500);

    const where = `${req.method} ${redactConfigInPath(req.originalUrl || req.url)} -> ${status}`;
    // A 5xx logs its stack; a 4xx one line. The stack, never the error object,
    // whose properties can carry request data (a failed `new URL()` holds its
    // input, which can include credentials).
    if (status >= 500) console.error(`[error] ${where}:`, err?.stack || String(err));
    else console.warn(`[error] ${where}: ${err?.message}`);

    // Once the body has started there is no status left to set, and the
    // response is already half-written; hand back to Express, which closes the
    // connection rather than appending a stack to a partial body.
    if (res.headersSent) return next(err);

    res.status(status).type('text/plain').end(status < 500 ? 'bad request' : 'internal error');
}

app.use(terminalErrorHandler);

// Only bind the port and install process-wide handlers when run directly, so
// `require('./index.js')` from a test can exercise the internals below without
// starting a server or hijacking the test runner's exception handling.
if (require.main === module) {
    // Before binding a port: a production deploy with a weak or absent secret
    // should fail loudly at startup, not quietly issue forgeable install URLs.
    enforceConfigSecretPolicy();
    warnOnUnpinnedBaseUrl();
    warnOnUndiciMismatch();

    // Only when actually serving: importing this module for tests should not
    // leave a timer running.
    startCacheSweeper();

    const server = applyServerTimeouts(app.listen(PORT, HOST, () => {
        console.log(`Addon running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
        console.log(`Configure: http://localhost:${PORT}/configure`);
    }));

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`Port ${PORT} is already in use. Kill the existing process or use a different port: PORT=3001 npm start`);
        } else {
            console.error('Server error:', err.message);
        }
        process.exit(1);
    });

    const shutdown = createShutdownHandler(server);
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    // No AbortError exemption: client disconnects are handled where they happen,
    // so an abort reaching here is a real gap.
    process.on('uncaughtException', (err) => {
        // Process state is undefined after an uncaught throw; exit and be restarted.
        console.error('Uncaught exception, exiting:', err);
        process.exit(1);
    });
    // Same for an unhandled rejection; Express 5 already routes async route
    // errors to the terminal handler, so anything here is a bug.
    process.on('unhandledRejection', (err) => {
        console.error('Unhandled rejection, exiting:', err);
        process.exit(1);
    });
}

// Exported for the test suite only — nothing here is a public API.
module.exports = {
    app,
    getManifest,
    ratingOf,
    encodeConfig,
    decodeConfig,
    xtremioGet,
    UPSTREAM_HEADER_TIMEOUT_MS,
    UPSTREAM_IDLE_TIMEOUT_MS,
    UPSTREAM_BODY_TIMEOUT_MS,
    isProgrammingError,
    noteUndecodableToken,
    noteDegradedCatalog,
    degradedCatalogLogged,
    DEGRADED_CATALOG_LOG_INTERVAL_MS,
    undecodableTokens,
    UNDECODABLE_REPORT_INTERVAL_MS,
    validateConfig,
    configSecretProblems,
    enforceConfigSecretPolicy,
    warnOnUnpinnedBaseUrl,
    corsApplies,
    deriveConfigKey,
    CONFIG_TOKEN_VERSION,
    CONFIG_SECRET_MIN_BYTES,
    SCRYPT_PARAMS,
    getBaseUrl,
    escapeHtml,
    normalizeUrl,
    serverInfoOrigin,
    hostnameOf,
    sealConfig,
    deriveConfigKeys,
    resolveHostAddresses,
    dnsFallback,
    DNS_TIMEOUT_MS,
    DNS_SERVERS,
    parseDnsServers,
    makeDnsResolver,
    parseHostList,
    panelHostAllowed,
    ALLOWED_PANEL_HOSTS,
    terminalErrorHandler,
    buildUrl,
    buildXtremioApiUrl,
    isNumericId,
    getPrefixedNumericId,
    parseEpisodeId,
    typeMatchesId,
    catalogTypesFor,
    withCacheHints,
    parseCatalogId,
    CATALOG_KINDS,
    catalogComparator,
    featuredEpoch,
    FEATURED_PERIOD_MS,
    filterByName,
    titleOf,
    toCatalogMetas,
    selectCatalogSource,
    sortedCatalogItems,
    cachedCatalogSelection,
    rememberCatalogSelection,
    catalogViewKey,
    sortedCatalogViews,
    normalizeContainerExt,
    statedContainerExt,
    isNotWebReady,
    normalizeAcceptRanges,
    hlsPrefixVerdict,
    sniffPlaylistStart,
    setRelayHeaders,
    CONFIGURE_TIMEOUT_MS,
    CONFIGURE_PROBE_TIMEOUT_MS,
    estimateBytes,
    CACHE_MAX_STREAM_BYTES,
    PLAYLIST_BODY_TIMEOUT_MS,
    PLAYLIST_REWRITE_TIMEOUT_MS,
    PROXY_HEADER_TIMEOUT_MS,
    MAX_PLAYLIST_ORIGINS,
    signTokenBody,
    rewriteHlsPlaylist,
    looksLikePlaylist,
    encodeHlsTarget,
    decodeHlsTarget,
    signHlsTarget,
    HLS_SIGNATURE_TTL_MS,
    MAX_PLAYLIST_BYTES,
    isPrivateIp,
    readJsonCapped,
    MAX_UPSTREAM_BYTES,
    MAX_PARSED_TO_BODY_RATIO,
    weighJson,
    assertSafeOutboundUrl,
    discardBody,
    acquireProxySlot,
    proxyInFlight,
    PROXY_MAX_CONCURRENT_PER_TOKEN,
    PROXY_MAX_CONCURRENT_PER_CLIENT,
    PROXY_MAX_CONCURRENT_TOTAL,
    proxyInFlightByClient,
    proxyRelays,
    makeHlsProxyMapper,
    hlsTargetOrigins,
    HLS_TARGET_ALLOWED_HOSTS,
    hlsOriginVetCache,
    HLS_ORIGIN_VET_TTL_MS,
    asString,
    redactConfigInPath,
    pinnedLookup,
    pinResolvedAddresses,
    dnsPins,
    PINNED_DISPATCHER,
    DNS_PIN_TTL_MS,
    warnOnUndiciMismatch,
    parseExtra,
    rawExtraSegment,
    parseYear,
    toIsoDate,
    splitList,
    youtubeTrailers,
    pickBackdrop,
    isUsableSeriesInfo,
    isUsableVodInfo,
    getCategories,
    getAllVodStreams,
    getAllSeriesStreams,
    getAllLiveStreams,
    getSeriesInfo,
    getVodInfo,
    getCategoryStreams,
    createSingleFlight,
    createKeyedCache,
    accountCacheKey,
    catCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    seriesInfoCache,
    vodInfoCache,
    categoryStreamsCache,
    CACHE_TTL,
    CACHE_FAILURE_TTL,
    CACHE_REFRESH_AHEAD,
    PAGE_SIZE,
    BoundedMap,
    sweepCaches,
    startCacheSweeper,
    CACHE_MAX_ACCOUNTS,
    CACHE_MAX_STREAM_ACCOUNTS,
    CACHE_MAX_SERIES_INFO,
    CACHE_MAX_VOD_INFO,
    CACHE_MAX_CATEGORY_LISTS,
    CACHE_MAX_BYTES,
    CACHE_BUDGET,
    CacheBudget,
    CACHE_STALE_MAX_AGE_MS,
    readSeriesInfoEntry,
    setNegativeSeriesInfo,
    getCachedSeriesInfo,
    setCachedSeriesInfo,
    fetchSeriesInfo,
    SERIES_INFO_NEGATIVE_TTL,
    SERIES_INFO_MAX_ATTEMPTS,
    validateXtremioCredentials,
    describeDowngrade,
    schemeOf,
    renderConfigPage,
    rateLimitConfigure,
    configureAttempts,
    clientKey,
    addressBucket,
    forwardedValue,
    TRUST_PROXY_HOPS,
    CONFIGURE_RATE_LIMIT,
    CONFIGURE_RATE_WINDOW_MS,
    CONFIGURE_RATE_MAX_CLIENTS,
    applyServerTimeouts,
    createShutdownHandler,
    isShuttingDown,
    setShuttingDown,
    SHUTDOWN_TIMEOUT_MS,
    KEEPALIVE_TIMEOUT_MS,
    HEADERS_TIMEOUT_MS,
    REQUEST_TIMEOUT_MS,
    HEALTH_MAX_EVENT_LOOP_LAG_MS
};