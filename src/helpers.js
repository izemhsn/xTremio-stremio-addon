// Pure value helpers: URL and id shapes on one side, and the coercions that make
// a provider's JSON safe to render on the other.
//
// Nothing here does I/O, reads the environment or knows about Express, which is
// what makes it the bottom of the dependency graph — every other module may
// require this one.
//
// The coercions exist because Xtream payloads are not typed. `cast`/`genre`
// arrive as a string or an array, `backdrop_path` as either, and a panel
// encoding with PHP's JSON_NUMERIC_CHECK sends the title `1917` as a JSON
// *number* — which is what once threw out of a search and emptied every movie
// shelf on that account.

// Query and body values arrive as string, array, object or undefined depending
// on what the client sent. Anything that is not a string is treated as absent
// rather than coerced: `String(['a','b'])` would silently accept "a,b".
function asString(value) {
    return typeof value === 'string' ? value : '';
}

// The scheme is matched case-insensitively and then lowercased, because every
// later test of it is a case-sensitive string comparison: schemeOf, the http ->
// https upgrade in validateXtremioCredentials, describeDowngrade. A phone's
// auto-capitalized `Http://` matched none of them and none of this either, so it
// was prefixed again and became `http://Http://panel`, and /configure went on to
// look up a host called `http`. Lowercasing here rather than adding an `i` flag
// at each of those sites is what keeps a typed `HTTPS://` from counting as http
// and being tried over http, which is the rule audit S7 exists for.
function normalizeUrl(url) {
    url = String(url || '').trim().replace(/\/+$/, '');
    if (!url) throw new Error('serverUrl is required');
    if (/^https?:\/\//i.test(url)) return url.replace(/^https?/i, (s) => s.toLowerCase());
    return 'http://' + url;
}

function buildUrl(base, pathname, params = {}) {
    const url = new URL(pathname, base);
    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
            url.searchParams.set(key, String(value));
        }
    }
    return url.toString();
}

function buildXtremioApiUrl(cfg, action, params = {}) {
    return buildUrl(normalizeUrl(cfg.serverUrl), '/player_api.php', {
        username: cfg.username,
        password: cfg.password,
        action,
        ...params
    });
}

function isNumericId(value) {
    return /^\d+$/.test(String(value || ''));
}

function getPrefixedNumericId(id, prefix) {
    if (!String(id || '').startsWith(prefix)) return null;
    const value = id.slice(prefix.length);
    return isNumericId(value) ? value : null;
}

function parseEpisodeId(id) {
    if (!String(id || '').startsWith('xtremio_episode_')) return null;
    const parts = id.slice('xtremio_episode_'.length).split(':');
    if (parts.length !== 3 || !parts.every(isNumericId)) return null;
    return { seriesId: parts[0], seasonNum: parts[1], episodeId: parts[2] };
}

// Stremio's `:type` path segment is advisory here — every route dispatches on
// the id prefix instead — but without a check a mismatched pair (say
// type=XT-Movies with a live id) is happily served under the wrong type.
// Series are declared under `XT-Series` in the manifest's catalog list yet emit
// `series` metas, so both spellings are accepted wherever a series is involved.
const ID_PREFIX_TYPES = {
    'xtremio_episode_': ['series', 'XT-Series'],
    'xtremio_series_': ['series', 'XT-Series'],
    'xtremio_movie_': ['XT-Movies'],
    'xtremio_live_': ['Live TV']
};

function typeMatchesId(type, id) {
    const str = String(id || '');
    const prefix = Object.keys(ID_PREFIX_TYPES).find(p => str.startsWith(p));
    // An id we do not recognise is left to the route, which already answers it
    // with the empty payload rather than an error.
    if (!prefix) return true;
    return ID_PREFIX_TYPES[prefix].includes(String(type));
}

// Catalog ids are not item ids and overlap their prefixes (`xtremio_series_new`
// starts with `xtremio_series_`), so catalogs are matched separately — see
// `catalogTypesFor`, which lives with the catalog table in src/catalog/kinds.js.

// The container the provider named, or null when it named none usable. The
// stream route needs that difference: a guessed extension must not be cached.
function statedContainerExt(ext) {
    const clean = String(ext || '').trim();
    return /^[A-Za-z0-9]+$/.test(clean) ? clean : null;
}

function normalizeContainerExt(ext) {
    return statedContainerExt(ext) || 'mp4';
}

// Per Stremio SDK: notWebReady must be true when the URL is http:// or
// the file is not an MP4 container. Without this, the player may stop
// after a short period (e.g. ~1 min) and Stremio treats it as "ended",
// returning to details (movies) or auto-advancing (series episodes).
function isNotWebReady(url, ext) {
    const isHttps = /^https:\/\//i.test(url);
    const isMp4 = String(ext || '').toLowerCase() === 'mp4';
    return !(isHttps && isMp4);
}

function toIsoDate(s) {
    if (!s) return undefined;
    const d = new Date(s);
    return isNaN(d.getTime()) ? undefined : d.toISOString();
}

// A provider's title is not reliably a string: PHP's JSON_NUMERIC_CHECK sends 1917
// and 300 as numbers. Strings and finite numbers count; anything else is no title.
function titleOf(value) {
    if (typeof value === 'string') return value;
    return typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

// Xtream sends `rating: "0"` — or 0, or "" — for a title nobody has rated, and
// the string "0" is truthy, so Stremio showed a rating of 0 rather than none.
// Anything that is not a positive number is no rating at all.
function ratingOf(value) {
    if (typeof value !== 'string' && typeof value !== 'number') return undefined;
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? String(n) : undefined;
}

// Xtream providers return `cast`/`genre` as either a comma-separated string or an array.
function splitList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value.map(v => String(v).trim()).filter(Boolean);
    return String(value).split(',').map(v => v.trim()).filter(Boolean);
}

// Stremio has no `trailer` meta field: a trailer is an entry in `trailers`,
// `{ source, type }`, where source is the YouTube video id — so the old key was
// simply ignored and the button never appeared (audit L2). Panels put either a
// bare id or a watch/share URL in `youtube_trailer`, and both are accepted.
// Anything that does not reduce to an id is dropped rather than passed on: a
// trailer button that cannot play is worse than no button.
const YOUTUBE_ID = /^[A-Za-z0-9_-]{11}$/;

function youtubeTrailers(value) {
    const raw = String(value || '').trim();
    if (!raw) return undefined;
    let id = raw;
    if (raw.includes('/')) {
        id = '';
        // Panels store these without a scheme as often as with one.
        for (const candidate of [raw, `https://${raw}`]) {
            try {
                const url = new URL(candidate);
                id = url.searchParams.get('v') || url.pathname.split('/').filter(Boolean).pop() || '';
                break;
            } catch { /* not a URL in this spelling; try the next */ }
        }
    }
    return YOUTUBE_ID.test(id) ? [{ source: id, type: 'Trailer' }] : undefined;
}

// `backdrop_path` can be an array of URLs or a single URL string.
function pickBackdrop(value) {
    if (!value) return undefined;
    if (Array.isArray(value)) return value[0] || undefined;
    return String(value) || undefined;
}

// fetch hides the real reason in `cause`: the message is a flat 'fetch failed'
// and the code that says which failure it was — ECONNREFUSED, ENOTFOUND, a TLS
// error — is one level down. Here rather than beside either caller, because the
// two log lines that use it are the ones an operator compares when a panel starts
// failing and they must read the same.
function causeSuffix(e) {
    return e?.cause ? ` (cause: ${e.cause.code || e.cause.message || e.cause})` : '';
}

module.exports = {
    causeSuffix,
    asString,
    normalizeUrl,
    buildUrl,
    buildXtremioApiUrl,
    isNumericId,
    getPrefixedNumericId,
    parseEpisodeId,
    ID_PREFIX_TYPES,
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
};
