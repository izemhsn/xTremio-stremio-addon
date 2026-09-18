// Reading a Stremio catalog request and answering with the right cache hints.
//
// The `extra` segment is the awkward part. Stremio sends it as one path segment
// holding `key=value` pairs, and both the separator and the `=` arrive
// percent-encoded or not depending on the client — while a search term may itself
// contain a literal `&` or `=`. So the split is anchored on the *declared* keys
// rather than on the separators, which is what makes it unambiguous.
// The keys this addon declares in its manifest `extra` blocks. Nothing else is
// a pair separator's right-hand side, which is what makes the split below safe.
const EXTRA_KEYS = ['skip', 'genre', 'search'];

// A pair boundary is a separator followed by one of those keys and its '='; a '&'
// anywhere else belongs to a value ("Kids & Family"). Separator and '=' are matched
// raw or escaped, since clients escape different amounts of the segment.
const EXTRA_KEY_ALT = EXTRA_KEYS.join('|');
const EXTRA_PAIR_SPLIT = new RegExp(`(?:&|%26)(?=(?:${EXTRA_KEY_ALT})(?:=|%3D))`, 'i');
const EXTRA_KEY_HEAD = new RegExp(`^(${EXTRA_KEY_ALT})(?:=|%3D)`, 'i');

// decodeURIComponent throws on a malformed escape, and "100%" is a legitimate
// search term, so a part that will not decode is kept verbatim. Decoding here is
// only correct because the input is the *raw* segment (see rawExtraSegment); on
// an already-decoded param this would be a second decode and would corrupt it.
function decodeExtraPart(part) {
    try {
        return decodeURIComponent(part);
    } catch {
        return part;
    }
}

function parseExtra(extra) {
    const params = {};
    if (!extra) return params;

    for (const pair of extra.split(EXTRA_PAIR_SPLIT)) {
        const head = EXTRA_KEY_HEAD.exec(pair);
        if (head) {
            params[head[1].toLowerCase()] = decodeExtraPart(pair.slice(head[0].length));
            continue;
        }
        // Not a key this addon declares. Kept rather than dropped, on the first
        // literal '=', so an extra added to the manifest without being added to
        // EXTRA_KEYS still arrives instead of vanishing silently.
        const i = pair.indexOf('=');
        const [k, v] = i === -1 ? [pair, ''] : [pair.slice(0, i), pair.slice(i + 1)];
        params[decodeExtraPart(k)] = decodeExtraPart(v);
    }
    return params;
}

// The still-encoded :extra segment, or undefined when the request matched the
// route pattern that has no extra. `originalUrl` is the one place the escapes
// survive; `req.params.extra` has already lost them.
function rawExtraSegment(req) {
    if (req.params.extra === undefined) return undefined;
    const path = req.originalUrl.split('?')[0];
    return path.slice(path.lastIndexOf('/') + 1).replace(/\.json$/i, '');
}

const PAGE_SIZE = 100;

// Sets the Cache-Control header that stremio-addon-sdk derives from the
// `cacheMaxAge`/`staleRevalidate` body fields, and returns the fields too.
// `private` because every response is account-specific and the path is a bearer
// token.
function withCacheHints(res, cacheMaxAge, staleRevalidate) {
    const directives = ['private', `max-age=${cacheMaxAge}`];
    if (staleRevalidate) directives.push(`stale-while-revalidate=${staleRevalidate}`);
    res.setHeader('Cache-Control', directives.join(', '));
    return staleRevalidate === undefined ? { cacheMaxAge } : { cacheMaxAge, staleRevalidate };
}

module.exports = {
    EXTRA_KEYS,
    decodeExtraPart,
    parseExtra,
    rawExtraSegment,
    PAGE_SIZE,
    withCacheHints
};
