// Signing, encrypting and rewriting HLS playlists.
//
// Deliberately knows nothing about DNS, the SSRF guard or Express.
// rewriteHlsPlaylist takes its `toProxyUrl` mapper as an argument, and the
// production mapper — which vets a target before signing it — is built in
// index.js, where the guard lives. That is what keeps this module a leaf.
const crypto = require('node:crypto');

const {
    HLS_ENC_KEY,
    HLS_MAC_KEY,
    GCM_IV_BYTES,
    GCM_TAG_BYTES,
    timingSafeEqualString
} = require('../config-token.js');

// --- HLS playlist proxying -------------------------------------------------
//
// An Xtream playlist names its segments by absolute URLs with the account's
// credentials in the path, so playlists are rewritten: every URI becomes a link
// back through this server. Each link's target is HMAC-signed (its own key, and an
// `hls:` prefix) so the proxy is not an open relay, and encrypted so the
// credentials cannot be read from a query string in a log. The signature and the
// GCM associated data both cover the config token and an expiry, so a link is
// bound to one account and dies. None of the signed fields can contain a `:`, so
// concatenating them is unambiguous.
const HLS_SIGNATURE_TTL_MS = Math.max(60 * 1000, Number(process.env.HLS_SIGNATURE_TTL_MS) || 60 * 60 * 1000);

function signHlsTarget(payload, configToken = '', expiresAt = 0) {
    return crypto.createHmac('sha256', HLS_MAC_KEY)
        .update(`hls:${configToken}:${expiresAt}:${payload}`)
        .digest('base64url');
}

// The same three fields the MAC covers, in the same order, bound to the
// ciphertext instead of concatenated with it. `expiresAt` is stringified here
// because the query carries it as a string and the decrypt side must associate
// the identical bytes.
function hlsTargetAad(configToken, expiresAt) {
    return Buffer.from(`hls:${configToken}:${expiresAt}`, 'utf8');
}

// The plaintext is one kind byte and then the URL. The kind is what the
// playlist said the target was — see HLS_PLAYLIST_URI_TAGS — and the proxy route
// needs it before the body arrives: a nested playlist must be buffered and
// rewritten in turn, while a segment must keep its Range support and stream.
// It rides inside the ciphertext rather than beside it as another query field,
// so it is covered by the GCM tag and the MAC with nothing further to sign.
const HLS_KIND_PLAYLIST = 'p';
const HLS_KIND_SEGMENT = 's';

function encodeHlsTarget(absoluteUrl, configToken = '', now = Date.now(), playlist = false) {
    const expiresAt = now + HLS_SIGNATURE_TTL_MS;
    const iv = crypto.randomBytes(GCM_IV_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', HLS_ENC_KEY, iv);
    cipher.setAAD(hlsTargetAad(configToken, String(expiresAt)));
    const plaintext = (playlist ? HLS_KIND_PLAYLIST : HLS_KIND_SEGMENT) + absoluteUrl;
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    // iv | tag | ciphertext in one field: the lengths are fixed, so the decrypt
    // side slices rather than splitting, and the payload stays a single
    // separator-free base64url string the way the signed string requires.
    const payload = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
    return { u: payload, s: signHlsTarget(payload, configToken, expiresAt), e: String(expiresAt) };
}

// Returns `{ url, playlist }` only when the signature verifies for this config
// token and the expiry has not lapsed, so a caller cannot point this server at a
// host of their choosing even holding a valid config token of their own.
function decodeHlsTarget(payload, signature, expiry, configToken = '', now = Date.now()) {
    if (typeof payload !== 'string' || typeof signature !== 'string') return null;
    if (payload.length > 4096) return null;

    // Parsed strictly: `Number('12e9')` and `Number(' 12 ')` both succeed, and
    // an expiry that round-trips differently to the string that was signed
    // would verify against a value it does not equal.
    const expiresAt = typeof expiry === 'string' && /^\d{1,15}$/.test(expiry) ? Number(expiry) : NaN;
    if (!Number.isSafeInteger(expiresAt)) return null;

    // Signature first, then the clock, then the decrypt: the MAC is the cheapest
    // of the three and rejects a forged link before any key schedule is set up,
    // the same order the config token uses.
    if (!timingSafeEqualString(signHlsTarget(payload, configToken, expiry), signature)) return null;
    if (expiresAt <= now) return null;

    try {
        const raw = Buffer.from(payload, 'base64url');
        // Strictly greater: the nonce and tag alone are a well-formed payload
        // carrying an empty URL, which no minting path produces.
        if (raw.length <= GCM_IV_BYTES + GCM_TAG_BYTES) return null;
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            HLS_ENC_KEY,
            raw.subarray(0, GCM_IV_BYTES),
            { authTagLength: GCM_TAG_BYTES }
        );
        decipher.setAuthTag(raw.subarray(GCM_IV_BYTES, GCM_IV_BYTES + GCM_TAG_BYTES));
        decipher.setAAD(hlsTargetAad(configToken, expiry));
        const plaintext = Buffer.concat([
            decipher.update(raw.subarray(GCM_IV_BYTES + GCM_TAG_BYTES)),
            decipher.final()
        ]).toString('utf8');

        const kind = plaintext[0];
        if (kind !== HLS_KIND_PLAYLIST && kind !== HLS_KIND_SEGMENT) return null;

        const url = new URL(plaintext.slice(1));
        if (!['http:', 'https:'].includes(url.protocol)) return null;
        return { url: url.toString(), playlist: kind === HLS_KIND_PLAYLIST };
    } catch {
        return null;
    }
}

const HLS_CONTENT_TYPES = /^(application\/(vnd\.apple\.mpegurl|x-mpegurl)|audio\/(mpegurl|x-mpegurl))/i;

// The extension is the hint that matters: providers commonly return
// text/plain or octet-stream for a playlist, so content-type alone would miss
// them — and a missed playlist is relayed verbatim, with the provider's
// credential-bearing URLs still in the body. `hlsTargetExt` is what supplies an
// extension on the sub-resource route, where the request carries no file name.
// A body that then turns out not to be a playlist is refused rather than
// rewritten; see the EXTM3U check in relayUpstream.
function looksLikePlaylist(ext, contentType) {
    if (String(ext || '').toLowerCase() === 'm3u8') return true;
    return HLS_CONTENT_TYPES.test(String(contentType || ''));
}

// What the sub-resource route should expect of a signed target, decided before
// any of the body arrives — it has to be, because the streaming path forwards
// Range and relays bytes through untouched.
//
// Two things say "playlist" ahead of the body. The capability itself, when the
// URI sat on a tag that can only name one, is the reliable half: it comes from
// the playlist's own structure rather than from anything the provider labelled.
// A path ending in .m3u8 covers the rest — a playlist reached by a link this
// server did not mint, or one whose tag context said nothing.
//
// Sniffing the body for #EXTM3U is deliberately not a third signal here. The
// decision has to be made before reading anything, and the alternative to a
// playlist on this route is a segment that may be gigabytes; buffering one to
// find out is exactly what the streaming path exists to avoid.
const PLAYLIST_PATH_EXT = /\.m3u8?$/i;

// Every HLS playlist starts with this tag; the spec requires it on the first
// line. A byte-order mark and leading blank lines are tolerated because real
// panels emit both.
const HLS_BODY_PREFIX = /^\uFEFF?\s*#EXTM3U/;

// How much of a body has to be in hand to test that prefix: a byte-order mark
// and a few blank lines, and no more — this is read before anything is relayed.
const HLS_SNIFF_BYTES = 64;

function hlsTargetExt(target) {
    if (target.playlist) return 'm3u8';
    // Parsed by decodeHlsTarget already, so this cannot throw.
    return PLAYLIST_PATH_EXT.test(new URL(target.url).pathname) ? 'm3u8' : null;
}

// Playlists are kilobytes; anything far larger is not one. Bounded because the
// rewrite has to buffer the whole body, unlike the streaming path.
const MAX_PLAYLIST_BYTES = 4 * 1024 * 1024;

// URI="..." appears on EXT-X-KEY, EXT-X-MAP, EXT-X-MEDIA, EXT-X-PART and
// friends; those are sub-resources exactly like segment lines and leak the
// same credentials if left alone.
const HLS_URI_ATTR = /URI="([^"]*)"/gi;

// Which lines name a *playlist* rather than a segment or a key. The distinction
// is carried into the signed link, because the route that later fetches the
// target cannot recover it: a variant playlist need not end in .m3u8 and is
// routinely served as text/plain, and one relayed as if it were a segment goes
// to the player unrewritten, credentials and all.
// HLS states it unambiguously here instead. EXT-X-MEDIA and EXT-X-RENDITION-
// REPORT name Media Playlists, EXT-X-I-FRAME-STREAM-INF an I-frame playlist,
// and the URI *line* following an EXT-X-STREAM-INF is a Variant Stream's
// playlist. Every other URI — EXT-X-KEY, EXT-X-MAP, EXT-X-PART, a plain segment
// line — is a segment or a key, and must keep its Range support.
const HLS_PLAYLIST_URI_TAGS = /^#EXT-X-(MEDIA|I-FRAME-STREAM-INF|RENDITION-REPORT)[:\s]/i;
const HLS_STREAM_INF_TAG = /^#EXT-X-STREAM-INF[:\s]/i;

// `toProxyUrl` maps one absolute upstream URL to a URL on this server.
// Anything that will not resolve, or is not http(s), is left untouched rather
// than dropped: a malformed line is the provider's business, and removing it
// would silently corrupt the playlist.
// `toProxyUrl` may be async — the mapper used in production resolves DNS to
// check the target before signing it — so this is async throughout.
async function rewriteHlsPlaylist(text, baseUrl, toProxyUrl, { deadline = null } = {}) {
    const mapUri = async (raw, playlist) => {
        // Checked here rather than around the whole pass because this is the only
        // point that awaits: a timer cannot interrupt an await chain, so the loop
        // has to look. Throwing rather than emitting a partly-rewritten playlist
        // is deliberate — the un-rewritten lines are the provider's own URLs, and
        // those carry the account credentials this rewrite exists to hide.
        if (deadline !== null && Date.now() > deadline) {
            const err = new Error('playlist rewrite deadline exceeded');
            err.code = 'PLAYLIST_REWRITE_TIMEOUT';
            throw err;
        }
        const uri = String(raw).trim();
        if (!uri) return null;
        let absolute;
        try {
            absolute = new URL(uri, baseUrl);
        } catch {
            return null;
        }
        if (!['http:', 'https:'].includes(absolute.protocol)) return null;
        const mapped = await toProxyUrl(absolute.toString(), Boolean(playlist));
        if (mapped) return mapped;
        // The mapper refused this target. Leaving the line would hand the player
        // the provider's credential-bearing URL, and dropping it is unsafe (a
        // dropped EXT-X-KEY URI makes encrypted segments look plaintext), so the
        // whole playlist is refused.
        const err = new Error('playlist names a target this server will not proxy');
        err.code = 'PLAYLIST_TARGET_REFUSED';
        throw err;
    };

    // replace() cannot await, so URI attributes are walked by hand. The regex is
    // built per call rather than shared: awaiting mid-scan would otherwise let a
    // concurrent rewrite move lastIndex out from under this one.
    const rewriteUriAttrs = async (body, playlist) => {
        const scanner = new RegExp(HLS_URI_ATTR.source, HLS_URI_ATTR.flags);
        const parts = [];
        let cursor = 0;
        let match;
        while ((match = scanner.exec(body)) !== null) {
            const mapped = await mapUri(match[1], playlist);
            parts.push(body.slice(cursor, match.index), mapped ? `URI="${mapped}"` : match[0]);
            cursor = match.index + match[0].length;
        }
        parts.push(body.slice(cursor));
        return parts.join('');
    };

    const out = [];
    // Set by an EXT-X-STREAM-INF and consumed by the next URI line, which is the
    // one place a playlist's kind is stated by position rather than by the tag
    // the URI sits on. Not cleared by the tags and comments that may sit in
    // between: the spec says the URI line follows immediately, and erring toward
    // "playlist" costs a buffered fetch, while erring the other way relays a
    // playlist to the player with the provider's credentials still in it.
    let nextUriIsPlaylist = false;

    for (const line of text.split('\n')) {
        // Preserve CRLF exactly: some players are strict about the line ending.
        const cr = line.endsWith('\r') ? '\r' : '';
        const body = cr ? line.slice(0, -1) : line;

        if (!body.trim()) {
            out.push(line);
            continue;
        }
        if (body.startsWith('#')) {
            out.push(await rewriteUriAttrs(body, HLS_PLAYLIST_URI_TAGS.test(body)) + cr);
            if (HLS_STREAM_INF_TAG.test(body)) nextUriIsPlaylist = true;
            continue;
        }

        const mapped = await mapUri(body, nextUriIsPlaylist);
        nextUriIsPlaylist = false;
        out.push(mapped ? mapped + cr : line);
    }
    return out.join('\n');
}

module.exports = {
    HLS_SIGNATURE_TTL_MS,
    HLS_KIND_PLAYLIST,
    HLS_KIND_SEGMENT,
    HLS_SNIFF_BYTES,
    HLS_BODY_PREFIX,
    HLS_CONTENT_TYPES,
    HLS_PLAYLIST_URI_TAGS,
    HLS_STREAM_INF_TAG,
    HLS_URI_ATTR,
    PLAYLIST_PATH_EXT,
    MAX_PLAYLIST_BYTES,
    signHlsTarget,
    hlsTargetAad,
    encodeHlsTarget,
    decodeHlsTarget,
    looksLikePlaylist,
    hlsTargetExt,
    rewriteHlsPlaylist
};
