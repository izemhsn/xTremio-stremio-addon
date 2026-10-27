// GET|HEAD /:config/proxy/:kind/:file   — a movie, episode or live channel
// GET|HEAD /:config/proxy/hls           — a piece of an HLS playlist
//
// These are the URLs the stream route hands to the player. Each one is turned
// into the provider's real URL (which contains the account's username and
// password), fetched, and relayed back. The relaying itself — timeouts, Range
// requests, rewriting playlists — lives in src/proxy/relay.js and is shared by
// both routes.
const express = require('express');

const { decodeConfig } = require('../config-token.js');
const { isNumericId, normalizeUrl } = require('../helpers.js');
const { decodeHlsTarget, looksLikePlaylist, hlsTargetExt } = require('../hls/playlist.js');
const {
    relayUpstream,
    panelOrigin,
    hlsTargetOrigins,
    makeHlsProxyMapper,
    acquireProxySlot,
    rejectOverCap
} = require('../proxy/relay.js');
const { getBaseUrl } = require('./request.js');

const router = express.Router();

const PROXY_KINDS = ['movie', 'series', 'live'];

router.all('/:config/proxy/:kind/:file', async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).end('method not allowed');
    }
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.status(401).end('unauthorized');

    const { kind, file } = req.params;
    if (!PROXY_KINDS.includes(kind)) return res.status(400).end('bad kind');
    // `file` is `<numeric id>.<extension>`, e.g. `1234.mkv`.
    const match = /^([^./]+)\.([A-Za-z0-9]+)$/.exec(file);
    if (!match) return res.status(400).end('bad file');
    const [, streamId, ext] = match;
    if (!isNumericId(streamId)) return res.status(400).end('bad stream id');

    // The provider's URL for this file. A token minted before server URLs were
    // validated can hold one that does not parse. The resulting TypeError would
    // carry this URL — username and password included — so it is answered here
    // rather than thrown to the error handler, which logs it.
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

    // Taken only once the request is known to be valid, so a malformed one is
    // answered as such rather than refused because the account is at its cap.
    const refused = acquireProxySlot(cfg, req, res);
    if (refused) return rejectOverCap(res, refused);

    const base = getBaseUrl(req);
    await relayUpstream(req, res, {
        upstreamUrl,
        label: `${kind}/${streamId}.${ext}`,
        ext,
        // If the response is an HLS playlist, its URIs are rewritten to point
        // back at /proxy/hls on this server.
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
// Only reachable through URLs this server generated and signed (see
// makeHlsProxyMapper), so although the target travels in the query string, the
// caller cannot choose it. A nested playlist is rewritten in turn, which is what
// makes master playlists work.
router.all('/:config/proxy/hls', async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).end('method not allowed');
    }
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.status(401).end('unauthorized');

    // The signature is bound to this config token: a link minted for another
    // account's playlist does not verify here.
    const target = decodeHlsTarget(req.query.u, req.query.s, req.query.e, req.params.config);
    if (!target) return res.status(400).end('bad target');

    const refused = acquireProxySlot(cfg, req, res);
    if (refused) return rejectOverCap(res, refused);

    const upstreamUrl = target.url;
    // Whether this target is a playlist, decided from what the parent playlist
    // said about it or from its path — not from the content type, which
    // providers often get wrong (text/plain). Knowing it up front also means
    // no Range header is forwarded, so the response cannot come back as a
    // partial 206 that skips the rewrite.
    const ext = hlsTargetExt(target);

    const base = getBaseUrl(req);
    await relayUpstream(req, res, {
        upstreamUrl,
        label: 'hls sub-resource',
        ext,
        rewriteFor: (finalUrl, contentType) => {
            if (!looksLikePlaylist(ext, contentType)) return null;
            // `upstreamUrl` is included as well as `finalUrl` because a variant
            // playlist that redirects may still name its segments back on the
            // host it was fetched from.
            return makeHlsProxyMapper(
                base,
                req.params.config,
                hlsTargetOrigins(panelOrigin(cfg), upstreamUrl, finalUrl)
            );
        }
    });
});

module.exports = { router };
