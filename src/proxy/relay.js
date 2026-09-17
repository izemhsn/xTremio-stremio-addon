// Relaying bytes from a provider to the player.
//
// This exists because Xtream providers 302 to a CDN URL whose token expires in
// about a minute, and because a live URL carries the account's credentials in its
// path — returning either to the player would leak them or break playback. Both
// proxy routes share relayUpstream, so changes to abort handling, timeouts or
// header forwarding belong here rather than in one route.
//
// The deadlines are not interchangeable. PROXY_HEADER_TIMEOUT_MS bounds the wait
// for response headers and is re-armed for the GET that follows a failed HEAD;
// PLAYLIST_BODY_TIMEOUT_MS bounds reading a whole playlist body, the only path
// that buffers before it can answer; PLAYLIST_REWRITE_TIMEOUT_MS bounds the
// rewrite itself. The streaming branch takes none of its own — a paused movie is
// a legitimately idle connection — and does not need one, since undici's own
// bodyTimeout ends a relay whose upstream has gone silent while leaving a reader
// applying backpressure alone.
const { Readable } = require('node:stream');

const { normalizeUrl } = require('../helpers.js');
const { BoundedMap } = require('../cache/bounded-map.js');
const { registerSweepable, accountCacheKey } = require('../cache/layers.js');
const { parseHostList, hostnameOf } = require('../panel-allowlist.js');
const { clientKey } = require('../routes/request.js');
const {
    safeFetch,
    discardBody,
    assertSafeOutboundUrl,
    blockedOutbound,
    DNS_PIN_TTL_MS
} = require('../net/safe-fetch.js');
const { readTextCapped } = require('../upstream/read-capped.js');
const {
    MAX_PLAYLIST_BYTES,
    HLS_BODY_PREFIX,
    HLS_SNIFF_BYTES,
    encodeHlsTarget,
    looksLikePlaylist,
    rewriteHlsPlaylist
} = require('../hls/playlist.js');

// Browser-like UA — many Xtream CDNs reject or shortchange non-browser UAs.
const PROXY_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// How long to wait for upstream response headers in the proxy. Applies to the
// headers only — never to the body, which is a legitimate long-lived stream.
const PROXY_HEADER_TIMEOUT_MS = Math.max(1000, Number(process.env.PROXY_HEADER_TIMEOUT_MS) || 20000);

// Separate, longer deadline for the one path that buffers a whole body before
// answering: the playlist rewrite. The streaming path must stay unbounded — a
// paused movie is a legitimately idle connection — so this is not a general
// body timeout.
const PLAYLIST_BODY_TIMEOUT_MS = Math.max(1000, Number(process.env.PLAYLIST_BODY_TIMEOUT_MS) || 30000);

// The rewrite after the body read resolves DNS once per distinct origin, so it is
// bounded twice: the origin cap bounds the number of lookups, and the deadline is
// the backstop for a slow resolver. The deadline is checked between lookups, so one
// hung resolution can overrun it by that lookup's own timeout.
const MAX_PLAYLIST_ORIGINS = Math.max(1, Number(process.env.MAX_PLAYLIST_ORIGINS) || 32);
const PLAYLIST_REWRITE_TIMEOUT_MS = Math.max(1000, Number(process.env.PLAYLIST_REWRITE_TIMEOUT_MS) || 15000);

// Signing-time vetting of the origins named in HLS playlists, shared across
// rewrites since a live playlist is re-fetched every few seconds. Keyed by origin,
// not account. The TTL is the DNS pin's, so a decision about a hostname cannot
// outlive its pinned addresses; caching is safe because safeFetch re-checks on
// every segment request.
const HLS_ORIGIN_VET_TTL_MS = DNS_PIN_TTL_MS;
const HLS_ORIGIN_VET_MAX = 512;
// No ledger: this holds promises about hostnames, not bytes of provider data, so
// it is bounded by count and age alone. Swept all the same, which is why
// registration is not tied to the budget.
const hlsOriginVetCache = registerSweepable(new BoundedMap({
    maxEntries: HLS_ORIGIN_VET_MAX,
    maxAgeMs: HLS_ORIGIN_VET_TTL_MS
}));

// Returns a promise for whether this origin may be signed. The promise itself is
// cached, so concurrent rewrites naming the same host share one resolution
// instead of racing. It never rejects.
function vetHlsOrigin(absolute, origin) {
    const cached = hlsOriginVetCache.get(origin);
    if (cached && cached.ts > Date.now() - HLS_ORIGIN_VET_TTL_MS) return cached.ok;
    const ok = assertSafeOutboundUrl(absolute).then(() => true, (e) => {
        // Only a policy refusal is kept; a failed lookup is dropped so a resolver
        // blip does not refuse the channel for the whole window. Checked by
        // identity so a newer entry is left alone.
        if (e?.code !== 'OUTBOUND_BLOCKED' && hlsOriginVetCache.peek(origin)?.ok === ok) {
            hlsOriginVetCache.delete(origin);
        }
        return false;
    });
    hlsOriginVetCache.set(origin, { ok, ts: Date.now() });
    return ok;
}

// Accept-Ranges carries a range-*unit* (RFC 9110 §14.3), and providers get it wrong
// both ways: one sends a range instead of a unit, another claims `bytes` while
// ignoring Range. So the header is decided by what the exchange demonstrated.
const RANGE_UNIT = /^(?:bytes|none)$/i;

// Every HLS playlist starts with this tag, on the first line.
const HLS_BODY_TAG = '#EXTM3U';

// Whether what has arrived so far begins that tag, cannot, or is still only the
// start of it. `more` is what makes the sniff below safe on a live stream: a body
// is ruled out at the first byte that could not belong to the tag.
function hlsPrefixVerdict(text) {
    const rest = text.replace(/^\uFEFF?\s*/, '');
    if (rest.startsWith(HLS_BODY_TAG)) return 'playlist';
    return HLS_BODY_TAG.startsWith(rest) ? 'more' : 'other';
}

// Reads only as far as it takes to know whether a body starts with #EXTM3U, and
// hands back every byte it read so the caller can write them on. The two bounds
// are both load-bearing on a route that relays live video: it stops at the first
// byte that rules a playlist out, so a segment that sends one byte and then
// pauses — a legitimately idle stream this route must never break — is decided
// immediately; and it never waits past `maxBytes`, so a body of nothing but the
// whitespace the tag tolerates cannot hold it open either.
function sniffPlaylistStart(stream, maxBytes = HLS_SNIFF_BYTES) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const prefix = Buffer.alloc(maxBytes);
        let filled = 0;
        const verdict = () => hlsPrefixVerdict(prefix.subarray(0, filled).toString('utf8'));
        const finish = (err, ended, playlist) => {
            stream.off('readable', onReadable);
            stream.off('end', onEnd);
            stream.off('error', onError);
            if (err) return reject(err);
            resolve({ head: Buffer.concat(chunks), ended, playlist });
        };
        const onReadable = () => {
            let chunk;
            while ((chunk = stream.read()) !== null) {
                chunks.push(chunk);
                if (filled < maxBytes) {
                    filled += chunk.copy(prefix, filled, 0, Math.min(chunk.length, maxBytes - filled));
                }
                const so_far = verdict();
                if (so_far !== 'more') return finish(null, false, so_far === 'playlist');
                if (filled >= maxBytes) return finish(null, false, false);
            }
        };
        const onEnd = () => finish(null, true, verdict() === 'playlist');
        const onError = (e) => finish(e, false, false);
        stream.on('readable', onReadable);
        stream.once('end', onEnd);
        stream.once('error', onError);
        onReadable();
    });
}

// Every response that carries provider bytes gets these, in both branches of
// relayUpstream. The content type is the panel's and is forwarded as sent, so a
// panel could serve text/html from this origin: `nosniff` stops a body it
// labelled something else being sniffed into one, and `sandbox` — with no
// allow- tokens — puts anything that is HTML in an opaque origin with no
// scripts, no forms and no top-level navigation (audit L8). The impact is small
// because this site sets no cookies, but the panel is untrusted and this is two
// headers. `no-store` rides along because it belongs to the same rule: nothing
// relayed here is worth a cache's memory of it.
function setRelayHeaders(res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', 'sandbox');
}

function normalizeAcceptRanges({ status, upstreamValue, sentRange, sentIfRange }) {
    // A 206 is proof: the origin honoured a byte range in this very exchange.
    if (status === 206) return 'bytes';

    // We asked for a range and did not get a partial body, so the origin
    // ignored it. An If-Range that failed to match legitimately produces a
    // whole 200 and proves nothing, so that case falls through instead.
    if (sentRange && !sentIfRange) return null;

    // No evidence from this exchange: trust a well-formed unit from upstream.
    const unit = String(upstreamValue || '').trim();
    if (RANGE_UNIT.test(unit)) return unit.toLowerCase();

    // Nothing usable either way. Stay optimistic, as before: plenty of Xtream
    // CDNs serve ranges without advertising them, and nothing here contradicts
    // that. Never relay a malformed value — omitting beats lying, and this
    // returns a valid unit or nothing at all.
    return 'bytes';
}

// The shared body of both proxy routes: resolve the upstream, forward the headers
// that matter for playback, and either rewrite a playlist or stream the bytes.
// `rewriteFor(finalUrl, contentType)` returns a mapper for playlist URIs, or null
// to stream the body untouched.
async function relayUpstream(req, res, { upstreamUrl, label, ext, rewriteFor }) {
    const headers = { 'User-Agent': PROXY_USER_AGENT };
    // A Range on a playlist would yield a partial body that cannot be parsed or
    // rewritten. Players do not range-request playlists; skip it when we already
    // know from the extension that one is coming.
    const expectPlaylist = String(ext || '').toLowerCase() === 'm3u8';
    if (!expectPlaylist) {
        // Left unset, undici's fetch offers gzip/deflate. An origin that honours
        // that on a byte relay answers a Range with a Content-Range in
        // *compressed* offsets, which no longer describe the decompressed bytes
        // relayed — and decompressing video spends CPU on the relaying thread.
        // Playlists keep the default: they are text and rewritten whole.
        headers['Accept-Encoding'] = 'identity';
        if (req.headers.range) headers['Range'] = req.headers.range;
        if (req.headers['if-range']) headers['If-Range'] = req.headers['if-range'];
    }
    // What we asked for is half the evidence normalizeAcceptRanges needs below.
    const sentRange = Boolean(headers['Range']);
    const sentIfRange = Boolean(headers['If-Range']);

    const controller = new AbortController();
    const abort = () => {
        if (!controller.signal.aborted) {
            try { controller.abort(); } catch {}
        }
    };
    req.on('close', abort);
    req.on('aborted', abort);

    const isAbortErr = (e) => e && (e.name === 'AbortError' || e.code === 'ABORT_ERR' || controller.signal.aborted);

    let upstream;
    let finalUrl = upstreamUrl;
    // Bound the wait for response *headers* only. An upstream that accepts the
    // connection and then stalls would otherwise pin this request and its
    // socket forever. The timer is cleared as soon as headers arrive so the
    // body itself can stream for as long as playback needs.
    let headersTimedOut = false;
    let headerTimer = null;
    // Re-armable, because the deadline bounds one exchange (audit L12). See the
    // fallback below for why that matters.
    const armHeaderTimer = () => {
        clearTimeout(headerTimer);
        headerTimer = setTimeout(() => { headersTimedOut = true; abort(); }, PROXY_HEADER_TIMEOUT_MS);
    };
    armHeaderTimer();
    try {
        // HEAD is passed through, and anything short of a usable response falls
        // back to GET. Do not narrow this to 405/501: the real panel answers HEAD
        // with a 502 and its CDN drops the connection, so fetch throws.
        if (req.method === 'HEAD') {
            try {
                const head = await safeFetch(upstreamUrl, {
                    method: 'HEAD',
                    headers,
                    signal: controller.signal
                }, { onFinalUrl: (u) => { finalUrl = u; } });
                if (head.status < 400) upstream = head;
                else discardBody(head);
            } catch (e) {
                // A timeout or a client disconnect is not a statement about HEAD
                // support, and retrying would paper over it.
                if (headersTimedOut || isAbortErr(e)) throw e;
            }
        }

        if (!upstream) {
            // The fallback is a second exchange and gets its own deadline (audit
            // L12). The real panel answers HEAD with a 502 and its CDN drops the
            // connection, and it can take its time doing either; sharing one timer
            // left the GET whatever remained of it, which on a slow panel is
            // nothing at all. Two deadlines rather than one is the honest cost of
            // trying HEAD first, and only a request that already spent the first
            // one can pay the second.
            if (req.method === 'HEAD') armHeaderTimer();
            upstream = await safeFetch(upstreamUrl, {
                method: 'GET',
                headers,
                signal: controller.signal
            }, { onFinalUrl: (u) => { finalUrl = u; } });
        }
    } catch (e) {
        if (headersTimedOut) {
            console.warn(`[proxy] upstream headers timed out after ${PROXY_HEADER_TIMEOUT_MS}ms for ${label}`);
            if (!res.headersSent) res.status(504).end('upstream timeout');
            return;
        }
        if (!isAbortErr(e)) {
            console.warn(`[proxy] upstream fetch failed for ${label}: ${e.message}`);
        }
        if (!res.headersSent) res.status(502).end('upstream fetch failed');
        return;
    } finally {
        clearTimeout(headerTimer);
    }

    const contentType = upstream.headers.get('content-type');
    // Only a complete 200 body is rewritable; a 206 is a fragment, and an error
    // body is not a playlist whatever the extension says. A successful HEAD has
    // no body at all, but still needs to know a GET would be rewritten, so its
    // headers do not describe the provider's unrewritten body.
    const mapper = (upstream.status === 200 && (upstream.body || req.method === 'HEAD') && rewriteFor)
        ? rewriteFor(finalUrl, contentType)
        : null;

    // Fail closed on a partial playlist: a 206 skips the rewrite and would relay
    // the provider's credential-bearing URIs.
    if (!mapper && upstream.status === 206 && looksLikePlaylist(ext, contentType)) {
        console.warn(`[proxy] refusing to relay a partial playlist for ${label}`);
        discardBody(upstream);
        if (!res.headersSent) res.status(502).end('partial playlist');
        return;
    }

    if (mapper && req.method !== 'HEAD') {
        let text;
        // This branch buffers the whole body, so it gets its own deadline; the
        // header timer is already cleared.
        let bodyTimedOut = false;
        const bodyTimer = setTimeout(() => { bodyTimedOut = true; abort(); }, PLAYLIST_BODY_TIMEOUT_MS);
        try {
            text = await readTextCapped(upstream.body, MAX_PLAYLIST_BYTES);
        } catch (e) {
            if (bodyTimedOut) {
                console.warn(`[proxy] playlist body timed out after ${PLAYLIST_BODY_TIMEOUT_MS}ms for ${label}`);
                if (!res.headersSent) res.status(504).end('upstream timeout');
                return;
            }
            if (!isAbortErr(e)) console.warn(`[proxy] playlist read failed for ${label}: ${e.message}`);
            // readTextCapped holds a reader, so the body is locked and cannot be
            // cancelled — abort the request instead of leaving the socket half-read.
            abort();
            if (!res.headersSent) res.status(502).end('bad playlist');
            return;
        } finally {
            clearTimeout(bodyTimer);
        }

        // The body confirms what the headers suggested. A body without #EXTM3U
        // is refused, not relayed: it may still carry credential-bearing URLs.
        if (!HLS_BODY_PREFIX.test(text)) {
            console.warn(`[proxy] expected a playlist for ${label} but the body does not start with #EXTM3U; refusing`);
            if (!res.headersSent) res.status(502).end('bad playlist');
            return;
        }

        // The two timers above are both cleared by now, so this phase carries its
        // own deadline. See PLAYLIST_REWRITE_TIMEOUT_MS.
        let rewritten;
        try {
            rewritten = await rewriteHlsPlaylist(text, finalUrl, mapper, {
                deadline: Date.now() + PLAYLIST_REWRITE_TIMEOUT_MS
            });
        } catch (e) {
            const timedOut = e.code === 'PLAYLIST_REWRITE_TIMEOUT';
            const refused = e.code === 'PLAYLIST_TARGET_REFUSED';
            const how = timedOut
                ? `timed out after ${PLAYLIST_REWRITE_TIMEOUT_MS}ms`
                : (refused ? 'refused a target' : 'failed');
            console.warn(
                `[proxy] playlist rewrite ${how} for ${label}${timedOut ? '' : `: ${e.message}`}`
            );
            if (!res.headersSent) {
                res.status(timedOut ? 504 : 502)
                    .end(timedOut ? 'upstream timeout' : (refused ? 'playlist target refused' : 'bad playlist'));
            }
            return;
        }
        res.status(upstream.status);
        // Deliberately not forwarding content-length: the rewritten body is a
        // different size. Nor accept-ranges — a playlist is not seekable.
        if (contentType) res.setHeader('Content-Type', contentType);
        setRelayHeaders(res);
        return res.end(Buffer.from(rewritten, 'utf8'));
    }

    // A playlist can also arrive where only bytes were expected: a segment path and
    // a content type that says nothing route it straight here, and relaying it
    // verbatim hands the player the provider's own credential-bearing URLs — the
    // disclosure the rewrite exists to prevent, on the one path that never looked
    // (audit L10, confirmed: /live/ID.ts answered with an m3u8 as text/plain).
    //
    // Refused, not rewritten. What a body is has to be decided before any of it is
    // read, because the alternative here is a segment that must stream and keep its
    // Range support; sniffing stays a confirmation of a body already in hand, never
    // the thing that routes one. A provider naming a playlist on a segment path is
    // misbehaving, and 502 says so without leaking anything.
    let relay = null;
    if (!mapper && req.method !== 'HEAD' && upstream.status === 200 && upstream.body) {
        const stream = Readable.fromWeb(upstream.body);
        try {
            relay = { stream, ...await sniffPlaylistStart(stream) };
        } catch (e) {
            if (!isAbortErr(e)) console.warn(`[proxy] upstream body failed for ${label}: ${e.message}`);
            stream.destroy();
            abort();
            if (!res.headersSent) res.status(502).end('upstream stream failed');
            return;
        }
        if (relay.playlist) {
            console.warn(
                `[proxy] refusing to relay a playlist served as ${JSON.stringify(contentType || '')} for ${label}`
            );
            stream.destroy();
            abort();
            if (!res.headersSent) res.status(502).end('playlist on a segment path');
            return;
        }
    }

    res.status(upstream.status);

    // Forward headers relevant for seekable playback.
    // accept-ranges is deliberately absent: it is the one header here that is a
    // claim about the origin rather than a fact about this body, so it is
    // derived below instead of relayed.
    const forward = [
        'content-type',
        'content-length',
        'content-range',
        'last-modified',
        'etag'
    ];
    // undici decompresses transparently, so on a content-encoded response the
    // body handed to us is longer than the content-length that came with it.
    // Forwarding that number makes the client stop short or hang waiting for
    // bytes that already arrived. Unlikely for media, plausible for a playlist
    // or an error page, and the length is optional — Express falls back to
    // chunked encoding without it.
    const encoded = Boolean(upstream.headers.get('content-encoding'));
    // Only a HEAD reaches here with a mapper. The GET it previews is rewritten,
    // so upstream's length is the wrong body's, and a playlist is not seekable —
    // the same two headers the rewrite branch above leaves out.
    const previewsRewrite = Boolean(mapper);
    for (const h of forward) {
        if ((encoded || previewsRewrite) && h === 'content-length') continue;
        const v = upstream.headers.get(h);
        if (v) res.setHeader(h, v);
    }

    const acceptRanges = previewsRewrite ? null : normalizeAcceptRanges({
        status: upstream.status,
        upstreamValue: upstream.headers.get('accept-ranges'),
        sentRange,
        sentIfRange
    });
    if (acceptRanges) res.setHeader('Accept-Ranges', acceptRanges);
    setRelayHeaders(res);

    if (req.method === 'HEAD' || !upstream.body) {
        // A HEAD that fell back to GET above still has a body nobody will read.
        discardBody(upstream);
        return res.end();
    }

    // Already wrapped if the sniff ran; the web body can only be taken once.
    const nodeStream = relay ? relay.stream : Readable.fromWeb(upstream.body);
    nodeStream.on('error', (e) => {
        if (!isAbortErr(e)) {
            console.warn(`[proxy] stream error for ${label}: ${e.message}`);
        }
        // The client is already gone, or the response already finished.
        if (res.destroyed || res.writableEnded) return;
        // Once bytes are out, status and length are promised: destroy the socket
        // so the player retries, rather than leaving it waiting on keep-alive.
        if (res.headersSent) return res.destroy();
        // Nothing sent yet: drop the upstream headers and answer a bare 502.
        for (const h of [...forward, 'accept-ranges']) res.removeHeader(h);
        const body = 'upstream stream failed';
        res.status(502);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Content-Length', String(Buffer.byteLength(body)));
        res.end(body);
    });
    res.on('error', () => abort());
    res.on('close', () => {
        abort();
        nodeStream.destroy();
    });
    if (relay && relay.head.length) res.write(relay.head);
    if (relay && relay.ended) return res.end();
    nodeStream.pipe(res);
}

// Stream proxy. Providers 302 to a CDN URL whose token expires in about a minute,
// so every range request is re-resolved here; this also keeps the credentials in
// the upstream path off the player.
//
// Extra hostnames a playlist may name beyond the panel and the playlist's own
// origin, for a provider that fans out. Every entry is a host this server will
// fetch from on a provider's instruction.
const HLS_TARGET_ALLOWED_HOSTS = parseHostList(process.env.HLS_TARGET_ALLOWED_HOSTS, 'HLS_TARGET_ALLOWED_HOSTS');

// The origins a playlist may name: the panel, and the URLs the playlist was
// requested from and finally fetched from, since providers 302 playlists to a CDN.
// A panel URL that will not parse contributes nothing.
function panelOrigin(cfg) {
    try {
        return normalizeUrl(cfg.serverUrl);
    } catch {
        return null;
    }
}

function hlsTargetOrigins(...candidates) {
    const origins = new Set();
    for (const candidate of candidates) {
        if (!candidate) continue;
        try {
            origins.add(new URL(candidate).origin);
        } catch { /* not a usable origin; simply contributes nothing */ }
    }
    return origins;
}

// `allowedOrigins` is required, with no permissive default, so a caller that forgets
// it signs nothing. It bounds a misbehaving playlist from an honest panel, not a
// malicious panel, whose own origins are in the set (audit D1; see S3).
function makeHlsProxyMapper(base, configToken, allowedOrigins) {
    // Vetting is per origin, shared through hlsOriginVetCache, and distinct origins
    // are capped per playlist; past the cap the playlist is refused.
    const seen = new Set();
    let warned = false;
    let refusedOrigin = false;
    return async (absolute, playlist = false) => {
        let url;
        try {
            url = new URL(absolute);
        } catch {
            return null;
        }
        const origin = url.origin;

        // Checked before the cap and any DNS work, so foreign hosts cost nothing.
        // assertSafeOutboundUrl alone would admit every public host.
        if (!(allowedOrigins && allowedOrigins.has(origin))
            && !HLS_TARGET_ALLOWED_HOSTS.has(url.hostname.toLowerCase())) {
            if (!refusedOrigin) {
                refusedOrigin = true;
                console.warn(
                    `[proxy] playlist names ${origin}, which is neither the account's panel nor the ` +
                    'origin the playlist came from; refusing the playlist ' +
                    '(add it to HLS_TARGET_ALLOWED_HOSTS if the provider legitimately uses it)'
                );
            }
            return null;
        }

        if (!seen.has(origin)) {
            if (seen.size >= MAX_PLAYLIST_ORIGINS) {
                if (!warned) {
                    warned = true;
                    console.warn(
                        `[proxy] playlist names more than ${MAX_PLAYLIST_ORIGINS} distinct origins; ` +
                        'refusing the playlist (raise MAX_PLAYLIST_ORIGINS if a provider legitimately fans out)'
                    );
                }
                return null;
            }
            seen.add(origin);
        }

        if (!await vetHlsOrigin(absolute, origin)) return null;

        const { u, s, e } = encodeHlsTarget(absolute, configToken, Date.now(), playlist);
        return `${base}/${configToken}/proxy/hls?u=${u}&s=${s}&e=${e}`;
    };
}

// Concurrent relay caps. An install URL is a bearer credential, and a leaked or
// shared one could otherwise open unlimited full-rate streams. The per-account cap
// is keyed by account, not token string, since /configure mints fresh tokens for
// the same credentials on demand. Parsed by hand because 0 (disabled) is meaningful
// and `Number(x) || default` would turn it into the default.
function relayLimitFromEnv(name, fallback) {
    const raw = process.env[name];
    if (typeof raw !== 'string' || !raw.trim()) return fallback;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

const PROXY_MAX_CONCURRENT_PER_TOKEN = relayLimitFromEnv('PROXY_MAX_CONCURRENT_PER_TOKEN', 16);

// Accounts are free to make (audit S3), so relays are also capped per client
// (keyed by clientKey; generous, for carrier NAT) and in total (size it to your
// bandwidth).
const PROXY_MAX_CONCURRENT_PER_CLIENT = relayLimitFromEnv('PROXY_MAX_CONCURRENT_PER_CLIENT', 32);
const PROXY_MAX_CONCURRENT_TOTAL = relayLimitFromEnv('PROXY_MAX_CONCURRENT_TOTAL', 256);

const proxyInFlight = new Map();          // relays per account
const proxyInFlightByClient = new Map();  // relays per client bucket
const proxyRelays = { total: 0 };         // an object, so an importer sees it change

function releaseCount(map, key) {
    const left = (map.get(key) || 1) - 1;
    // Delete at zero: the key space is every account and address that ever
    // streamed, and an idle one must not cost an entry.
    if (left > 0) map.set(key, left);
    else map.delete(key);
}

// Takes a slot for the life of this response and returns null, or returns the
// limit that refused it ({ scope }). All limits are checked before any is counted.
// Released on the response's `close`, which fires once on completion and on abort
// alike; relayUpstream returns long before a relay ends.
function acquireProxySlot(cfg, req, res) {
    if (!PROXY_MAX_CONCURRENT_PER_TOKEN && !PROXY_MAX_CONCURRENT_PER_CLIENT && !PROXY_MAX_CONCURRENT_TOTAL) {
        return null;
    }
    const account = accountCacheKey(cfg);
    const client = clientKey(req);
    const byAccount = proxyInFlight.get(account) || 0;
    const byClient = proxyInFlightByClient.get(client) || 0;

    if (PROXY_MAX_CONCURRENT_PER_TOKEN && byAccount >= PROXY_MAX_CONCURRENT_PER_TOKEN) {
        console.warn(
            `[proxy] per-account concurrency cap reached (${byAccount}/${PROXY_MAX_CONCURRENT_PER_TOKEN}); ` +
            'raise PROXY_MAX_CONCURRENT_PER_TOKEN if this is legitimate traffic'
        );
        return { scope: 'account' };
    }
    if (PROXY_MAX_CONCURRENT_PER_CLIENT && byClient >= PROXY_MAX_CONCURRENT_PER_CLIENT) {
        console.warn(
            `[proxy] per-client concurrency cap reached for ${client} (${byClient}/${PROXY_MAX_CONCURRENT_PER_CLIENT}); ` +
            'raise PROXY_MAX_CONCURRENT_PER_CLIENT if this is legitimate traffic, or check TRUST_PROXY if every client shares one address'
        );
        return { scope: 'client' };
    }
    if (PROXY_MAX_CONCURRENT_TOTAL && proxyRelays.total >= PROXY_MAX_CONCURRENT_TOTAL) {
        console.warn(
            `[proxy] total concurrency cap reached (${proxyRelays.total}/${PROXY_MAX_CONCURRENT_TOTAL}); ` +
            'raise PROXY_MAX_CONCURRENT_TOTAL if the host has the bandwidth'
        );
        return { scope: 'total' };
    }

    if (PROXY_MAX_CONCURRENT_PER_TOKEN) proxyInFlight.set(account, byAccount + 1);
    if (PROXY_MAX_CONCURRENT_PER_CLIENT) proxyInFlightByClient.set(client, byClient + 1);
    if (PROXY_MAX_CONCURRENT_TOTAL) proxyRelays.total += 1;
    let released = false;
    res.once('close', () => {
        if (released) return;
        released = true;
        if (PROXY_MAX_CONCURRENT_PER_TOKEN) releaseCount(proxyInFlight, account);
        if (PROXY_MAX_CONCURRENT_PER_CLIENT) releaseCount(proxyInFlightByClient, client);
        if (PROXY_MAX_CONCURRENT_TOTAL) proxyRelays.total = Math.max(0, proxyRelays.total - 1);
    });
    return null;
}

// A caller over its own budget gets 429: the limit is a property of its usage, not
// of the server's health, and Retry-After tells a player to come back for the
// segment rather than treating it as the end of the stream. The total limit is the
// server's capacity, which is what 503 says, with a longer wait since a slot there
// frees only when someone else's stream ends.
function rejectOverCap(res, refused = { scope: 'account' }) {
    if (refused.scope === 'total') {
        res.setHeader('Retry-After', '5');
        return res.status(503).end('server at stream capacity');
    }
    res.setHeader('Retry-After', '1');
    return res.status(429).end('too many concurrent streams');
}

module.exports = {
    PROXY_USER_AGENT,
    PROXY_HEADER_TIMEOUT_MS,
    PLAYLIST_BODY_TIMEOUT_MS,
    MAX_PLAYLIST_ORIGINS,
    PLAYLIST_REWRITE_TIMEOUT_MS,
    HLS_ORIGIN_VET_TTL_MS,
    HLS_ORIGIN_VET_MAX,
    hlsOriginVetCache,
    vetHlsOrigin,
    hlsPrefixVerdict,
    sniffPlaylistStart,
    setRelayHeaders,
    normalizeAcceptRanges,
    relayUpstream,
    panelOrigin,
    hlsTargetOrigins,
    makeHlsProxyMapper,
    HLS_TARGET_ALLOWED_HOSTS,
    relayLimitFromEnv,
    PROXY_MAX_CONCURRENT_PER_TOKEN,
    PROXY_MAX_CONCURRENT_PER_CLIENT,
    PROXY_MAX_CONCURRENT_TOTAL,
    proxyInFlight,
    proxyInFlightByClient,
    proxyRelays,
    acquireProxySlot,
    rejectOverCap
};
