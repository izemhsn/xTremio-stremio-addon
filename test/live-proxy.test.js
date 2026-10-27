// M9 — live TV handed the account credentials to the player.
//
// The live stream route used to return `${serverUrl}/live/${user}/${pass}/${id}.m3u8`
// straight to Stremio. Unlike movies and episodes, which have always gone
// through the proxy, that put the password in the player's logs and — for the
// http-only providers that are the norm — in cleartext on the wire.
//
// Routing live through the proxy fixes the .ts case for free, because a
// transport stream relays byte-for-byte. It does not fix .m3u8: an Xtream
// playlist names its segments by absolute URLs that embed /user/pass/
// themselves, so relaying that body unchanged would move the disclosure from
// the URL into the body. Playlists are therefore rewritten, and the rewritten
// sub-resource links are HMAC-signed so the passthrough route cannot be used
// as an open proxy.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const http = require('node:http');

const {
    app,
    encodeConfig,
    signTokenBody,
    rewriteHlsPlaylist,
    looksLikePlaylist,
    encodeHlsTarget,
    decodeHlsTarget,
    signHlsTarget,
    hlsPrefixVerdict
} = require('./support/internals.js');

const realFetch = global.fetch;

// Distinctive enough that an assertion on their absence cannot pass by
// coincidence against a base64 token or a hex id.
const USERNAME = 'alice-user-must-not-leak';
const PASSWORD = 'p4ssword-must-not-leak';

let provider;          // the fake Xtream server
let providerBase;
let providerHits;      // every path the addon requested upstream
let providerEncodings; // the Accept-Encoding sent with each of those requests

let server;            // the addon under test
let base;
let CFG;

// --- the fake provider -----------------------------------------------------
//
// Serves the two live formats the way a real Xtream panel does, including the
// detail that matters here: the playlist's segment URLs carry the credentials.

function providerHandler(req, res) {
    providerHits.push(req.url);
    providerEncodings.push(req.headers['accept-encoding']);
    const creds = `${USERNAME}/${PASSWORD}`;

    // Playlists go out with an explicit Content-Length, the way a real panel
    // serving a file does. Node would otherwise pick chunked encoding, and a
    // proxy that wrongly forwards the upstream length onto a rewritten (and so
    // differently sized) body would go unnoticed.
    const sendPlaylist = (text) => {
        const buf = Buffer.from(text, 'utf8');
        // A Range request here must never happen: the proxy is supposed to
        // withhold it, because a fragment cannot be parsed or rewritten.
        // Answering one faithfully is what makes that testable.
        if (req.headers.range) {
            const fragment = buf.subarray(0, 12);
            res.writeHead(206, {
                'Content-Type': 'application/vnd.apple.mpegurl',
                'Content-Range': `bytes 0-11/${buf.length}`,
                'Content-Length': fragment.length
            });
            return res.end(fragment);
        }
        res.writeHead(200, {
            'Content-Type': 'application/vnd.apple.mpegurl',
            'Content-Length': buf.length
        });
        return res.end(buf);
    };

    if (req.url === `/live/${creds}/5.ts`) {
        res.writeHead(200, { 'Content-Type': 'video/mp2t' });
        return res.end('TS-BYTES-PAYLOAD');
    }

    // L10 — a panel answering a .ts stream request with a playlist, labelled as
    // something that is not one. Neither the path nor the content type says
    // "playlist", so nothing routes it to the rewrite, and its segment URLs carry
    // the account's credentials exactly like any other Xtream playlist.
    if (req.url === `/live/${creds}/13.ts`) {
        const body = [
            '#EXTM3U',
            '#EXT-X-TARGETDURATION:8',
            '#EXTINF:8.000,',
            `${providerBase}/hls/${creds}/seg1.ts`,
            ''
        ].join('\n');
        res.writeHead(200, {
            'Content-Type': 'text/plain',
            'Content-Length': Buffer.byteLength(body)
        });
        return res.end(body);
    }

    // A body shorter than the sniff window, which therefore ends inside it. The
    // relay has to send exactly these bytes and finish, not wait for more.
    if (req.url === `/live/${creds}/14.ts`) {
        res.writeHead(200, { 'Content-Type': 'video/mp2t', 'Content-Length': 3 });
        return res.end('TSx');
    }

    // A panel answering a stream request with an error page, which real ones do.
    // It reaches the player as what it is; the L8 headers are what keep it from
    // being rendered as a document on this addon's origin.
    if (req.url === `/live/${creds}/12.ts`) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end('<script>alert(document.domain)</script>');
    }

    // A media playlist whose segments are absolute and credential-bearing.
    if (req.url === `/live/${creds}/5.m3u8`) {
        return sendPlaylist([
            '#EXTM3U',
            '#EXT-X-VERSION:3',
            '#EXT-X-TARGETDURATION:8',
            `#EXT-X-KEY:METHOD=AES-128,URI="${providerBase}/hls/${creds}/key.bin"`,
            '#EXTINF:8.000,',
            `${providerBase}/hls/${creds}/seg1.ts`,
            '#EXTINF:8.000,',
            'seg2.ts',
            ''
        ].join('\n'));
    }

    // A master playlist, to prove nested rewriting works.
    if (req.url === `/live/${creds}/7.m3u8`) {
        return sendPlaylist([
            '#EXTM3U',
            '#EXT-X-STREAM-INF:BANDWIDTH=1200000',
            `${providerBase}/hls/${creds}/variant.m3u8`,
            ''
        ].join('\n'));
    }

    // A channel that redirects to a CDN path several segments deep, the way a
    // real provider does. The playlist it lands on uses a relative segment, so
    // resolving against the *requested* URL instead of the final one would
    // produce a wrong target.
    if (req.url === `/live/${creds}/9.m3u8`) {
        res.writeHead(302, { Location: '/cdn/deep/path/play.m3u8' });
        return res.end();
    }

    if (req.url === '/cdn/deep/path/play.m3u8') {
        return sendPlaylist('#EXTM3U\n#EXTINF:8.000,\nrelseg.ts\n');
    }

    // A playlist that names a host outside both the account's panel and the
    // origin it was served from. Nothing on that host may be signed.
    if (req.url === `/live/${creds}/8.m3u8`) {
        return sendPlaylist([
            '#EXTM3U',
            '#EXTINF:8.000,',
            `${providerBase}/hls/${creds}/seg1.ts`,
            '#EXTINF:8.000,',
            'http://foreign-cdn.example.net/seg9.ts',
            ''
        ].join('\n'));
    }

    if (req.url === `/hls/${creds}/variant.m3u8`) {
        return sendPlaylist(`#EXTM3U\n#EXTINF:8.000,\n${providerBase}/hls/${creds}/seg9.ts\n`);
    }

    // C5 — a master playlist whose variant is named without an extension. Real
    // panels do this, and serve the variant as text/plain, so neither the path
    // nor the content type says "playlist".
    if (req.url === `/live/${creds}/11.m3u8`) {
        return sendPlaylist([
            '#EXTM3U',
            '#EXT-X-STREAM-INF:BANDWIDTH=1200000',
            `${providerBase}/hls/${creds}/chunklist_dvr`,
            ''
        ].join('\n'));
    }

    // An .m3u8 path with a content type that says nothing, so only the path can
    // identify it.
    if (req.url === `/hls/${creds}/plain.m3u8`) {
        const body = `#EXTM3U\n#EXTINF:8.000,\n${providerBase}/hls/${creds}/seg9.ts\n`;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': Buffer.byteLength(body)
        });
        return res.end(body);
    }

    if (req.url === `/hls/${creds}/chunklist_dvr`) {
        const body = `#EXTM3U\n#EXTINF:8.000,\n${providerBase}/hls/${creds}/seg9.ts\n`;
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(body) });
        return res.end(body);
    }

    // Answers 206 whether or not a Range was asked for, which is the only way a
    // fragment of a playlist can still reach the relay now that Range is
    // withheld for anything known to be one.
    if (req.url === `/hls/${creds}/rogue206.m3u8`) {
        const body = `#EXTM3U\n#EXTINF:8.000,\n${providerBase}/hls/${creds}/seg1.ts\n`;
        const fragment = Buffer.from(body, 'utf8').subarray(0, 12);
        res.writeHead(206, {
            'Content-Type': 'application/vnd.apple.mpegurl',
            'Content-Range': `bytes 0-11/${Buffer.byteLength(body)}`,
            'Content-Length': fragment.length
        });
        return res.end(fragment);
    }

    // Named .m3u8 and really a transport stream. Detection happens before the
    // body arrives, so this is what reaches the rewrite.
    if (req.url === `/hls/${creds}/notreally.m3u8`) {
        res.writeHead(200, { 'Content-Type': 'video/mp2t' });
        return res.end(Buffer.from([0x47, 0x40, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03]));
    }

    if (req.url.endsWith('seg1.ts') || req.url.endsWith('seg9.ts')) {
        // Explicit, because Node only derives a length from the body on a GET, and
        // a HEAD test needs one upstream to prove it is forwarded.
        res.writeHead(200, { 'Content-Type': 'video/mp2t', 'Content-Length': Buffer.byteLength('SEGMENT-BYTES') });
        return res.end('SEGMENT-BYTES');
    }

    if (req.url.endsWith('key.bin')) {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        return res.end('KEYMATERIAL0123x');
    }

    res.writeHead(404).end('nope');
}

beforeAll(async () => {
    provider = http.createServer(providerHandler);
    await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
    providerBase = `http://127.0.0.1:${provider.address().port}`;

    CFG = encodeConfig({ serverUrl: providerBase, username: USERNAME, password: PASSWORD });

    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => provider.close(resolve));
});

beforeEach(() => { providerHits = []; providerEncodings = []; });

// The addon's own outbound calls go through global.fetch; the test client must
// not, so it uses the reference saved before any stubbing.
const get = (path) => realFetch(`${base}/${CFG}${path}`);

// A rewritten link names its target as ciphertext bound to this account's token
// and to the link's own expiry, so a test reads it back the way the route does.
// Decoding the `u` payload directly used to work, which was the whole problem:
// anything that could read the URL could read the provider credentials in it.
const targetOf = (link) => {
    const q = new URL(link).searchParams;
    return decodeHlsTarget(q.get('u'), q.get('s'), q.get('e'), CFG)?.url;
};

// --- rewriteHlsPlaylist ----------------------------------------------------

const proxied = (url) => `PROXY(${url})`;

test('rewriteHlsPlaylist rewrites segment URI lines', async () => {
    const out = await rewriteHlsPlaylist(
        '#EXTM3U\n#EXTINF:8.000,\nhttp://cdn.test/a/seg1.ts\n',
        'http://cdn.test/a/play.m3u8',
        proxied
    );
    expect(out).toMatch(/PROXY\(http:\/\/cdn\.test\/a\/seg1\.ts\)/);
    // Tags without a URI are untouched.
    expect(out).toMatch(/^#EXTM3U$/m);
    expect(out).toMatch(/^#EXTINF:8\.000,$/m);
});

test('relative URIs resolve against the playlist URL, not the requested one', async () => {
    // This is why safeFetch reports its final URL: the provider redirects
    // /live/... to a CDN path, and resolving against the original request
    // would point every segment at the wrong place.
    const out = await rewriteHlsPlaylist(
        '#EXTM3U\nseg2.ts\n',
        'http://cdn.test/deep/path/play.m3u8',
        proxied
    );
    expect(out).toMatch(/PROXY\(http:\/\/cdn\.test\/deep\/path\/seg2\.ts\)/);
});

test('URI="..." attributes are rewritten too', async () => {
    // EXT-X-KEY is the one that matters most: it is a real sub-resource, and on
    // an Xtream provider its URL carries the credentials like any segment.
    const out = await rewriteHlsPlaylist(
        '#EXT-X-KEY:METHOD=AES-128,URI="http://cdn.test/k.bin",IV=0x1\n#EXT-X-MEDIA:TYPE=AUDIO,URI="alt.m3u8"\n',
        'http://cdn.test/play.m3u8',
        proxied
    );
    expect(out).toMatch(/URI="PROXY\(http:\/\/cdn\.test\/k\.bin\)"/);
    expect(out).toMatch(/URI="PROXY\(http:\/\/cdn\.test\/alt\.m3u8\)"/);
    // Other attributes on the same line survive intact.
    expect(out).toMatch(/METHOD=AES-128/);
    expect(out).toMatch(/IV=0x1/);
});

test('blank lines and CRLF endings are preserved', async () => {
    // Some players are strict about line endings; a rewrite that silently
    // normalised them would break playback for reasons nobody would guess.
    const out = await rewriteHlsPlaylist(
        '#EXTM3U\r\n\r\nseg.ts\r\n',
        'http://cdn.test/p.m3u8',
        proxied
    );
    expect(out).toContain('#EXTM3U\r\n');
    expect(out).toContain('PROXY(http://cdn.test/seg.ts)\r\n');
    expect(out, 'blank line kept').toContain('\r\n\r\n');
});

test('unresolvable or non-http URIs are left alone rather than dropped', async () => {
    const out = await rewriteHlsPlaylist(
        '#EXT-X-KEY:METHOD=AES-128,URI="data:text/plain;base64,AAAA"\n',
        'http://cdn.test/p.m3u8',
        proxied
    );
    expect(out).toMatch(/URI="data:text\/plain;base64,AAAA"/);
    expect(out).not.toContain('PROXY(');
});

test('looksLikePlaylist keys off the extension or the content type', () => {
    // Providers routinely mislabel playlists as text/plain, so the extension
    // has to be enough on its own.
    expect(looksLikePlaylist('m3u8', 'text/plain')).toBeTruthy();
    expect(looksLikePlaylist('M3U8', null)).toBeTruthy();
    expect(looksLikePlaylist(null, 'application/vnd.apple.mpegurl')).toBeTruthy();
    expect(looksLikePlaylist(null, 'application/x-mpegURL; charset=utf-8')).toBeTruthy();
    expect(looksLikePlaylist('ts', 'video/mp2t')).toBeFalsy();
    expect(looksLikePlaylist(null, 'video/mp2t')).toBeFalsy();
});

// --- signed sub-resource targets -------------------------------------------

test('a signed target round-trips', () => {
    const { u, s, e } = encodeHlsTarget('http://cdn.test/a/seg1.ts?tok=9', CFG);
    expect(decodeHlsTarget(u, s, e, CFG)?.url).toBe('http://cdn.test/a/seg1.ts?tok=9');
});

test('an unsigned or forged target is rejected', () => {
    // Without this the /proxy/hls route would fetch any URL a caller named,
    // making the instance an open proxy to anyone holding an install token.
    const { u, s, e } = encodeHlsTarget('http://cdn.test/seg.ts', CFG);
    const evil = Buffer.from('http://attacker.test/', 'utf8').toString('base64url');

    expect(decodeHlsTarget(u, 'not-a-signature', e, CFG)).toBeNull();
    expect(decodeHlsTarget(evil, s, e, CFG), 'signature for a different payload').toBeNull();
    expect(decodeHlsTarget(u, undefined, e, CFG)).toBeNull();
    expect(decodeHlsTarget(undefined, undefined, e, CFG)).toBeNull();
});

test('non-http targets are rejected even when correctly signed', () => {
    // Minted through encodeHlsTarget so the payload is genuinely this server's
    // own ciphertext: a hand-built one would be turned away by the MAC or the
    // GCM tag first and never reach the protocol check this test is about.
    const { u, s, e } = encodeHlsTarget('file:///etc/passwd', CFG);
    expect(decodeHlsTarget(u, s, e, CFG)).toBeNull();
});

test('HLS signatures are domain-separated from config-token MACs', () => {
    // They use different keys, and the "hls:" prefix separates the signed
    // strings as well, so a value valid in one position cannot be replayed in
    // the other however either format changes.
    const body = 'v3.aaa.bbb.ccc';
    expect(signHlsTarget(body)).not.toBe(signTokenBody(body));
});

// --- the M9 regression itself ----------------------------------------------

test('the live stream route hands out no credentials', async () => {
    const res = await get('/stream/Live%20TV/xtremio_live_5.json');
    expect(res.status).toBe(200);
    const body = await res.text();

    expect(body, 'password must not reach the player').not.toContain(PASSWORD);
    expect(body, 'username must not reach the player').not.toContain(USERNAME);

    const { streams } = JSON.parse(body);
    expect(streams.length, 'both HLS and MPEG-TS still offered').toBe(2);
    for (const s of streams) {
        expect(s.url.startsWith(`${base}/${CFG}/proxy/live/5.`), `proxied: ${s.url}`).toBeTruthy();
        // Neither format is MP4, so the player must not treat it as web-ready —
        // getting this wrong makes playback stop after about a minute.
        expect(s.behaviorHints.notWebReady).toBe(true);
    }
    // No upstream call is needed to answer this.
    expect(providerHits).toStrictEqual([]);
});

test('the .ts proxy relays the stream and authenticates upstream itself', async () => {
    const res = await get('/proxy/live/5.ts');
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('TS-BYTES-PAYLOAD');
    // The credentials still go upstream — they just stop at this server.
    expect(providerHits).toStrictEqual([`/live/${USERNAME}/${PASSWORD}/5.ts`]);
});

test('the .m3u8 proxy rewrites the playlist so no credentials reach the player', async () => {
    const res = await get('/proxy/live/5.m3u8');
    expect(res.status).toBe(200);
    const body = await res.text();

    // The whole point: the provider's own playlist named the credentials in
    // every segment URL, and relaying it verbatim would have leaked them.
    expect(body, `password leaked in playlist body:\n${body}`).not.toContain(PASSWORD);
    expect(body, 'username leaked in playlist body').not.toContain(USERNAME);

    // Structure is preserved and every URI now points back at this server.
    expect(body).toMatch(/^#EXTM3U$/m);
    expect(body).toMatch(/^#EXT-X-TARGETDURATION:8$/m);
    const links = body.split('\n').filter(l => l.includes('/proxy/hls?'));
    expect(links.length, 'key + 2 segments rewritten').toBe(3);
    for (const line of links) {
        expect(line, line).toContain(`${base}/${CFG}/proxy/hls?u=`);
    }

    // The rewritten body is longer than the one upstream declared, so
    // forwarding that content-length would truncate the response. Asserting
    // the received length against the header would be self-fulfilling — a
    // truncated body matches a truncated header — so the check is that the
    // last line survived and the length matches the *upstream* body's, which
    // it must not.
    expect(body, 'body reaches its final line').toMatch(/seg2\.ts|\/proxy\/hls\?u=[^\n]*\n?$/);
    expect(body.trimEnd().split('\n').length === 8, `all 8 lines present:\n${body}`).toBeTruthy();
    expect(res.headers.get('content-length')).toBe(String(Buffer.byteLength(body)));
});

test('a byte relay asks upstream for an unencoded body', async () => {
    // Left to undici's default it offered gzip, and an origin honouring that on
    // a ranged request answers with offsets into the compressed representation,
    // which do not describe the decompressed bytes being relayed.
    const res = await get('/proxy/live/5.ts');
    expect(res.status).toBe(200);
    await res.text();
    expect(providerEncodings).toStrictEqual(['identity']);
});

test('a playlist fetch keeps compression negotiable', async () => {
    // Playlists are text, read whole and rewritten, so gzip is a plain win there.
    await (await get('/proxy/live/5.m3u8')).text();
    expect(providerEncodings.length).toBe(1);
    expect(providerEncodings[0]).not.toBe('identity');
});

test('a HEAD on a playlist does not advertise the unrewritten length', async () => {
    // HEAD used to forward upstream's Content-Length, which describes the
    // provider's body; the GET that follows returns a rewritten, longer one.
    const head = await realFetch(`${base}/${CFG}/proxy/live/5.m3u8`, { method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(head.headers.get('content-length')).toBeNull();
    expect(head.headers.get('accept-ranges'), 'a playlist is not seekable').toBeNull();
    expect(head.headers.get('content-type') || '').toMatch(/mpegurl/i);
});

test('a HEAD on a byte relay still forwards its length and range support', async () => {
    // The other side of the change above: nothing is rewritten here, so the
    // upstream length is the real one.
    const head = await realFetch(`${base}/${CFG}/proxy/hls?${new URLSearchParams(
        encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/seg1.ts`, CFG)
    )}`, { method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(head.headers.get('content-length')).toBe(String(Buffer.byteLength('SEGMENT-BYTES')));
    expect(head.headers.get('accept-ranges')).toBe('bytes');
});

test('a Range header is not forwarded to a playlist request', async () => {
    // A 206 fragment cannot be parsed or rewritten, so the proxy withholds
    // Range when it knows a playlist is coming. Were it forwarded, this
    // provider would answer 206 with the first 12 bytes and the rewrite would
    // be skipped — relaying the provider's own credential-bearing body.
    const res = await realFetch(`${base}/${CFG}/proxy/live/5.m3u8`, {
        headers: { Range: 'bytes=0-11' }
    });
    expect(res.status, 'a full playlist, not a 206 fragment').toBe(200);
    const body = await res.text();
    expect(body, 'a fragment would have been relayed unrewritten').not.toContain(PASSWORD);
    expect(body, 'still rewritten').toContain('/proxy/hls?u=');
});

test('a Range on a nested playlist is withheld, not forwarded', async () => {
    // The sub-resource route forwards Range for EXT-X-BYTERANGE segments, and a
    // ranged request for a nested *playlist* used to come back 206 and bypass
    // the rewrite. The route now knows a playlist is coming before it asks, so
    // it withholds the Range and gets a whole body it can rewrite. The fake
    // provider answers 206 whenever it sees a Range, so a 200 here is the proof.
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/variant.m3u8`, CFG);
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${u}&s=${s}&e=${e}`, {
        headers: { Range: 'bytes=0-11' }
    });
    const body = await res.text();

    expect(res.status).toBe(200);
    expect(body).not.toContain(PASSWORD);
    expect(body, 'the segment inside was rewritten').toContain('/proxy/hls?u=');
});

test('a partial playlist is refused rather than relayed unrewritten', async () => {
    // A provider that answers 206 unasked. The fragment cannot be parsed or
    // rewritten, and relaying it would leak the credentials it names.
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/rogue206.m3u8`, CFG);
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${u}&s=${s}&e=${e}`);

    expect(res.status).toBe(502);
    expect((await res.text())).not.toContain(PASSWORD);
});

// --- C5: a nested playlist the provider labelled as anything else -----------

test('a variant playlist with no extension and a text/plain type is rewritten', async () => {
    // The finding. Detection rested on the response's content type alone, and
    // this variant has neither an .m3u8 path nor an HLS content type — so the
    // body was relayed exactly as the provider wrote it, with the segment URLs
    // that carry the account credentials still in it. What settles it now is the
    // master playlist: a URI on an EXT-X-STREAM-INF line can only be a playlist,
    // and the link minted for it says so.
    const master = await (await get('/proxy/live/11.m3u8')).text();
    const variantLink = master.split('\n').find(l => l.includes('/proxy/hls?u='));
    expect(variantLink, 'the variant was rewritten in the master').toBeTruthy();

    const res = await realFetch(variantLink);
    const body = await res.text();

    expect(res.status).toBe(200);
    expect(body, 'no credentials reach the player').not.toContain(PASSWORD);
    expect(body).not.toContain(USERNAME);
    expect(body, 'its segment was rewritten in turn').toContain('/proxy/hls?u=');
});

test('the kind a link carries is the playlist structure, not a guess', async () => {
    const master = await (await get('/proxy/live/11.m3u8')).text();
    const variantLink = master.split('\n').find(l => l.includes('/proxy/hls?u='));

    const media = await (await get('/proxy/live/5.m3u8')).text();
    const segmentLink = media.split('\n').find(l => l.startsWith(base) && !l.startsWith('#'));
    const keyLine = media.split('\n').find(l => l.startsWith('#EXT-X-KEY'));
    const keyLink = keyLine.replace(/^#.*URI="/, '').replace(/"$/, '');

    const kindOf = (link) => {
        const q = new URL(link).searchParams;
        return decodeHlsTarget(q.get('u'), q.get('s'), q.get('e'), CFG).playlist;
    };

    expect(kindOf(variantLink), 'a variant stream URI').toBe(true);
    expect(kindOf(segmentLink), 'a segment line keeps its Range support').toBe(false);
    expect(kindOf(keyLink), 'an EXT-X-KEY URI is a key, not a playlist').toBe(false);
});

test('a .m3u8 path is enough on its own, whatever the content type says', async () => {
    // The other half of the detection: a target this server did not mint from a
    // tag context still identifies itself by its path. Served as
    // application/octet-stream, so the content type contributes nothing.
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/plain.m3u8`, CFG);
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${u}&s=${s}&e=${e}`);
    const body = await res.text();

    expect(res.status).toBe(200);
    expect(body).not.toContain(PASSWORD);
    expect(body).toContain('/proxy/hls?u=');
});

test('a target that claims .m3u8 but sends a video body is refused, not mangled', async () => {
    // Detection happens before any of the body arrives, so a mislabelled target
    // reaches the rewrite. Parsing a transport stream as a playlist would hand
    // the player a corrupted body; refusing says what actually happened.
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/notreally.m3u8`, CFG);
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${u}&s=${s}&e=${e}`);

    expect(res.status).toBe(502);
    expect(await res.text()).toBe('bad playlist');
});

test('a rewritten segment link fetches through the signed passthrough', async () => {
    const playlist = await (await get('/proxy/live/5.m3u8')).text();
    const segLine = playlist.split('\n').find(l => l.startsWith(base) && !l.startsWith('#'));
    expect(segLine, 'a segment line was rewritten').toBeTruthy();

    providerHits = [];
    const res = await realFetch(segLine);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('SEGMENT-BYTES');
    expect(providerHits).toStrictEqual([`/hls/${USERNAME}/${PASSWORD}/seg1.ts`]);
});

test('a relative segment resolves against the playlist, not the proxy path', async () => {
    // `seg2.ts` in the provider's playlist must become the provider's
    // /live/<creds>/seg2.ts, not a URL on this server.
    const playlist = await (await get('/proxy/live/5.m3u8')).text();
    const lines = playlist.split('\n').filter(l => l.includes('/proxy/hls?u='));
    const targets = lines.map((l) => targetOf(l.replace(/^#.*URI="/, '').replace(/"$/, '')));
    expect(
        targets.some(t => t === `${providerBase}/live/${USERNAME}/${PASSWORD}/seg2.ts`),
        `relative segment resolved wrongly: ${JSON.stringify(targets)}`
    ).toBeTruthy();
});

test('relative segments resolve against the post-redirect playlist URL', async () => {
    // The end-to-end case for safeFetch's onFinalUrl. The provider redirects
    // /live/<creds>/9.m3u8 to /cdn/deep/path/play.m3u8; the relative `relseg.ts`
    // inside must resolve against *that*, not against the requested URL.
    const playlist = await (await get('/proxy/live/9.m3u8')).text();
    const line = playlist.split('\n').find(l => l.includes('/proxy/hls?u='));
    expect(line, 'segment rewritten').toBeTruthy();

    expect(targetOf(line)).toBe(`${providerBase}/cdn/deep/path/relseg.ts`);
});

test('a master playlist has its variant playlists rewritten in turn', async () => {
    const master = await (await get('/proxy/live/7.m3u8')).text();
    const variantLink = master.split('\n').find(l => l.includes('/proxy/hls?u='));
    expect(variantLink, 'variant playlist rewritten').toBeTruthy();

    // Following it must yield a *rewritten* variant, not the provider's raw one.
    const variant = await (await realFetch(variantLink)).text();
    expect(variant, `nested playlist leaked credentials:\n${variant}`).not.toContain(PASSWORD);
    expect(variant, 'nested segments rewritten').toContain('/proxy/hls?u=');
});

test('a playlist naming a host the proxy will not fetch is refused, not half-rewritten', async () => {
    // The route half-rewrote it: the signable segments became proxy links and the
    // rest were passed through as the provider wrote them — which on this panel
    // means /live/<user>/<password>/ in the player's hands, the exact disclosure
    // the rewrite exists to prevent.
    const res = await get('/proxy/live/8.m3u8');
    expect(res.status).toBe(502);

    const body = await res.text();
    expect(body).toBe('playlist target refused');
    expect(body, 'password must not reach the player').not.toContain(PASSWORD);
    expect(body, 'username must not reach the player').not.toContain(USERNAME);
});

test('the passthrough route refuses an unsigned target and makes no request', async () => {
    const evil = Buffer.from('http://127.0.0.1:1/private', 'utf8').toString('base64url');
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${evil}&s=forged`);
    expect(res.status).toBe(400);
    expect(providerHits, 'rejected before any outbound call').toStrictEqual([]);
});

test('the passthrough route still requires a valid config token', async () => {
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/x/y/seg1.ts`, CFG);
    const res = await realFetch(`${base}/not-a-token/proxy/hls?u=${u}&s=${s}&e=${e}`);
    expect(res.status).toBe(401);
    expect(providerHits).toStrictEqual([]);
});

// --- L8 — relayed bytes are the provider's, served from this origin ---------
//
// The proxy forwards the panel's Content-Type as sent, so a panel could serve
// text/html from this addon's origin and have a browser render it there. The
// impact is bounded — the site sets no cookies and the relay carries no CORS
// headers — but the panel is untrusted, and the two headers that close it cost
// nothing. `nosniff` stops a body labelled something else being sniffed into a
// document; `sandbox`, with no allow- tokens, gives anything that is one an
// opaque origin with no scripts, no forms and no top-level navigation.

test('a byte relay is marked unsniffable and sandboxed', async () => {
    const res = await get('/proxy/live/5.ts');

    expect(res.status).toBe(200);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe('sandbox');
    expect(res.headers.get('cache-control')).toBe('no-store');
});

test('a rewritten playlist gets the same headers as a byte relay', async () => {
    // The two branches answer from different code, and a header set in only one
    // of them is the kind of gap that survives review.
    const res = await get('/proxy/live/5.m3u8');

    expect(res.status).toBe(200);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe('sandbox');
    expect(res.headers.get('cache-control')).toBe('no-store');
});

test('the signed passthrough carries them too', async () => {
    // Every segment and key a player fetches comes through this route, so it is
    // the one a hostile body would most likely arrive on.
    const playlist = await (await get('/proxy/live/5.m3u8')).text();
    // A bare URI line, not the #EXT-X-KEY attribute that also carries one.
    const link = playlist.split('\n').find(l => l.startsWith(base) && !l.startsWith('#'));
    expect(link, 'a segment line was rewritten').toBeTruthy();
    const res = await realFetch(link);

    expect(res.status).toBe(200);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe('sandbox');
});

test('an html body from the panel is still relayed, just not as a document', async () => {
    // Not blocked: a panel that answers an error page has to reach the player as
    // whatever it is. The headers are what make that safe, so the assertion is
    // that the type survives *and* the headers came with it.
    const res = await get('/proxy/live/12.ts');

    expect(res.headers.get('content-type') || '').toMatch(/text\/html/);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe('sandbox');
});

// --- L10 — a playlist arriving where only bytes were expected ---------------
//
// A .ts path says "segment" and the content type said "text/plain", so nothing
// routed this to the rewrite and the body was relayed exactly as the panel sent
// it — with /user/pass/ in every segment URL. That is the disclosure the whole
// rewrite exists to prevent, arriving on the one path that never looks.
//
// It is refused rather than rewritten on the spot: deciding what a body is has
// to happen before any of it is read, because the alternative on this route is a
// segment that must stream. Sniffing stays a confirmation, never a detector.

test('a playlist served on a .ts path is refused, not relayed', async () => {
    const res = await get('/proxy/live/13.ts');
    const body = await res.text();

    expect(body, `password leaked in a relayed body:\n${body}`).not.toContain(PASSWORD);
    expect(body, 'username leaked in a relayed body').not.toContain(USERNAME);
    expect(res.status).toBe(502);
});

test('the sniff decides at the first byte that rules a playlist out', () => {
    // This is what keeps the check off the critical path of a live stream: a
    // segment is settled by its first byte, never by waiting for a window to fill.
    expect(hlsPrefixVerdict('G'), 'an MPEG-TS sync byte').toBe('other');
    expect(hlsPrefixVerdict('\u0000'), 'the start of an MP4 box').toBe('other');
    expect(hlsPrefixVerdict('<html>')).toBe('other');
    expect(hlsPrefixVerdict('#EXTINF'), 'a real tag, but not the first one').toBe('other');
});

test('the sniff keeps reading only while a playlist is still possible', () => {
    for (const partial of ['', '#', '#EX', '#EXTM3', '\uFEFF', '\n\n', '\uFEFF  #E']) {
        expect(hlsPrefixVerdict(partial), JSON.stringify(partial)).toBe('more');
    }
    for (const yes of ['#EXTM3U', '#EXTM3U\n#EXT-X-VERSION:3', '\uFEFF#EXTM3U', '\n \n#EXTM3U']) {
        expect(hlsPrefixVerdict(yes), JSON.stringify(yes)).toBe('playlist');
    }
});

test('a body shorter than the sniff window is relayed whole', async () => {
    // The bytes the sniff read are written on by the caller, and a body that ended
    // inside them is already complete — piping it afterwards would never end.
    const res = await get('/proxy/live/14.ts');

    expect(res.status).toBe(200);
    expect(await res.text()).toBe('TSx');
});

test('a byte relay still streams when the sniff cannot fill its window', async () => {
    // The regression that found this: waiting for a full window stalled forever on
    // an upstream that sends one byte and then pauses, which is an ordinary live
    // stream. test/proxy-concurrency.test.js drives exactly that shape and would
    // hang; this pins the smaller case the same rule covers.
    const res = await get('/proxy/live/5.ts');

    expect(res.status).toBe(200);
    expect(await res.text()).toBe('TS-BYTES-PAYLOAD');
});
