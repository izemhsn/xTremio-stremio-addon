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

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const {
    app,
    encodeConfig,
    signTokenBody,
    rewriteHlsPlaylist,
    looksLikePlaylist,
    encodeHlsTarget,
    decodeHlsTarget,
    signHlsTarget
} = require('../index.js');

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

test.before(async () => {
    provider = http.createServer(providerHandler);
    await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
    providerBase = `http://127.0.0.1:${provider.address().port}`;

    CFG = encodeConfig({ serverUrl: providerBase, username: USERNAME, password: PASSWORD });

    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => provider.close(resolve));
});

test.beforeEach(() => { providerHits = []; providerEncodings = []; });

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
    assert.match(out, /PROXY\(http:\/\/cdn\.test\/a\/seg1\.ts\)/);
    // Tags without a URI are untouched.
    assert.match(out, /^#EXTM3U$/m);
    assert.match(out, /^#EXTINF:8\.000,$/m);
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
    assert.match(out, /PROXY\(http:\/\/cdn\.test\/deep\/path\/seg2\.ts\)/);
});

test('URI="..." attributes are rewritten too', async () => {
    // EXT-X-KEY is the one that matters most: it is a real sub-resource, and on
    // an Xtream provider its URL carries the credentials like any segment.
    const out = await rewriteHlsPlaylist(
        '#EXT-X-KEY:METHOD=AES-128,URI="http://cdn.test/k.bin",IV=0x1\n#EXT-X-MEDIA:TYPE=AUDIO,URI="alt.m3u8"\n',
        'http://cdn.test/play.m3u8',
        proxied
    );
    assert.match(out, /URI="PROXY\(http:\/\/cdn\.test\/k\.bin\)"/);
    assert.match(out, /URI="PROXY\(http:\/\/cdn\.test\/alt\.m3u8\)"/);
    // Other attributes on the same line survive intact.
    assert.match(out, /METHOD=AES-128/);
    assert.match(out, /IV=0x1/);
});

test('blank lines and CRLF endings are preserved', async () => {
    // Some players are strict about line endings; a rewrite that silently
    // normalised them would break playback for reasons nobody would guess.
    const out = await rewriteHlsPlaylist(
        '#EXTM3U\r\n\r\nseg.ts\r\n',
        'http://cdn.test/p.m3u8',
        proxied
    );
    assert.ok(out.includes('#EXTM3U\r\n'));
    assert.ok(out.includes('PROXY(http://cdn.test/seg.ts)\r\n'));
    assert.ok(out.includes('\r\n\r\n'), 'blank line kept');
});

test('unresolvable or non-http URIs are left alone rather than dropped', async () => {
    const out = await rewriteHlsPlaylist(
        '#EXT-X-KEY:METHOD=AES-128,URI="data:text/plain;base64,AAAA"\n',
        'http://cdn.test/p.m3u8',
        proxied
    );
    assert.match(out, /URI="data:text\/plain;base64,AAAA"/);
    assert.ok(!out.includes('PROXY('));
});

test('looksLikePlaylist keys off the extension or the content type', () => {
    // Providers routinely mislabel playlists as text/plain, so the extension
    // has to be enough on its own.
    assert.ok(looksLikePlaylist('m3u8', 'text/plain'));
    assert.ok(looksLikePlaylist('M3U8', null));
    assert.ok(looksLikePlaylist(null, 'application/vnd.apple.mpegurl'));
    assert.ok(looksLikePlaylist(null, 'application/x-mpegURL; charset=utf-8'));
    assert.ok(!looksLikePlaylist('ts', 'video/mp2t'));
    assert.ok(!looksLikePlaylist(null, 'video/mp2t'));
});

// --- signed sub-resource targets -------------------------------------------

test('a signed target round-trips', () => {
    const { u, s, e } = encodeHlsTarget('http://cdn.test/a/seg1.ts?tok=9', CFG);
    assert.strictEqual(decodeHlsTarget(u, s, e, CFG)?.url, 'http://cdn.test/a/seg1.ts?tok=9');
});

test('an unsigned or forged target is rejected', () => {
    // Without this the /proxy/hls route would fetch any URL a caller named,
    // making the instance an open proxy to anyone holding an install token.
    const { u, s, e } = encodeHlsTarget('http://cdn.test/seg.ts', CFG);
    const evil = Buffer.from('http://attacker.test/', 'utf8').toString('base64url');

    assert.strictEqual(decodeHlsTarget(u, 'not-a-signature', e, CFG), null);
    assert.strictEqual(decodeHlsTarget(evil, s, e, CFG), null, 'signature for a different payload');
    assert.strictEqual(decodeHlsTarget(u, undefined, e, CFG), null);
    assert.strictEqual(decodeHlsTarget(undefined, undefined, e, CFG), null);
});

test('non-http targets are rejected even when correctly signed', () => {
    // Minted through encodeHlsTarget so the payload is genuinely this server's
    // own ciphertext: a hand-built one would be turned away by the MAC or the
    // GCM tag first and never reach the protocol check this test is about.
    const { u, s, e } = encodeHlsTarget('file:///etc/passwd', CFG);
    assert.strictEqual(decodeHlsTarget(u, s, e, CFG), null);
});

test('HLS signatures are domain-separated from config-token MACs', () => {
    // They use different keys, and the "hls:" prefix separates the signed
    // strings as well, so a value valid in one position cannot be replayed in
    // the other however either format changes.
    const body = 'v3.aaa.bbb.ccc';
    assert.notStrictEqual(signHlsTarget(body), signTokenBody(body));
});

// --- the M9 regression itself ----------------------------------------------

test('the live stream route hands out no credentials', async () => {
    const res = await get('/stream/Live%20TV/xtremio_live_5.json');
    assert.strictEqual(res.status, 200);
    const body = await res.text();

    assert.ok(!body.includes(PASSWORD), 'password must not reach the player');
    assert.ok(!body.includes(USERNAME), 'username must not reach the player');

    const { streams } = JSON.parse(body);
    assert.strictEqual(streams.length, 2, 'both HLS and MPEG-TS still offered');
    for (const s of streams) {
        assert.ok(s.url.startsWith(`${base}/${CFG}/proxy/live/5.`), `proxied: ${s.url}`);
        // Neither format is MP4, so the player must not treat it as web-ready —
        // getting this wrong makes playback stop after about a minute.
        assert.strictEqual(s.behaviorHints.notWebReady, true);
    }
    // No upstream call is needed to answer this.
    assert.deepStrictEqual(providerHits, []);
});

test('the .ts proxy relays the stream and authenticates upstream itself', async () => {
    const res = await get('/proxy/live/5.ts');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.text(), 'TS-BYTES-PAYLOAD');
    // The credentials still go upstream — they just stop at this server.
    assert.deepStrictEqual(providerHits, [`/live/${USERNAME}/${PASSWORD}/5.ts`]);
});

test('the .m3u8 proxy rewrites the playlist so no credentials reach the player', async () => {
    const res = await get('/proxy/live/5.m3u8');
    assert.strictEqual(res.status, 200);
    const body = await res.text();

    // The whole point: the provider's own playlist named the credentials in
    // every segment URL, and relaying it verbatim would have leaked them.
    assert.ok(!body.includes(PASSWORD), `password leaked in playlist body:\n${body}`);
    assert.ok(!body.includes(USERNAME), 'username leaked in playlist body');

    // Structure is preserved and every URI now points back at this server.
    assert.match(body, /^#EXTM3U$/m);
    assert.match(body, /^#EXT-X-TARGETDURATION:8$/m);
    const links = body.split('\n').filter(l => l.includes('/proxy/hls?'));
    assert.strictEqual(links.length, 3, 'key + 2 segments rewritten');
    for (const line of links) {
        assert.ok(line.includes(`${base}/${CFG}/proxy/hls?u=`), line);
    }

    // The rewritten body is longer than the one upstream declared, so
    // forwarding that content-length would truncate the response. Asserting
    // the received length against the header would be self-fulfilling — a
    // truncated body matches a truncated header — so the check is that the
    // last line survived and the length matches the *upstream* body's, which
    // it must not.
    assert.match(body, /seg2\.ts|\/proxy\/hls\?u=[^\n]*\n?$/, 'body reaches its final line');
    assert.ok(body.trimEnd().split('\n').length === 8, `all 8 lines present:\n${body}`);
    assert.strictEqual(res.headers.get('content-length'), String(Buffer.byteLength(body)));
});

test('a byte relay asks upstream for an unencoded body', async () => {
    // Left to undici's default it offered gzip, and an origin honouring that on
    // a ranged request answers with offsets into the compressed representation,
    // which do not describe the decompressed bytes being relayed.
    const res = await get('/proxy/live/5.ts');
    assert.strictEqual(res.status, 200);
    await res.text();
    assert.deepStrictEqual(providerEncodings, ['identity']);
});

test('a playlist fetch keeps compression negotiable', async () => {
    // Playlists are text, read whole and rewritten, so gzip is a plain win there.
    await (await get('/proxy/live/5.m3u8')).text();
    assert.strictEqual(providerEncodings.length, 1);
    assert.notStrictEqual(providerEncodings[0], 'identity');
});

test('a HEAD on a playlist does not advertise the unrewritten length', async () => {
    // HEAD used to forward upstream's Content-Length, which describes the
    // provider's body; the GET that follows returns a rewritten, longer one.
    const head = await realFetch(`${base}/${CFG}/proxy/live/5.m3u8`, { method: 'HEAD' });
    assert.strictEqual(head.status, 200);
    assert.strictEqual(head.headers.get('content-length'), null);
    assert.strictEqual(head.headers.get('accept-ranges'), null, 'a playlist is not seekable');
    assert.match(head.headers.get('content-type') || '', /mpegurl/i);
});

test('a HEAD on a byte relay still forwards its length and range support', async () => {
    // The other side of the change above: nothing is rewritten here, so the
    // upstream length is the real one.
    const head = await realFetch(`${base}/${CFG}/proxy/hls?${new URLSearchParams(
        encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/seg1.ts`, CFG)
    )}`, { method: 'HEAD' });
    assert.strictEqual(head.status, 200);
    assert.strictEqual(head.headers.get('content-length'), String(Buffer.byteLength('SEGMENT-BYTES')));
    assert.strictEqual(head.headers.get('accept-ranges'), 'bytes');
});

test('a Range header is not forwarded to a playlist request', async () => {
    // A 206 fragment cannot be parsed or rewritten, so the proxy withholds
    // Range when it knows a playlist is coming. Were it forwarded, this
    // provider would answer 206 with the first 12 bytes and the rewrite would
    // be skipped — relaying the provider's own credential-bearing body.
    const res = await realFetch(`${base}/${CFG}/proxy/live/5.m3u8`, {
        headers: { Range: 'bytes=0-11' }
    });
    assert.strictEqual(res.status, 200, 'a full playlist, not a 206 fragment');
    const body = await res.text();
    assert.ok(!body.includes(PASSWORD), 'a fragment would have been relayed unrewritten');
    assert.ok(body.includes('/proxy/hls?u='), 'still rewritten');
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

    assert.strictEqual(res.status, 200);
    assert.ok(!body.includes(PASSWORD));
    assert.ok(body.includes('/proxy/hls?u='), 'the segment inside was rewritten');
});

test('a partial playlist is refused rather than relayed unrewritten', async () => {
    // A provider that answers 206 unasked. The fragment cannot be parsed or
    // rewritten, and relaying it would leak the credentials it names.
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/rogue206.m3u8`, CFG);
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${u}&s=${s}&e=${e}`);

    assert.strictEqual(res.status, 502);
    assert.ok(!(await res.text()).includes(PASSWORD));
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
    assert.ok(variantLink, 'the variant was rewritten in the master');

    const res = await realFetch(variantLink);
    const body = await res.text();

    assert.strictEqual(res.status, 200);
    assert.ok(!body.includes(PASSWORD), 'no credentials reach the player');
    assert.ok(!body.includes(USERNAME));
    assert.ok(body.includes('/proxy/hls?u='), 'its segment was rewritten in turn');
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

    assert.strictEqual(kindOf(variantLink), true, 'a variant stream URI');
    assert.strictEqual(kindOf(segmentLink), false, 'a segment line keeps its Range support');
    assert.strictEqual(kindOf(keyLink), false, 'an EXT-X-KEY URI is a key, not a playlist');
});

test('a .m3u8 path is enough on its own, whatever the content type says', async () => {
    // The other half of the detection: a target this server did not mint from a
    // tag context still identifies itself by its path. Served as
    // application/octet-stream, so the content type contributes nothing.
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/plain.m3u8`, CFG);
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${u}&s=${s}&e=${e}`);
    const body = await res.text();

    assert.strictEqual(res.status, 200);
    assert.ok(!body.includes(PASSWORD));
    assert.ok(body.includes('/proxy/hls?u='));
});

test('a target that claims .m3u8 but sends a video body is refused, not mangled', async () => {
    // Detection happens before any of the body arrives, so a mislabelled target
    // reaches the rewrite. Parsing a transport stream as a playlist would hand
    // the player a corrupted body; refusing says what actually happened.
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/${USERNAME}/${PASSWORD}/notreally.m3u8`, CFG);
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${u}&s=${s}&e=${e}`);

    assert.strictEqual(res.status, 502);
    assert.strictEqual(await res.text(), 'bad playlist');
});

test('a rewritten segment link fetches through the signed passthrough', async () => {
    const playlist = await (await get('/proxy/live/5.m3u8')).text();
    const segLine = playlist.split('\n').find(l => l.startsWith(base) && !l.startsWith('#'));
    assert.ok(segLine, 'a segment line was rewritten');

    providerHits = [];
    const res = await realFetch(segLine);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.text(), 'SEGMENT-BYTES');
    assert.deepStrictEqual(providerHits, [`/hls/${USERNAME}/${PASSWORD}/seg1.ts`]);
});

test('a relative segment resolves against the playlist, not the proxy path', async () => {
    // `seg2.ts` in the provider's playlist must become the provider's
    // /live/<creds>/seg2.ts, not a URL on this server.
    const playlist = await (await get('/proxy/live/5.m3u8')).text();
    const lines = playlist.split('\n').filter(l => l.includes('/proxy/hls?u='));
    const targets = lines.map((l) => targetOf(l.replace(/^#.*URI="/, '').replace(/"$/, '')));
    assert.ok(
        targets.some(t => t === `${providerBase}/live/${USERNAME}/${PASSWORD}/seg2.ts`),
        `relative segment resolved wrongly: ${JSON.stringify(targets)}`
    );
});

test('relative segments resolve against the post-redirect playlist URL', async () => {
    // The end-to-end case for safeFetch's onFinalUrl. The provider redirects
    // /live/<creds>/9.m3u8 to /cdn/deep/path/play.m3u8; the relative `relseg.ts`
    // inside must resolve against *that*, not against the requested URL.
    const playlist = await (await get('/proxy/live/9.m3u8')).text();
    const line = playlist.split('\n').find(l => l.includes('/proxy/hls?u='));
    assert.ok(line, 'segment rewritten');

    assert.strictEqual(targetOf(line), `${providerBase}/cdn/deep/path/relseg.ts`);
});

test('a master playlist has its variant playlists rewritten in turn', async () => {
    const master = await (await get('/proxy/live/7.m3u8')).text();
    const variantLink = master.split('\n').find(l => l.includes('/proxy/hls?u='));
    assert.ok(variantLink, 'variant playlist rewritten');

    // Following it must yield a *rewritten* variant, not the provider's raw one.
    const variant = await (await realFetch(variantLink)).text();
    assert.ok(!variant.includes(PASSWORD), `nested playlist leaked credentials:\n${variant}`);
    assert.ok(variant.includes('/proxy/hls?u='), 'nested segments rewritten');
});

test('a playlist naming a host the proxy will not fetch is refused, not half-rewritten', async () => {
    // The route half-rewrote it: the signable segments became proxy links and the
    // rest were passed through as the provider wrote them — which on this panel
    // means /live/<user>/<password>/ in the player's hands, the exact disclosure
    // the rewrite exists to prevent.
    const res = await get('/proxy/live/8.m3u8');
    assert.strictEqual(res.status, 502);

    const body = await res.text();
    assert.strictEqual(body, 'playlist target refused');
    assert.ok(!body.includes(PASSWORD), 'password must not reach the player');
    assert.ok(!body.includes(USERNAME), 'username must not reach the player');
});

test('the passthrough route refuses an unsigned target and makes no request', async () => {
    const evil = Buffer.from('http://127.0.0.1:1/private', 'utf8').toString('base64url');
    const res = await realFetch(`${base}/${CFG}/proxy/hls?u=${evil}&s=forged`);
    assert.strictEqual(res.status, 400);
    assert.deepStrictEqual(providerHits, [], 'rejected before any outbound call');
});

test('the passthrough route still requires a valid config token', async () => {
    const { u, s, e } = encodeHlsTarget(`${providerBase}/hls/x/y/seg1.ts`, CFG);
    const res = await realFetch(`${base}/not-a-token/proxy/hls?u=${u}&s=${s}&e=${e}`);
    assert.strictEqual(res.status, 401);
    assert.deepStrictEqual(providerHits, []);
});
