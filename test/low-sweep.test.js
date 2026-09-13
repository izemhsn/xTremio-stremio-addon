// The Low table from the audit ledger, swept in one pass:
//
//   M-1 — a HEAD from the player became a GET upstream whose body was dropped
//         unread, spending a buffer window of provider bandwidth per probe.
//   L-1 — redirect responses in safeFetch were abandoned without cancelling the
//         body, holding a connection until GC. Every proxy request takes a 302.
//   L-3 — content-length was forwarded from a content-encoded response, which
//         undici had already decompressed, so the number described a body the
//         client never receives.
//   L-4 — isUsableSeriesInfo accepted a payload with only a cover, cached it
//         positively for 30 minutes, and the meta route then rendered it as
//         meta: null for the full TTL.
//   L-5 — parseCatalogId accepted any suffix, so xtremio_movies_bogus resolved
//         to a real kind and was served unsorted rather than rejected.
//   L-9 — episodes with no release date were given 1970-01-01, which Stremio
//         renders as a literal date rather than as absent.
//   L-10 — escapeHtml(0) returned '' because of String(str || '').
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const zlib = require('node:zlib');

const {
    app,
    encodeConfig,
    escapeHtml,
    parseCatalogId,
    isUsableSeriesInfo,
    discardBody
} = require('../index.js');

const realFetch = global.fetch;

const USERNAME = 'u';
const PASSWORD = 'p';

let provider, providerBase, providerHits;
let server, base, CFG;
let redirectClosed;

// Item ids in a proxy path have to be numeric — getPrefixedNumericId enforces
// that before anything reaches an upstream URL — so each case gets an id rather
// than a readable filename.
//
//   1 — an ordinary 4-byte body
//   2 — a CDN that refuses HEAD, which real ones do
//   3 — a gzipped body whose content-length describes the compressed size
//   4 — a 302 carrying a body that is never ended, to /5
function providerHandler(req, res) {
    providerHits.push({ method: req.method, url: req.url });
    const id = (req.url.match(/\/(\d+)\.[A-Za-z0-9]+$/) || [])[1];

    if (id === '2') {
        if (req.method === 'HEAD') {
            res.writeHead(405, { 'Content-Type': 'text/plain' });
            return res.end();
        }
        res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '9' });
        return res.end('nine char');
    }

    if (id === '3') {
        const body = zlib.gzipSync(Buffer.from('D'.repeat(5000), 'utf8'));
        res.writeHead(200, {
            'Content-Type': 'video/mp4',
            'Content-Encoding': 'gzip',
            'Content-Length': String(body.length)
        });
        return res.end(req.method === 'HEAD' ? undefined : body);
    }

    // What the real Xtream panel does: 502 to a HEAD, with no redirect. The
    // first version of the M-1 fix fell back only on 405/501 and turned every
    // real HEAD into a 502.
    if (id === '6') {
        if (req.method === 'HEAD') {
            res.writeHead(502, { 'Content-Type': 'text/html', 'Content-Length': '154' });
            return res.end();
        }
        res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '4' });
        return res.end('abcd');
    }

    // What the CDN behind that panel's 302 does: drops the connection, so fetch
    // throws rather than returning a status at all.
    if (id === '7') {
        if (req.method === 'HEAD') {
            return req.socket.destroy();
        }
        res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '4' });
        return res.end('abcd');
    }

    if (id === '4') {
        res.writeHead(302, {
            Location: req.url.replace('/4.', '/5.'),
            'Content-Type': 'text/plain'
        });
        // Deliberately never ended: the only thing that closes this socket is
        // the client cancelling the body it is not going to read.
        res.write('x'.repeat(1024));
        res.on('close', () => { redirectClosed = true; });
        return;
    }

    res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '4' });
    res.end(req.method === 'HEAD' ? undefined : 'abcd');
}

test.before(async () => {
    provider = http.createServer(providerHandler);
    await new Promise(r => provider.listen(0, '127.0.0.1', r));
    providerBase = `http://127.0.0.1:${provider.address().port}`;
    CFG = encodeConfig({ serverUrl: providerBase, username: USERNAME, password: PASSWORD });
    await new Promise(r => { server = app.listen(0, '127.0.0.1', r); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    await new Promise(r => server.close(r));
    await new Promise(r => provider.close(r));
});

test.beforeEach(() => { providerHits = []; redirectClosed = false; });

// --- M-1: the method reaches upstream ---------------------------------------

test('a HEAD from the player is a HEAD upstream, not a GET', async () => {
    const res = await realFetch(`${base}/${CFG}/proxy/movie/1.mp4`, { method: 'HEAD' });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-length'), '4');
    assert.equal(await res.text(), '', 'a HEAD response carries no body');

    assert.ok(providerHits.length >= 1);
    assert.ok(providerHits.every(h => h.method === 'HEAD'),
        `upstream should only have seen HEAD, saw ${JSON.stringify(providerHits)}`);
});

test('a GET still goes upstream as a GET and still delivers the body', async () => {
    const res = await realFetch(`${base}/${CFG}/proxy/movie/1.mp4`);
    assert.equal(await res.text(), 'abcd');
    assert.ok(providerHits.every(h => h.method === 'GET'));
});

test('a provider that refuses HEAD falls back to GET rather than failing', async () => {
    // The regression this guards: trading wasted bytes for a broken probe would
    // be a worse bug than the one M-1 describes.
    const res = await realFetch(`${base}/${CFG}/proxy/movie/2.mp4`, { method: 'HEAD' });
    assert.equal(res.status, 200, 'the 405 must not reach the player');
    assert.equal(res.headers.get('content-length'), '9');

    const methods = providerHits.map(h => h.method);
    assert.deepEqual(methods, ['HEAD', 'GET'], 'HEAD first, then the fallback');
});

test('a 502 to a HEAD falls back too — the shape the real provider sends', async () => {
    // Measured, not imagined: the live Xtream panel answers HEAD with 502 and no
    // redirect. A fallback scoped to 405/501 let that reach the player, which is
    // exactly what happened on the first attempt at this fix.
    const res = await realFetch(`${base}/${CFG}/proxy/movie/6.mp4`, { method: 'HEAD' });
    assert.equal(res.status, 200, 'a 502 from a HEAD must not reach the player');
    assert.equal(res.headers.get('content-length'), '4');
    assert.deepEqual(providerHits.map(h => h.method), ['HEAD', 'GET']);
});

test('a HEAD that kills the connection falls back too', async () => {
    // The other half of the same live measurement: the CDN behind the panel's
    // 302 drops the socket on a HEAD, so fetch throws instead of returning a
    // status. A status-only check never sees this one.
    const res = await realFetch(`${base}/${CFG}/proxy/movie/7.mp4`, { method: 'HEAD' });
    assert.equal(res.status, 200, 'a thrown HEAD must not reach the player');
    assert.equal(res.headers.get('content-length'), '4');
    assert.deepEqual(providerHits.map(h => h.method), ['HEAD', 'GET']);
});

// --- L-3: content-length vs a decompressed body ------------------------------

test('content-length is dropped when upstream sent content-encoding', async () => {
    const res = await realFetch(`${base}/${CFG}/proxy/movie/3.mp4`);
    const body = await res.text();

    assert.equal(body.length, 5000, 'the client gets the decompressed body');
    // The compressed length would be a few dozen bytes; forwarding it would make
    // a client stop after those and treat the rest as a broken stream.
    assert.equal(res.headers.get('content-length'), null,
        'a length describing the compressed body must not be forwarded');
});

test('content-length is still forwarded when nothing was encoded', async () => {
    const res = await realFetch(`${base}/${CFG}/proxy/movie/1.mp4`);
    assert.equal(res.headers.get('content-length'), '4');
    assert.equal(await res.text(), 'abcd');
});

// --- L-1: abandoned bodies are cancelled -------------------------------------

test('discardBody cancels an unread body and never throws', async () => {
    let cancelled = false;
    const stream = new ReadableStream({
        start(c) { c.enqueue(new Uint8Array([1])); },
        cancel() { cancelled = true; }
    });
    discardBody({ body: stream });
    await new Promise(r => setImmediate(r));
    assert.equal(cancelled, true);

    // The shapes it must tolerate: no response, no body, and a body someone is
    // already reading (locked), which is the case that would throw.
    const locked = new ReadableStream({ start(c) { c.close(); } });
    locked.getReader();
    assert.doesNotThrow(() => {
        discardBody(undefined);
        discardBody({});
        discardBody({ body: null });
        discardBody({ body: locked });
    });
});

test('a redirect body is released, and the redirect is still followed', async () => {
    // L-1 was recorded as a leak: an abandoned 302 body holding a connection
    // until GC, on the hot path since every proxy request takes a redirect.
    // Measured through this exact path, it is not one — the socket closed in
    // under 10 ms with and without the cancel, because undici cannot return a
    // half-read response to the pool either way. So this asserts the behaviour
    // that matters and is stable (the redirect is followed, its socket does not
    // linger); the cancel itself is unit-tested above as the hygiene it is.
    const res = await realFetch(`${base}/${CFG}/proxy/movie/4.mp4`);
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'abcd', 'the redirect is still followed');
    assert.deepEqual(providerHits.map(h => h.url.slice(-6)), ['/4.mp4', '/5.mp4']);

    const deadline = Date.now() + 3000;
    while (!redirectClosed && Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 5));
    }
    assert.equal(redirectClosed, true, 'the abandoned redirect body still holds its socket');
});

// --- L-4: "usable" must mean what the caller needs ---------------------------

test('a series payload carrying only a cover is not usable', () => {
    // The exact shape that used to be cached positively for 30 minutes and then
    // rendered as meta: null by the route that requires a name or episodes.
    assert.equal(isUsableSeriesInfo({ info: { cover: 'http://x/c.jpg' } }), false);
    assert.equal(isUsableSeriesInfo({ info: { plot: 'a plot' } }), false);
    assert.equal(isUsableSeriesInfo({ info: { genre: 'Drama' } }), false);
    assert.equal(isUsableSeriesInfo({ info: {}, episodes: {} }), false);
});

test('a name or any episode is still usable', () => {
    assert.equal(isUsableSeriesInfo({ info: { name: 'Show' } }), true);
    assert.equal(isUsableSeriesInfo({ episodes: { 1: [{ id: '5' }] } }), true);
    // This used to assert `true`, on a key count: `{ 1: [] }` is one season, so
    // the payload "had episodes". It has none — the meta route iterates the
    // arrays and builds no videos at all, so `hasContent` said false and the
    // series rendered as `meta: null` from a payload this call had just declared
    // usable. That disagreement is the one this predicate exists to avoid, so an
    // empty season now counts for nothing. A payload with episodes and no info
    // block still works, which is what the line above holds.
    assert.equal(isUsableSeriesInfo({ episodes: { 1: [] } }), false);
});

test('the rejects stay rejected', () => {
    for (const bad of [null, undefined, 'string', 42, {}, { info: null }]) {
        assert.equal(isUsableSeriesInfo(bad), false, `${JSON.stringify(bad)} is not usable`);
    }
});

// --- L-5: unknown catalog variants are rejected ------------------------------

test('only the three declared variants parse', () => {
    for (const kind of ['movies', 'series']) {
        for (const variant of ['new', 'popular', 'featured']) {
            assert.deepEqual(parseCatalogId(`xtremio_${kind}_${variant}`), { kind, variant, search: false });
        }
        assert.equal(parseCatalogId(`xtremio_${kind}_bogus`), null);
        assert.equal(parseCatalogId(`xtremio_${kind}_`), null);
        assert.equal(parseCatalogId(`xtremio_${kind}_NEW`), null, 'variants are case-sensitive');
    }
    // The ids that are not variant-suffixed at all must be untouched by this.
    assert.deepEqual(parseCatalogId('xtremio_live'), { kind: 'live', variant: null, search: false });
    assert.deepEqual(parseCatalogId('xtremio_search_movies'), { kind: 'movies', variant: null, search: true });
    assert.deepEqual(parseCatalogId('xtremio_search_series'), { kind: 'series', variant: null, search: true });
    assert.equal(parseCatalogId(''), null);
    assert.equal(parseCatalogId(undefined), null);
});

test('an unknown catalog id is an empty shelf, not an unsorted one', async () => {
    const res = await realFetch(`${base}/${CFG}/catalog/XT-Movies/xtremio_movies_bogus.json`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { metas: [] });
    // And it costs nothing upstream, which is the other half of rejecting early.
    assert.deepEqual(providerHits, []);
});

// --- L-9 / L-10: small correctness ------------------------------------------

test('escapeHtml stringifies falsy values instead of erasing them', () => {
    assert.equal(escapeHtml(0), '0');
    assert.equal(escapeHtml(false), 'false');
    assert.equal(escapeHtml(''), '');
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
    // Escaping itself is unchanged.
    assert.equal(escapeHtml('<a href="x">&\'</a>'),
        '&lt;a href=&quot;x&quot;&gt;&amp;&#039;&lt;/a&gt;');
});

// --- L-6: no mistyped spec field in the manifest -----------------------------

test('the manifest no longer carries a non-spec `config` object', async () => {
    const res = await realFetch(`${base}/manifest.json`);
    const manifest = await res.json();

    // The spec's `config` is an array of field descriptors; this addon emitted
    // an object. A client that starts honouring the field would get the wrong
    // type, and configurable is what actually routes the user to /configure.
    assert.equal('config' in manifest, false);
    assert.equal(manifest.behaviorHints.configurable, true);
    assert.equal(manifest.behaviorHints.configurationRequired, true);
});

// --- L-7: credentials do not arrive by query string --------------------------

test('GET /configure ignores loose credential query parameters', async () => {
    const res = await realFetch(
        `${base}/configure?serverUrl=http://evil.test:8080&username=leaked-user&password=leaked-pass`
    );
    const html = await res.text();

    // Escaped, so this was never XSS — the bug is that such a URL exists at all
    // and lands in history, referrers and logs. Honouring it is what made it
    // worth constructing.
    for (const value of ['evil.test', 'leaked-user', 'leaked-pass']) {
        assert.ok(!html.includes(value), `${value} must not be echoed back`);
    }
    assert.match(html, /name="serverUrl" value=""/);
    assert.match(html, /name="username" value=""/);
    assert.match(html, /name="password" value=""/);
});

// --- M-4 / L-12: a token never gives its password back -----------------------

// PASSWORD is a single letter, which any HTML page contains; asserting absence
// needs a value that cannot turn up by accident.
const DISTINCT_PASSWORD = 'Sup3r-S3cret-Passw0rd';

function assertPrefilledWithoutPassword(html) {
    assert.ok(html.includes(providerBase), 'server url prefilled');
    assert.match(html, new RegExp(`name="username" value="${USERNAME}"`));
    assert.match(html, /name="password" value=""/);
    assert.ok(!html.includes(DISTINCT_PASSWORD), 'the password must not appear anywhere on the page');
}

test('GET /configure prefills from a token, but never the password', async () => {
    // The token is the install URL Stremio stores and syncs. Rendering its
    // password into the form made this page decrypt it for whoever held one.
    const token = encodeConfig({ serverUrl: providerBase, username: USERNAME, password: DISTINCT_PASSWORD });
    const res = await realFetch(`${base}/configure?config=${token}`);
    assertPrefilledWithoutPassword(await res.text());
});

test('GET /:config/configure, where Stremio\'s Configure button lands, serves the same page', async () => {
    const token = encodeConfig({ serverUrl: providerBase, username: USERNAME, password: DISTINCT_PASSWORD });
    const res = await realFetch(`${base}/${token}/configure`);
    assert.equal(res.status, 200);
    assertPrefilledWithoutPassword(await res.clone().text());

    // It is the credential page, so it carries that page's headers — and not the
    // wildcard the addon resources under the same token prefix get.
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.match(res.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
    assert.equal(res.headers.get('access-control-allow-origin'), null);

    // A form without an action would POST back to /<token>/configure, which has
    // no handler.
    assert.match(await res.text(), /<form method="POST" action="\/configure">/);
});

test('GET /:config/configure with an undecodable token renders the empty form', async () => {
    const res = await realFetch(`${base}/not-a-real-token/configure`);
    const html = await res.text();
    assert.equal(res.status, 200);
    assert.match(html, /name="serverUrl" value=""/);
    assert.match(html, /name="username" value=""/);
    assert.match(html, /name="password" value=""/);
});

// --- L-8: a rejection is as fatal as a throw ---------------------------------

test('unhandledRejection exits like uncaughtException', () => {
    // Asserted against the source, the way the existing handler tests are: the
    // handlers live inside `if (require.main === module)` and cannot be reached
    // from an in-process require.
    const src = require('node:fs').readFileSync(require.resolve('../index.js'), 'utf8');
    const bootstrap = src.slice(src.indexOf('if (require.main === module)'));
    const rejection = bootstrap.slice(bootstrap.indexOf("process.on('unhandledRejection'"));

    assert.match(rejection, /Unhandled rejection, exiting/);
    assert.match(rejection.slice(0, 300), /process\.exit\(1\)/,
        'a rejection must not leave a wedged process answering /health with 200');
});

test('no epoch date is written into an episode', () => {
    // Pinned against the source: the meta route needs a whole series payload to
    // exercise, but the bug was a single literal, and its return would be silent
    // — Stremio renders "1970" next to the episode rather than omitting a date.
    const src = require('node:fs').readFileSync(require.resolve('../index.js'), 'utf8');
    const inCode = src
        .split('\n')
        .filter(line => line.includes('1970-01-01') && !line.trim().startsWith('//'));
    assert.deepEqual(inCode, [], 'the epoch fallback must not come back');
});
