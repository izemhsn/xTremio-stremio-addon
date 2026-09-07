// M-5 — the playlist read had no deadline once response headers arrived.
//
// The header timer is cleared as soon as headers land, which is right for the
// streaming path: a paused movie is a legitimately idle connection and must not
// be killed. But the rewrite branch then buffers the entire body before it can
// answer, with no deadline at all. An upstream that sends headers and then
// trickles one byte a minute held the request, its socket and up to
// MAX_PLAYLIST_BYTES of buffer indefinitely. REQUEST_TIMEOUT_MS does not help —
// it bounds receiving the *request*, not the response.
//
// A short deadline is set here so the test does not have to wait 30 seconds.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.PLAYLIST_BODY_TIMEOUT_MS = '1200';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const { app, encodeConfig, PLAYLIST_BODY_TIMEOUT_MS } = require('../index.js');

const realFetch = global.fetch;

let provider;
let server;
let base;
let cfg;

// Sockets the provider has accepted and is deliberately holding open, so the
// test can prove they are released rather than merely that the client gave up.
let heldSockets = [];

function providerHandler(req, res) {
    heldSockets.push(res.socket);

    // Stream id 1 trickles; anything else answers normally. The route only
    // accepts numeric ids, so the shape has to come from the id.
    if (req.url.includes('/1.m3u8')) {
        // Headers immediately, then a body that never finishes. This is the
        // shape the finding describes: nothing times out on its own.
        res.writeHead(200, { 'Content-Type': 'application/x-mpegURL' });
        res.write('#EXTM3U\n');
        const timer = setInterval(() => res.write('#'), 400);
        res.on('close', () => clearInterval(timer));
        return;
    }

    res.writeHead(200, { 'Content-Type': 'application/x-mpegURL' });
    res.end(`#EXTM3U\n#EXTINF:8,\nhttp://127.0.0.1:${provider.address().port}/seg1.ts\n`);
}

test.before(async () => {
    provider = await new Promise((resolve) => {
        const s = http.createServer(providerHandler);
        s.listen(0, '127.0.0.1', () => resolve(s));
    });
    server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    base = `http://127.0.0.1:${server.address().port}`;
    cfg = encodeConfig({
        serverUrl: `http://127.0.0.1:${provider.address().port}`,
        username: 'u',
        password: 'p'
    });
});

test.after(async () => {
    global.fetch = realFetch;
    await new Promise(r => server.close(r));
    await new Promise(r => provider.close(r));
});

test('the deadline is configurable and separate from the header timeout', () => {
    assert.equal(PLAYLIST_BODY_TIMEOUT_MS, 1200);
});

test('a trickling playlist body is cut off instead of held forever', async () => {
    heldSockets = [];
    const started = Date.now();
    const res = await realFetch(`${base}/${cfg}/proxy/live/1.m3u8`);
    const elapsed = Date.now() - started;

    assert.equal(res.status, 504);
    assert.equal(await res.text(), 'upstream timeout');
    assert.ok(
        elapsed >= PLAYLIST_BODY_TIMEOUT_MS - 100 && elapsed < PLAYLIST_BODY_TIMEOUT_MS + 3000,
        `expected to give up near the deadline, took ${elapsed}ms`
    );
});

test('the upstream socket is released, not leaked', async () => {
    // Timing out is only half the fix: an abandoned request that keeps its
    // upstream connection open is the same resource leak with a nicer status.
    heldSockets = [];
    const res = await realFetch(`${base}/${cfg}/proxy/live/1.m3u8`);
    assert.equal(res.status, 504);
    await res.text();

    await new Promise(r => setTimeout(r, 500));
    const stillOpen = heldSockets.filter(s => s && !s.destroyed).length;
    assert.equal(stillOpen, 0, `${stillOpen} upstream socket(s) still open after the timeout`);
});

test('a playlist that arrives in time is unaffected', async () => {
    // The deadline must not be a general body timeout: a normal playlist, and
    // the streaming path behind it, keep working exactly as before.
    const res = await realFetch(`${base}/${cfg}/proxy/live/9.m3u8`);
    const body = await res.text();

    assert.equal(res.status, 200);
    assert.ok(body.includes('/proxy/hls?u='), 'still rewritten');
    assert.ok(!body.includes('127.0.0.1:' + provider.address().port + '/seg1.ts'), 'and not relayed raw');
});
