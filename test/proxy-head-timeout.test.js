// L12 — HEAD and its GET fallback shared one header deadline.
//
// relayUpstream passes the player's HEAD through and falls back to GET whenever
// that does not produce a usable response, which the real Xtream panel forces on
// every probe: it answers HEAD with a 502. Both requests were bounded by a single
// timer armed before the HEAD, so a panel that takes its time saying 502 left the
// fallback GET whatever remained of it — and on a slow panel that is nothing. The
// probe then failed with a 504 for a file the panel was about to serve.
//
// The deadline bounds one exchange, so the fallback re-arms it. The second test
// is the other half: re-arming must not turn the bound off.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.PROXY_HEADER_TIMEOUT_MS = '1000';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const { app, encodeConfig, PROXY_HEADER_TIMEOUT_MS } = require('../index.js');

const realFetch = global.fetch;

let provider, providerBase, providerHits;
let server, base, CFG;

// Ids rather than names, because a proxy path's item id has to be numeric.
//
//   1 — a slow 502 to HEAD, then a slow-but-answerable GET. Neither exceeds the
//       deadline on its own; together they exceed a single one. The delays are
//       800 + 600 against 1000 ms, so each half of the assertion has ~400 ms of
//       margin rather than resting on exact timing.
//   2 — a prompt 502 to HEAD, then a GET whose headers never arrive at all.
function providerHandler(req, res) {
    providerHits.push({ method: req.method, url: req.url });
    const id = (req.url.match(/\/(\d+)\.[A-Za-z0-9]+$/) || [])[1];

    if (id === '2') {
        if (req.method === 'HEAD') {
            res.writeHead(502, { 'Content-Type': 'text/plain' });
            return res.end();
        }
        return; // headers never sent; the deadline is the only thing that ends this
    }

    if (req.method === 'HEAD') {
        return setTimeout(() => {
            res.writeHead(502, { 'Content-Type': 'text/plain' });
            res.end();
        }, 800);
    }
    setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '4' });
        res.end('abcd');
    }, 600);
}

test.before(async () => {
    provider = http.createServer(providerHandler);
    await new Promise(r => provider.listen(0, '127.0.0.1', r));
    providerBase = `http://127.0.0.1:${provider.address().port}`;
    CFG = encodeConfig({ serverUrl: providerBase, username: 'u', password: 'p' });
    await new Promise(r => { server = app.listen(0, '127.0.0.1', r); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    await new Promise(r => server.close(r));
    await new Promise(r => provider.close(r));
});

test.beforeEach(() => { providerHits = []; });

test('the env override this file depends on is in effect', () => {
    assert.equal(PROXY_HEADER_TIMEOUT_MS, 1000,
        'the two timing tests below are written against a 1000 ms deadline');
});

test('a slow 502 to HEAD does not eat the fallback GET deadline', async () => {
    const started = Date.now();
    const res = await realFetch(`${base}/${CFG}/proxy/movie/1.mp4`, { method: 'HEAD' });
    const elapsed = Date.now() - started;

    assert.equal(res.status, 200, 'the fallback GET had time to answer');
    assert.equal(res.headers.get('content-length'), '4');
    assert.deepEqual(providerHits.map(h => h.method), ['HEAD', 'GET']);
    assert.ok(elapsed > PROXY_HEADER_TIMEOUT_MS,
        `the exchange should outlast a single deadline, took ${elapsed}ms`);
});

test('the fallback GET is still bounded by its own deadline', async () => {
    const started = Date.now();
    const res = await realFetch(`${base}/${CFG}/proxy/movie/2.mp4`, { method: 'HEAD' });
    const elapsed = Date.now() - started;

    assert.equal(res.status, 504, 'a GET whose headers never arrive must still time out');
    assert.deepEqual(providerHits.map(h => h.method), ['HEAD', 'GET']);
    assert.ok(elapsed < PROXY_HEADER_TIMEOUT_MS * 2.5,
        `re-arming must not compound the deadline, took ${elapsed}ms`);
});
