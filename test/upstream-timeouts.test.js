// R5 — slow panels never finished loading their lists.
//
// One timeout covered the whole upstream call, headers and body together, so a 25 MB
// list from a panel slower than ~1.7 MB/s could never complete, and every retry began
// again from nothing. Headers, the gap between chunks and the whole response now each
// have a deadline of their own.
//
// The deadlines are lowered for this file so the stalls can be exercised in real time.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.UPSTREAM_IDLE_TIMEOUT_MS = '250';
process.env.UPSTREAM_BODY_TIMEOUT_MS = '1500';

const http = require('node:http');

const { xtremioGet, UPSTREAM_IDLE_TIMEOUT_MS, UPSTREAM_BODY_TIMEOUT_MS } = require('./support/internals.js');

// A panel that misbehaves in whichever way the request's `action` names.
function handler(req, res) {
    const action = new URL(req.url, 'http://panel.test').searchParams.get('action');
    if (action === 'no_headers') return; // never answers at all

    res.writeHead(200, { 'Content-Type': 'application/json' });

    if (action === 'slow_steady') {
        // Eight writes 150 ms apart: about a second in all, several times the 300 ms
        // header deadline each test passes, but never idle for 250 ms.
        const items = Array.from({ length: 6 }, (_, i) => JSON.stringify({ stream_id: i }));
        const writes = ['[', ...items.map((item, i) => (i ? ',' : '') + item), ']'];
        let i = 0;
        const next = () => {
            res.write(writes[i++]);
            if (i < writes.length) setTimeout(next, 150);
            else res.end();
        };
        return next();
    }
    if (action === 'stalled') {
        res.write('[');
        return; // and nothing more, ever
    }
    if (action === 'trickle') {
        // JSON whitespace every 150 ms: always inside the idle window, never finished.
        res.write('[');
        const timer = setInterval(() => res.write(' '), 150);
        res.on('close', () => clearInterval(timer));
    }
}

let provider;
let cfg;

beforeAll(async () => {
    await new Promise(resolve => { provider = http.createServer(handler).listen(0, '127.0.0.1', resolve); });
    cfg = { serverUrl: `http://127.0.0.1:${provider.address().port}`, username: 'u', password: 'p' };
});

afterAll(async () => {
    provider.closeAllConnections();
    await new Promise(resolve => provider.close(resolve));
});

test('the fixture sets the deadlines this file relies on', () => {
    expect(UPSTREAM_IDLE_TIMEOUT_MS).toBe(250);
    expect(UPSTREAM_BODY_TIMEOUT_MS).toBe(1500);
});

test('a slow download that keeps moving completes', async () => {
    // It takes several times the header deadline in all. A single timeout used to
    // cover the whole of it, and abandoned it.
    const data = await xtremioGet(cfg, 'slow_steady', {}, { timeoutMs: 300 });
    expect(data.length).toBe(6);
});

test('a download that stalls is abandoned at the idle deadline, and says so', async () => {
    const started = Date.now();
    await expect(xtremioGet(cfg, 'stalled', {}, { timeoutMs: 300 })).rejects.toThrow(/timed out waiting for the next chunk after 250 ms/);
    expect(Date.now() - started, 'long before the overall deadline').toBeLessThan(UPSTREAM_BODY_TIMEOUT_MS);
});

test('a trickle that never finishes is abandoned at the overall deadline', async () => {
    const started = Date.now();
    await expect(xtremioGet(cfg, 'trickle', {}, { timeoutMs: 300 })).rejects.toThrow(/timed out waiting for the whole response after 1500 ms/);
    const elapsed = Date.now() - started;
    expect(elapsed, `gave up after only ${elapsed} ms`).toBeGreaterThanOrEqual(UPSTREAM_BODY_TIMEOUT_MS - 100);
});

test('headers that never come are abandoned at the header deadline', async () => {
    const started = Date.now();
    await expect(xtremioGet(cfg, 'no_headers', {}, { timeoutMs: 300 })).rejects.toThrow(/timed out waiting for headers after 300 ms/);
    expect(Date.now() - started).toBeLessThan(UPSTREAM_BODY_TIMEOUT_MS);
});
