// Audit L-8: nothing bounded how much of the host's egress one install URL could
// take. The token is a bearer credential and the README says so, but a leaked or
// deliberately shared one opens as many simultaneous relays as the sharers have
// players, each a full-rate video stream paid for by the operator. The caches
// bound memory and the timeouts bound stalled requests; a thousand *healthy*
// concurrent relays looked exactly like a popular household.
//
// Set before the module is required: the limit is read once, at load.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.PROXY_MAX_CONCURRENT_PER_TOKEN = '2';

const http = require('node:http');

const {
    app,
    encodeConfig,
    encodeHlsTarget,
    proxyInFlight,
    PROXY_MAX_CONCURRENT_PER_TOKEN
} = require('./support/internals.js');

const CAP = PROXY_MAX_CONCURRENT_PER_TOKEN;

// --- a provider that holds its responses open ------------------------------
//
// A relay only occupies a slot while it is actually relaying, so the fixture has
// to be able to keep several responses in flight at once and let them go on
// command. Headers go out immediately; the body does not end until released.

let provider;
let providerBase;
let open;          // responses currently held open, by the order they arrived
let arrived;       // resolves for the Nth request to reach the provider

function providerHandler(req, res) {
    res.writeHead(200, { 'Content-Type': 'video/mp4' });
    res.write('x');   // headers and a first byte, so the addon starts piping
    open.push(res);
    const waiter = arrived.shift();
    if (waiter) waiter();
}

function releaseAll() {
    for (const res of open.splice(0)) res.end();
}

// Resolves once `n` requests are being held open upstream.
function whenHeld(n) {
    const needed = n - open.length;
    if (needed <= 0) return Promise.resolve();
    return Promise.all(Array.from({ length: needed }, () => new Promise(r => arrived.push(r))));
}

let server;
let base;
let CFG;
let OTHER;

beforeAll(async () => {
    open = [];
    arrived = [];
    await new Promise(resolve => { provider = http.createServer(providerHandler).listen(0, '127.0.0.1', resolve); });
    providerBase = `http://127.0.0.1:${provider.address().port}`;

    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;

    CFG = encodeConfig({ serverUrl: providerBase, username: 'alice', password: 'secret' });
    OTHER = encodeConfig({ serverUrl: providerBase, username: 'bob', password: 'other' });
});

afterAll(async () => {
    releaseAll();
    await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => provider.close(resolve));
});

afterEach(async () => {
    releaseAll();
    // Slots are released on the response's `close` event, which lands a tick or
    // two after the body ends.
    for (let i = 0; i < 200 && proxyInFlight.size; i++) {
        await new Promise(r => setTimeout(r, 5));
    }
});

// Starts a relay and resolves once its headers are in. The body is left
// unread — that is the point — so the caller must abort or release it.
function startRelay(token = CFG, path = 'movie/1.mp4') {
    const controller = new AbortController();
    const done = fetch(`${base}/${token}/proxy/${path}`, { signal: controller.signal });
    return { controller, done };
}

test('a token may not exceed its concurrent relay budget', async () => {
    const relays = Array.from({ length: CAP }, () => startRelay());
    const held = await Promise.all(relays.map(r => r.done));
    for (const res of held) expect(res.status).toBe(200);
    await whenHeld(CAP);

    const over = await fetch(`${base}/${CFG}/proxy/movie/9.mp4`);
    expect(over.status, 'the relay over the cap was allowed through').toBe(429);
    expect(
        over.headers.get('retry-after'),
        'a player needs to be told to come back for the segment, not that the stream ended'
    ).toBe('1');
    await over.text();

    for (const r of relays) r.controller.abort();
});

test('finishing a relay returns its slot', async () => {
    const relays = Array.from({ length: CAP }, () => startRelay());
    await Promise.all(relays.map(r => r.done));
    await whenHeld(CAP);

    expect((await fetch(`${base}/${CFG}/proxy/movie/9.mp4`)).status).toBe(429);

    releaseAll();
    await Promise.all(relays.map(async r => { await (await r.done).text(); }));
    for (let i = 0; i < 200 && proxyInFlight.size; i++) await new Promise(r => setTimeout(r, 5));

    const after = await fetch(`${base}/${CFG}/proxy/movie/9.mp4`);
    expect(after.status, 'the budget did not recover after the relays finished').toBe(200);
    after.body.cancel();
});

test('a client that disconnects mid-stream returns its slot', async () => {
    // The release is bound to the response's `close`, not to the end of the
    // handler, precisely so that an abandoned relay is not counted forever. A
    // player seeking or a device sleeping is an abort, and it is far more common
    // than a clean finish.
    const relays = Array.from({ length: CAP }, () => startRelay());
    await Promise.all(relays.map(r => r.done));
    await whenHeld(CAP);

    for (const r of relays) r.controller.abort();
    for (let i = 0; i < 200 && proxyInFlight.size; i++) await new Promise(r => setTimeout(r, 5));

    expect(proxyInFlight.size, 'an aborted relay leaked its slot').toBe(0);
    const after = await fetch(`${base}/${CFG}/proxy/movie/9.mp4`);
    expect(after.status).toBe(200);
    after.body.cancel();
});

test('one account at its cap does not throttle another', async () => {
    const relays = Array.from({ length: CAP }, () => startRelay());
    await Promise.all(relays.map(r => r.done));
    await whenHeld(CAP);

    expect((await fetch(`${base}/${CFG}/proxy/movie/9.mp4`)).status).toBe(429);

    const other = await fetch(`${base}/${OTHER}/proxy/movie/9.mp4`);
    expect(other.status, 'the budget is shared between accounts').toBe(200);
    other.body.cancel();

    for (const r of relays) r.controller.abort();
});

test('a fresh token for the same credentials shares one budget', async () => {
    // The token carries a random IV, so `/configure` mints a different string for
    // the same account every time it is asked. A budget a new install URL resets
    // is not a budget, which is why the counter is keyed by the account, the way the
    // rest of the file keys its caches.
    const reminted = encodeConfig({ serverUrl: providerBase, username: 'alice', password: 'secret' });
    expect(reminted, 'the fixture assumes tokens are not deterministic').not.toBe(CFG);

    const relays = Array.from({ length: CAP }, () => startRelay());
    await Promise.all(relays.map(r => r.done));
    await whenHeld(CAP);

    const over = await fetch(`${base}/${reminted}/proxy/movie/9.mp4`);
    expect(over.status, 're-minting the token bought a fresh allowance').toBe(429);
    await over.text();

    for (const r of relays) r.controller.abort();
});

test('a different spelling of the server URL shares one budget (audit M1)', async () => {
    // The budget was keyed on the URL as typed, so a path or query nothing upstream
    // ever sees bought a whole second allowance: 32 relays against a cap of 16.
    const respelled = encodeConfig({ serverUrl: `${providerBase}/x?y=1`, username: 'alice', password: 'secret' });

    const relays = Array.from({ length: CAP }, () => startRelay());
    await Promise.all(relays.map(r => r.done));
    await whenHeld(CAP);

    const over = await fetch(`${base}/${respelled}/proxy/movie/9.mp4`);
    expect(over.status, 're-spelling the server URL bought a fresh allowance').toBe(429);
    await over.text();

    for (const r of relays) r.controller.abort();
});

test('the signed sub-resource route is capped too', async () => {
    // The HLS route is the one that serves live segments, so leaving it uncapped
    // would leave the cap off for the traffic that runs continuously.
    const target = `${providerBase}/live/alice/secret/1.ts`;
    const { u, s, e } = encodeHlsTarget(target, CFG);
    const hls = `hls?u=${u}&s=${encodeURIComponent(s)}&e=${e}`;

    const relays = Array.from({ length: CAP }, () => startRelay(CFG, hls));
    const held = await Promise.all(relays.map(r => r.done));
    for (const res of held) expect(res.status).toBe(200);
    await whenHeld(CAP);

    const over = await fetch(`${base}/${CFG}/proxy/${hls}`);
    expect(over.status).toBe(429);
    await over.text();

    for (const r of relays) r.controller.abort();
});

test('an idle account costs no entry', async () => {
    // The key space is every account that has ever streamed. Holding a zero for
    // each of them would make the limiter its own slow leak.
    const relay = startRelay();
    await relay.done;
    await whenHeld(1);
    expect(proxyInFlight.size).toBe(1);

    relay.controller.abort();
    for (let i = 0; i < 200 && proxyInFlight.size; i++) await new Promise(r => setTimeout(r, 5));
    expect(proxyInFlight.size, 'the counter kept a zero entry for an idle account').toBe(0);
});

test('an unauthorized request is refused before it can take a slot', async () => {
    const res = await fetch(`${base}/not-a-real-token/proxy/movie/1.mp4`);
    expect(res.status).toBe(401);
    await res.text();
    expect(proxyInFlight.size).toBe(0);
});

test('a malformed request is answered as one, not refused by the cap', async () => {
    // The slot used to be taken before the request was validated, so an account at
    // its cap got 429 — "come back later" — for a request that could never work.
    const relays = Array.from({ length: CAP }, () => startRelay());
    await Promise.all(relays.map(r => r.done));
    await whenHeld(CAP);

    const badFile = await fetch(`${base}/${CFG}/proxy/movie/not-a-number.mp4`);
    expect(badFile.status).toBe(400);
    await badFile.text();

    const badTarget = await fetch(`${base}/${CFG}/proxy/hls?u=forged&s=forged&e=1`);
    expect(badTarget.status).toBe(400);
    await badTarget.text();

    for (const r of relays) r.controller.abort();
});

test('the limit can be turned off', async () => {
    // Loaded in a second module instance, because the value is read at import.
    // An operator behind their own rate limiting has a legitimate reason to want
    // this off, and "0 disables" is documented, so it is worth pinning.
    // All three relay limits are zeroed: each disables independently, and with any
    // one of them still on, taking a slot is exactly what should happen.
    const names = ['PROXY_MAX_CONCURRENT_PER_TOKEN', 'PROXY_MAX_CONCURRENT_PER_CLIENT', 'PROXY_MAX_CONCURRENT_TOTAL'];
    // Both the barrel and the module that reads the values have to be evicted, or
    // the barrel comes back fresh still holding the cached limits.
    const paths = [require.resolve('./support/internals.js'), require.resolve('../src/proxy/relay.js')];
    const saved = Object.fromEntries(names.map(name => [name, process.env[name]]));
    for (const name of names) process.env[name] = '0';
    for (const p of paths) delete require.cache[p];
    try {
        const fresh = require('./support/internals.js');
        expect(fresh.PROXY_MAX_CONCURRENT_PER_TOKEN).toBe(0);
        // Nothing is counted, so nothing can be refused.
        expect(fresh.acquireProxySlot(
            { serverUrl: 'x', username: 'y', password: 'z' },
            { headers: {}, socket: { remoteAddress: '203.0.113.5' } },
            { once() { throw new Error('must not register a release when disabled'); } }
        )).toBeNull();
        expect(fresh.proxyInFlight.size).toBe(0);
    } finally {
        for (const name of names) {
            if (saved[name] === undefined) delete process.env[name];
            else process.env[name] = saved[name];
        }
        for (const p of paths) delete require.cache[p];
        require('./support/internals.js');
    }
});
