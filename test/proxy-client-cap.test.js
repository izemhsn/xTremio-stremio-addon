// S3 on an instance anyone may use with any provider: the per-account relay cap
// does not bound a caller who can make accounts. /configure mints one for any panel
// that passes the credential check, so a caller with a panel of their own — or many
// made-up usernames on one — got a fresh allowance for every account. Relays are now
// also bounded per client address and in total.
//
// TRUST_PROXY is on so one test process can speak as several clients, and the
// per-account cap is set high so that it never decides a result in this file.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.TRUST_PROXY = 'true';
process.env.PROXY_MAX_CONCURRENT_PER_TOKEN = '100';
process.env.PROXY_MAX_CONCURRENT_PER_CLIENT = '2';
process.env.PROXY_MAX_CONCURRENT_TOTAL = '3';

const http = require('node:http');

const {
    app,
    encodeConfig,
    proxyInFlight,
    proxyInFlightByClient,
    proxyRelays,
    PROXY_MAX_CONCURRENT_PER_CLIENT,
    PROXY_MAX_CONCURRENT_TOTAL
} = require('./support/internals.js');

// --- a provider that holds its responses open ------------------------------

let provider;
let providerBase;
let server;
let base;
let open = [];
let arrived = [];

function providerHandler(req, res) {
    res.writeHead(200, { 'Content-Type': 'video/mp4' });
    res.write('x'); // headers and a first byte, so the addon starts piping
    open.push(res);
    const waiter = arrived.shift();
    if (waiter) waiter();
}

function releaseAll() {
    for (const res of open.splice(0)) res.end();
}

function whenHeld(n) {
    const needed = n - open.length;
    if (needed <= 0) return Promise.resolve();
    return Promise.all(Array.from({ length: needed }, () => new Promise(r => arrived.push(r))));
}

async function idle() {
    for (let i = 0; i < 200 && (proxyRelays.total || proxyInFlightByClient.size || proxyInFlight.size); i++) {
        await new Promise(r => setTimeout(r, 5));
    }
}

beforeAll(async () => {
    await new Promise(resolve => { provider = http.createServer(providerHandler).listen(0, '127.0.0.1', resolve); });
    providerBase = `http://127.0.0.1:${provider.address().port}`;
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
    releaseAll();
    await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => provider.close(resolve));
});

afterEach(async () => {
    releaseAll();
    await idle();
});

// A distinct account on every call: the made-up usernames the per-account cap
// cannot tell apart from real households.
let accounts = 0;
const freshAccount = () => encodeConfig({ serverUrl: providerBase, username: `made-up-${++accounts}`, password: 'x' });

function relay(client, token = freshAccount(), signal) {
    return fetch(`${base}/${token}/proxy/movie/1.mp4`, { signal, headers: { 'x-forwarded-for': client } });
}

function startRelay(client) {
    const controller = new AbortController();
    return { controller, done: relay(client, freshAccount(), controller.signal) };
}

test('the fixture sets the limits this file relies on', () => {
    expect(PROXY_MAX_CONCURRENT_PER_CLIENT).toBe(2);
    expect(PROXY_MAX_CONCURRENT_TOTAL).toBe(3);
});

test('one client cannot exceed its relay budget by using many accounts', async () => {
    const relays = [startRelay('203.0.113.5'), startRelay('203.0.113.5')];
    for (const res of await Promise.all(relays.map(r => r.done))) expect(res.status).toBe(200);
    await whenHeld(2);

    const over = await relay('203.0.113.5');
    expect(over.status, 'a brand-new account from the same client still counts against the client').toBe(429);
    expect(over.headers.get('retry-after')).toBe('1');
    await over.text();

    for (const r of relays) r.controller.abort();
});

test('another client is not throttled by the first', async () => {
    const relays = [startRelay('203.0.113.5'), startRelay('203.0.113.5')];
    await Promise.all(relays.map(r => r.done));
    await whenHeld(2);

    const other = await relay('198.51.100.9');
    expect(other.status).toBe(200);
    other.body.cancel();

    for (const r of relays) r.controller.abort();
});

test('an IPv6 client is one client across its /64', async () => {
    const relays = [startRelay('2001:db8:1:2::a'), startRelay('2001:db8:1:2::b')];
    await Promise.all(relays.map(r => r.done));
    await whenHeld(2);

    const over = await relay('2001:db8:1:2::c');
    expect(over.status, 'a new address in the same /64 is the same subscriber').toBe(429);
    await over.text();

    for (const r of relays) r.controller.abort();
});

test('the whole server is bounded, however many clients there are', async () => {
    const relays = ['203.0.113.1', '203.0.113.2', '203.0.113.3'].map(startRelay);
    for (const res of await Promise.all(relays.map(r => r.done))) expect(res.status).toBe(200);
    await whenHeld(3);

    const over = await relay('203.0.113.4');
    expect(over.status, "capacity is the server's, not this caller's usage").toBe(503);
    expect(over.headers.get('retry-after')).toBe('5');
    await over.text();

    for (const r of relays) r.controller.abort();
});

test('a refused relay holds no slot anywhere', async () => {
    const relays = [startRelay('203.0.113.5'), startRelay('203.0.113.5')];
    await Promise.all(relays.map(r => r.done));
    await whenHeld(2);

    const counts = () => ({
        total: proxyRelays.total,
        client: proxyInFlightByClient.get('203.0.113.5'),
        accounts: proxyInFlight.size
    });
    const before = counts();

    const over = await relay('203.0.113.5');
    expect(over.status).toBe(429);
    await over.text();
    expect(counts(), 'the refusal took nothing it would then have to give back').toStrictEqual(before);

    for (const r of relays) r.controller.abort();
});

test('every count returns to zero when the relays end', async () => {
    const relays = ['203.0.113.1', '203.0.113.2'].map(startRelay);
    await Promise.all(relays.map(r => r.done));
    await whenHeld(2);
    expect(proxyRelays.total).toBe(2);
    expect(proxyInFlightByClient.size).toBe(2);

    for (const r of relays) r.controller.abort();
    await idle();

    expect(proxyRelays.total).toBe(0);
    expect(proxyInFlightByClient.size, 'an idle client costs no entry').toBe(0);
    expect(proxyInFlight.size).toBe(0);
});
