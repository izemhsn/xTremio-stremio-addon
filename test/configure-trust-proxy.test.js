// TRUST_PROXY is read once at module load, so the enabled path needs its own
// file: behind a real proxy every request arrives from the proxy's socket, and
// without honoring X-Forwarded-For all users would share one bucket.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.TRUST_PROXY = 'true';

const {
    rateLimitConfigure,
    configureAttempts,
    clientKey,
    getBaseUrl,
    TRUST_PROXY_HOPS,
    CONFIGURE_RATE_LIMIT
} = require('./support/internals.js');

function reqFrom(ip, headers = {}) {
    return { socket: { remoteAddress: ip }, headers };
}

beforeEach(() => configureAttempts.clear());

test('with TRUST_PROXY on, the forwarded client address is the bucket key', () => {
    const proxied = reqFrom('10.0.0.1', { 'x-forwarded-for': '203.0.113.5' });
    expect(clientKey(proxied), 'not the proxy socket address').toBe('203.0.113.5');
});

test('two users behind one proxy get separate buckets', () => {
    const a = reqFrom('10.0.0.1', { 'x-forwarded-for': '203.0.113.5' });
    const b = reqFrom('10.0.0.1', { 'x-forwarded-for': '198.51.100.9' });

    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) rateLimitConfigure(a);
    expect(rateLimitConfigure(a).allowed).toBe(false);
    expect(rateLimitConfigure(b).allowed, 'b is not punished for a').toBe(true);
});

test('the entry the trusted proxy appended is the client, not one the client wrote', () => {
    // Audit S5. This test used to assert the opposite: that a chain resolves to its
    // leftmost entry, "the original client". But a proxy *appends* the address it
    // saw, so everything left of that entry arrived from the client, and taking the
    // leftmost let `X-Forwarded-For: <anything>` pick the bucket. nginx's
    // $proxy_add_x_forwarded_for produces exactly this shape.
    const spoofed = reqFrom('10.0.0.1', { 'x-forwarded-for': 'spoofed-by-client, 198.51.100.7' });
    expect(clientKey(spoofed)).toBe('198.51.100.7');

    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) {
        rateLimitConfigure(reqFrom('10.0.0.1', { 'x-forwarded-for': `203.0.113.${i}, 198.51.100.7` }));
    }
    expect(
        rateLimitConfigure(reqFrom('10.0.0.1', { 'x-forwarded-for': '192.0.2.99, 198.51.100.7' })).allowed,
        'varying what the client wrote no longer buys a fresh bucket'
    ).toBe(false);
});

test('TRUST_PROXY=true counts one hop', () => {
    expect(TRUST_PROXY_HOPS).toBe(1);
    const chained = reqFrom('10.0.0.1', { 'x-forwarded-for': '203.0.113.5, 10.0.0.7, 198.51.100.7' });
    expect(clientKey(chained)).toBe('198.51.100.7');
});

test('a forwarded value that is not an address falls back to the socket', () => {
    // A garbage key would be a free bucket.
    expect(clientKey(reqFrom('10.0.0.1', { 'x-forwarded-for': 'not-an-ip' }))).toBe('10.0.0.1');
});

test('a proxied IPv6 client is bucketed by its /64', () => {
    const a = reqFrom('10.0.0.1', { 'x-forwarded-for': '2001:db8:1:2::a' });
    const b = reqFrom('10.0.0.1', { 'x-forwarded-for': '2001:db8:1:2:ffff:ffff:ffff:ffff' });
    expect(clientKey(a)).toBe(clientKey(b));
});

test('install links use what the trusted proxy reported', () => {
    // Audit D4: honoured only with TRUST_PROXY on (configure-rate-limit covers the
    // off case), and read from the right like the client address.
    const req = {
        protocol: 'http',
        socket: {},
        headers: { host: 'internal:3000', 'x-forwarded-proto': 'https', 'x-forwarded-host': 'addon.example.com' }
    };
    expect(getBaseUrl(req)).toBe('https://addon.example.com');
});

test('TRUST_PROXY can count more than one hop', () => {
    // Behind a CDN and nginx that both append, the client is two in from the right.
    // Loaded in a second module instance, because the setting is read at import —
    // which means evicting the module that reads it as well as the barrel that
    // re-exports it, or the barrel comes back fresh holding the cached old value.
    const paths = [require.resolve('./support/internals.js'), require.resolve('../src/routes/request.js')];
    const saved = process.env.TRUST_PROXY;
    process.env.TRUST_PROXY = '2';
    for (const p of paths) delete require.cache[p];
    try {
        const fresh = require('./support/internals.js');
        expect(fresh.TRUST_PROXY_HOPS).toBe(2);
        const chained = reqFrom('10.0.0.1', { 'x-forwarded-for': 'spoofed, 198.51.100.7, 172.16.0.9' });
        expect(fresh.clientKey(chained)).toBe('198.51.100.7');
    } finally {
        process.env.TRUST_PROXY = saved;
        for (const p of paths) delete require.cache[p];
        require('./support/internals.js');
    }
});

test('a proxied request with no forwarded header falls back to the socket', () => {
    expect(clientKey(reqFrom('10.0.0.1'))).toBe('10.0.0.1');
});
