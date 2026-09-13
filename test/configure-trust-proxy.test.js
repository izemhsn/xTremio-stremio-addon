// TRUST_PROXY is read once at module load, so the enabled path needs its own
// file: behind a real proxy every request arrives from the proxy's socket, and
// without honoring X-Forwarded-For all users would share one bucket.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.TRUST_PROXY = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    rateLimitConfigure,
    configureAttempts,
    clientKey,
    getBaseUrl,
    TRUST_PROXY_HOPS,
    CONFIGURE_RATE_LIMIT
} = require('../index.js');

function reqFrom(ip, headers = {}) {
    return { socket: { remoteAddress: ip }, headers };
}

test.beforeEach(() => configureAttempts.clear());

test('with TRUST_PROXY on, the forwarded client address is the bucket key', () => {
    const proxied = reqFrom('10.0.0.1', { 'x-forwarded-for': '203.0.113.5' });
    assert.strictEqual(clientKey(proxied), '203.0.113.5', 'not the proxy socket address');
});

test('two users behind one proxy get separate buckets', () => {
    const a = reqFrom('10.0.0.1', { 'x-forwarded-for': '203.0.113.5' });
    const b = reqFrom('10.0.0.1', { 'x-forwarded-for': '198.51.100.9' });

    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) rateLimitConfigure(a);
    assert.strictEqual(rateLimitConfigure(a).allowed, false);
    assert.strictEqual(rateLimitConfigure(b).allowed, true, 'b is not punished for a');
});

test('the entry the trusted proxy appended is the client, not one the client wrote', () => {
    // Audit S5. This test used to assert the opposite: that a chain resolves to its
    // leftmost entry, "the original client". But a proxy *appends* the address it
    // saw, so everything left of that entry arrived from the client, and taking the
    // leftmost let `X-Forwarded-For: <anything>` pick the bucket. nginx's
    // $proxy_add_x_forwarded_for produces exactly this shape.
    const spoofed = reqFrom('10.0.0.1', { 'x-forwarded-for': 'spoofed-by-client, 198.51.100.7' });
    assert.strictEqual(clientKey(spoofed), '198.51.100.7');

    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) {
        rateLimitConfigure(reqFrom('10.0.0.1', { 'x-forwarded-for': `203.0.113.${i}, 198.51.100.7` }));
    }
    assert.strictEqual(
        rateLimitConfigure(reqFrom('10.0.0.1', { 'x-forwarded-for': '192.0.2.99, 198.51.100.7' })).allowed,
        false,
        'varying what the client wrote no longer buys a fresh bucket'
    );
});

test('TRUST_PROXY=true counts one hop', () => {
    assert.strictEqual(TRUST_PROXY_HOPS, 1);
    const chained = reqFrom('10.0.0.1', { 'x-forwarded-for': '203.0.113.5, 10.0.0.7, 198.51.100.7' });
    assert.strictEqual(clientKey(chained), '198.51.100.7');
});

test('a forwarded value that is not an address falls back to the socket', () => {
    // A garbage key would be a free bucket.
    assert.strictEqual(clientKey(reqFrom('10.0.0.1', { 'x-forwarded-for': 'not-an-ip' })), '10.0.0.1');
});

test('a proxied IPv6 client is bucketed by its /64', () => {
    const a = reqFrom('10.0.0.1', { 'x-forwarded-for': '2001:db8:1:2::a' });
    const b = reqFrom('10.0.0.1', { 'x-forwarded-for': '2001:db8:1:2:ffff:ffff:ffff:ffff' });
    assert.strictEqual(clientKey(a), clientKey(b));
});

test('install links use what the trusted proxy reported', () => {
    // Audit D4: honoured only with TRUST_PROXY on (configure-rate-limit covers the
    // off case), and read from the right like the client address.
    const req = {
        protocol: 'http',
        socket: {},
        headers: { host: 'internal:3000', 'x-forwarded-proto': 'https', 'x-forwarded-host': 'addon.example.com' }
    };
    assert.strictEqual(getBaseUrl(req), 'https://addon.example.com');
});

test('TRUST_PROXY can count more than one hop', () => {
    // Behind a CDN and nginx that both append, the client is two in from the right.
    // Loaded in a second module instance, because the setting is read at import.
    const path = require.resolve('../index.js');
    const saved = process.env.TRUST_PROXY;
    process.env.TRUST_PROXY = '2';
    delete require.cache[path];
    try {
        const fresh = require('../index.js');
        assert.strictEqual(fresh.TRUST_PROXY_HOPS, 2);
        const chained = reqFrom('10.0.0.1', { 'x-forwarded-for': 'spoofed, 198.51.100.7, 172.16.0.9' });
        assert.strictEqual(fresh.clientKey(chained), '198.51.100.7');
    } finally {
        process.env.TRUST_PROXY = saved;
        delete require.cache[path];
        require('../index.js');
    }
});

test('a proxied request with no forwarded header falls back to the socket', () => {
    assert.strictEqual(clientKey(reqFrom('10.0.0.1')), '10.0.0.1');
});
