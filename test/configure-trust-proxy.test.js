// TRUST_PROXY is read once at module load, so the enabled path needs its own
// file: behind a real proxy every request arrives from the proxy's socket, and
// without honoring X-Forwarded-For all users would share one bucket.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.TRUST_PROXY = 'true';

const test = require('node:test');
const assert = require('node:assert');

const { rateLimitConfigure, configureAttempts, clientKey, CONFIGURE_RATE_LIMIT } = require('../index.js');

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

test('a proxy chain uses the original client, not an appended hop', () => {
    const chained = reqFrom('10.0.0.1', { 'x-forwarded-for': '203.0.113.5, 10.0.0.7, 10.0.0.1' });
    assert.strictEqual(clientKey(chained), '203.0.113.5');
});

test('a proxied request with no forwarded header falls back to the socket', () => {
    assert.strictEqual(clientKey(reqFrom('10.0.0.1')), '10.0.0.1');
});
