// POST /configure makes an outbound request to a caller-chosen host with
// caller-chosen credentials, before any authentication. Without a limit the
// instance is a port scanner and a credential-stuffing relay on its own IP.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const {
    rateLimitConfigure,
    configureAttempts,
    clientKey,
    CONFIGURE_RATE_LIMIT,
    CONFIGURE_RATE_WINDOW_MS,
    CONFIGURE_RATE_MAX_CLIENTS,
    getBaseUrl
} = require('./support/internals.js');

// A request stub carrying only what the limiter reads.
function reqFrom(ip, headers = {}) {
    return { socket: { remoteAddress: ip }, headers };
}

beforeEach(() => configureAttempts.clear());

test('requests under the limit are allowed', () => {
    const req = reqFrom('203.0.113.5');
    for (let i = 0; i < CONFIGURE_RATE_LIMIT; i++) {
        expect(rateLimitConfigure(req).allowed, `attempt ${i + 1} should pass`).toBe(true);
    }
});

test('the attempt after the limit is blocked, with a Retry-After', () => {
    const req = reqFrom('203.0.113.5');
    for (let i = 0; i < CONFIGURE_RATE_LIMIT; i++) rateLimitConfigure(req);

    const blocked = rateLimitConfigure(req);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfter, 'a blocked caller is told when to retry').toBeGreaterThan(0);
    expect(blocked.retryAfter, 'retryAfter never exceeds the window').toBeLessThanOrEqual(Math.ceil(CONFIGURE_RATE_WINDOW_MS / 1000));
});

test('one client being blocked does not block another', () => {
    const attacker = reqFrom('203.0.113.5');
    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) rateLimitConfigure(attacker);
    expect(rateLimitConfigure(attacker).allowed).toBe(false);

    expect(rateLimitConfigure(reqFrom('198.51.100.9')).allowed).toBe(true);
});

test('the window expires and the client is allowed again', () => {
    const req = reqFrom('203.0.113.5');
    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) rateLimitConfigure(req);
    expect(rateLimitConfigure(req).allowed).toBe(false);

    // Age the window out rather than sleeping through it.
    configureAttempts.get(clientKey(req)).resetAt = Date.now() - 1;

    expect(rateLimitConfigure(req).allowed, 'a new window starts clean').toBe(true);
});

test('expired entries are swept, so the map tracks only active clients', () => {
    for (let i = 0; i < 50; i++) rateLimitConfigure(reqFrom(`203.0.113.${i}`));
    expect(configureAttempts.size).toBe(50);

    for (const entry of configureAttempts.values()) entry.resetAt = Date.now() - 1;

    rateLimitConfigure(reqFrom('198.51.100.1'));
    expect(configureAttempts.size, 'the sweep dropped all 50 expired buckets').toBe(1);
});

test('a full limiter map evicts its oldest bucket rather than switching itself off', () => {
    // Audit S5. This used to assert that a full map let every new client through —
    // "fails open rather than locking everyone out". But untracked meant unlimited,
    // so 10,000 addresses in one window turned the limiter off for everyone. Evicting
    // the oldest bucket keeps limiting the clients that are still arriving.
    const future = Date.now() + CONFIGURE_RATE_WINDOW_MS;
    for (let i = 0; i < CONFIGURE_RATE_MAX_CLIENTS; i++) {
        configureAttempts.set(`filler-${i}`, { count: 1, resetAt: future });
    }

    const fresh = reqFrom('198.51.100.77');
    expect(rateLimitConfigure(fresh).allowed, 'a new client still gets its first attempt').toBe(true);
    expect(configureAttempts.size, 'the map does not grow past the bound').toBe(CONFIGURE_RATE_MAX_CLIENTS);
    expect(configureAttempts.has('filler-0'), 'the oldest bucket made room').toBeFalsy();

    for (let i = 1; i < CONFIGURE_RATE_LIMIT; i++) rateLimitConfigure(fresh);
    expect(rateLimitConfigure(fresh).allowed, 'and the new client is limited, not waved through').toBe(false);
});

// The whole point of defaulting TRUST_PROXY off: the header is client-supplied,
// so honoring it with no proxy in front hands every caller an unlimited supply
// of fresh buckets.
test('a spoofed X-Forwarded-For cannot escape the bucket when TRUST_PROXY is off', () => {
    expect(process.env.TRUST_PROXY, 'this test asserts the default').not.toBe('true');

    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) {
        rateLimitConfigure(reqFrom('203.0.113.5', { 'x-forwarded-for': `10.0.0.${i}` }));
    }

    const spoofed = rateLimitConfigure(reqFrom('203.0.113.5', { 'x-forwarded-for': '10.9.9.9' }));
    expect(spoofed.allowed, 'the socket address still governs').toBe(false);
    expect(configureAttempts.size, 'varying the header created no extra buckets').toBe(1);
});

test('forwarded headers do not choose the install link host when TRUST_PROXY is off', () => {
    // Audit D4. getBaseUrl used to honour X-Forwarded-Proto and -Host regardless of
    // the flag the rate limiter already required for X-Forwarded-For.
    const req = {
        protocol: 'http',
        socket: {},
        headers: { host: 'addon.example.com', 'x-forwarded-proto': 'https', 'x-forwarded-host': 'attacker.example' }
    };
    expect(getBaseUrl(req)).toBe('http://addon.example.com');
});

test('an IPv6 client is limited by its /64, not by each address in it', () => {
    // One connection is routinely assigned a whole /64: 2^64 buckets per subscriber.
    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) {
        rateLimitConfigure(reqFrom(`2001:db8:aaaa:bbbb::${(i + 1).toString(16)}`));
    }
    expect(rateLimitConfigure(reqFrom('2001:db8:aaaa:bbbb:1234:5678:9abc:def0')).allowed).toBe(false);
    expect(
        rateLimitConfigure(reqFrom('2001:db8:aaaa:cccc::1')).allowed,
        'a different /64 is a different client'
    ).toBe(true);
});

test('an IPv4 client on a dual-stack socket is the same bucket either way', () => {
    expect(clientKey(reqFrom('::ffff:203.0.113.5'))).toBe(clientKey(reqFrom('203.0.113.5')));
});

test('a request with no discoverable address still gets a bucket', () => {
    const req = { socket: {}, headers: {} };
    for (let i = 0; i <= CONFIGURE_RATE_LIMIT; i++) rateLimitConfigure(req);
    expect(rateLimitConfigure(req).allowed, 'unknown callers are limited, not exempt').toBe(false);
});
