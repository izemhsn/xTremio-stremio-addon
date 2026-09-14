// S6 — DNS lookups had no deadline and could starve the thread pool.
//
// dns.lookup runs getaddrinfo on libuv's four-thread pool, cannot be cancelled and
// ignores the fetch's abort signal. A panel on a domain whose nameserver never
// answers held a pool thread for the resolver's whole timeout, so four concurrent
// /configure attempts — two lookups each — and every proxied range request on the
// instance, each of which resolved again, queued behind them.
//
// ALLOW_PRIVATE_NETWORKS is deliberately left unset: it skips the SSRF check, and
// with it the resolver this file is about.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const { resolveHostAddresses, assertSafeOutboundUrl, dnsPins, dnsFallback, DNS_TIMEOUT_MS } = require('../index.js');

// Stands in for dns.Resolver: answers per family, or never answers at all.
function fakeResolver({ v4 = [], v6 = [], hang = false } = {}) {
    const state = { cancelled: false };
    const answer = (value) => {
        if (hang) return new Promise(() => {});
        return value instanceof Error ? Promise.reject(value) : Promise.resolve(value);
    };
    return {
        state,
        makeResolver: () => ({
            resolve4: () => answer(v4),
            resolve6: () => answer(v6),
            cancel() { state.cancelled = true; }
        })
    };
}

const failure = (code) => Object.assign(new Error(code), { code });

// --- the resolver ----------------------------------------------------------------

test('a nameserver that never answers is abandoned at the deadline, and cancelled', async () => {
    const { state, makeResolver } = fakeResolver({ hang: true });
    const started = Date.now();

    await assert.rejects(
        () => resolveHostAddresses('dead.test', { timeoutMs: 100, makeResolver }),
        (e) => e.code === 'ETIMEOUT'
    );

    const elapsed = Date.now() - started;
    assert.ok(elapsed < 1000, `gave up after ${elapsed} ms`);
    assert.ok(state.cancelled, 'the lookup was cancelled, not left running');
});

test('the default deadline is finite', () => {
    assert.ok(DNS_TIMEOUT_MS >= 500 && DNS_TIMEOUT_MS <= 30000, `DNS_TIMEOUT_MS is ${DNS_TIMEOUT_MS}`);
});

test('an IPv4-only host resolves', async () => {
    const { makeResolver } = fakeResolver({ v4: ['93.184.216.34'], v6: failure('ENODATA') });
    assert.deepEqual(await resolveHostAddresses('v4.test', { makeResolver }), [{ address: '93.184.216.34', family: 4 }]);
});

test('an IPv6-only host resolves', async () => {
    const { makeResolver } = fakeResolver({ v4: failure('ENODATA'), v6: ['2606:2800:220:1::1'] });
    assert.deepEqual(await resolveHostAddresses('v6.test', { makeResolver }), [{ address: '2606:2800:220:1::1', family: 6 }]);
});

test('both families are returned together', async () => {
    const { makeResolver } = fakeResolver({ v4: ['93.184.216.34'], v6: ['2606:2800:220:1::1'] });
    const addresses = await resolveHostAddresses('dual.test', { makeResolver });
    assert.deepEqual(addresses.map(a => a.family).sort(), [4, 6]);
});

test('a host with no addresses reports why, not just that one family was empty', async () => {
    const { makeResolver } = fakeResolver({ v4: failure('ENOTFOUND'), v6: failure('ENODATA') });
    await assert.rejects(
        () => resolveHostAddresses('gone.test', { makeResolver }),
        (e) => e.code === 'ENOTFOUND'
    );
});

// --- falling back when c-ares itself is unusable ----------------------------------
//
// Measured on a Windows host: c-ares was configured with 127.0.0.1 alone, nothing
// listened there, and every query failed at once with ECONNREFUSED while the OS
// resolver answered normally. /configure then called every panel unreachable.

function countingLookup(answer) {
    const calls = [];
    return {
        calls,
        lookup: async (host) => {
            calls.push(host);
            if (answer === 'hang') return new Promise(() => {});
            return answer;
        }
    };
}

function quietLog() {
    const warnings = [];
    return { warnings, log: { warn: (msg) => warnings.push(msg) } };
}

test('an unreachable nameserver falls back to the OS resolver, with one warning', async () => {
    dnsFallback.warned = false;
    const { makeResolver } = fakeResolver({ v4: failure('ECONNREFUSED'), v6: failure('ECONNREFUSED') });
    const { calls, lookup } = countingLookup([{ address: '93.184.216.34', family: 4 }]);
    const { warnings, log } = quietLog();

    for (let i = 0; i < 2; i++) {
        assert.deepEqual(
            await resolveHostAddresses('panel.test', { makeResolver, lookup, log }),
            [{ address: '93.184.216.34', family: 4 }]
        );
    }
    assert.deepEqual(calls, ['panel.test', 'panel.test']);
    assert.equal(warnings.length, 1, 'the operator hears it once, not on every lookup');
    assert.match(warnings[0], /ECONNREFUSED/);
});

test('a bad name or a slow nameserver does not fall back', async () => {
    // A timeout falling back would put getaddrinfo — uncancellable, on the shared
    // pool — back in front of every relay: the S6 stall.
    const { log } = quietLog();

    const gone = countingLookup([{ address: '93.184.216.34', family: 4 }]);
    await assert.rejects(
        () => resolveHostAddresses('gone.test', {
            makeResolver: fakeResolver({ v4: failure('ENOTFOUND'), v6: failure('ENODATA') }).makeResolver,
            lookup: gone.lookup,
            log
        }),
        (e) => e.code === 'ENOTFOUND'
    );
    assert.deepEqual(gone.calls, []);

    const slow = countingLookup([{ address: '93.184.216.34', family: 4 }]);
    await assert.rejects(
        () => resolveHostAddresses('dead.test', {
            timeoutMs: 100,
            makeResolver: fakeResolver({ hang: true }).makeResolver,
            lookup: slow.lookup,
            log
        }),
        (e) => e.code === 'ETIMEOUT'
    );
    assert.deepEqual(slow.calls, []);
});

test('the fallback is held to the same deadline', async () => {
    const { makeResolver } = fakeResolver({ v4: failure('ECONNREFUSED'), v6: failure('ECONNREFUSED') });
    const { lookup } = countingLookup('hang');
    const { log } = quietLog();
    const started = Date.now();

    await assert.rejects(
        () => resolveHostAddresses('stuck.test', { timeoutMs: 100, makeResolver, lookup, log }),
        (e) => e.code === 'ETIMEOUT'
    );
    assert.ok(Date.now() - started < 1000);
});

// --- the SSRF check that uses it --------------------------------------------------

test('a host vetted within the pin window is not looked up again', async () => {
    // Audit P4: every range request of a movie paid a fresh lookup, which is what put
    // the resolver on the hot path in the first place.
    dnsPins.clear();
    let lookups = 0;
    const resolve = async () => {
        lookups++;
        return [{ address: '93.184.216.34', family: 4 }];
    };

    await assertSafeOutboundUrl('http://cdn.reuse.test/a.ts', { resolve });
    const expiresAt = dnsPins.get('cdn.reuse.test').expiresAt;
    await assertSafeOutboundUrl('http://cdn.reuse.test/b.ts', { resolve });
    await assertSafeOutboundUrl('https://cdn.reuse.test:8443/c.ts', { resolve });

    assert.equal(lookups, 1);
    assert.equal(dnsPins.get('cdn.reuse.test').expiresAt, expiresAt, 'reuse does not extend the pin');

    dnsPins.get('cdn.reuse.test').expiresAt = Date.now() - 1;
    await assertSafeOutboundUrl('http://cdn.reuse.test/d.ts', { resolve });
    assert.equal(lookups, 2, 'an expired pin is looked up again');
});

test('an address the resolver returns is still vetted', async () => {
    await assert.rejects(
        () => assertSafeOutboundUrl('http://sneaky.test/', { resolve: async () => [{ address: '10.0.0.5', family: 4 }] }),
        (e) => e.code === 'OUTBOUND_BLOCKED'
    );
});

test('localhost names are refused by name, without a lookup', async () => {
    // The resolver does not read /etc/hosts, so it would not answer for these at
    // all; they must be refused as loopback rather than fail as unresolvable.
    let lookups = 0;
    const resolve = async () => {
        lookups++;
        return [];
    };
    for (const url of ['http://localhost:8080/', 'http://api.localhost/', 'http://LOCALHOST./']) {
        await assert.rejects(() => assertSafeOutboundUrl(url, { resolve }), (e) => e.code === 'OUTBOUND_BLOCKED', url);
    }
    assert.equal(lookups, 0);
});
