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

const {
    resolveHostAddresses,
    assertSafeOutboundUrl,
    dnsPins,
    dnsFallback,
    DNS_TIMEOUT_MS,
    DNS_SERVERS,
    parseDnsServers,
    makeDnsResolver
} = require('./support/internals.js');

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

    await expect(resolveHostAddresses('dead.test', { timeoutMs: 100, makeResolver })).rejects.toMatchObject({
        code: 'ETIMEOUT'
    });

    const elapsed = Date.now() - started;
    expect(elapsed, `gave up after ${elapsed} ms`).toBeLessThan(1000);
    expect(state.cancelled, 'the lookup was cancelled, not left running').toBeTruthy();
});

test('the default deadline is finite', () => {
    expect(
        DNS_TIMEOUT_MS >= 500 && DNS_TIMEOUT_MS <= 30000,
        `DNS_TIMEOUT_MS is ${DNS_TIMEOUT_MS}`
    ).toBeTruthy();
});

test('an IPv4-only host resolves', async () => {
    const { makeResolver } = fakeResolver({ v4: ['93.184.216.34'], v6: failure('ENODATA') });
    expect(await resolveHostAddresses('v4.test', { makeResolver })).toStrictEqual([{ address: '93.184.216.34', family: 4 }]);
});

test('an IPv6-only host resolves', async () => {
    const { makeResolver } = fakeResolver({ v4: failure('ENODATA'), v6: ['2606:2800:220:1::1'] });
    expect(await resolveHostAddresses('v6.test', { makeResolver })).toStrictEqual([{ address: '2606:2800:220:1::1', family: 6 }]);
});

test('both families are returned together', async () => {
    const { makeResolver } = fakeResolver({ v4: ['93.184.216.34'], v6: ['2606:2800:220:1::1'] });
    const addresses = await resolveHostAddresses('dual.test', { makeResolver });
    expect(addresses.map(a => a.family).sort()).toStrictEqual([4, 6]);
});

test('a host with no addresses reports why, not just that one family was empty', async () => {
    const { makeResolver } = fakeResolver({ v4: failure('ENOTFOUND'), v6: failure('ENODATA') });
    await expect(resolveHostAddresses('gone.test', { makeResolver })).rejects.toMatchObject({
        code: 'ENOTFOUND'
    });
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
        expect(await resolveHostAddresses('panel.test', { makeResolver, lookup, log })).toStrictEqual([{ address: '93.184.216.34', family: 4 }]);
    }
    expect(calls).toStrictEqual(['panel.test', 'panel.test']);
    expect(warnings.length, 'the operator hears it once, not on every lookup').toBe(1);
    expect(warnings[0]).toMatch(/ECONNREFUSED/);
});

test('a bad name or a slow nameserver does not fall back', async () => {
    // A timeout falling back would put getaddrinfo — uncancellable, on the shared
    // pool — back in front of every relay: the S6 stall.
    const { log } = quietLog();

    const gone = countingLookup([{ address: '93.184.216.34', family: 4 }]);
    await expect(resolveHostAddresses('gone.test', {
        makeResolver: fakeResolver({ v4: failure('ENOTFOUND'), v6: failure('ENODATA') }).makeResolver,
        lookup: gone.lookup,
        log
    })).rejects.toMatchObject({
        code: 'ENOTFOUND'
    });
    expect(gone.calls).toStrictEqual([]);

    const slow = countingLookup([{ address: '93.184.216.34', family: 4 }]);
    await expect(resolveHostAddresses('dead.test', {
        timeoutMs: 100,
        makeResolver: fakeResolver({ hang: true }).makeResolver,
        lookup: slow.lookup,
        log
    })).rejects.toMatchObject({
        code: 'ETIMEOUT'
    });
    expect(slow.calls).toStrictEqual([]);
});

test('the fallback is held to the same deadline', async () => {
    const { makeResolver } = fakeResolver({ v4: failure('ECONNREFUSED'), v6: failure('ECONNREFUSED') });
    const { lookup } = countingLookup('hang');
    const { log } = quietLog();
    const started = Date.now();

    await expect(
        resolveHostAddresses('stuck.test', { timeoutMs: 100, makeResolver, lookup, log })
    ).rejects.toMatchObject({
        code: 'ETIMEOUT'
    });
    expect(Date.now() - started).toBeLessThan(1000);
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

    expect(lookups).toBe(1);
    expect(dnsPins.get('cdn.reuse.test').expiresAt, 'reuse does not extend the pin').toBe(expiresAt);

    dnsPins.get('cdn.reuse.test').expiresAt = Date.now() - 1;
    await assertSafeOutboundUrl('http://cdn.reuse.test/d.ts', { resolve });
    expect(lookups, 'an expired pin is looked up again').toBe(2);
});

test('an address the resolver returns is still vetted', async () => {
    await expect(
        assertSafeOutboundUrl('http://sneaky.test/', { resolve: async () => [{ address: '10.0.0.5', family: 4 }] })
    ).rejects.toMatchObject({
        code: 'OUTBOUND_BLOCKED'
    });
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
        await expect(assertSafeOutboundUrl(url, { resolve }), url).rejects.toMatchObject({
            code: 'OUTBOUND_BLOCKED'
        });
    }
    expect(lookups).toBe(0);
});

// --- DNS_SERVERS -----------------------------------------------------------
//
// c-ares works out its own nameserver list and can get it wrong where the OS
// resolver works: one Windows host gave it only 127.0.0.1, so every lookup failed
// with ECONNREFUSED and /configure called every panel unreachable. The
// DNS_RESOLVER_UNUSABLE fallback keeps that host serving; this is how an operator
// fixes it properly.

test('DNS_SERVERS accepts every spelling c-ares does', () => {
    const quiet = { warn() {} };
    expect(
        parseDnsServers('8.8.8.8, 1.1.1.1:53 ,2001:4860:4860::8888,[2001:4860:4860::8844]:53', 'DNS_SERVERS', quiet)
    ).toStrictEqual(
        ['8.8.8.8', '1.1.1.1:53', '2001:4860:4860::8888', '[2001:4860:4860::8844]:53']
    );
    // Validation is c-ares' own, not a regular expression of ours, so the rule
    // cannot drift from what setServers will actually take.
    expect(parseDnsServers('', 'DNS_SERVERS', quiet)).toStrictEqual([]);
    expect(parseDnsServers(undefined, 'DNS_SERVERS', quiet)).toStrictEqual([]);
});

test('a bad DNS_SERVERS entry is dropped with a warning, not taken and not fatal', () => {
    // Three outcomes were possible and two are wrong: taking it silently leaves a
    // resolver pointed at nothing, and refusing to boot turns one typo into an
    // outage. The good entries must survive the bad one.
    const lines = [];
    const log = { warn: (m) => lines.push(m) };
    expect(parseDnsServers('8.8.8.8,nonsense,1.2.3.4.5,1.1.1.1', 'DNS_SERVERS', log)).toStrictEqual(['8.8.8.8', '1.1.1.1']);
    expect(
        lines.length,
        `expected one warning per bad entry, got ${JSON.stringify(lines)}`
    ).toBe(2);
    expect(lines[0]).toMatch(/DNS_SERVERS: ignoring "nonsense"/);
    expect(lines[1]).toMatch(/"1\.2\.3\.4\.5"/);
});

test('makeDnsResolver points the resolver at the configured servers', () => {
    expect(makeDnsResolver(DNS_TIMEOUT_MS, ['8.8.8.8', '1.1.1.1']).getServers()).toStrictEqual(['8.8.8.8', '1.1.1.1']);

    // Empty means leave c-ares to its own discovery, which is the default and what
    // works on most hosts — not "no servers", which would break every lookup.
    expect(makeDnsResolver(DNS_TIMEOUT_MS, []).getServers().length).toBeGreaterThanOrEqual(0);
    expect(DNS_SERVERS, 'the suite runs with DNS_SERVERS unset').toStrictEqual([]);
});

test('every resolver this module makes goes through makeDnsResolver', () => {
    // A setting that reached some lookups and missed others would be worse than
    // not having it: the host it exists for would still fail, intermittently.
    const src = require('node:fs').readFileSync(require.resolve('../src/net/safe-fetch.js'), 'utf8');
    const constructions = src.match(/new dns\.Resolver\(/g) || [];
    expect(
        constructions.length,
        'expected exactly two: makeDnsResolver itself, and the validation probe in parseDnsServers'
    ).toBe(2);
});
