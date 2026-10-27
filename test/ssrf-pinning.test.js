// H-2 — the HLS rewriter signed whatever URL the provider put in its playlist,
// and the only thing left standing between a signed target and an internal
// service was a DNS check that the HTTP client then repeated for itself.
//
// Two separate holes, fixed independently:
//
//   Signing.  rewriteHlsPlaylist handed every URI to encodeHlsTarget with no
//   filter beyond http(s), so a hostile or compromised panel got this server to
//   mint valid, permanent capabilities for any URL at all — a strictly larger
//   primitive than the fixed /movie/user/pass/id.ext shape the earlier audit
//   was scoped against. Targets are now vetted before they are signed.
//
//   Fetching.  assertSafeOutboundUrl resolved the hostname, checked the
//   addresses, threw them away, and called fetch(), which resolved again. A
//   record with a near-zero TTL alternating between a public address and
//   169.254.169.254 passed the check and connected to the internal one. The
//   vetted addresses are now pinned and handed to the connector, which performs
//   no lookup of its own.
//
// This file deliberately does NOT set ALLOW_PRIVATE_NETWORKS: the guard has to
// be on for any of it to mean anything.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
delete process.env.ALLOW_PRIVATE_NETWORKS;

const http = require('node:http');
const fs = require('node:fs');

const {
    makeHlsProxyMapper,
    rewriteHlsPlaylist,
    decodeHlsTarget,
    assertSafeOutboundUrl,
    pinnedLookup,
    pinResolvedAddresses,
    dnsPins,
    PINNED_DISPATCHER
} = require('./support/internals.js');

const realFetch = global.fetch;
// The guard and the pin live here now. The two assertions below read source
// rather than behaviour — the properties they pin are invisible from outside —
// so they have to name the file the code is actually written in.
const SAFE_FETCH_SRC = require.resolve('../src/net/safe-fetch.js');

// A literal address, so nothing here depends on DNS or on being online.
const PUBLIC_IP = '93.184.216.34';

// These tests are about the private-address rule, so the origins under test are
// admitted by the M-3 allowlist and the only thing left to refuse them is the
// address check itself. Signing an off-origin target has its own file.
const ALLOWED = new Set([
    'https://addon.test',
    `http://${PUBLIC_IP}`,
    'http://169.254.169.254',
    'http://127.0.0.1:1234',
    'http://[::1]:8080',
    'http://10.0.0.5',
    'http://192.168.1.1'
]);

// --- signing-time validation -----------------------------------------------

test('a private or link-local target is never signed', async () => {
    const map = makeHlsProxyMapper('https://addon.test', 'CFG', ALLOWED);

    // The two from the confirmed exploit: the cloud metadata endpoint reached
    // through an EXT-X-KEY, and a loopback admin port reached through a segment.
    for (const target of [
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://127.0.0.1:1234/internal/admin?secret=1',
        'http://[::1]:8080/x',
        'http://10.0.0.5/x',
        'http://192.168.1.1/x'
    ]) {
        expect(await map(target), `${target} must not be signed`).toBeNull();
    }
});

test('a public target is still signed and still round-trips', async () => {
    const map = makeHlsProxyMapper('https://addon.test', 'CFG', ALLOWED);
    const proxied = await map(`http://${PUBLIC_IP}/a/seg1.ts`);

    expect(
        proxied?.startsWith('https://addon.test/CFG/proxy/hls?'),
        `unexpected: ${proxied}`
    ).toBeTruthy();
    const { searchParams } = new URL(proxied);
    expect(
        decodeHlsTarget(searchParams.get('u'), searchParams.get('s'), searchParams.get('e'), 'CFG')?.url
    ).toBe(`http://${PUBLIC_IP}/a/seg1.ts`);
});

test('a playlist naming a refused target is refused whole, not half-rewritten', async () => {
    // This used to assert that a refused line was left exactly as the provider
    // wrote it, so the player failed on that one sub-resource. That is the S2
    // leak: on an Xtream panel the lines left behind are absolute URLs carrying
    // the account's credentials, so half a rewrite discloses them to the player.
    const playlist = [
        '#EXTM3U',
        '#EXT-X-KEY:METHOD=AES-128,URI="http://169.254.169.254/latest/meta-data/"',
        '#EXTINF:10,',
        'http://127.0.0.1:1234/internal/admin?secret=1',
        '#EXTINF:10,',
        `http://${PUBLIC_IP}/ok/seg2.ts`,
        ''
    ].join('\n');

    await expect(rewriteHlsPlaylist(
        playlist,
        `http://${PUBLIC_IP}/a/play.m3u8`,
        makeHlsProxyMapper('https://addon.test', 'CFG', ALLOWED)
    )).rejects.toMatchObject({
        code: 'PLAYLIST_TARGET_REFUSED'
    });
});

test('a playlist whose targets all pass is still rewritten in full', async () => {
    const playlist = ['#EXTM3U', '#EXTINF:10,', `http://${PUBLIC_IP}/ok/seg2.ts`, ''].join('\n');

    const out = await rewriteHlsPlaylist(
        playlist,
        `http://${PUBLIC_IP}/a/play.m3u8`,
        makeHlsProxyMapper('https://addon.test', 'CFG', ALLOWED)
    );

    expect((out.match(/proxy\/hls\?/g) || []).length).toBe(1);
    expect(out, 'nothing may be relayed raw').not.toContain(`http://${PUBLIC_IP}/ok/seg2.ts`);
});

test('the fetch-time check still refuses those targets too', async () => {
    // Signing-time validation is defence in depth, not a replacement: a target
    // signed by an older build must still be refused when it is fetched.
    for (const target of ['http://169.254.169.254/x', 'http://127.0.0.1:1234/x']) {
        await expect(assertSafeOutboundUrl(target)).rejects.toThrow(/Blocked private outbound address/);
    }
});

// --- DNS pinning -----------------------------------------------------------

test('assertSafeOutboundUrl is the only thing that can pin an address', () => {
    // Not a style point: an address in this map is treated as vetted, so
    // anything else writing to it would be handing out the exemption.
    const src = fs.readFileSync(SAFE_FETCH_SRC, 'utf8');
    const writes = src.match(/pinResolvedAddresses\(/g) || [];
    expect(writes.length, 'expected one definition and exactly one call site').toBe(2);
    expect(src).toMatch(/if \(!directIp\) pinResolvedAddresses\(hostname, addresses\);/);
});

test('safeFetch connects through the pinning dispatcher', () => {
    // Invisible from outside — a fetch without the dispatcher succeeds exactly
    // as before, it just resolves the hostname a second time — so it is asserted
    // against the source, and against the dispatcher actually existing when the
    // guard is on.
    expect(PINNED_DISPATCHER, 'the guard is on, so there must be a dispatcher').toBeTruthy();
    const src = fs.readFileSync(SAFE_FETCH_SRC, 'utf8');
    expect(src).toMatch(/PINNED_DISPATCHER \? \{ dispatcher: PINNED_DISPATCHER \} : \{\}/);
});

test('a pinned host connects to the pinned address, never a fresh lookup', async () => {
    // cdn.pinned.test does not resolve anywhere. If the connector did its own
    // lookup this request could not succeed at all, so reaching the stub proves
    // the pin is what the connection followed.
    const server = await new Promise((resolve) => {
        const s = http.createServer((req, res) => res.end('reached-the-pinned-address'));
        s.listen(0, '127.0.0.1', () => resolve(s));
    });
    const port = server.address().port;

    try {
        pinResolvedAddresses('cdn.pinned.test', [{ address: '127.0.0.1', family: 4 }]);
        const res = await realFetch(`http://cdn.pinned.test:${port}/seg.ts`, { dispatcher: PINNED_DISPATCHER });
        expect(await res.text()).toBe('reached-the-pinned-address');
    } finally {
        server.close();
    }
});

test('an unpinned host fails closed rather than resolving', async () => {
    dnsPins.delete('cdn.unpinned.test');
    await expect(
        realFetch('http://cdn.unpinned.test/seg.ts', { dispatcher: PINNED_DISPATCHER })
    ).rejects.toSatisfy((err) => {
        // The rejection is fetch's own TypeError; the reason is the cause.
        expect(String(err.cause?.message || err.message)).toMatch(/No vetted address pinned/);
        return true;
    });
});

test('an expired pin is not a usable pin', () => {
    dnsPins.set('stale.test', {
        addresses: [{ address: '203.0.113.9', family: 4 }],
        expiresAt: Date.now() - 1
    });

    let error;
    pinnedLookup('stale.test', {}, (err) => { error = err; });
    expect(error?.code).toBe('ENOTFOUND');
});

test('pinnedLookup answers in whichever shape the connector asked for', () => {
    pinResolvedAddresses('multi.test', [
        { address: '203.0.113.9', family: 4 },
        { address: '2001:db8::1', family: 6 }
    ]);

    // Happy-eyeballs asks for every address at once...
    let all;
    pinnedLookup('multi.test', { all: true }, (err, result) => { all = { err, result }; });
    expect(all.err).toBeNull();
    expect(all.result).toStrictEqual([
        { address: '203.0.113.9', family: 4 },
        { address: '2001:db8::1', family: 6 }
    ]);

    // ...and a plain connect asks for one, as two positional arguments.
    let single;
    pinnedLookup('multi.test', {}, (err, address, family) => { single = { err, address, family }; });
    expect(single).toStrictEqual({ err: null, address: '203.0.113.9', family: 4 });

    // A family filter narrows it, and narrowing to nothing fails closed.
    let v6;
    pinnedLookup('multi.test', { family: 6 }, (err, address) => { v6 = { err, address }; });
    expect(v6.address).toBe('2001:db8::1');

    pinResolvedAddresses('v4only.test', [{ address: '203.0.113.9', family: 4 }]);
    let none;
    pinnedLookup('v4only.test', { family: 6 }, (err) => { none = err; });
    expect(none?.code).toBe('ENOTFOUND');
});

test('the pin map is bounded', () => {
    // It is keyed by a provider-influenced hostname, so an unbounded map is a
    // slow memory leak on a busy instance.
    dnsPins.clear();
    for (let i = 0; i < 1200; i++) {
        pinResolvedAddresses(`host${i}.test`, [{ address: '203.0.113.9', family: 4 }]);
    }
    expect(dnsPins.size, `pin map grew to ${dnsPins.size}`).toBeLessThanOrEqual(1000);
    // Eviction is by age, so the newest pin is the one that survives.
    expect(dnsPins.has('host1199.test')).toBeTruthy();
    expect(dnsPins.has('host0.test')).toBeFalsy();
});

afterAll(() => PINNED_DISPATCHER?.close());
