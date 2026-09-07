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

const test = require('node:test');
const assert = require('node:assert');
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
} = require('../index.js');

const realFetch = global.fetch;
const INDEX = require.resolve('../index.js');

// A literal address, so nothing here depends on DNS or on being online.
const PUBLIC_IP = '93.184.216.34';

// --- signing-time validation -----------------------------------------------

test('a private or link-local target is never signed', async () => {
    const map = makeHlsProxyMapper('https://addon.test', 'CFG');

    // The two from the confirmed exploit: the cloud metadata endpoint reached
    // through an EXT-X-KEY, and a loopback admin port reached through a segment.
    for (const target of [
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://127.0.0.1:1234/internal/admin?secret=1',
        'http://[::1]:8080/x',
        'http://10.0.0.5/x',
        'http://192.168.1.1/x'
    ]) {
        assert.equal(await map(target), null, `${target} must not be signed`);
    }
});

test('a public target is still signed and still round-trips', async () => {
    const map = makeHlsProxyMapper('https://addon.test', 'CFG');
    const proxied = await map(`http://${PUBLIC_IP}/a/seg1.ts`);

    assert.ok(proxied?.startsWith('https://addon.test/CFG/proxy/hls?'), `unexpected: ${proxied}`);
    const { searchParams } = new URL(proxied);
    assert.equal(
        decodeHlsTarget(searchParams.get('u'), searchParams.get('s'), searchParams.get('e'), 'CFG'),
        `http://${PUBLIC_IP}/a/seg1.ts`
    );
});

test('a refused target is left in the playlist verbatim, not dropped', async () => {
    // Removing the line would silently corrupt the playlist; leaving it means
    // the player fails on that one sub-resource, which is the honest outcome.
    const playlist = [
        '#EXTM3U',
        '#EXT-X-KEY:METHOD=AES-128,URI="http://169.254.169.254/latest/meta-data/"',
        '#EXTINF:10,',
        'http://127.0.0.1:1234/internal/admin?secret=1',
        '#EXTINF:10,',
        `http://${PUBLIC_IP}/ok/seg2.ts`,
        ''
    ].join('\n');

    const out = await rewriteHlsPlaylist(
        playlist,
        `http://${PUBLIC_IP}/a/play.m3u8`,
        makeHlsProxyMapper('https://addon.test', 'CFG')
    );

    assert.ok(out.includes('URI="http://169.254.169.254/latest/meta-data/"'), 'key line should be untouched');
    assert.ok(out.includes('http://127.0.0.1:1234/internal/admin?secret=1'), 'segment line should be untouched');
    // Exactly one line was rewritten: the public one.
    assert.equal((out.match(/proxy\/hls\?/g) || []).length, 1);
});

test('the fetch-time check still refuses those targets too', async () => {
    // Signing-time validation is defence in depth, not a replacement: a target
    // signed by an older build must still be refused when it is fetched.
    for (const target of ['http://169.254.169.254/x', 'http://127.0.0.1:1234/x']) {
        await assert.rejects(() => assertSafeOutboundUrl(target), /Blocked private outbound address/);
    }
});

// --- DNS pinning -----------------------------------------------------------

test('assertSafeOutboundUrl is the only thing that can pin an address', () => {
    // Not a style point: an address in this map is treated as vetted, so
    // anything else writing to it would be handing out the exemption.
    const src = fs.readFileSync(INDEX, 'utf8');
    const writes = src.match(/pinResolvedAddresses\(/g) || [];
    assert.equal(writes.length, 2, 'expected one definition and exactly one call site');
    assert.match(src, /if \(!directIp\) pinResolvedAddresses\(hostname, addresses\);/);
});

test('safeFetch connects through the pinning dispatcher', () => {
    // Invisible from outside — a fetch without the dispatcher succeeds exactly
    // as before, it just resolves the hostname a second time — so it is asserted
    // against the source, and against the dispatcher actually existing when the
    // guard is on.
    assert.ok(PINNED_DISPATCHER, 'the guard is on, so there must be a dispatcher');
    const src = fs.readFileSync(INDEX, 'utf8');
    assert.match(src, /PINNED_DISPATCHER \? \{ dispatcher: PINNED_DISPATCHER \} : \{\}/);
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
        assert.equal(await res.text(), 'reached-the-pinned-address');
    } finally {
        server.close();
    }
});

test('an unpinned host fails closed rather than resolving', async () => {
    dnsPins.delete('cdn.unpinned.test');
    await assert.rejects(
        () => realFetch('http://cdn.unpinned.test/seg.ts', { dispatcher: PINNED_DISPATCHER }),
        (err) => {
            // The rejection is fetch's own TypeError; the reason is the cause.
            assert.match(String(err.cause?.message || err.message), /No vetted address pinned/);
            return true;
        }
    );
});

test('an expired pin is not a usable pin', () => {
    dnsPins.set('stale.test', {
        addresses: [{ address: '203.0.113.9', family: 4 }],
        expiresAt: Date.now() - 1
    });

    let error;
    pinnedLookup('stale.test', {}, (err) => { error = err; });
    assert.equal(error?.code, 'ENOTFOUND');
});

test('pinnedLookup answers in whichever shape the connector asked for', () => {
    pinResolvedAddresses('multi.test', [
        { address: '203.0.113.9', family: 4 },
        { address: '2001:db8::1', family: 6 }
    ]);

    // Happy-eyeballs asks for every address at once...
    let all;
    pinnedLookup('multi.test', { all: true }, (err, result) => { all = { err, result }; });
    assert.equal(all.err, null);
    assert.deepEqual(all.result, [
        { address: '203.0.113.9', family: 4 },
        { address: '2001:db8::1', family: 6 }
    ]);

    // ...and a plain connect asks for one, as two positional arguments.
    let single;
    pinnedLookup('multi.test', {}, (err, address, family) => { single = { err, address, family }; });
    assert.deepEqual(single, { err: null, address: '203.0.113.9', family: 4 });

    // A family filter narrows it, and narrowing to nothing fails closed.
    let v6;
    pinnedLookup('multi.test', { family: 6 }, (err, address) => { v6 = { err, address }; });
    assert.equal(v6.address, '2001:db8::1');

    pinResolvedAddresses('v4only.test', [{ address: '203.0.113.9', family: 4 }]);
    let none;
    pinnedLookup('v4only.test', { family: 6 }, (err) => { none = err; });
    assert.equal(none?.code, 'ENOTFOUND');
});

test('the pin map is bounded', () => {
    // It is keyed by a provider-influenced hostname, so an unbounded map is a
    // slow memory leak on a busy instance.
    dnsPins.clear();
    for (let i = 0; i < 1200; i++) {
        pinResolvedAddresses(`host${i}.test`, [{ address: '203.0.113.9', family: 4 }]);
    }
    assert.ok(dnsPins.size <= 1000, `pin map grew to ${dnsPins.size}`);
    // Eviction is by age, so the newest pin is the one that survives.
    assert.ok(dnsPins.has('host1199.test'));
    assert.ok(!dnsPins.has('host0.test'));
});

test.after(() => PINNED_DISPATCHER?.close());
