// M-2 — the rewrite phase that follows the playlist read was unbounded.
//
// `rewriteHlsPlaylist` awaits its mapper once per line, sequentially, and the
// mapper resolves DNS once per distinct origin. That ran after the body timer was
// cleared and long after the header timer, so no deadline covered it at all. At
// MAX_PLAYLIST_BYTES a playlist can name tens of thousands of distinct hostnames,
// which held one request, its socket and the buffered body for tens of minutes
// while emitting a resolver query per host.
//
// Three bounds are pinned here: a cap on distinct origins, a deadline over the
// phase, and vetting shared across passes rather than memoised per pass.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.MAX_PLAYLIST_ORIGINS = '4';
process.env.PLAYLIST_REWRITE_TIMEOUT_MS = '1000';
// ALLOW_PRIVATE_NETWORKS is deliberately NOT set: assertSafeOutboundUrl returns
// early when private networks are allowed, and the DNS work this test measures
// would never happen.

const test = require('node:test');
const assert = require('node:assert');

// index.js holds `require('dns').promises` and calls `dns.lookup(...)`, so the
// property is read at call time and patching it here is seen.
const dnsPromises = require('dns').promises;
const realLookup = dnsPromises.lookup;

let lookups = [];
let lookupDelayMs = 0;
// A public address, so vetting passes and the URI is signed. A test that needs a
// different answer sets these rather than replacing the function, so it cannot
// leave the resolver pointing somewhere else for the rest of the file.
const PUBLIC_ANSWER = [{ address: '93.184.216.34', family: 4 }];
let lookupAddresses = PUBLIC_ANSWER;
let lookupError = null;
dnsPromises.lookup = async (hostname) => {
    lookups.push(hostname);
    if (lookupDelayMs) await new Promise(r => setTimeout(r, lookupDelayMs));
    if (lookupError) throw lookupError;
    return lookupAddresses;
};

const {
    encodeConfig,
    rewriteHlsPlaylist,
    makeHlsProxyMapper,
    hlsOriginVetCache,
    dnsPins,
    MAX_PLAYLIST_ORIGINS,
    PLAYLIST_REWRITE_TIMEOUT_MS
} = require('../index.js');

const realFetch = global.fetch;
const CFG = encodeConfig({ serverUrl: 'http://provider.test', username: 'u', password: 'p' });

// These tests are about the *bounds* on the rewrite, not about which origins are
// allowed, so every host they use is admitted explicitly. M-3's origin rule has
// its own file.
const ALLOWED = new Set([
    'http://provider.test',
    'http://cdn.example.com',
    ...Array.from({ length: 600 }, (_, i) => `http://h${i}.example.com`)
]);

function playlistOver(hosts) {
    const lines = ['#EXTM3U', '#EXT-X-TARGETDURATION:8'];
    for (const h of hosts) lines.push('#EXTINF:8,', `http://${h}/seg.ts`);
    return lines.join('\n');
}

function reset() {
    lookups = [];
    lookupDelayMs = 0;
    lookupAddresses = PUBLIC_ANSWER;
    lookupError = null;
    hlsOriginVetCache.clear();
    dnsPins.clear();
}

test.beforeEach(reset);
test.after(() => { dnsPromises.lookup = realLookup; global.fetch = realFetch; });

test('the bounds are configurable', () => {
    assert.equal(MAX_PLAYLIST_ORIGINS, 4);
    assert.equal(PLAYLIST_REWRITE_TIMEOUT_MS, 1000);
});

test('a playlist naming many origins resolves only up to the cap', async () => {
    // The assertion on the excess URIs used to be that they were left exactly as
    // the provider wrote them. That was the leak: on an Xtream panel those lines
    // are absolute URLs carrying the account's credentials, so a playlist served
    // half-rewritten hands them to the player. Past the cap the playlist is
    // refused instead, the same answer the deadline gives.
    const hosts = Array.from({ length: 40 }, (_, i) => `h${i}.example.com`);
    await assert.rejects(
        () => rewriteHlsPlaylist(
            playlistOver(hosts),
            'http://h0.example.com/live.m3u8',
            makeHlsProxyMapper('http://addon.test', CFG, ALLOWED)
        ),
        (e) => e.code === 'PLAYLIST_TARGET_REFUSED'
    );

    // The cap has to stop the *work*, not just the signing — that is the whole
    // point. 40 origins must not cost 40 resolutions.
    assert.equal(new Set(lookups).size, MAX_PLAYLIST_ORIGINS,
        `resolved ${new Set(lookups).size} hosts, expected ${MAX_PLAYLIST_ORIGINS}`);
});

test('a real playlist, all on one host, is unaffected by the cap', async () => {
    const body = [
        '#EXTM3U',
        '#EXT-X-KEY:METHOD=AES-128,URI="http://cdn.example.com/key.bin"',
        '#EXTINF:8,',
        'http://cdn.example.com/1.ts',
        '#EXTINF:8,',
        'http://cdn.example.com/2.ts'
    ].join('\n');

    const out = await rewriteHlsPlaylist(body, 'http://cdn.example.com/live.m3u8',
        makeHlsProxyMapper('http://addon.test', CFG, ALLOWED));

    // Two segments plus the EXT-X-KEY URI: key and map URIs are sub-resources
    // exactly like segment lines, and leak the same credentials if left alone.
    assert.equal(out.split('\n').filter(l => l.includes('/proxy/hls?u=')).length, 3);
    assert.ok(out.includes('URI="http://addon.test/'), 'the key URI is rewritten too');
    assert.ok(!out.includes('http://cdn.example.com/'), 'nothing may be relayed raw');
    assert.equal(lookups.length, 1, 'one host is one lookup');
});

test('origin vetting is shared across rewrites, not repeated per playlist', async () => {
    // A live playlist is re-fetched every few seconds. Memoising per pass meant
    // re-resolving the same CDN host for the life of the channel; only OS-level
    // DNS caching hid it.
    const body = playlistOver(['cdn.example.com', 'cdn.example.com']);

    await rewriteHlsPlaylist(body, 'http://cdn.example.com/live.m3u8',
        makeHlsProxyMapper('http://addon.test', CFG, ALLOWED));
    assert.equal(lookups.length, 1);

    for (let i = 0; i < 5; i++) {
        await rewriteHlsPlaylist(body, 'http://cdn.example.com/live.m3u8',
            makeHlsProxyMapper('http://addon.test', CFG, ALLOWED));
    }
    assert.equal(lookups.length, 1, 'later passes re-resolved a host already vetted');
});

test('concurrent rewrites of the same origin share one resolution', async () => {
    // The cached value is the promise, so passes that overlap do not race into
    // separate lookups.
    lookupDelayMs = 50;
    const body = playlistOver(['cdn.example.com']);
    await Promise.all(Array.from({ length: 6 }, () =>
        rewriteHlsPlaylist(body, 'http://cdn.example.com/live.m3u8',
            makeHlsProxyMapper('http://addon.test', CFG, ALLOWED))
    ));
    assert.equal(lookups.length, 1);
});

test('a lookup that merely failed is not remembered as a refusal', async () => {
    // The vet cache holds a verdict for DNS_PIN_TTL_MS. A resolver blip cached as
    // "refused" used to leave the origin unsignable for the rest of that window,
    // and an unsignable origin now costs the whole playlist — so one failed
    // lookup would take a live channel down for a minute.
    const body = playlistOver(['cdn.example.com']);
    const map = () => makeHlsProxyMapper('http://addon.test', CFG, ALLOWED);

    lookupError = new Error('queryA EAI_AGAIN cdn.example.com');
    await assert.rejects(
        () => rewriteHlsPlaylist(body, 'http://cdn.example.com/live.m3u8', map()),
        (e) => e.code === 'PLAYLIST_TARGET_REFUSED'
    );

    // The resolver recovers, and the very next rewrite succeeds.
    lookupError = null;
    const out = await rewriteHlsPlaylist(body, 'http://cdn.example.com/live.m3u8', map());
    assert.ok(out.includes('/proxy/hls?u='), 'a transient failure was cached as a verdict');
});

test('a private address is remembered, so it costs one lookup', async () => {
    // The other half: a policy refusal is a real verdict and stays cached, which
    // is what keeps a hostile playlist from re-resolving on every pass.
    const body = playlistOver(['internal.example.com']);
    const allowed = new Set(['http://internal.example.com']);
    const map = () => makeHlsProxyMapper('http://addon.test', CFG, allowed);

    lookupAddresses = [{ address: '10.0.0.5', family: 4 }];
    for (let i = 0; i < 3; i++) {
        await assert.rejects(
            () => rewriteHlsPlaylist(body, 'http://internal.example.com/live.m3u8', map()),
            (e) => e.code === 'PLAYLIST_TARGET_REFUSED'
        );
    }
    assert.equal(lookups.length, 1, 'a settled refusal was re-resolved');
});

test('the rewrite phase gives up on its own deadline', async () => {
    // A mapper that never returns quickly is the shape a slow resolver produces.
    // Slow, but it does map: a mapper that refused would now fail the playlist on
    // its first line and the deadline would never be reached.
    const slow = async (uri) => {
        await new Promise(r => setTimeout(r, 40));
        return `http://addon.test/p?u=${encodeURIComponent(uri)}`;
    };
    const hosts = Array.from({ length: 500 }, (_, i) => `h${i}.example.com`);

    const started = Date.now();
    await assert.rejects(
        () => rewriteHlsPlaylist(playlistOver(hosts), 'http://h0.example.com/live.m3u8', slow,
            { deadline: Date.now() + 300 }),
        (e) => e.code === 'PLAYLIST_REWRITE_TIMEOUT'
    );
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 3000, `expected to give up near the deadline, took ${elapsed}ms`);
});

test('without a deadline the rewrite behaves exactly as before', async () => {
    // The parameter is optional, so every existing caller and test is unchanged.
    const out = await rewriteHlsPlaylist(
        playlistOver(['cdn.example.com']),
        'http://cdn.example.com/live.m3u8',
        makeHlsProxyMapper('http://addon.test', CFG, ALLOWED)
    );
    assert.ok(out.includes('/proxy/hls?u='));
});

// The 504 wiring in relayUpstream is deliberately not covered end to end. Driving
// the rewrite phase past its deadline through the route needs either a loopback
// provider — which the SSRF guard blocks in the very mode where the DNS work
// happens — or roughly a second of CPU on a maximum-size playlist, measured at
// 945 ms against a 1000 ms deadline floor. A test that close to the line reports
// the machine it runs on rather than the code, so the throw is pinned above and
// the mapping from that throw to a 504 is left to review.
