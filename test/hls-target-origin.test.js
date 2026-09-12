// M-3 — a signed HLS target was constrained only to "not a private address".
//
// `assertSafeOutboundUrl` refuses private, loopback and link-local targets and
// nothing else, so every *public* URL a panel chose to name in its playlist was
// HMAC-signed, and then fetched and relayed from the operator's address with no
// rate limit and no bandwidth cap. Standing up a panel that answers
// `player_api.php` with `{user_info:{auth:1}}` is the whole bar for getting a
// config token, so anyone who could reach /configure could turn the proxy into a
// relay for arbitrary public hosts.
//
// The rule now is an origin set: the account's own panel, plus the origin the
// playlist was actually fetched from, plus anything an operator names explicitly.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.HLS_TARGET_ALLOWED_HOSTS = 'extra-cdn.example.net';

const test = require('node:test');
const assert = require('node:assert');

const {
    makeHlsProxyMapper,
    hlsTargetOrigins,
    rewriteHlsPlaylist,
    decodeHlsTarget,
    HLS_TARGET_ALLOWED_HOSTS
} = require('../index.js');

const PANEL = 'http://panel.example.com:8080';
const CDN = 'http://185.217.39.88';

// What the two proxy routes build: the panel the account is configured with, the
// URL the playlist was requested at, and the URL it was finally served from.
const ALLOWED = hlsTargetOrigins(PANEL, `${PANEL}/live/u/p/1.m3u8`, `${CDN}/hls/abc/1.m3u8`);

function mapper() {
    return makeHlsProxyMapper('https://addon.test', 'CFG', ALLOWED);
}

test('the derived set is origins, not URLs', () => {
    assert.deepEqual([...ALLOWED].sort(), [CDN, PANEL].sort());
    // A path on an allowed origin contributes that origin and nothing more.
    assert.deepEqual([...hlsTargetOrigins('http://a.test/deep/path?q=1')], ['http://a.test']);
    // Unusable candidates are skipped rather than throwing.
    assert.deepEqual([...hlsTargetOrigins(null, undefined, '', 'not a url')], []);
});

test('the CDN the playlist actually came from is signable', async () => {
    // This is the case that makes the panel origin alone wrong: real providers
    // 302 the playlist to a different host, and this account's segments arrive
    // from a bare IP that is not the panel hostname at all.
    const signed = await mapper()(`${CDN}/hls/abc/28939_5867.ts`);
    assert.ok(signed?.startsWith('https://addon.test/CFG/proxy/hls?'), `unexpected: ${signed}`);

    const { searchParams } = new URL(signed);
    assert.equal(
        decodeHlsTarget(searchParams.get('u'), searchParams.get('s'), searchParams.get('e'), 'CFG'),
        `${CDN}/hls/abc/28939_5867.ts`
    );
});

test('the account panel is signable, including its own port', async () => {
    assert.ok(await mapper()(`${PANEL}/live/u/p/2.ts`));
    // A different port is a different origin, and is not the configured panel.
    assert.equal(await mapper()('http://panel.example.com:9090/live/u/p/2.ts'), null);
    // Nor is the same host over a different scheme.
    assert.equal(await mapper()('https://panel.example.com:8080/live/u/p/2.ts'), null);
});

test('an unrelated public host is refused, which is the finding', async () => {
    for (const target of [
        'https://example.com/secret-key',
        'https://example.com/some/third-party/object.bin',
        'https://www.iana.org/unrelated/asset.ts',
        'http://attacker.example.org/4gb-of-egress.bin'
    ]) {
        assert.equal(await mapper()(target), null, `${target} must not be signed`);
    }
});

test('HLS_TARGET_ALLOWED_HOSTS is the operator escape hatch', async () => {
    assert.ok(HLS_TARGET_ALLOWED_HOSTS.has('extra-cdn.example.net'));
    // Matched by hostname, so one entry covers both schemes and any port — a
    // provider serving playlists over http and segments over https needs one.
    assert.ok(await mapper()('http://extra-cdn.example.net/seg.ts'));
    assert.ok(await mapper()('https://extra-cdn.example.net:8443/seg.ts'));
    // And it is not a substring match.
    assert.equal(await mapper()('http://evil-extra-cdn.example.net/seg.ts'), null);
    assert.equal(await mapper()('http://extra-cdn.example.net.evil.test/seg.ts'), null);
});

test('a mapper built without an origin set signs nothing', async () => {
    // Fail closed: a call site that forgets the argument must not silently
    // restore the open relay. Every real caller passes one.
    const forgetful = makeHlsProxyMapper('https://addon.test', 'CFG');
    assert.equal(await forgetful(`${CDN}/hls/abc/1.ts`), null);
    assert.equal(await forgetful(`${PANEL}/live/u/p/1.ts`), null);
});

test('a playlist naming a host it may not proxy is refused whole', async () => {
    // This used to assert the opposite: the foreign lines were left verbatim so
    // the playlist was not corrupted. That is the leak S2 closes — the lines left
    // behind are the provider's own URLs, and on an Xtream panel those carry the
    // account's credentials, which is the disclosure the rewrite exists to
    // prevent. Refusing is also what the rewrite deadline already does, and
    // dropping only the offending line is not equivalent: a dropped EXT-X-KEY URI
    // leaves the player treating encrypted segments as plaintext.
    const playlist = [
        '#EXTM3U',
        '#EXT-X-KEY:METHOD=AES-128,URI="https://example.com/secret-key"',
        '#EXTINF:10,',
        `${CDN}/hls/abc/1.ts`,
        '#EXTINF:10,',
        'https://www.iana.org/unrelated/asset.ts',
        '#EXTINF:10,',
        `${CDN}/hls/abc/2.ts`,
        ''
    ].join('\n');

    await assert.rejects(
        () => rewriteHlsPlaylist(playlist, `${CDN}/hls/abc/1.m3u8`, mapper()),
        (e) => e.code === 'PLAYLIST_TARGET_REFUSED'
    );
});

test('a playlist naming only allowed origins is rewritten in full', async () => {
    // The other side of the rule: an ordinary provider playlist still works, and
    // nothing of the provider's own URLs survives in it.
    const playlist = [
        '#EXTM3U',
        `#EXT-X-KEY:METHOD=AES-128,URI="${CDN}/hls/abc/key.bin"`,
        '#EXTINF:10,',
        `${CDN}/hls/abc/1.ts`,
        '#EXTINF:10,',
        `${PANEL}/live/u/p/2.ts`,
        ''
    ].join('\n');

    const out = await rewriteHlsPlaylist(playlist, `${CDN}/hls/abc/1.m3u8`, mapper());

    assert.equal((out.match(/proxy\/hls\?/g) || []).length, 3, 'key and both segments signed');
    assert.ok(!out.includes(`${CDN}/hls/abc/1.ts`), 'the provider segment must not be relayed raw');
    assert.ok(!out.includes(`${PANEL}/live/u/p/2.ts`), 'the panel URL must not be relayed raw');
});
