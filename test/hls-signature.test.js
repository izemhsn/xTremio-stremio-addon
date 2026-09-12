// M-7 — HLS target signatures were unbound to the account and never expired.
//
// signHlsTarget(payload) was a pure function of the URL and the global MAC key:
// no config, no account identity, no timestamp. So a signature minted while
// rewriting user A's playlist verified under *any* user's token, forever. The
// target it names is an Xtream segment URL with /username/password/ in its
// path, so a replayed capability streams A's content on A's credentials.
//
// Obtaining one already requires A's token, so this was durability rather than
// escalation: a signed URL captured once from a log, a shared screen or a proxy
// cache stayed valid indefinitely and survived the user reconfiguring. Both
// halves are now covered by the MAC — the config token and an expiry.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    encodeHlsTarget,
    decodeHlsTarget,
    signHlsTarget,
    signTokenBody,
    HLS_SIGNATURE_TTL_MS
} = require('../index.js');

const realFetch = global.fetch;

const ALICE = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' });
const BOB = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'bob', password: 'other' });
const TARGET = 'http://cdn.test/live/alice/secret/seg1.ts';

// --- binding to the account ------------------------------------------------

test('a signature minted for one account does not verify for another', () => {
    // The finding in one assertion. Both tokens are valid; only the one the
    // capability was minted for may use it.
    const { u, s, e } = encodeHlsTarget(TARGET, ALICE);

    assert.equal(decodeHlsTarget(u, s, e, ALICE), TARGET, 'the owner can still use it');
    assert.equal(decodeHlsTarget(u, s, e, BOB), null, 'another account must not');
});

test('reconfiguring kills the outstanding capabilities', () => {
    // Re-entering the same credentials mints a different token (a fresh IV), so
    // links from the previous configuration stop verifying — which is what a
    // user revoking access would reasonably expect.
    const reissued = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' });
    assert.notEqual(reissued, ALICE, 'tokens are non-deterministic');

    const { u, s, e } = encodeHlsTarget(TARGET, ALICE);
    assert.equal(decodeHlsTarget(u, s, e, reissued), null);
});

// --- expiry ----------------------------------------------------------------

test('a lapsed signature is refused even though the MAC is correct', () => {
    const now = Date.now();
    const { u, s, e } = encodeHlsTarget(TARGET, ALICE, now);

    assert.equal(decodeHlsTarget(u, s, e, ALICE, now + HLS_SIGNATURE_TTL_MS - 1000), TARGET);
    assert.equal(decodeHlsTarget(u, s, e, ALICE, now + HLS_SIGNATURE_TTL_MS), null, 'exactly at the expiry');
    assert.equal(decodeHlsTarget(u, s, e, ALICE, now + HLS_SIGNATURE_TTL_MS + 1000), null);
});

test('the expiry cannot be extended without the key', () => {
    // The MAC covers it, so pushing the deadline out invalidates the signature
    // rather than buying more time.
    const now = Date.now();
    const { u, s } = encodeHlsTarget(TARGET, ALICE, now);
    const later = String(now + 10 * 365 * 24 * 60 * 60 * 1000);

    assert.equal(decodeHlsTarget(u, s, later, ALICE, now), null);
});

test('a malformed expiry is refused rather than coerced', () => {
    // Number('12e9') and Number(' 12 ') both succeed, and a value that
    // round-trips differently to the string that was signed would verify
    // against something it does not equal.
    const now = Date.now();
    const valid = String(now + HLS_SIGNATURE_TTL_MS);
    const { u } = encodeHlsTarget(TARGET, ALICE, now);

    for (const expiry of ['12e9', ` ${valid} `, `+${valid}`, '', 'soon', null, undefined, Number(valid), '0'.repeat(20)]) {
        const signature = signHlsTarget(u, ALICE, expiry);
        assert.equal(decodeHlsTarget(u, signature, expiry, ALICE, now), null, `expiry ${JSON.stringify(expiry)}`);
    }
});

test('a missing expiry is not treated as no expiry', () => {
    const { u, s } = encodeHlsTarget(TARGET, ALICE);
    assert.equal(decodeHlsTarget(u, s, undefined, ALICE), null);
    assert.equal(decodeHlsTarget(u, s, null, ALICE), null);
});

// --- S1: the target itself is confidential ---------------------------------

test('the link does not carry the provider credentials it points at', () => {
    // The payload used to be plain base64url of the target, and the target is an
    // Xtream URL with /username/password/ in its path. Query strings are written
    // to player logs, to Stremio's history and to every reverse-proxy access
    // log, so anyone who read one held credentials that work against the
    // provider directly and outlive a CONFIG_SECRET rotation.
    const { u, s, e } = encodeHlsTarget(TARGET, ALICE);
    const query = `u=${u}&s=${s}&e=${e}`;
    // latin1 rather than utf8: the payload is ciphertext, and utf8 would replace
    // the bytes that do not form characters instead of comparing them.
    const decoded = Buffer.from(u, 'base64url').toString('latin1');

    assert.ok(!query.includes('secret'), 'no credential in the link as written');
    assert.ok(!decoded.includes('secret'), 'and none once the payload is decoded');
    assert.ok(!decoded.includes('cdn.test'), 'the host it names is not readable either');

    // And it still works for the account it was minted for.
    assert.equal(decodeHlsTarget(u, s, e, ALICE), TARGET);
});

test('the ciphertext is bound to the token and the expiry, not only the MAC', () => {
    // The same three fields the MAC covers are the GCM associated data, so this
    // holds even for someone who can mint a MAC over fields of their choosing:
    // a payload lifted onto another account's token, or onto a deadline they
    // pushed out, does not decrypt.
    const { u, e } = encodeHlsTarget(TARGET, ALICE);

    assert.equal(decodeHlsTarget(u, signHlsTarget(u, BOB, e), e, BOB), null, 'another token');

    const later = String(Number(e) + 60000);
    assert.equal(decodeHlsTarget(u, signHlsTarget(u, ALICE, later), later, ALICE), null, 'a later deadline');
});

test('a tampered payload is rejected even when the MAC agrees', () => {
    const { u, e } = encodeHlsTarget(TARGET, ALICE);
    const raw = Buffer.from(u, 'base64url');
    raw[raw.length - 1] ^= 0x01;
    const tampered = raw.toString('base64url');

    assert.equal(decodeHlsTarget(tampered, signHlsTarget(tampered, ALICE, e), e, ALICE), null);
});

test('a payload too short to hold a nonce, a tag and a target is rejected', () => {
    // Without the length check the slices would read an empty ciphertext, and a
    // nonce and tag alone would be a well-formed link to nowhere.
    const e = String(Date.now() + 60000);
    for (const short of ['', 'AAAA', Buffer.alloc(28).toString('base64url')]) {
        assert.equal(
            decodeHlsTarget(short, signHlsTarget(short, ALICE, e), e, ALICE),
            null,
            `payload ${JSON.stringify(short)}`
        );
    }
});

// --- what must keep working ------------------------------------------------

test('the earlier guarantees still hold', () => {
    const now = Date.now();
    const { u, s, e } = encodeHlsTarget(TARGET, ALICE, now);
    const evil = Buffer.from('http://attacker.test/', 'utf8').toString('base64url');

    assert.equal(decodeHlsTarget(evil, s, e, ALICE, now), null, 'signature for a different payload');
    assert.equal(decodeHlsTarget(u, 'forged', e, ALICE, now), null);

    // Still domain-separated from config-token MACs, which no longer share the
    // key either.
    const body = 'v3.aaa.bbb.ccc';
    assert.notEqual(signHlsTarget(body, ALICE, e), signTokenBody(body));

    // And the three signed fields cannot be shifted into one another.
    assert.notEqual(signHlsTarget('a', 'b:c', e), signHlsTarget('a:b', 'c', e));
});

// --- end to end ------------------------------------------------------------

let server;
let base;

test.before(async () => {
    server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    global.fetch = realFetch;
    await new Promise(r => server.close(r));
});

test('the route refuses a capability minted for a different token', async () => {
    let upstreamCalls = 0;
    global.fetch = async () => { upstreamCalls++; throw new Error('should never be reached'); };

    const { u, s, e } = encodeHlsTarget(TARGET, ALICE);
    const res = await realFetch(`${base}/${BOB}/proxy/hls?u=${u}&s=${s}&e=${e}`);

    assert.equal(res.status, 400);
    assert.equal(await res.text(), 'bad target');
    assert.equal(upstreamCalls, 0, 'rejected before any outbound call');
});

test('the route refuses a lapsed capability', async () => {
    let upstreamCalls = 0;
    global.fetch = async () => { upstreamCalls++; throw new Error('should never be reached'); };

    const stale = Date.now() - 1000;
    const { u } = encodeHlsTarget(TARGET, ALICE);
    const e = String(stale);
    const s = signHlsTarget(u, ALICE, e);

    const res = await realFetch(`${base}/${ALICE}/proxy/hls?u=${u}&s=${s}&e=${e}`);
    assert.equal(res.status, 400);
    assert.equal(upstreamCalls, 0);
});

test('an array-typed expiry degrades rather than throwing', async () => {
    // ?e=1&e=2 makes req.query.e an array; the strict type check has to hold.
    const { u, s } = encodeHlsTarget(TARGET, ALICE);
    const res = await realFetch(`${base}/${ALICE}/proxy/hls?u=${u}&s=${s}&e=1&e=2`);
    assert.equal(res.status, 400);
});
