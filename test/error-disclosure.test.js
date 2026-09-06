// H-1 — an unauthenticated request could make the process throw, and Express's
// default error handler wrote the stack into the response body.
//
// Two independent ways in. POST /configure read req.body.serverUrl before the
// try block, so a body that parsed to an object or an array (or did not parse
// at all) threw a TypeError; and a malformed percent-escape anywhere in a path
// throws a URIError out of the router *while matching*, before any handler
// runs — no amount of coercion inside a handler can catch that one. Both leaked
// absolute filesystem paths and the dependency tree on any deployment that
// forgot NODE_ENV=production, and the /configure route threw before the rate
// limiter counted the attempt.
//
// The fix is a terminal error handler plus string coercion of the body fields.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const { app, encodeConfig, asString, redactConfigInPath } = require('../index.js');

const realFetch = global.fetch;

let server;
let base;

test.before(async () => {
    server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => server?.close());

// Everything the old handler disclosed. Asserted as a set on every error
// response, so a future handler that reverts to sending `err.stack` fails here
// whatever shape the stack happens to take.
function assertNoDisclosure(body, label) {
    for (const marker of ['index.js', 'node_modules', 'TypeError', 'URIError', ' at ', 'D:\\', '/xTremio']) {
        assert.ok(!body.includes(marker), `${label} leaked ${JSON.stringify(marker)}: ${body.slice(0, 200)}`);
    }
}

// --- the body-type route ---------------------------------------------------

test('POST /configure survives a body that is not three strings', async () => {
    // extended urlencoded parsing turns these into an object and an array.
    const cases = [
        ['object-typed field', { 'serverUrl[a]': '1', username: 'u', password: 'p' }],
        ['array-typed field', { 'serverUrl[]': ['a', 'b'], username: 'u' }]
    ];

    for (const [label, fields] of cases) {
        const form = new URLSearchParams();
        for (const [k, v] of Object.entries(fields)) {
            for (const one of [].concat(v)) form.append(k, one);
        }
        const res = await realFetch(`${base}/configure`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: form.toString()
        });
        const body = await res.text();
        assert.equal(res.status, 200, `${label} should render the page, not fail`);
        assertNoDisclosure(body, label);
    }
});

test('POST /configure survives a body nothing parsed', async () => {
    // req.body is undefined when no parser matched: no Content-Type at all, or
    // a JSON one, since only urlencoded is mounted.
    for (const [label, headers] of [
        ['json content-type', { 'Content-Type': 'application/json' }],
        ['no content-type', {}]
    ]) {
        const res = await realFetch(`${base}/configure`, {
            method: 'POST',
            headers,
            body: '{"serverUrl":"http://x"}'
        });
        const body = await res.text();
        assert.equal(res.status, 200, `${label} should render the page, not fail`);
        assertNoDisclosure(body, label);
    }
});

test('asString treats a non-string as absent rather than coercing it', () => {
    assert.equal(asString('http://a.b'), 'http://a.b');
    // The point of not using String(): these would otherwise become "a,b" and
    // "[object Object]", both of which look like input a user typed.
    assert.equal(asString(['a', 'b']), '');
    assert.equal(asString({ a: '1' }), '');
    assert.equal(asString(undefined), '');
    assert.equal(asString(null), '');
    assert.equal(asString(7), '');
});

// --- the router route ------------------------------------------------------

test('a malformed percent-escape is a clean 400 on every route shape', async () => {
    const CFG = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'u', password: 'p' });
    const paths = [
        '/%zz/manifest.json',
        `/${CFG}/catalog/XT-Movies/xtremio_movies_new/%zz.json`,
        `/${CFG}/meta/series/%zz.json`,
        `/${CFG}/stream/series/%zz.json`,
        `/${CFG}/proxy/live/%zz.ts`
    ];

    for (const path of paths) {
        const res = await realFetch(base + path);
        const body = await res.text();
        assert.equal(res.status, 400, `${path} should be a bad request`);
        assertNoDisclosure(body, path);
    }
});

test('an unknown path gets a plain 404, not Express default HTML', async () => {
    const res = await realFetch(`${base}/no/such/route`);
    const body = await res.text();
    assert.equal(res.status, 404);
    assertNoDisclosure(body, 'unknown path');
    // The default handler names the method and the path in an HTML page.
    assert.ok(!body.includes('<'), `404 body should not be HTML: ${body}`);
});

// --- logging ---------------------------------------------------------------

test('a config token is redacted out of a logged path', () => {
    const cfg = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' });
    const redacted = redactConfigInPath(`/${cfg}/meta/series/xtremio_series_1.json`);
    assert.ok(!redacted.includes(cfg), 'the token is a bearer credential and must not reach the log');
    assert.equal(redacted, '/<config>/meta/series/xtremio_series_1.json');

    // Short first segments are route names, not tokens, and stay readable.
    assert.equal(redactConfigInPath('/manifest.json'), '/manifest.json');
    assert.equal(redactConfigInPath('/configure'), '/configure');
    assert.equal(redactConfigInPath('/health'), '/health');
});
