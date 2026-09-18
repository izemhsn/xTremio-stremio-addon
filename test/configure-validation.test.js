// L-7 from the audit — a missing field answered with the catch-all error.
//
// An empty serverUrl made normalizeUrl throw, the POST handler's catch turned
// that into "Something went wrong. Please try again.", and the user was left to
// guess which of three fields was at fault. The browser's `required` attributes
// normally prevent it, so this is only reachable by a direct POST — but the
// generic message was also the one shown for a genuine internal error, which
// made the two indistinguishable.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const { app, configureAttempts } = require('../index.js');

const realFetch = global.fetch;
let upstreamCalls = 0;

test.beforeEach(() => {
    upstreamCalls = 0;
    configureAttempts.clear();
    // Any outbound call at all would be a failure of the check under test.
    global.fetch = async () => { upstreamCalls++; throw new Error('should not be reached'); };
});
test.after(() => { global.fetch = realFetch; });

async function post(body) {
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    try {
        const res = await realFetch(`http://127.0.0.1:${server.address().port}/configure`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body
        });
        return { status: res.status, html: await res.text() };
    } finally {
        await new Promise(r => server.close(r));
    }
}

test('a missing field is named, not reported as "something went wrong"', async () => {
    const cases = [
        ['serverUrl=&username=alice&password=secret', 'server URL'],
        ['serverUrl=http%3A%2F%2Fp.test&username=&password=secret', 'username'],
        ['serverUrl=http%3A%2F%2Fp.test&username=alice&password=', 'password']
    ];
    for (const [body, field] of cases) {
        const { html } = await post(body);
        assert.ok(html.includes(`Please enter your ${field}.`), `expected the ${field} to be named`);
        assert.ok(!html.includes('Something went wrong'), `${field}: fell through to the generic error`);
    }
});

test('several missing fields are listed readably', async () => {
    const { html } = await post('serverUrl=&username=&password=');
    assert.ok(
        html.includes('Please enter your server URL, username and password.'),
        'expected all three named in one sentence'
    );
});

test('the check costs no outbound request', async () => {
    // The point of answering locally: a POST with nothing in it must not become
    // a connection attempt, which is the same property the rate limiter exists
    // to protect.
    await post('serverUrl=&username=&password=');
    assert.equal(upstreamCalls, 0);
});

test('whitespace and trailing slashes do not disguise an empty server URL', async () => {
    // rawServerUrl is trimmed and stripped of trailing slashes before this runs,
    // so "  /// " is empty by the time the check sees it.
    const { html } = await post('serverUrl=%20%20%2F%2F%2F%20&username=alice&password=secret');
    assert.ok(html.includes('Please enter your server URL.'), 'a slash-only URL is still empty');
});

// Audit F2. `http://bad host:8080` normalizes fine but does not parse, so
// buildUrl threw inside the attempt loop — and the catch's own log line called
// `new URL(url)` on the same value and threw a *second* time, out of
// validateXtremioCredentials entirely. The route answered the same catch-all
// "Something went wrong" that L-7 above was written to get rid of, and logged
// nothing, so neither the user nor the operator learned the URL was at fault.
test('a server URL that does not parse is named as the problem', async () => {
    const cases = [
        ['http://bad host:8080', 'a space in the host'],
        ['https://a b', 'a space with a typed scheme'],
        ['bad host:1', 'a space with no scheme at all']
    ];
    for (const [url, what] of cases) {
        const { html } = await post(
            `serverUrl=${encodeURIComponent(url)}&username=alice&password=secret`
        );
        assert.ok(
            html.includes('That server URL is not valid'),
            `${url} (${what}) should be reported as an invalid URL, not a generic failure`
        );
        assert.ok(
            !html.includes('Something went wrong'),
            `${url} must not fall through to the catch-all`
        );
    }
    assert.equal(upstreamCalls, 0, 'a URL that cannot be parsed is never dialled');
});

test('the form is redisplayed with the bad URL still in it', async () => {
    // The user has to be able to see and correct what they typed; the whole
    // point of naming the field is lost if the form comes back empty.
    const { html } = await post('serverUrl=http%3A%2F%2Fbad%20host&username=alice&password=secret');
    assert.ok(html.includes('value="http://bad host"'), 'the typed URL is echoed back');
    assert.ok(html.includes('value="alice"'), 'and so is the username');
});

// Audit O2. express.urlencoded was mounted app-wide, so a POST to any path at
// all had its body parsed before the 404 that was always coming — work done on
// the thread that also relays video, for a request that was never going to be
// answered. The parser now sits on POST /configure, the only route that reads a
// form, and the two halves of that are observable: a large body to another path
// is no longer refused by the parser, and one to /configure still is.
async function postTo(path, body, headers = {}) {
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    try {
        const res = await realFetch(`http://127.0.0.1:${server.address().port}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
            body
        });
        return { status: res.status, text: await res.text() };
    } finally {
        await new Promise(r => server.close(r));
    }
}

test('a form body is only parsed on the route that reads one', async () => {
    const big = 'x=' + 'a'.repeat(200 * 1024);

    // Another path: the 404 it was always going to get, not the parser's 413.
    const other = await postTo('/not-a-route', big);
    assert.strictEqual(other.status, 404, 'an unrouted POST is answered without parsing its body');

    // /configure: the parser runs, and its limit is what answers.
    const configure = await postTo('/configure', big);
    assert.strictEqual(configure.status, 413, 'the form route still bounds what it will parse');
    assert.strictEqual(configure.text, 'bad request',
        'and the terminal handler honours the status body-parser set');
});

test('a normal form still reaches the route', async () => {
    // The guard against mounting the parser and forgetting to pass it: without
    // it req.body is undefined and every field reads as missing.
    const { text } = await postTo('/configure', 'serverUrl=&username=alice&password=secret');
    assert.ok(text.includes('Please enter your server URL.'), 'the fields were parsed');
    assert.ok(text.includes('value="alice"'), 'and echoed back');
});
