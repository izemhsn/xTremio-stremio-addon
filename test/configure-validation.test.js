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
