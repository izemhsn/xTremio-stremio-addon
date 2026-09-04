// If https failed for any reason, validation used to retry over http and bake
// that http URL into the config token — so credentials travelled in cleartext
// forever because https hiccuped once during setup, with nothing said about it.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    validateXtremioCredentials,
    describeDowngrade,
    schemeOf,
    renderConfigPage
} = require('../index.js');

const realFetch = global.fetch;

const OK_USER = { username: 'alice', auth: 1, status: 'Active' };

// Answers only for the schemes in `works`; anything else refuses the connection.
// `serverInfo` lets a provider name its own URL back, as real ones do.
function stubProvider({ works = ['https'], serverInfo = null } = {}) {
    const attempted = [];
    global.fetch = async (url) => {
        const scheme = new URL(url).protocol.replace(':', '');
        attempted.push(scheme);
        if (!works.includes(scheme)) {
            const err = new Error('connect refused');
            err.cause = { code: 'ECONNREFUSED' };
            throw err;
        }
        return {
            ok: true,
            status: 200,
            json: async () => ({ user_info: OK_USER, ...(serverInfo ? { server_info: serverInfo } : {}) })
        };
    };
    return attempted;
}

test.after(() => { global.fetch = realFetch; });

// --- the pure helpers ------------------------------------------------------

test('schemeOf reads the scheme, defaulting to http', () => {
    assert.strictEqual(schemeOf('https://a.test'), 'https');
    assert.strictEqual(schemeOf('http://a.test'), 'http');
    assert.strictEqual(schemeOf(''), 'http');
    assert.strictEqual(schemeOf(undefined), 'http');
});

test('describeDowngrade only fires on a real https to http drop', () => {
    assert.deepStrictEqual(
        describeDowngrade('https://a.test', 'http://a.test', 'fallback'),
        { from: 'https', to: 'http', source: 'fallback' }
    );
    assert.strictEqual(describeDowngrade('http://a.test', 'http://a.test', 'fallback'), null,
        'http to http is not a downgrade');
    assert.strictEqual(describeDowngrade('https://a.test', 'https://a.test', 'fallback'), null,
        'https preserved is not a downgrade');
    assert.strictEqual(describeDowngrade('http://a.test', 'https://a.test', 'fallback'), null,
        'an upgrade is not a downgrade');
});

// --- the fallback route ----------------------------------------------------

test('an https request that falls back to http is reported', async () => {
    const attempted = stubProvider({ works: ['http'] });

    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, true, 'the fallback still connects — this is a warning, not a failure');
    assert.deepStrictEqual(attempted, ['https', 'http'], 'https was tried first');
    assert.deepStrictEqual(result.downgrade, { from: 'https', to: 'http', source: 'fallback' });
    assert.match(result.resolvedUrl, /^http:/, 'and http is what gets baked into the token');
});

test('https that works is never reported as downgraded', async () => {
    stubProvider({ works: ['https'] });

    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.downgrade, null, 'nothing to warn about');
});

test('a user who asked for http is not warned about getting http', async () => {
    stubProvider({ works: ['http'] });

    const result = await validateXtremioCredentials('http://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.downgrade, null, 'they never asked for https');
});

// --- the provider-controlled route -----------------------------------------

test('a provider downgrading a working https connection is reported', async () => {
    stubProvider({
        works: ['https'],
        serverInfo: { url: 'provider.test', server_protocol: 'http', port: '8080' }
    });

    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');

    assert.deepStrictEqual(result.downgrade, { from: 'https', to: 'http', source: 'provider' },
        'attributed to the provider, not the fallback');
    assert.match(result.resolvedUrl, /^http:\/\/provider\.test:8080/);
});

test('a provider that keeps https is not reported', async () => {
    stubProvider({
        works: ['https'],
        serverInfo: { url: 'provider.test', server_protocol: 'https', https_port: '443' }
    });

    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');
    assert.strictEqual(result.downgrade, null);
});

// --- what the user actually sees -------------------------------------------

test('the configure page warns when the connection was downgraded', () => {
    const html = renderConfigPage({
        serverUrl: 'http://provider.test',
        username: 'alice',
        password: 'secret',
        status: { valid: true, userInfo: OK_USER, downgrade: { from: 'https', to: 'http', source: 'fallback' } }
    });

    // Match the banner markup, not the class name — the stylesheet mentions
    // `status-warning` on every render whether or not a banner is shown.
    assert.match(html, /status-banner status-warning/, 'a warning banner is rendered');
    assert.match(html, /Connected over http, not https/);
    assert.match(html, /cleartext/, 'the actual consequence is spelled out');
    assert.match(html, /https connection failed/, 'and the fallback cause is named');
});

test('the page explains a provider-caused downgrade differently', () => {
    const html = renderConfigPage({
        serverUrl: 'http://provider.test',
        username: 'alice',
        password: 'secret',
        status: { valid: true, userInfo: OK_USER, downgrade: { from: 'https', to: 'http', source: 'provider' } }
    });

    assert.match(html, /provider asked for http/, 'the cause is attributed correctly');
    assert.doesNotMatch(html, /https connection failed/, 'and not blamed on a failed connection');
});

test('a clean connection renders no warning at all', () => {
    const html = renderConfigPage({
        serverUrl: 'https://provider.test',
        username: 'alice',
        password: 'secret',
        status: { valid: true, userInfo: OK_USER, downgrade: null }
    });

    assert.doesNotMatch(html, /status-banner status-warning/, 'no warning banner');
    assert.doesNotMatch(html, /cleartext/, 'and no scare text anywhere');
    assert.match(html, /status-banner status-success/, 'just the success banner');
});
