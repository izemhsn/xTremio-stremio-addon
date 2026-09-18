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
    renderConfigPage,
    CONFIGURE_TIMEOUT_MS,
    CONFIGURE_PROBE_TIMEOUT_MS
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

    // Audit S7. This test used to be titled "an https request that falls back to
    // http is reported" and asserted that the retry happened: the password went out
    // over http, and the warning came afterwards. Anything that made the https
    // attempt fail — a reset on port 443 from someone on the path included — chose
    // cleartext on the user's behalf.
    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, false, 'https that fails is never retried over http');
    assert.deepStrictEqual(attempted, ['https'], 'no request went out over http');
    assert.match(result.error, /over https/);
    assert.match(result.error, /http:\/\//, 'and the user is told how to choose http themselves');
});

test('without a scheme, https is tried before the password can go out in cleartext', async () => {
    // Audit L9. This used to assert ['http', 'https']: the password went to the
    // panel's cleartext port first and reached TLS only after that failed, so a
    // panel supporting both never protected the one request that matters — and no
    // warning afterwards takes a sent password back.
    const attempted = stubProvider({ works: ['https'] });

    const result = await validateXtremioCredentials('provider.test', 'u', 'p');

    assert.deepStrictEqual(attempted, ['https'], 'nothing went out over http');
    assert.strictEqual(result.valid, true);
    assert.match(result.resolvedUrl, /^https:/);
    assert.strictEqual(result.downgrade, null);
});

test('a scheme-less URL still reaches an http-only panel, just second', async () => {
    // The order is a preference, not a restriction. Most Xtream panels are http
    // only, and they have to keep working for a user who typed no scheme.
    const attempted = stubProvider({ works: ['http'] });

    const result = await validateXtremioCredentials('provider.test', 'u', 'p');

    assert.deepStrictEqual(attempted, ['https', 'http'], 'https first, then what works');
    assert.strictEqual(result.valid, true);
    assert.match(result.resolvedUrl, /^http:/, 'the panel that answered is the one baked into the token');
    // Not a downgrade: they never asked for https, so there is nothing they lost.
    assert.strictEqual(result.downgrade, null);
});

test('a typed http:// is still tried first, with https only as the upgrade', async () => {
    // The scheme-less reordering must not second-guess a scheme the user typed.
    const attempted = stubProvider({ works: ['http', 'https'] });

    const result = await validateXtremioCredentials('http://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, true);
    assert.deepStrictEqual(attempted, ['http'], 'what the user asked for is what is used');
});

// Audit F1. The two halves of the case fix, asserted where the scheme order is
// decided rather than in the helper: a capitalized scheme has to reach the panel
// it names, and a capitalized `HTTPS://` has to keep the S7 protection that a
// lowercase one gets. A case-insensitive test in normalizeUrl alone would pass
// the first of these and fail the second.
test('a typed Http:// reaches the panel over http, not a host called http', async () => {
    const attempted = stubProvider({ works: ['http', 'https'] });

    const result = await validateXtremioCredentials('Http://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, true);
    assert.deepStrictEqual(attempted, ['http'], 'the typed scheme is honoured, not re-prefixed');
    assert.strictEqual(result.resolvedUrl, 'http://provider.test');
});

test('a typed HTTPS:// is never tried over http', async () => {
    const attempted = stubProvider({ works: ['http'] });

    const result = await validateXtremioCredentials('HTTPS://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, false, 'https that fails is never retried over http');
    assert.deepStrictEqual(attempted, ['https'], 'the password never went out in cleartext');
});

test('the guessed scheme is bounded by the shorter deadline, not the full one', async () => {
    // Trying https first costs nothing when it fails fast, but an http-only panel
    // behind a firewalled 443 hangs instead — and that wait is paid by every
    // scheme-less /configure. The attempt the user did not ask for gets the probe
    // deadline; the one they did gets the full one.
    assert.ok(
        CONFIGURE_PROBE_TIMEOUT_MS < CONFIGURE_TIMEOUT_MS,
        'a guess must not cost as much as a request the user actually made'
    );

    const deadlines = [];
    const realSetTimeout = global.setTimeout;
    global.setTimeout = (fn, ms, ...rest) => {
        deadlines.push(ms);
        return realSetTimeout(fn, ms, ...rest);
    };
    try {
        stubProvider({ works: ['http'] });
        await validateXtremioCredentials('provider.test', 'u', 'p');
    } finally {
        global.setTimeout = realSetTimeout;
    }

    // One timer per attempt, in attempt order: the https guess, then http.
    const attemptDeadlines = deadlines.filter(
        ms => ms === CONFIGURE_PROBE_TIMEOUT_MS || ms === CONFIGURE_TIMEOUT_MS
    );
    assert.deepStrictEqual(attemptDeadlines, [CONFIGURE_PROBE_TIMEOUT_MS, CONFIGURE_TIMEOUT_MS]);
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

test('a provider cannot move someone who asked for https onto http', async () => {
    // Audit S7. This used to assert that the provider's http was adopted and reported.
    // Adopting it baked cleartext into the install URL on the strength of the panel's
    // own configuration, for a user who had typed https.
    stubProvider({
        works: ['https'],
        serverInfo: { url: 'provider.test', server_protocol: 'http', port: '8080' }
    });

    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.downgrade, null);
    assert.match(result.resolvedUrl, /^https:\/\/provider\.test/, 'the https URL that connected is kept');
});

test('a provider downgrade is still reported where the user never asked for https', async () => {
    // Typed without a scheme: http failed, https worked, and the panel names http on
    // another port. The user did not ask for https, so the panel is followed — and the
    // banner says so. The named origin has to answer: since audit S8, one is adopted
    // only once the credentials work there too.
    const serverInfo = { url: 'provider.test', server_protocol: 'http', port: '8080' };
    global.fetch = async (url) => {
        if (new URL(url).origin === 'http://provider.test') {
            throw Object.assign(new Error('connect refused'), { cause: { code: 'ECONNREFUSED' } });
        }
        return { ok: true, status: 200, json: async () => ({ user_info: OK_USER, server_info: serverInfo }) };
    };

    const result = await validateXtremioCredentials('provider.test', 'u', 'p');

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
