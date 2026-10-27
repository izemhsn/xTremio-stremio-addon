// If https failed for any reason, validation used to retry over http and bake
// that http URL into the config token — so credentials travelled in cleartext
// forever because https hiccuped once during setup, with nothing said about it.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const {
    validateXtremioCredentials,
    describeDowngrade,
    schemeOf,
    renderConfigPage,
    CONFIGURE_TIMEOUT_MS,
    CONFIGURE_PROBE_TIMEOUT_MS
} = require('./support/internals.js');

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

afterAll(() => { global.fetch = realFetch; });

// --- the pure helpers ------------------------------------------------------

test('schemeOf reads the scheme, defaulting to http', () => {
    expect(schemeOf('https://a.test')).toBe('https');
    expect(schemeOf('http://a.test')).toBe('http');
    expect(schemeOf('')).toBe('http');
    expect(schemeOf(undefined)).toBe('http');
});

test('describeDowngrade only fires on a real https to http drop', () => {
    expect(describeDowngrade('https://a.test', 'http://a.test', 'fallback')).toStrictEqual({ from: 'https', to: 'http', source: 'fallback' });
    expect(
        describeDowngrade('http://a.test', 'http://a.test', 'fallback'),
        'http to http is not a downgrade'
    ).toBeNull();
    expect(
        describeDowngrade('https://a.test', 'https://a.test', 'fallback'),
        'https preserved is not a downgrade'
    ).toBeNull();
    expect(
        describeDowngrade('http://a.test', 'https://a.test', 'fallback'),
        'an upgrade is not a downgrade'
    ).toBeNull();
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

    expect(result.valid, 'https that fails is never retried over http').toBe(false);
    expect(attempted, 'no request went out over http').toStrictEqual(['https']);
    expect(result.error).toMatch(/over https/);
    expect(result.error, 'and the user is told how to choose http themselves').toMatch(/http:\/\//);
});

test('without a scheme, https is tried before the password can go out in cleartext', async () => {
    // Audit L9. This used to assert ['http', 'https']: the password went to the
    // panel's cleartext port first and reached TLS only after that failed, so a
    // panel supporting both never protected the one request that matters — and no
    // warning afterwards takes a sent password back.
    const attempted = stubProvider({ works: ['https'] });

    const result = await validateXtremioCredentials('provider.test', 'u', 'p');

    expect(attempted, 'nothing went out over http').toStrictEqual(['https']);
    expect(result.valid).toBe(true);
    expect(result.resolvedUrl).toMatch(/^https:/);
    expect(result.downgrade).toBeNull();
});

test('a scheme-less URL still reaches an http-only panel, just second', async () => {
    // The order is a preference, not a restriction. Most Xtream panels are http
    // only, and they have to keep working for a user who typed no scheme.
    const attempted = stubProvider({ works: ['http'] });

    const result = await validateXtremioCredentials('provider.test', 'u', 'p');

    expect(attempted, 'https first, then what works').toStrictEqual(['https', 'http']);
    expect(result.valid).toBe(true);
    expect(result.resolvedUrl, 'the panel that answered is the one baked into the token').toMatch(/^http:/);
    // Not a downgrade: they never asked for https, so there is nothing they lost.
    expect(result.downgrade).toBeNull();
});

test('a typed http:// is still tried first, with https only as the upgrade', async () => {
    // The scheme-less reordering must not second-guess a scheme the user typed.
    const attempted = stubProvider({ works: ['http', 'https'] });

    const result = await validateXtremioCredentials('http://provider.test', 'u', 'p');

    expect(result.valid).toBe(true);
    expect(attempted, 'what the user asked for is what is used').toStrictEqual(['http']);
});

// Audit F1. The two halves of the case fix, asserted where the scheme order is
// decided rather than in the helper: a capitalized scheme has to reach the panel
// it names, and a capitalized `HTTPS://` has to keep the S7 protection that a
// lowercase one gets. A case-insensitive test in normalizeUrl alone would pass
// the first of these and fail the second.
test('a typed Http:// reaches the panel over http, not a host called http', async () => {
    const attempted = stubProvider({ works: ['http', 'https'] });

    const result = await validateXtremioCredentials('Http://provider.test', 'u', 'p');

    expect(result.valid).toBe(true);
    expect(attempted, 'the typed scheme is honoured, not re-prefixed').toStrictEqual(['http']);
    expect(result.resolvedUrl).toBe('http://provider.test');
});

test('a typed HTTPS:// is never tried over http', async () => {
    const attempted = stubProvider({ works: ['http'] });

    const result = await validateXtremioCredentials('HTTPS://provider.test', 'u', 'p');

    expect(result.valid, 'https that fails is never retried over http').toBe(false);
    expect(attempted, 'the password never went out in cleartext').toStrictEqual(['https']);
});

test('the guessed scheme is bounded by the shorter deadline, not the full one', async () => {
    // Trying https first costs nothing when it fails fast, but an http-only panel
    // behind a firewalled 443 hangs instead — and that wait is paid by every
    // scheme-less /configure. The attempt the user did not ask for gets the probe
    // deadline; the one they did gets the full one.
    expect(
        CONFIGURE_PROBE_TIMEOUT_MS,
        'a guess must not cost as much as a request the user actually made'
    ).toBeLessThan(CONFIGURE_TIMEOUT_MS);

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
    expect(attemptDeadlines).toStrictEqual([CONFIGURE_PROBE_TIMEOUT_MS, CONFIGURE_TIMEOUT_MS]);
});

test('https that works is never reported as downgraded', async () => {
    stubProvider({ works: ['https'] });

    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');

    expect(result.valid).toBe(true);
    expect(result.downgrade, 'nothing to warn about').toBeNull();
});

test('a user who asked for http is not warned about getting http', async () => {
    stubProvider({ works: ['http'] });

    const result = await validateXtremioCredentials('http://provider.test', 'u', 'p');

    expect(result.valid).toBe(true);
    expect(result.downgrade, 'they never asked for https').toBeNull();
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

    expect(result.valid).toBe(true);
    expect(result.downgrade).toBeNull();
    expect(result.resolvedUrl, 'the https URL that connected is kept').toMatch(/^https:\/\/provider\.test/);
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

    expect(result.downgrade, 'attributed to the provider, not the fallback').toStrictEqual({ from: 'https', to: 'http', source: 'provider' });
    expect(result.resolvedUrl).toMatch(/^http:\/\/provider\.test:8080/);
});

test('a provider that keeps https is not reported', async () => {
    stubProvider({
        works: ['https'],
        serverInfo: { url: 'provider.test', server_protocol: 'https', https_port: '443' }
    });

    const result = await validateXtremioCredentials('https://provider.test', 'u', 'p');
    expect(result.downgrade).toBeNull();
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
    expect(html, 'a warning banner is rendered').toMatch(/status-banner status-warning/);
    expect(html).toMatch(/Connected over http, not https/);
    expect(html, 'the actual consequence is spelled out').toMatch(/cleartext/);
    expect(html, 'and the fallback cause is named').toMatch(/https connection failed/);
});

test('the page explains a provider-caused downgrade differently', () => {
    const html = renderConfigPage({
        serverUrl: 'http://provider.test',
        username: 'alice',
        password: 'secret',
        status: { valid: true, userInfo: OK_USER, downgrade: { from: 'https', to: 'http', source: 'provider' } }
    });

    expect(html, 'the cause is attributed correctly').toMatch(/provider asked for http/);
    expect(html, 'and not blamed on a failed connection').not.toMatch(/https connection failed/);
});

test('a clean connection renders no warning at all', () => {
    const html = renderConfigPage({
        serverUrl: 'https://provider.test',
        username: 'alice',
        password: 'secret',
        status: { valid: true, userInfo: OK_USER, downgrade: null }
    });

    expect(html, 'no warning banner').not.toMatch(/status-banner status-warning/);
    expect(html, 'and no scare text anywhere').not.toMatch(/cleartext/);
    expect(html, 'just the success banner').toMatch(/status-banner status-success/);
});
