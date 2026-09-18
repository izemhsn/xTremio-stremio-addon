// S3 — anyone who could reach /configure could make this instance an open relay.
//
// The credential check accepts any host that answers
// {"user_info":{"auth":1,"status":"Active"}}. A few-line fake panel therefore gets
// an install URL, and the proxy then fetches /movie/<user>/<pass>/1.mp4 from it and
// follows its redirect to any public URL, relaying the bytes from this server's
// address. The per-account relay cap does not bound it — every made-up username is
// a new account — and nothing stateless can tell a fake panel from a real one.
// ALLOWED_PANEL_HOSTS names the real ones.
//
// The list is read at module load, so it is set before the require, and it is
// written the untidy ways an operator might write it.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.ALLOWED_PANEL_HOSTS = 'panel.allowed.test, http://Second.Allowed.test:8080/player_api.php, 2001:db8::1, *.wild.test';

const test = require('node:test');
const assert = require('node:assert');

const bootWarnings = [];
const realWarn = console.warn;
console.warn = (...args) => bootWarnings.push(args.join(' '));
const {
    app,
    encodeConfig,
    decodeConfig,
    hostnameOf,
    parseHostList,
    panelHostAllowed,
    ALLOWED_PANEL_HOSTS,
    configureAttempts
} = require('../index.js');
console.warn = realWarn;

const realFetch = global.fetch;
let upstreamCalls = 0;
let server;
let base;

test.before(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
});

test.beforeEach(() => {
    upstreamCalls = 0;
    configureAttempts.clear();
    // Any outbound call is a failure unless a test says otherwise.
    global.fetch = async () => { upstreamCalls++; throw new Error('should not be reached'); };
});

const jsonResponse = (value) => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });

function panelAnswering(payload) {
    return async () => {
        upstreamCalls++;
        return jsonResponse(payload);
    };
}

const ACTIVE = { user_info: { auth: 1, status: 'Active', username: 'alice' } };

async function postConfigure(serverUrl) {
    const body = new URLSearchParams({ serverUrl, username: 'alice', password: 'secret' }).toString();
    const res = await realFetch(`${base}/configure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
    });
    return res.text();
}

// The install token, from the link a successful configure page renders.
function tokenFrom(html) {
    const match = html.match(/href="stremio:\/\/[^/"]+\/([^/"]+)\/manifest\.json"/);
    return match ? match[1] : null;
}

function captureWarnings(fn) {
    const logged = [];
    const previous = console.warn;
    console.warn = (...args) => logged.push(args.join(' '));
    try {
        fn();
    } finally {
        console.warn = previous;
    }
    return logged;
}

// --- reading the list ----------------------------------------------------------

test('entries are read the way an operator writes them', () => {
    assert.deepEqual(
        [...ALLOWED_PANEL_HOSTS].sort(),
        ['[2001:db8::1]', 'panel.allowed.test', 'second.allowed.test'],
        'a URL with a port and a path names its host; a bare IPv6 address is bracketed'
    );
    assert.ok(
        bootWarnings.some(w => w.includes('ALLOWED_PANEL_HOSTS: ignoring "*.wild.test"')),
        'a wildcard is refused out loud rather than silently matching nothing'
    );
});

test('an empty list names no hosts', () => {
    // Every other test file runs with the variable unset, which is this: any panel.
    assert.equal(parseHostList('', 'X').size, 0);
    assert.equal(parseHostList(' , ,', 'X').size, 0);
});

test('a listed host is allowed by any scheme, port or case, and nothing else is', () => {
    for (const url of [
        'http://panel.allowed.test',
        'https://PANEL.allowed.test:8443',
        'panel.allowed.test:8080',
        'http://second.allowed.test',
        'http://[2001:db8::1]:8080'
    ]) {
        assert.ok(panelHostAllowed(url), `${url} should be allowed`);
    }
    for (const url of [
        'http://evil.test',
        'http://sub.panel.allowed.test',
        'http://panel.allowed.test.evil.test',
        'http://allowed.test',
        '',
        'http://',
        'not a url at all'
    ]) {
        assert.ok(!panelHostAllowed(url), `${JSON.stringify(url)} should be refused`);
    }
});

// --- minting --------------------------------------------------------------------

test('/configure refuses an unlisted panel without making any request to it', async () => {
    // The credential check is itself an outbound fetch to a URL the caller chose.
    const html = await postConfigure('http://evil.test:8080');

    assert.equal(upstreamCalls, 0, 'the host was never contacted');
    assert.match(html, /only accepts accounts from specific providers/);
    assert.equal(tokenFrom(html), null, 'no install link');
    assert.doesNotMatch(html, /panel\.allowed\.test/, 'and the reply does not list the hosts that are allowed');
});

test('/configure still mints an install URL for a listed panel', async () => {
    global.fetch = panelAnswering(ACTIVE);
    const html = await postConfigure('http://panel.allowed.test:8080');

    assert.equal(upstreamCalls, 1);
    const token = tokenFrom(html);
    assert.ok(token, 'an install link was rendered');
    assert.equal(hostnameOf(decodeConfig(token).serverUrl), 'panel.allowed.test');
});

test("a listed panel's server_info cannot move the install URL to an unlisted host", async () => {
    // server_info is provider data. Adopting it would bake an unlisted host into the
    // token, which decodeConfig then refuses — a "Connected!" page whose link never
    // works.
    global.fetch = panelAnswering({ ...ACTIVE, server_info: { url: 'evil.test', port: '80', server_protocol: 'http' } });
    const html = await postConfigure('http://panel.allowed.test:8080');

    const token = tokenFrom(html);
    assert.ok(token);
    assert.equal(hostnameOf(decodeConfig(token).serverUrl), 'panel.allowed.test', 'kept the URL that connected');
});

// --- use ------------------------------------------------------------------------

test('an install URL for an unlisted panel is refused on every route, however it was minted', async () => {
    // A token like this still decrypts: it was minted before the list was set, or
    // while it was empty — exactly when a fake panel could get one.
    const token = encodeConfig({ serverUrl: 'http://evil-old.test:8080', username: 'u', password: 'p' });
    assert.equal(decodeConfig(token), null);

    const manifest = await (await realFetch(`${base}/${token}/manifest.json`)).json();
    assert.deepEqual(manifest.catalogs, [], 'the unconfigured manifest');

    const catalog = await (await realFetch(
        `${base}/${token}/catalog/XT-Movies/xtremio_search_movies/${encodeURIComponent('search=a')}.json`
    )).json();
    assert.deepEqual(catalog.metas, []);

    const streams = await (await realFetch(`${base}/${token}/stream/XT-Movies/xtremio_movie_1.json`)).json();
    assert.deepEqual(streams.streams, []);

    const proxied = await realFetch(`${base}/${token}/proxy/movie/1.mp4`);
    assert.equal(proxied.status, 401, 'and above all, nothing is relayed');

    const page = await (await realFetch(`${base}/configure?config=${token}`)).text();
    assert.doesNotMatch(page, /evil-old\.test/, 'nor is the refused host prefilled into the form');

    assert.equal(upstreamCalls, 0, 'not one request reached the panel');
});

test('an install URL for a listed panel keeps working', () => {
    const token = encodeConfig({ serverUrl: 'https://second.allowed.test', username: 'u', password: 'p' });
    assert.deepEqual(decodeConfig(token), { serverUrl: 'https://second.allowed.test', username: 'u', password: 'p' });
});

test('a refused install URL is logged once per host, not once per request', () => {
    // One broken install fires every catalog, meta and stream request Stremio makes.
    const repeated = encodeConfig({ serverUrl: 'http://noisy.test', username: 'u', password: 'p' });
    const other = encodeConfig({ serverUrl: 'http://other-refused.test', username: 'u', password: 'p' });

    const logged = captureWarnings(() => {
        for (let i = 0; i < 5; i++) decodeConfig(repeated);
        decodeConfig(other);
    });

    assert.equal(logged.filter(l => l.includes('"noisy.test"')).length, 1);
    assert.equal(logged.filter(l => l.includes('"other-refused.test"')).length, 1);
    assert.match(logged.join('\n'), /not in ALLOWED_PANEL_HOSTS/, 'and it names the setting');
});
