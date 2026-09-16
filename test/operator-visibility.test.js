// R6 — silent degradation hid failures from the operator.
//
// The routes answer every failure quietly, because Stremio shows raw errors to users.
// That was right for the user and left the operator with nothing: install URLs that
// stopped decoding after a restart were never logged, and a route logged only
// e.message, so a bug in the addon read exactly like a provider outage.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');
const util = require('node:util');
const crypto = require('node:crypto');

const {
    app,
    encodeConfig,
    decodeConfig,
    sealConfig,
    deriveConfigKeys,
    isProgrammingError,
    noteUndecodableToken,
    undecodableTokens,
    UNDECODABLE_REPORT_INTERVAL_MS,
    catCache,
    vodStreamsCache,
    categoryStreamsCache
} = require('../index.js');

const realFetch = global.fetch;
const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);

function capture(fn) {
    const lines = [];
    const saved = { warn: console.warn, error: console.error, log: console.log };
    for (const name of Object.keys(saved)) console[name] = (...args) => lines.push(util.format(...args));
    const restore = () => Object.assign(console, saved);
    try {
        const result = fn();
        if (result && typeof result.then === 'function') {
            return result.then(() => lines, (e) => { throw e; }).finally(restore);
        }
    } catch (e) {
        restore();
        throw e;
    }
    restore();
    return lines;
}

function resetReports() {
    undecodableTokens.secret = 0;
    undecodableTokens.version = 0;
    undecodableTokens.lastReportAt = 0;
}

// A string with the shape every token version has written — a 12-byte IV, a
// 16-byte tag, a non-empty ciphertext and a 32-byte MAC — under a version prefix
// that will not open. Built by hand because sealConfig can only produce the
// current version, and an older one is exactly what the version counter is for.
function shapedToken(version) {
    const b64 = (n) => crypto.randomBytes(n).toString('base64url');
    return [version, b64(12), b64(16), b64(48), b64(32)].join('.');
}

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
    catCache.clear();
    vodStreamsCache.map.clear();
    categoryStreamsCache.map.clear();
});

const searchUrl = () => `${base}/${CFG}/catalog/XT-Movies/xtremio_search_movies/${encodeURIComponent('search=a')}.json`;

// --- route errors ----------------------------------------------------------------

test('what counts as a bug in the addon and what counts as the provider', () => {
    assert.equal(isProgrammingError(new TypeError("Cannot read properties of null (reading 'name')")), true);
    assert.equal(isProgrammingError(new ReferenceError('x is not defined')), true);
    assert.equal(isProgrammingError(new TypeError('fetch failed', { cause: new Error('ECONNREFUSED') })), false);
    assert.equal(isProgrammingError(new Error('xtremio get_vod_streams failed: HTTP 502')), false);
    assert.equal(isProgrammingError(Object.assign(new Error('aborted'), { name: 'AbortError' })), false);
    assert.equal(isProgrammingError(new SyntaxError('Unexpected token < in JSON')), false, 'a provider sending HTML is not a bug');
});

test('a bug in a route is logged with its stack', async () => {
    // A provider list holding a null item: code that assumed every item is an object
    // throws a TypeError, which used to be logged as one line indistinguishable from
    // the panel being down.
    global.fetch = async (url) => ({
        ok: true,
        status: 200,
        headers: { get: () => null },
        json: async () => (new URL(url).searchParams.get('action') === 'get_vod_streams'
            ? [null, { stream_id: 1, name: 'Alpha', added: 1 }]
            : [])
    });

    let body;
    const logged = await capture(async () => {
        body = await (await realFetch(searchUrl())).json();
    });

    assert.deepEqual(body.metas, [], 'the user still gets the quiet answer');
    const text = logged.join('\n');
    assert.match(text, /\[catalog\] unexpected error: TypeError/);
    assert.match(text, /\n\s+at /, 'with its stack');
});

test('a provider failure stays a single line', async () => {
    global.fetch = async () => {
        throw new TypeError('fetch failed', { cause: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) });
    };

    const logged = await capture(async () => {
        await (await realFetch(searchUrl())).json();
    });

    const text = logged.join('\n');
    assert.match(text, /\[catalog\] Error: fetch failed/);
    assert.doesNotMatch(text, /unexpected error/);
});

// --- install URLs that will not decode --------------------------------------------

test('install URLs sealed under another secret are reported once, and counted after', () => {
    resetReports();
    const foreign = sealConfig(CFG_ARGS, deriveConfigKeys('a-secret-this-server-never-had-0123456789'));

    const logged = capture(() => {
        for (let i = 0; i < 5; i++) assert.equal(decodeConfig(foreign), null);
    });

    const reports = logged.filter(line => line.includes('install URLs refused'));
    assert.equal(reports.length, 1, 'one broken install fires many requests; one line says why');
    assert.match(reports[0], /1 sealed under a secret this server does not have/);
    assert.match(reports[0], /CONFIG_SECRET/);
    assert.equal(undecodableTokens.secret, 4, 'the rest wait for the next report');
});

test('the next report carries everything counted since the last one', () => {
    resetReports();
    const t0 = 10 * UNDECODABLE_REPORT_INTERVAL_MS;
    capture(() => noteUndecodableToken('secret', t0));

    const quiet = capture(() => {
        noteUndecodableToken('secret', t0 + 1000);
        noteUndecodableToken('version', t0 + 2000);
    });
    assert.deepEqual(quiet, [], 'nothing inside the interval');

    const logged = capture(() => noteUndecodableToken('secret', t0 + UNDECODABLE_REPORT_INTERVAL_MS));
    assert.match(logged.join('\n'), /2 sealed under a secret.*1 from an older token version/);
});

test('scanner garbage is not counted, and a token from an older version is', () => {
    resetReports();
    const logged = capture(() => {
        decodeConfig('wp-admin');
        decodeConfig('favicon.ico');
        decodeConfig(shapedToken('v2'));
    });
    assert.equal(undecodableTokens.secret, 0);
    assert.match(logged.join('\n'), /1 from an older token version/);
});

// L5 — five dot-separated parts under a version prefix was enough to be counted,
// so a scanner walking made-up paths raised the "CONFIG_SECRET changed" report.
test('a five-part string that is not token-shaped is not counted (L5)', () => {
    resetReports();
    const iv = crypto.randomBytes(12).toString('base64url');
    const tag = crypto.randomBytes(16).toString('base64url');
    const ct = crypto.randomBytes(48).toString('base64url');
    const mac = crypto.randomBytes(32).toString('base64url');

    // With lastReportAt at 0 the first thing counted reports immediately, so an
    // empty log is the assertion — and it is read from the log rather than from
    // the counters, which that same report zeroes on its way out.
    const quiet = capture(() => {
        decodeConfig('v3.a.b.c.d');                      // the finding's own example
        decodeConfig('v2.aaa.bbb.ccc.ddd');              // and under an older version
        decodeConfig(`v3.${'!'.repeat(16)}.${tag}.${ct}.${mac}`);  // right length, not base64url
        decodeConfig(`v3.${iv}.${tag}..${mac}`);         // nothing to decrypt
        decodeConfig(`v3.${iv}.${tag}.${ct}.${mac.slice(0, -4)}`); // MAC short of 32 bytes
    });
    assert.deepEqual(quiet, [], 'none of these is a token this server could have issued');

    // The positive controls: without them this test would also pass if decodeConfig
    // had stopped counting altogether.
    resetReports();
    const sealedElsewhere = capture(() => {
        decodeConfig(sealConfig(CFG_ARGS, deriveConfigKeys('a-secret-this-server-never-had-0123456789')));
    });
    assert.match(sealedElsewhere.join('\n'), /1 sealed under a secret/);

    resetReports();
    const olderVersion = capture(() => decodeConfig(shapedToken('v2')));
    assert.match(olderVersion.join('\n'), /1 from an older token version/);
});

test('a valid install URL is never reported', () => {
    resetReports();
    const logged = capture(() => assert.ok(decodeConfig(CFG)));
    assert.deepEqual(logged.filter(line => line.includes('install URLs refused')), []);
    assert.equal(undecodableTokens.secret + undecodableTokens.version, 0);
});
