// Audit L-10: a provider's server_info went into the install token unchecked.
//
// validateXtremioCredentials built `${proto}://${si.url}:${port}` from fields the
// provider controls and never parsed the result. A `url` that already carried
// its port gave a string that is not a URL; one with a trailing slash parsed but
// silently lost the port. Either way /configure said "Connected!" and handed out
// a link whose every catalog was empty — and on that link the proxy route's
// `new URL()` threw outside any try, and the terminal handler logged the whole
// error object, whose `input` is a path holding the username and password.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');
const util = require('node:util');

const {
    app,
    encodeConfig,
    validateXtremioCredentials,
    serverInfoOrigin,
    terminalErrorHandler
} = require('../index.js');

const realFetch = global.fetch;

// Distinctive, so its absence from a log means something.
const SECRET = 'Sup3r-S3cret-Passw0rd';

// Everything written to the console while `fn` runs, formatted the way the
// console would format it — an object argument is inspected, properties and all.
async function captureConsole(fn) {
    const lines = [];
    const saved = { log: console.log, warn: console.warn, error: console.error };
    for (const name of Object.keys(saved)) {
        console[name] = (...args) => lines.push(util.format(...args));
    }
    try {
        await fn();
    } finally {
        Object.assign(console, saved);
    }
    return lines.join('\n');
}

test.after(() => { global.fetch = realFetch; });

// --- serverInfoOrigin -------------------------------------------------------

test('a well-formed server_info becomes its origin', () => {
    assert.equal(serverInfoOrigin({ url: 'line.example.com', port: '8080' }), 'http://line.example.com:8080');
    assert.equal(
        serverInfoOrigin({ url: 'line.example.com', server_protocol: 'https', https_port: '8443', port: '8080' }),
        'https://line.example.com:8443'
    );
    assert.equal(serverInfoOrigin({ url: 'line.example.com' }), 'http://line.example.com');
    // A url that carries its own port is fine, as long as nothing appends another.
    assert.equal(serverInfoOrigin({ url: 'line.example.com:8080' }), 'http://line.example.com:8080');
});

test('https server_info without an https_port uses the https default, not the http port', () => {
    // Audit S8. It borrowed `port`, giving https://line.example.com:80 — TLS spoken to
    // the http port, which never connects.
    assert.equal(
        serverInfoOrigin({ url: 'line.example.com', server_protocol: 'https', https_port: '', port: '80' }),
        'https://line.example.com'
    );
    assert.equal(
        serverInfoOrigin({ url: 'line.example.com', server_protocol: 'https', port: '8080' }),
        'https://line.example.com'
    );
});

test('server_info that does not form a bare http(s) origin is refused', () => {
    for (const [label, si] of [
        ['port in url and in port', { url: 'line.example.com:8080', port: '8080' }],
        ['trailing slash', { url: 'line.example.com/', port: '8080' }],
        ['scheme in url', { url: 'http://line.example.com', port: '8080' }],
        ['path in url', { url: 'line.example.com/panel' }],
        ['query in url', { url: 'line.example.com?x=1' }],
        ['credentials in url', { url: 'user:pw@line.example.com' }],
        ['non-http protocol', { url: 'line.example.com', server_protocol: 'ftp' }],
        ['non-numeric port', { url: 'line.example.com', port: 'eighty' }]
    ]) {
        assert.equal(serverInfoOrigin(si), null, label);
    }
    assert.equal(serverInfoOrigin(null), null);
    assert.equal(serverInfoOrigin({}), null);
});

// --- validation keeps the URL that worked -----------------------------------

function stubProvider(serverInfo) {
    global.fetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({
            user_info: { username: 'alice', auth: 1, status: 'Active' },
            server_info: serverInfo
        })
    });
}

test('an unusable server_info is ignored in favour of the URL that connected', async () => {
    for (const serverInfo of [
        { url: 'provider.test:8080', port: '8080' },
        { url: 'provider.test/', port: '8080' }
    ]) {
        stubProvider(serverInfo);
        let result;
        const logged = await captureConsole(async () => {
            result = await validateXtremioCredentials('http://provider.test:8080', 'alice', SECRET);
        });
        assert.equal(result.valid, true);
        assert.equal(result.resolvedUrl, 'http://provider.test:8080',
            `${JSON.stringify(serverInfo)} was baked into the token`);
        assert.match(logged, /server_info/, 'the operator should hear that the provider named a bad URL');
    }
});

test('a panel answering a JSON null is not a valid server, not an unreachable one', async () => {
    // `json.user_info` threw on null, and the catch reported "Cannot reach that
    // server" about a server that had just answered.
    global.fetch = async () => new Response('null', {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
    });
    const result = await validateXtremioCredentials('http://provider.test:8080', 'alice', SECRET);
    assert.equal(result.valid, false);
    assert.equal(result.error, 'Not a valid xTremio server');
});

test('a usable server_info is still honoured', async () => {
    stubProvider({ url: 'cdn.provider.test', port: '25461' });
    const result = await validateXtremioCredentials('http://provider.test:8080', 'alice', SECRET);
    assert.equal(result.resolvedUrl, 'http://cdn.provider.test:25461');
});

// --- a named origin has to work before it is adopted (audit S8) ---------------
//
// The origin a panel names for itself used to replace the URL that connected with
// no check at all. A panel reporting its internal address — a common
// misconfiguration — got "Connected!" and an install link whose every catalog was
// empty, because the SSRF guard then refused every request to it.

// Answers the credential check per origin: `answers` maps an origin to the
// user_info it returns, and any origin it does not list refuses the connection.
function stubByOrigin(answers, serverInfo) {
    const asked = [];
    global.fetch = async (url) => {
        const origin = new URL(url).origin;
        asked.push(origin);
        if (!(origin in answers)) {
            throw Object.assign(new Error('connect refused'), { cause: { code: 'ECONNREFUSED' } });
        }
        return {
            ok: true,
            status: 200,
            json: async () => ({ user_info: answers[origin], server_info: serverInfo })
        };
    };
    return asked;
}

const ACTIVE = { username: 'alice', auth: 1, status: 'Active' };

test('a named origin is adopted once the credentials have worked there too', async () => {
    const asked = stubByOrigin(
        { 'http://provider.test:8080': ACTIVE, 'http://cdn.provider.test:25461': ACTIVE },
        { url: 'cdn.provider.test', port: '25461' }
    );

    const result = await validateXtremioCredentials('http://provider.test:8080', 'alice', SECRET);

    assert.equal(result.resolvedUrl, 'http://cdn.provider.test:25461');
    assert.deepEqual(asked, ['http://provider.test:8080', 'http://cdn.provider.test:25461']);
});

test('a named origin that cannot be reached is not adopted', async () => {
    // The internal-address case. The guard refusing it and the host being down look
    // the same from here, and both mean an install link that would never work.
    const asked = stubByOrigin({ 'http://provider.test:8080': ACTIVE }, { url: '10.0.0.5', port: '8080' });

    let result;
    const logged = await captureConsole(async () => {
        result = await validateXtremioCredentials('http://provider.test:8080', 'alice', SECRET);
    });

    assert.equal(result.valid, true, 'the account itself is fine');
    assert.equal(result.resolvedUrl, 'http://provider.test:8080', 'kept the URL that connected');
    assert.deepEqual(asked, ['http://provider.test:8080', 'http://10.0.0.5:8080'], 'the named origin was tried');
    assert.match(logged, /server_info/, 'and the operator hears why it was not used');
    assert.ok(!logged.includes(SECRET), `the password reached the log:\n${logged}`);
});

test('a named origin where the credentials do not work is not adopted', async () => {
    stubByOrigin(
        { 'http://provider.test:8080': ACTIVE, 'http://elsewhere.test': { auth: 0 } },
        { url: 'elsewhere.test' }
    );

    const result = await validateXtremioCredentials('http://provider.test:8080', 'alice', SECRET);

    assert.equal(result.resolvedUrl, 'http://provider.test:8080');
});

test('a server_info naming the origin that connected costs no second request', async () => {
    const asked = stubByOrigin({ 'http://provider.test:8080': ACTIVE }, { url: 'provider.test', port: '8080' });

    const result = await validateXtremioCredentials('http://provider.test:8080', 'alice', SECRET);

    assert.equal(result.resolvedUrl, 'http://provider.test:8080');
    assert.equal(asked.length, 1);
});

// --- a token that already holds a bad URL -----------------------------------

test('the proxy answers 502 for a server URL that does not parse, and logs no password', async () => {
    // Tokens minted before the validation above can still carry one.
    const token = encodeConfig({ serverUrl: 'http://line.example.com:8080:8080', username: 'alice', password: SECRET });
    let fetches = 0;
    global.fetch = async () => { fetches++; throw new Error('no upstream call expected'); };

    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        let res;
        const logged = await captureConsole(async () => {
            res = await realFetch(`http://127.0.0.1:${server.address().port}/${token}/proxy/movie/1.mp4`);
            await res.text();
        });
        assert.equal(res.status, 502);
        assert.equal(fetches, 0, 'nothing should have been fetched from a URL that does not parse');
        assert.ok(!logged.includes(SECRET), `the password reached the log:\n${logged}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});

// --- the terminal handler ---------------------------------------------------

test("the terminal error handler logs a stack, never an error's own properties", async () => {
    // Defence in depth behind the route fix. This is the shape Node gives a failed
    // `new URL()`, and any other error carrying request data would print the same.
    const err = Object.assign(new TypeError('Invalid URL'), {
        code: 'ERR_INVALID_URL',
        input: `/movie/alice/${SECRET}/1.mp4`
    });
    let sentStatus;
    const res = {
        headersSent: false,
        status(code) { sentStatus = code; return this; },
        type() { return this; },
        end() { return this; }
    };

    const logged = await captureConsole(async () => {
        terminalErrorHandler(err, { method: 'GET', originalUrl: '/proxy/movie/1.mp4' }, res, () => {});
    });

    assert.equal(sentStatus, 500);
    assert.match(logged, /TypeError: Invalid URL/, 'the stack should still be logged');
    assert.ok(!logged.includes(SECRET), `the error's input reached the log:\n${logged}`);
});
