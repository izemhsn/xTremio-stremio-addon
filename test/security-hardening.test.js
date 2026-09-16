// Four audit findings about how this instance protects itself:
//
//   L7 — config-token keys were a bare SHA-256 of CONFIG_SECRET. Every install
//        URL carries ciphertext and a MAC, so a short passphrase could be
//        brute-forced offline at roughly the speed of a hash.
//   L8 — a missing CONFIG_SECRET only warned, so a production deploy could run
//        on a per-boot random key and hand out install URLs that die on restart.
//   L9 — Access-Control-Allow-Origin: * was set on every route, including the
//        credential page and the byte proxy.
//   H2 residual — the global uncaughtException handler exempted AbortErrors,
//        which also swallowed any genuine post-disconnect bug.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const {
    app,
    encodeConfig,
    decodeConfig,
    configSecretProblems,
    enforceConfigSecretPolicy,
    warnOnUnpinnedBaseUrl,
    corsApplies,
    deriveConfigKey,
    CONFIG_TOKEN_VERSION,
    CONFIG_SECRET_MIN_BYTES,
    SCRYPT_PARAMS
} = require('../index.js');

const INDEX = require.resolve('../index.js');
// The token crypto lives in its own module now. The source-level assertion below
// has to read the file the derivation is actually written in, not the barrel that
// re-exports it.
const CONFIG_TOKEN_SRC = require.resolve('../src/config-token.js');
const realFetch = global.fetch;
const CFG = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' });

function collect() {
    const entries = [];
    return { entries, warn: (m) => entries.push(['warn', m]), error: (m) => entries.push(['error', m]), log: () => {} };
}

// --- L7: key derivation ----------------------------------------------------

test('keys are derived with scrypt, not a bare hash of the secret', () => {
    const key = deriveConfigKey('config-enc');
    assert.equal(key.length, 32);

    // The exact thing the finding was about: the old derivation was one SHA-256
    // over a label and the secret, so a guess cost a single hash.
    const oldStyle = crypto.createHash('sha256')
        .update('xtremio-config-enc')
        .update(Buffer.from(process.env.CONFIG_SECRET, 'utf8'))
        .digest();
    assert.notDeepEqual(key, oldStyle);

    // And it really is scrypt with these parameters, not something cheaper.
    const expected = crypto.scryptSync(
        Buffer.from(process.env.CONFIG_SECRET, 'utf8'),
        `xtremio-config-enc-${CONFIG_TOKEN_VERSION}`,
        32,
        SCRYPT_PARAMS
    );
    assert.deepEqual(key, expected);
});

test('the scrypt cost is high enough to matter', () => {
    // N is the work factor and r sets the memory per attempt. Below this the
    // derivation stops being meaningfully more expensive than a plain hash.
    assert.ok(SCRYPT_PARAMS.N >= 16384, `N=${SCRYPT_PARAMS.N} is too low`);
    assert.ok(SCRYPT_PARAMS.r >= 8, `r=${SCRYPT_PARAMS.r} is too low`);
    // 128 * N * r bytes must fit, or scryptSync throws at boot.
    assert.ok(SCRYPT_PARAMS.maxmem >= 128 * SCRYPT_PARAMS.N * SCRYPT_PARAMS.r,
        'maxmem cannot hold the configured N and r');
});

test('the two keys are independent', () => {
    // Same secret, different labels. If these ever matched, the MAC key and the
    // encryption key would be the same value.
    assert.notDeepEqual(deriveConfigKey('config-enc'), deriveConfigKey('config-mac'));

    // The above only proves the function separates labels. Whether the module
    // actually *passes* two different ones is invisible from outside — reusing one
    // label leaves tokens round-tripping exactly as before — so this is asserted
    // against the source. The keys themselves are deliberately not exported:
    // handing a test any function of them would also hand an attacker an oracle.
    const src = require('node:fs').readFileSync(CONFIG_TOKEN_SRC, 'utf8');
    const enc = /const CONFIG_ENC_KEY = deriveConfigKey\('([^']+)'\)/.exec(src);
    const mac = /const CONFIG_MAC_KEY = deriveConfigKey\('([^']+)'\)/.exec(src);
    assert.ok(enc && mac, 'both keys must be derived through deriveConfigKey');
    assert.notEqual(enc[1], mac[1], 'the encryption and MAC keys share a derivation label');
});

test('the token version was bumped, so old install URLs are rejected', () => {
    assert.equal(CONFIG_TOKEN_VERSION, 'v3');
    assert.ok(encodeConfig({ serverUrl: 'http://a.b', username: 'u', password: 'p' }).startsWith('v3.'));
});

test('a token still round-trips under the new derivation', () => {
    const cfg = { serverUrl: 'http://example.com:8080', username: 'user', password: 'pass' };
    assert.deepEqual(decodeConfig(encodeConfig(cfg)), cfg);
});

// --- L8: secret policy -----------------------------------------------------

test('configSecretProblems flags a missing secret', () => {
    const problems = configSecretProblems(undefined);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /not set/);
});

test('configSecretProblems flags a secret below the minimum length', () => {
    const short = 'a'.repeat(CONFIG_SECRET_MIN_BYTES - 1);
    assert.match(configSecretProblems(short)[0], /bytes/);
    assert.deepEqual(configSecretProblems('a'.repeat(CONFIG_SECRET_MIN_BYTES)), []);
});

test('length is counted in bytes, not characters', () => {
    // 11 of these are 44 bytes but only 22 UTF-16 code units, so `.length` would
    // reject a secret that is comfortably long enough. The count has to straddle
    // the threshold in opposite directions for the two measures, or a revert to
    // `raw.length` passes unnoticed.
    const emoji = '🔐'.repeat(11);
    assert.equal(Buffer.byteLength(emoji, 'utf8'), 44);
    assert.equal(emoji.length, 22);
    assert.deepEqual(configSecretProblems(emoji), []);
    assert.equal(configSecretProblems('a'.repeat(16)).length, 1);
});

test('development warns and carries on', () => {
    const log = collect();
    let exited = null;
    const ok = enforceConfigSecretPolicy({ raw: undefined, production: false, log, exit: c => { exited = c; } });
    assert.equal(ok, true);
    assert.equal(exited, null, 'development must not exit');
    assert.ok(log.entries.some(([level]) => level === 'warn'));
});

test('production refuses to start on a missing or weak secret', () => {
    for (const raw of [undefined, '', 'too-short']) {
        const log = collect();
        let exited = null;
        const ok = enforceConfigSecretPolicy({ raw, production: true, log, exit: c => { exited = c; } });
        assert.equal(ok, false, `raw=${JSON.stringify(raw)} should be refused`);
        assert.equal(exited, 1);
        assert.ok(log.entries.some(([level]) => level === 'error'));
    }
});

test('production starts normally on a strong secret', () => {
    const log = collect();
    let exited = null;
    const ok = enforceConfigSecretPolicy({ raw: 'x'.repeat(48), production: true, log, exit: c => { exited = c; } });
    assert.equal(ok, true);
    assert.equal(exited, null);
    assert.deepEqual(log.entries, []);
});

test('a production boot with a weak secret exits rather than serving', () => {
    // The policy above is only useful if the bootstrap actually calls it.
    let code = 0;
    let output = '';
    try {
        output = execFileSync(process.execPath, [INDEX], {
            env: { ...process.env, NODE_ENV: 'production', CONFIG_SECRET: 'short', PORT: '3197' },
            encoding: 'utf8',
            timeout: 20000
        });
    } catch (e) {
        code = e.status;
        output = (e.stdout || '') + (e.stderr || '');
    }
    assert.equal(code, 1, 'a production boot with a weak secret must exit 1');
    assert.match(output, /Refusing to start/);
    assert.doesNotMatch(output, /Addon running at/, 'it must not have bound a port');
});

// --- L7 (later audit): an install link built from an unpinned Host ----------
//
// With PUBLIC_URL unset the install link /configure hands out is built from the
// request's Host, and SAFE_HOST only checks its shape. Any hostname an attacker
// controls and points at this instance therefore mints install URLs carrying
// that hostname; repointing its DNS later collects the config tokens users
// installed. It is a warning rather than a refusal because a single-host
// deployment behind a proxy that sets Host correctly is a legitimate setup.

test('production without PUBLIC_URL is warned about', () => {
    const log = collect();
    assert.equal(warnOnUnpinnedBaseUrl({ publicUrl: null, production: true, log }), true);
    assert.equal(log.entries.length, 1);
    const [level, message] = log.entries[0];
    assert.equal(level, 'warn', 'a warning, not a refusal');
    assert.match(message, /PUBLIC_URL/);
});

test('a pinned base URL, or development, says nothing', () => {
    // Warning in development would train operators to ignore it, and it is
    // exactly where running on the request Host is normal.
    for (const args of [
        { publicUrl: 'https://addon.example', production: true },
        { publicUrl: null, production: false },
        { publicUrl: 'https://addon.example', production: false }
    ]) {
        const log = collect();
        assert.equal(warnOnUnpinnedBaseUrl({ ...args, log }), false, JSON.stringify(args));
        assert.deepEqual(log.entries, [], JSON.stringify(args));
    }
});

test('a production boot without PUBLIC_URL warns and still serves', () => {
    // As with the secret policy above: the check is only useful if the bootstrap
    // calls it. The process is left running on purpose — the point is that this
    // one does not exit — so it is stopped by the timeout.
    const env = { ...process.env, NODE_ENV: 'production', CONFIG_SECRET: 'x'.repeat(48), PORT: '3196' };
    delete env.PUBLIC_URL;

    let output = '';
    try {
        output = execFileSync(process.execPath, [INDEX], { env, encoding: 'utf8', timeout: 3000 });
    } catch (e) {
        output = (e.stdout || '') + (e.stderr || '');
        assert.notEqual(e.status, 1, 'a missing PUBLIC_URL must not stop the server starting');
    }
    assert.match(output, /PUBLIC_URL is not set/);
    assert.match(output, /Addon running at/, 'it warned and carried on');
});

// --- L9: CORS scope --------------------------------------------------------

test('the addon protocol keeps its wildcard, the rest does not', () => {
    // web.stremio.com calls these cross-origin, so they genuinely need it.
    for (const path of ['/manifest.json', '/tok/manifest.json', '/tok/catalog/XT-Movies/x.json', '/tok/meta/series/x.json', '/tok/stream/series/x.json']) {
        assert.equal(corsApplies(path), true, `${path} needs CORS`);
    }
    // These do not: /configure handles plaintext credentials, and the landing
    // page and health probe are read by people and orchestrators.
    for (const path of ['/configure', '/tok/configure', '/', '/health', '/tok/proxy/movie/1.mp4']) {
        assert.equal(corsApplies(path), false, `${path} must not be wildcarded`);
    }
});

test('CORS headers on the wire match that scope', async () => {
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
        const wildcarded = await realFetch(`${base}/manifest.json`);
        assert.equal(wildcarded.headers.get('access-control-allow-origin'), '*');

        for (const path of ['/configure', '/health', '/']) {
            const res = await realFetch(base + path);
            assert.equal(res.headers.get('access-control-allow-origin'), null, `${path} still sends CORS`);
        }
    } finally {
        await new Promise(r => server.close(r));
    }
});

test('PROXY_CORS=true restores the wildcard on the byte proxy only', () => {
    // The escape hatch, in case a player turns out to need it. Checked in a child
    // process because the flag is read at module load.
    const out = execFileSync(process.execPath, ['-e', `
        const m = require(${JSON.stringify(INDEX)});
        console.log(JSON.stringify([m.corsApplies('/tok/proxy/movie/1.mp4'), m.corsApplies('/configure')]));
    `], {
        env: { ...process.env, PROXY_CORS: 'true', CONFIG_SECRET: 'x'.repeat(32) },
        encoding: 'utf8'
    });
    const [proxy, configure] = JSON.parse(out.trim().split('\n').pop());
    assert.equal(proxy, true, 'PROXY_CORS=true must re-enable the proxy wildcard');
    assert.equal(configure, false, 'and must not leak onto the credential page');
});

// --- H2 residual: no blanket AbortError exemption --------------------------

test('the exception handlers no longer exempt AbortErrors', () => {
    const src = require('node:fs').readFileSync(INDEX, 'utf8');
    const bootstrap = src.slice(src.indexOf('if (require.main === module)'));
    // Match the guard itself, not the word: the block still *mentions* AbortError
    // in the comment explaining why the exemption is gone. The proxy route also
    // still filters aborts locally, which is the point — this asserts only that
    // the process-wide handlers stopped swallowing them.
    assert.doesNotMatch(bootstrap, /name === 'AbortError'/,
        'the global handlers must not special-case AbortError any more');
    assert.doesNotMatch(bootstrap, /code === 'ABORT_ERR'/);
    assert.match(bootstrap, /Uncaught exception, exiting/);
});

test('a client disconnecting mid-stream does not take the process down', async () => {
    // The reason the exemption existed. With it gone, an abort escaping the proxy
    // route would now be fatal, so this has to be exercised for real: start the
    // server, begin a proxied stream, kill the socket mid-body, and confirm the
    // process is still serving afterwards.
    const net = require('node:net');
    const { spawn } = require('node:child_process');

    // An upstream that sends headers then trickles bytes, so there is a live body
    // to interrupt.
    const origin = require('node:http').createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '100000' });
        let sent = 0;
        const timer = setInterval(() => {
            if (sent >= 100000 || res.writableEnded) return clearInterval(timer);
            sent += 1000;
            res.write(Buffer.alloc(1000));
        }, 20);
        res.on('close', () => clearInterval(timer));
    });
    await new Promise(r => origin.listen(0, '127.0.0.1', r));
    const originPort = origin.address().port;

    const PORT = '3196';
    const child = spawn(process.execPath, [INDEX], {
        env: { ...process.env, PORT, CONFIG_SECRET: 'x'.repeat(32), ALLOW_PRIVATE_NETWORKS: 'true', NODE_ENV: '' }
    });
    let out = '';
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { out += d; });

    try {
        // Wait for it to bind.
        for (let i = 0; i < 60 && !out.includes('Addon running'); i++) {
            await new Promise(r => setTimeout(r, 100));
        }
        assert.ok(out.includes('Addon running'), `server did not start: ${out}`);

        const token = execFileSync(process.execPath, ['-e', `
            const m = require(${JSON.stringify(INDEX)});
            process.stdout.write(m.encodeConfig({ serverUrl: 'http://127.0.0.1:${originPort}', username: 'u', password: 'p' }));
        `], { env: { ...process.env, CONFIG_SECRET: 'x'.repeat(32) }, encoding: 'utf8' }).trim();

        // Raw socket so the connection can be destroyed mid-body.
        const sock = net.connect(Number(PORT), '127.0.0.1');
        await new Promise(r => sock.on('connect', r));
        sock.write(`GET /${token}/proxy/movie/1.mp4 HTTP/1.1\r\nHost: x\r\n\r\n`);
        await new Promise(r => sock.once('data', r));   // headers plus some body
        sock.destroy();

        await new Promise(r => setTimeout(r, 700));

        assert.equal(child.exitCode, null, `process died after a client disconnect:\n${out}`);
        const health = await realFetch(`http://127.0.0.1:${PORT}/health`);
        assert.equal(health.status, 200, 'still serving after the disconnect');
        assert.doesNotMatch(out, /Uncaught exception/, `an abort escaped to the global handler:\n${out}`);
    } finally {
        child.kill();
        await new Promise(r => origin.close(r));
    }
});
