// L-11 and L-12 from the audit ledger, which have to land together:
//
//   L-11 — /configure is the one surface handling plaintext credentials, and it
//          sent no Content-Security-Policy, X-Frame-Options or
//          X-Content-Type-Options. It was framable, so clickjacking a submit was
//          possible, and there was no backstop behind the escapeHtml discipline.
//   L-12 — the copy-link control used document.execCommand('copy') from an
//          inline onclick, which the CSP added for L-11 blocks outright. Fixing
//          L-11 alone would have silently broken the copy button.
//
// The two halves are asserted together for that reason: a policy that permits
// script-src 'unsafe-inline' would pass every header check below while giving
// back exactly the injected-script execution it exists to deny, so the tests
// pin the absence of inline handlers as hard as the presence of the headers.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const { app, renderConfigPage } = require('../index.js');

const realFetch = global.fetch;

async function withServer(fn) {
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    try {
        return await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(r => server.close(r));
    }
}

// Parse a CSP header into { directive: [values] } so assertions can name a
// directive rather than string-matching a whole policy, which would break on
// any reordering.
function parseCsp(header) {
    const out = {};
    for (const part of String(header || '').split(';')) {
        const [name, ...values] = part.trim().split(/\s+/);
        if (name) out[name.toLowerCase()] = values;
    }
    return out;
}

// A rendered success page, which is the only variant carrying the copy control
// and the script block.
function successPage(nonce) {
    return renderConfigPage({
        serverUrl: 'http://provider.test:8080',
        username: 'alice',
        password: 'secret',
        status: { valid: true, userInfo: { username: 'alice' } },
        baseUrl: 'http://localhost:3000',
        nonce
    });
}

// --- L-11: the headers themselves ------------------------------------------

test('GET /configure sends the framing, CSP and sniffing headers', async () => {
    await withServer(async (base) => {
        const res = await realFetch(`${base}/configure`);
        assert.equal(res.status, 200);

        assert.equal(res.headers.get('x-frame-options'), 'DENY');
        assert.equal(res.headers.get('x-content-type-options'), 'nosniff');

        const csp = parseCsp(res.headers.get('content-security-policy'));
        // frame-ancestors is the one with a live attack behind it: this page has
        // a submit button that sends plaintext credentials.
        assert.deepEqual(csp['frame-ancestors'], ["'none'"]);
        assert.deepEqual(csp['default-src'], ["'none'"]);
        assert.deepEqual(csp['base-uri'], ["'none'"]);
        // form-action does not fall back to default-src; without it the page's
        // own POST would be allowed anyway, but an injected form could post
        // the credentials anywhere.
        assert.deepEqual(csp['form-action'], ["'self'"]);

        // The existing pair must survive the addition.
        assert.equal(res.headers.get('cache-control'), 'no-store');
        assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    });
});

test('POST /configure sends them too', async () => {
    await withServer(async (base) => {
        // An empty body fails validation without any outbound call, which is
        // enough to exercise the response path.
        const res = await realFetch(`${base}/configure`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'serverUrl=&username=&password='
        });
        assert.equal(res.headers.get('x-frame-options'), 'DENY');
        assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
        assert.match(res.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
    });
});

test("the policy never allows script-src 'unsafe-inline'", async () => {
    await withServer(async (base) => {
        const csp = parseCsp((await realFetch(`${base}/configure`)).headers.get('content-security-policy'));
        assert.ok(csp['script-src'], 'script-src must be stated, not inherited');
        assert.ok(!csp['script-src'].includes("'unsafe-inline'"),
            "script-src 'unsafe-inline' would defeat the whole policy");
        assert.ok(!csp['script-src'].includes("'unsafe-eval'"));
        assert.ok(csp['script-src'].some(v => /^'nonce-[A-Za-z0-9+/]+={0,2}'$/.test(v)),
            'script-src must carry a nonce');
    });
});

test('style-src keeps unsafe-inline, because the page needs it', async () => {
    // Not an oversight to be tightened later without thought: the page has one
    // <style> block and several style="…" attributes, and a nonce does not
    // cover attributes. Pinned so the reason is visible if someone removes it
    // and the page renders unstyled.
    await withServer(async (base) => {
        const csp = parseCsp((await realFetch(`${base}/configure`)).headers.get('content-security-policy'));
        assert.deepEqual(csp['style-src'], ["'unsafe-inline'"]);
    });
});

// --- the nonce ---------------------------------------------------------------

test('the nonce is fresh per response and matches the script tag', async () => {
    await withServer(async (base) => {
        const seen = new Set();
        for (let i = 0; i < 3; i++) {
            const res = await realFetch(`${base}/configure`);
            const csp = parseCsp(res.headers.get('content-security-policy'));
            const nonce = csp['script-src'][0].replace(/^'nonce-|'$/g, '');
            assert.ok(nonce.length >= 16, 'a guessable nonce is not a nonce');
            seen.add(nonce);
        }
        assert.equal(seen.size, 3, 'a reused nonce is a static allowlist entry');
    });
});

test('the script tag on the success page carries the nonce from the header', () => {
    const html = successPage('TESTNONCE123456');
    assert.match(html, /<script nonce="TESTNONCE123456">/);
    // One script, so one nonce to match — a second, unnonced block would be
    // dead code that only fails in a browser.
    assert.equal((html.match(/<script/g) || []).length, 1);
});

// --- L-12: nothing inline is left to be blocked ------------------------------

test('the rendered page has no inline event handlers', () => {
    // The failure this prevents is silent: under the CSP an onclick simply does
    // not run, and the copy button looks fine while doing nothing.
    for (const html of [successPage('n'), renderConfigPage({ nonce: 'n' })]) {
        assert.doesNotMatch(html, /\son[a-z]+\s*=/i, 'inline handlers are dead under this CSP');
    }
});

test('copying uses navigator.clipboard, with execCommand only as a fallback', () => {
    const html = successPage('n');
    assert.match(html, /navigator\.clipboard/);
    assert.match(html, /addEventListener\('click'/);

    // execCommand is deliberately still present: navigator.clipboard is
    // undefined on insecure origins, which is how this addon is usually
    // reached (plain http on a LAN). It must be the fallback, not the path.
    const clipboardAt = html.indexOf('navigator.clipboard.writeText');
    const execAt = html.indexOf('execCommand');
    assert.ok(execAt !== -1, 'the insecure-origin fallback must stay');
    assert.ok(execAt < clipboardAt || html.includes('copyViaSelection'),
        'execCommand must be reachable only through the fallback helper');
});

test('the copy control is still there and still carries the install URL', () => {
    const html = successPage('n');
    assert.match(html, /id="copy-input"/);
    assert.match(html, /id="copy-label"/);
    assert.match(html, /value="http:\/\/localhost:3000\/[^"]+\/manifest\.json"/);
});

test('a page rendered without a nonce still renders', () => {
    // renderConfigPage is exported and called from tests; a missing nonce must
    // degrade to a page whose link is still selectable, not throw.
    const html = renderConfigPage({});
    assert.match(html, /<form method="POST">/);
    assert.doesNotMatch(html, /undefined/);
});
