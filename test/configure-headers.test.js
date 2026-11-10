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

const { app, renderConfigPage } = require('./support/internals.js');

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
        expect(res.status).toBe(200);

        expect(res.headers.get('x-frame-options')).toBe('DENY');
        expect(res.headers.get('x-content-type-options')).toBe('nosniff');

        const csp = parseCsp(res.headers.get('content-security-policy'));
        // frame-ancestors is the one with a live attack behind it: this page has
        // a submit button that sends plaintext credentials.
        expect(csp['frame-ancestors']).toStrictEqual(["'none'"]);
        expect(csp['default-src']).toStrictEqual(["'none'"]);
        expect(csp['base-uri']).toStrictEqual(["'none'"]);
        // form-action does not fall back to default-src; without it the page's
        // own POST would be allowed anyway, but an injected form could post
        // the credentials anywhere.
        expect(csp['form-action']).toStrictEqual(["'self'"]);

        // The existing pair must survive the addition.
        expect(res.headers.get('cache-control')).toBe('no-store');
        expect(res.headers.get('referrer-policy')).toBe('no-referrer');
    });
});

test('no response names the framework it runs on', async () => {
    // Express announces itself with X-Powered-By unless told not to.
    await withServer(async (base) => {
        for (const path of ['/manifest.json', '/configure', '/no-such-route']) {
            const res = await realFetch(`${base}${path}`);
            expect(res.headers.get('x-powered-by'), `${path} sent X-Powered-By`).toBeNull();
        }
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
        expect(res.headers.get('x-frame-options')).toBe('DENY');
        expect(res.headers.get('x-content-type-options')).toBe('nosniff');
        expect(res.headers.get('content-security-policy') || '').toMatch(/frame-ancestors 'none'/);
    });
});

test("the policy never allows script-src 'unsafe-inline'", async () => {
    await withServer(async (base) => {
        const csp = parseCsp((await realFetch(`${base}/configure`)).headers.get('content-security-policy'));
        expect(csp['script-src'], 'script-src must be stated, not inherited').toBeTruthy();
        expect(
            csp['script-src'],
            "script-src 'unsafe-inline' would defeat the whole policy"
        ).not.toContain("'unsafe-inline'");
        expect(csp['script-src']).not.toContain("'unsafe-eval'");
        expect(
            csp['script-src'].some(v => /^'nonce-[A-Za-z0-9+/]+={0,2}'$/.test(v)),
            'script-src must carry a nonce'
        ).toBeTruthy();
    });
});

test('style-src keeps unsafe-inline, because the page needs it', async () => {
    // Not an oversight to be tightened later without thought: the page has one
    // <style> block and several style="…" attributes, and a nonce does not
    // cover attributes. Pinned so the reason is visible if someone removes it
    // and the page renders unstyled.
    await withServer(async (base) => {
        const csp = parseCsp((await realFetch(`${base}/configure`)).headers.get('content-security-policy'));
        expect(csp['style-src']).toStrictEqual(["'unsafe-inline'"]);
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
            expect(nonce.length, 'a guessable nonce is not a nonce').toBeGreaterThanOrEqual(16);
            seen.add(nonce);
        }
        expect(seen.size, 'a reused nonce is a static allowlist entry').toBe(3);
    });
});

test('the script tag on the success page carries the nonce from the header', () => {
    const html = successPage('TESTNONCE123456');
    expect(html).toMatch(/<script nonce="TESTNONCE123456">/);
    // One script, so one nonce to match — a second, unnonced block would be
    // dead code that only fails in a browser.
    expect((html.match(/<script/g) || []).length).toBe(1);
});

// --- L-12: nothing inline is left to be blocked ------------------------------

test('the rendered page has no inline event handlers', () => {
    // The failure this prevents is silent: under the CSP an onclick simply does
    // not run, and the copy button looks fine while doing nothing.
    for (const html of [successPage('n'), renderConfigPage({ nonce: 'n' })]) {
        expect(html, 'inline handlers are dead under this CSP').not.toMatch(/\son[a-z]+\s*=/i);
    }
});

test('copying uses navigator.clipboard, with execCommand only as a fallback', () => {
    const html = successPage('n');
    expect(html).toMatch(/navigator\.clipboard/);
    expect(html).toMatch(/addEventListener\('click'/);

    // execCommand is deliberately still present: navigator.clipboard is
    // undefined on insecure origins, which is how this addon is usually
    // reached (plain http on a LAN). It must be the fallback, not the path.
    const clipboardAt = html.indexOf('navigator.clipboard.writeText');
    const execAt = html.indexOf('execCommand');
    expect(execAt !== -1, 'the insecure-origin fallback must stay').toBeTruthy();
    expect(
        execAt < clipboardAt || html.includes('copyViaSelection'),
        'execCommand must be reachable only through the fallback helper'
    ).toBeTruthy();
});

test('the copy control is still there and still carries the install URL', () => {
    const html = successPage('n');
    expect(html).toMatch(/id="copy-input"/);
    expect(html).toMatch(/id="copy-label"/);
    expect(html).toMatch(/value="http:\/\/localhost:3000\/[^"]+\/manifest\.json"/);
});

test('a page rendered without a nonce still renders', () => {
    // renderConfigPage is exported and called from tests; a missing nonce must
    // degrade to a page whose link is still selectable, not throw.
    const html = renderConfigPage({});
    expect(html).toMatch(/<form method="POST" action="\/configure">/);
    expect(html).not.toMatch(/undefined/);
});

// Audit F5. The server URL field was <input type="url">, so the browser refused
// to submit `panel.example:8080` at all — and the server's deliberate handling
// for an address with no scheme, which tries https first so the password is not
// sent in cleartext before the panel's TLS port has been tried (audit L9), was
// reachable only by a direct POST. The field is plain text for that reason, and
// the browser must not be allowed to validate or rewrite it: autocapitalize off
// is what stops a phone turning a typed address into `Http://panel` (audit F1).
test('the server URL field accepts an address with no scheme', () => {
    const html = renderConfigPage({ nonce: 'n' });
    const field = html.match(/<input[^>]*name="serverUrl"[^>]*>/)[0];

    expect(field, 'type="url" blocks a scheme-less address').not.toMatch(/type="url"/);
    expect(field).toMatch(/type="text"/);
    expect(field, 'the keyboard should still suit a URL').toMatch(/inputmode="url"/);
    expect(field).toMatch(/autocapitalize="off"/);
    expect(field).toMatch(/autocorrect="off"/);
    expect(field).toMatch(/spellcheck="false"/);
    expect(field).toMatch(/required/);
});

test('every field is labelled and carries the right autocomplete hint', () => {
    const html = renderConfigPage({ nonce: 'n' });

    // A <label> wrapping nothing and pointing at nothing is a label only to a
    // sighted user; the for/id pair is what makes it one to a screen reader and
    // what makes the label clickable.
    for (const name of ['serverUrl', 'username', 'password']) {
        expect(html, `${name} has no linked label`).toMatch(new RegExp(`<label for="${name}">`));
        expect(html, `${name} has no id`).toMatch(new RegExp(`<input[^>]*id="${name}"`));
    }

    const username = html.match(/<input[^>]*name="username"[^>]*>/)[0];
    const password = html.match(/<input[^>]*name="password"[^>]*>/)[0];
    expect(username).toMatch(/autocomplete="username"/);
    expect(password).toMatch(/autocomplete="current-password"/);
    expect(password, 'the password must never be a visible field').toMatch(/type="password"/);
});

test('the page declares its charset', () => {
    // The page interpolates provider-supplied strings, which are not ASCII.
    expect(renderConfigPage({ nonce: 'n' })).toMatch(/<meta charset="utf-8">/);
});
