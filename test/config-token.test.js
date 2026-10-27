// Config tokens carry the user's Xtream credentials in every request path.
// The keys are derived at module load, so the secret must be set before require.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const { encodeConfig, decodeConfig, validateConfig, CONFIG_TOKEN_VERSION } = require('./support/internals.js');

const CFG = { serverUrl: 'http://example.com:8080', username: 'user', password: 'pass' };

test('a token round-trips back to the original config', () => {
    const decoded = decodeConfig(encodeConfig(CFG));
    expect(decoded).toStrictEqual(CFG);
});

test('encoding is non-deterministic (fresh IV per token)', () => {
    // Two tokens for the same config must differ, or the IV is being reused.
    expect(encodeConfig(CFG)).not.toBe(encodeConfig(CFG));
    expect(decodeConfig(encodeConfig(CFG))).toStrictEqual(CFG);
});

test('token has the expected five-part shape, stamped with the current version', () => {
    const parts = encodeConfig(CFG).split('.');
    expect(parts.length).toBe(5);
    expect(parts[0]).toBe(CONFIG_TOKEN_VERSION);
    expect(parts.every(p => p.length > 0)).toBeTruthy();
});

test('a v2 token no longer decodes', () => {
    // v2 is the pre-scrypt derivation. This token was minted by that build and is
    // kept as a fixture: the version bump has to be a real break, not a rename
    // that still accepts old ciphertext under the old, weaker keys.
    const v2 = 'v2.q9Vf9SN04Nl0bBlH.BTym1Up_IjiRPlPBX-l-sw.2fiyK_ckFA51bHtKufoGX7o2'
        + 'HG5gKhCJhMNvA5qwca-EZAVeN3aauwJCao9Ftl-hWZlLEoEBiklnzLCPTEPM8H19_SfLGFO80Q'
        + '.qCaWmtL9bYh8pG9JnBiWPum4zzaHvZ75N6YTlmCtFtA';
    expect(CONFIG_TOKEN_VERSION).not.toBe('v2');
    expect(decodeConfig(v2)).toBeNull();
});

test('credentials do not appear in plaintext anywhere in the token', () => {
    const token = encodeConfig(CFG);
    expect(token).not.toContain('pass');
    expect(token).not.toContain('user');
    expect(token).not.toContain('example.com');
    expect(Buffer.from(token, 'base64url').toString('utf8')).not.toContain('pass');
});

test('tampering with any part is rejected', () => {
    const parts = encodeConfig(CFG).split('.');
    // Flip a character in each of iv, tag, ciphertext, mac in turn.
    for (const i of [1, 2, 3, 4]) {
        const mangled = [...parts];
        const original = mangled[i];
        mangled[i] = (original[0] === 'A' ? 'B' : 'A') + original.slice(1);
        expect(decodeConfig(mangled.join('.')), `part ${i} tamper not rejected`).toBeNull();
    }
});

test('a stripped or altered version prefix is rejected', () => {
    const parts = encodeConfig(CFG).split('.');
    parts[0] = 'v1';
    expect(decodeConfig(parts.join('.'))).toBeNull();
});

test('malformed input is rejected without throwing', () => {
    const V = CONFIG_TOKEN_VERSION;
    for (const bad of ['', null, undefined, 'notatoken', `${V}.a.b.c`, `${V}.a.b.c.d.e`, {}, 42]) {
        expect(decodeConfig(bad), `not rejected: ${String(bad)}`).toBeNull();
    }
});

test('over-long input is rejected before any crypto work', () => {
    expect(decodeConfig(`${CONFIG_TOKEN_VERSION}.` + 'A'.repeat(5000))).toBeNull();
});

test('a token minted under a different secret does not decode', () => {
    // Simulates a restart with a new CONFIG_SECRET, or a forged token. Minted in a
    // child process so it is a genuine current-version token rather than a fixture
    // that a version bump would silently reduce to a version-mismatch test.
    const { execFileSync } = require('node:child_process');
    const foreign = execFileSync(process.execPath, ['-e', `
        const m = require(${JSON.stringify(require.resolve('./support/internals.js'))});
        process.stdout.write(m.encodeConfig(${JSON.stringify(CFG)}));
    `], {
        env: { ...process.env, CONFIG_SECRET: 'a-completely-different-secret-value-here' },
        encoding: 'utf8'
    }).trim();

    expect(
        foreign.startsWith(`${CONFIG_TOKEN_VERSION}.`),
        `expected a current-version token, got ${foreign.slice(0, 16)}`
    ).toBeTruthy();
    expect(decodeConfig(foreign)).toBeNull();
});

test('validateConfig requires all three fields as non-empty strings', () => {
    expect(validateConfig(CFG)).toStrictEqual(CFG);
    expect(validateConfig({ serverUrl: 'x', username: 'y' })).toBeNull();
    expect(validateConfig({ serverUrl: 'x', username: 'y', password: '' })).toBeNull();
    expect(validateConfig({ serverUrl: 'x', username: 'y', password: 123 })).toBeNull();
    expect(validateConfig(null)).toBeNull();
    expect(validateConfig('string')).toBeNull();
});

test('validateConfig drops unexpected fields', () => {
    const extra = { ...CFG, admin: true, __proto__: { polluted: true } };
    expect(validateConfig(extra)).toStrictEqual(CFG);
});

test('encodeConfig refuses an invalid config', () => {
    expect(() => encodeConfig({ serverUrl: 'x' })).toThrow(/Invalid config/);
});
