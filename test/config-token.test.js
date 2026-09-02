// Config tokens carry the user's Xtream credentials in every request path.
// The keys are derived at module load, so the secret must be set before require.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const { encodeConfig, decodeConfig, validateConfig } = require('../index.js');

const CFG = { serverUrl: 'http://example.com:8080', username: 'user', password: 'pass' };

test('a token round-trips back to the original config', () => {
    const decoded = decodeConfig(encodeConfig(CFG));
    assert.deepStrictEqual(decoded, CFG);
});

test('encoding is non-deterministic (fresh IV per token)', () => {
    // Two tokens for the same config must differ, or the IV is being reused.
    assert.notStrictEqual(encodeConfig(CFG), encodeConfig(CFG));
    assert.deepStrictEqual(decodeConfig(encodeConfig(CFG)), CFG);
});

test('token has the expected v2 five-part shape', () => {
    const parts = encodeConfig(CFG).split('.');
    assert.strictEqual(parts.length, 5);
    assert.strictEqual(parts[0], 'v2');
    assert.ok(parts.every(p => p.length > 0));
});

test('credentials do not appear in plaintext anywhere in the token', () => {
    const token = encodeConfig(CFG);
    assert.ok(!token.includes('pass'));
    assert.ok(!token.includes('user'));
    assert.ok(!token.includes('example.com'));
    assert.ok(!Buffer.from(token, 'base64url').toString('utf8').includes('pass'));
});

test('tampering with any part is rejected', () => {
    const parts = encodeConfig(CFG).split('.');
    // Flip a character in each of iv, tag, ciphertext, mac in turn.
    for (const i of [1, 2, 3, 4]) {
        const mangled = [...parts];
        const original = mangled[i];
        mangled[i] = (original[0] === 'A' ? 'B' : 'A') + original.slice(1);
        assert.strictEqual(decodeConfig(mangled.join('.')), null, `part ${i} tamper not rejected`);
    }
});

test('a stripped or altered version prefix is rejected', () => {
    const parts = encodeConfig(CFG).split('.');
    parts[0] = 'v1';
    assert.strictEqual(decodeConfig(parts.join('.')), null);
});

test('malformed input is rejected without throwing', () => {
    for (const bad of ['', null, undefined, 'notatoken', 'v2.a.b.c', 'v2.a.b.c.d.e', {}, 42]) {
        assert.strictEqual(decodeConfig(bad), null, `not rejected: ${String(bad)}`);
    }
});

test('over-long input is rejected before any crypto work', () => {
    assert.strictEqual(decodeConfig('v2.' + 'A'.repeat(5000)), null);
});

test('a token from a different secret does not decode', () => {
    // Simulates a restart with a new CONFIG_SECRET, or a forged token.
    const foreign = 'v2.q9Vf9SN04Nl0bBlH.BTym1Up_IjiRPlPBX-l-sw.2fiyK_ckFA51bHtKufoGX7o2'
        + 'HG5gKhCJhMNvA5qwca-EZAVeN3aauwJCao9Ftl-hWZlLEoEBiklnzLCPTEPM8H19_SfLGFO80Q'
        + '.qCaWmtL9bYh8pG9JnBiWPum4zzaHvZ75N6YTlmCtFtA';
    assert.strictEqual(decodeConfig(foreign), null);
});

test('validateConfig requires all three fields as non-empty strings', () => {
    assert.deepStrictEqual(validateConfig(CFG), CFG);
    assert.strictEqual(validateConfig({ serverUrl: 'x', username: 'y' }), null);
    assert.strictEqual(validateConfig({ serverUrl: 'x', username: 'y', password: '' }), null);
    assert.strictEqual(validateConfig({ serverUrl: 'x', username: 'y', password: 123 }), null);
    assert.strictEqual(validateConfig(null), null);
    assert.strictEqual(validateConfig('string'), null);
});

test('validateConfig drops unexpected fields', () => {
    const extra = { ...CFG, admin: true, __proto__: { polluted: true } };
    assert.deepStrictEqual(validateConfig(extra), CFG);
});

test('encodeConfig refuses an invalid config', () => {
    assert.throws(() => encodeConfig({ serverUrl: 'x' }), /Invalid config/);
});
