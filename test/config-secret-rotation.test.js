// S11 — CONFIG_SECRET could not be rotated.
//
// Every install URL is sealed under CONFIG_SECRET, so replacing it broke every
// install at once. A secret that had leaked, or had only ever been a placeholder,
// stayed in service because replacing it was worse. CONFIG_SECRET_PREVIOUS keeps
// the old install URLs working while every new one is sealed under the current
// secret.
process.env.CONFIG_SECRET = 'current-secret-for-rotation-tests-01234567';
process.env.CONFIG_SECRET_PREVIOUS = 'previous-secret-for-rotation-tests-0123456';

const test = require('node:test');
const assert = require('node:assert');

const { encodeConfig, decodeConfig, sealConfig, deriveConfigKeys, signTokenBody } = require('../index.js');

const CFG = { serverUrl: 'http://panel.test:8080', username: 'alice', password: 'secret' };
const CURRENT = deriveConfigKeys(process.env.CONFIG_SECRET);
const PREVIOUS = deriveConfigKeys(process.env.CONFIG_SECRET_PREVIOUS);
const UNRELATED = deriveConfigKeys('an-unrelated-secret-nobody-configured-0123');

function captureWarnings(fn) {
    const logged = [];
    const realWarn = console.warn;
    console.warn = (...args) => logged.push(args.join(' '));
    try {
        fn();
    } finally {
        console.warn = realWarn;
    }
    return logged;
}

// First, because the note is once per process and any earlier decode would spend it.
test('use of the previous secret is noted once, so its removal can be judged', () => {
    const token = sealConfig(CFG, PREVIOUS);
    const logged = captureWarnings(() => {
        for (let i = 0; i < 3; i++) decodeConfig(token);
    });
    assert.equal(logged.filter(line => line.includes('CONFIG_SECRET_PREVIOUS')).length, 1);
});

test('an install URL sealed under the previous secret still works', () => {
    assert.deepEqual(decodeConfig(sealConfig(CFG, PREVIOUS)), CFG);
});

test('new install URLs are sealed under the current secret, not the previous one', () => {
    const token = encodeConfig(CFG);
    const parts = token.split('.');
    const body = parts.slice(0, 4).join('.');

    assert.equal(parts[4], signTokenBody(body, CURRENT.mac));
    assert.notEqual(parts[4], signTokenBody(body, PREVIOUS.mac));
    assert.deepEqual(decodeConfig(token), CFG);
});

test('a secret that is neither current nor previous is refused', () => {
    assert.equal(decodeConfig(sealConfig(CFG, UNRELATED)), null);
});

test('a previous-secret install URL that was tampered with is refused', () => {
    const parts = sealConfig(CFG, PREVIOUS).split('.');
    const ciphertext = Buffer.from(parts[3], 'base64url');
    ciphertext[0] ^= 0x01;
    parts[3] = ciphertext.toString('base64url');
    assert.equal(decodeConfig(parts.join('.')), null);
});

test('the key halves of the two secrets cannot be mixed', () => {
    // The MAC that verifies decides the decryption key, so a current MAC over a
    // ciphertext sealed under the previous key does not open.
    assert.equal(decodeConfig(sealConfig(CFG, { enc: PREVIOUS.enc, mac: CURRENT.mac })), null);
    assert.equal(decodeConfig(sealConfig(CFG, { enc: CURRENT.enc, mac: PREVIOUS.mac })), null);
});
