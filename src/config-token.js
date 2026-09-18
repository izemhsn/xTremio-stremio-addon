// The install-token crypto, and the secret policy around it.
//
// Every request path begins with one of these tokens, so this module is what
// decides whether a request has an account at all. It depends on the panel
// allowlist rather than the other way round: the ALLOWED_PANEL_HOSTS check is
// enforced inside decodeConfig so that no route can reach a token without it
// (audit S3).
//
// Keys are derived from the environment at require time, which is why index.js
// requires this near the top and why a test that needs a particular secret sets
// CONFIG_SECRET before requiring anything.
const crypto = require('node:crypto');
const { panelHostAllowed, noteRefusedPanel } = require('./panel-allowlist.js');

const CONFIG_TOKEN_VERSION = 'v3';
const RAW_CONFIG_SECRET = process.env.CONFIG_SECRET || process.env.XTREMIO_CONFIG_SECRET;
const CONFIG_SECRET = RAW_CONFIG_SECRET
    ? Buffer.from(RAW_CONFIG_SECRET, 'utf8')
    : crypto.randomBytes(32);
const CONFIG_SECRET_MIN_BYTES = 32;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// scrypt rather than a bare hash: every install URL carries ciphertext and a MAC,
// enough to test candidate secrets offline, and a single hash makes each guess
// free. N=32768/r=8 costs ~80 ms and 32 MB per guess. The salts are fixed,
// per-purpose labels because the keys must be re-derivable from the secret alone.
const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };

function deriveConfigKey(label, bytes = 32, secret = CONFIG_SECRET) {
    return crypto.scryptSync(secret, `xtremio-${label}-${CONFIG_TOKEN_VERSION}`, bytes, SCRYPT_PARAMS);
}

const CONFIG_ENC_KEY = deriveConfigKey('config-enc');
const CONFIG_MAC_KEY = deriveConfigKey('config-mac');
const CURRENT_CONFIG_KEYS = { enc: CONFIG_ENC_KEY, mac: CONFIG_MAC_KEY };

function deriveConfigKeys(secret) {
    const material = Buffer.from(String(secret), 'utf8');
    return {
        enc: deriveConfigKey('config-enc', 32, material),
        mac: deriveConfigKey('config-mac', 32, material)
    };
}

// Rotation (audit S11): install URLs sealed under the previous secret keep decoding
// while users reinstall, and every new one is sealed under the current secret. Only
// the config-token keys are derived for it — HLS links are re-minted on every
// playlist fetch.
const RAW_CONFIG_SECRET_PREVIOUS = process.env.CONFIG_SECRET_PREVIOUS || '';
const PREVIOUS_CONFIG_KEYS = RAW_CONFIG_SECRET_PREVIOUS && RAW_CONFIG_SECRET_PREVIOUS !== RAW_CONFIG_SECRET
    ? deriveConfigKeys(RAW_CONFIG_SECRET_PREVIOUS)
    : null;
if (RAW_CONFIG_SECRET_PREVIOUS && !PREVIOUS_CONFIG_KEYS) {
    console.warn('[security] CONFIG_SECRET_PREVIOUS is the same as CONFIG_SECRET, so it has no effect');
}

// Once per process: enough to say CONFIG_SECRET_PREVIOUS is still load-bearing, and a
// line an operator can watch for across restarts before removing it.
let previousSecretUseNoted = false;
function notePreviousSecretUse() {
    if (previousSecretUseNoted) return;
    previousSecretUseNoted = true;
    console.warn(
        '[security] an install URL sealed under CONFIG_SECRET_PREVIOUS was used; ' +
        'keep it set until this stops appearing after restarts'
    );
}

// Install URLs shaped like this server's tokens that will not open (audit R6). The
// routes degrade them quietly for the user, so this is what tells the operator that
// CONFIG_SECRET changed. Reported in aggregate at most once per interval, and only
// for well-formed tokens, so scanners do not raise it.
const UNDECODABLE_REPORT_INTERVAL_MS = 5 * 60 * 1000;
const undecodableTokens = { secret: 0, version: 0, lastReportAt: 0 };

function noteUndecodableToken(reason, now = Date.now()) {
    undecodableTokens[reason] += 1;
    if (now - undecodableTokens.lastReportAt < UNDECODABLE_REPORT_INTERVAL_MS) return;
    const findings = [];
    if (undecodableTokens.secret) {
        findings.push(
            `${undecodableTokens.secret} sealed under a secret this server does not have — ` +
            'if this follows a restart, CONFIG_SECRET changed or was not set (see CONFIG_SECRET_PREVIOUS)'
        );
    }
    if (undecodableTokens.version) {
        findings.push(`${undecodableTokens.version} from an older token version, whose users must reinstall`);
    }
    console.warn(`[config] install URLs refused since the last report: ${findings.join('; ')}`);
    undecodableTokens.secret = 0;
    undecodableTokens.version = 0;
    undecodableTokens.lastReportAt = now;
}

// HLS link keys are separate from the config-token pair, so no change to either
// message format can make a value valid in one replayable in the other. One 64-byte
// derivation split in two, because scrypt's cost is the mixing, not the length.
const HLS_KEY_MATERIAL = deriveConfigKey('hls', 64);
const HLS_ENC_KEY = HLS_KEY_MATERIAL.subarray(0, 32);
const HLS_MAC_KEY = HLS_KEY_MATERIAL.subarray(32);

// GCM's standard nonce and tag sizes, shared by the config token and the HLS
// target payload. Both are named rather than inlined because the decrypt side
// has to slice by them and state the tag length explicitly.
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
// The HMAC-SHA256 over a token body. Named because decodeConfig checks it as a
// length before it checks it as a signature.
const CONFIG_MAC_BYTES = 32;

// What is wrong with the configured secret, if anything. Split out from the
// enforcement below so the policy can be tested without exiting the process.
// `raw` is required rather than defaulted: a default would make an explicit
// `configSecretProblems(undefined)` silently check the real environment instead
// of the missing-secret case the caller meant.
function configSecretProblems(raw) {
    const problems = [];
    if (!raw) {
        problems.push('CONFIG_SECRET is not set, so a random one was generated at boot — every install URL will break on restart.');
        return problems;
    }
    const bytes = Buffer.byteLength(raw, 'utf8');
    if (bytes < CONFIG_SECRET_MIN_BYTES) {
        problems.push(`CONFIG_SECRET is ${bytes} bytes; ${CONFIG_SECRET_MIN_BYTES} or more are required. A short secret can be brute-forced offline from a single install URL.`);
    }
    return problems;
}

// Warn in development, refuse to start in production. Being strict everywhere
// would break local development and the test suite for a risk that only matters
// once real credentials are involved; being lax everywhere is how a placeholder
// secret reaches production unnoticed.
function enforceConfigSecretPolicy({ raw = RAW_CONFIG_SECRET, production = IS_PRODUCTION, log = console, exit = (code) => process.exit(code) } = {}) {
    const problems = configSecretProblems(raw);
    if (!problems.length) return true;
    for (const problem of problems) log.warn(`[security] ${problem}`);
    if (production) {
        log.error('[security] Refusing to start with NODE_ENV=production. Generate a secret with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
        exit(1);
        return false;
    }
    return true;
}

function validateConfig(cfg) {
    if (!cfg || typeof cfg !== 'object') return null;
    const { serverUrl, username, password } = cfg;
    if (typeof serverUrl !== 'string' || typeof username !== 'string' || typeof password !== 'string') return null;
    if (!serverUrl || !username || !password) return null;
    return { serverUrl, username, password };
}

function signTokenBody(body, key = CONFIG_MAC_KEY) {
    return crypto.createHmac('sha256', key).update(body).digest('base64url');
}

// base64url as `toString('base64url')` writes it: no padding, no other characters.
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

// One field of a token, decoded only if it really is that field. The charset is
// checked before the length because `Buffer.from(s, 'base64url')` drops anything
// outside the alphabet and truncates a trailing partial group, so the length of
// what it returns says nothing on its own about what went in.
function decodeTokenPart(part, bytes) {
    if (typeof part !== 'string' || !BASE64URL_RE.test(part)) return null;
    const buf = Buffer.from(part, 'base64url');
    if (bytes === undefined) return buf.length ? buf : null;
    return buf.length === bytes ? buf : null;
}

function timingSafeEqualString(a, b) {
    const ab = Buffer.from(a);
    const bb = Buffer.from(b);
    return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function encodeConfig(cfg) {
    return sealConfig(cfg, CURRENT_CONFIG_KEYS);
}

// Seals under an explicit key set. encodeConfig passes the current one; nothing in
// production seals under the previous one, which is only ever used to open.
function sealConfig(cfg, keys) {
    const clean = validateConfig(cfg);
    if (!clean) throw new Error('Invalid config');

    const iv = crypto.randomBytes(GCM_IV_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', keys.enc, iv);
    const ciphertext = Buffer.concat([
        cipher.update(JSON.stringify(clean), 'utf8'),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();
    const body = [
        CONFIG_TOKEN_VERSION,
        iv.toString('base64url'),
        tag.toString('base64url'),
        ciphertext.toString('base64url')
    ].join('.');
    return `${body}.${signTokenBody(body, keys.mac)}`;
}

function decodeConfig(encoded) {
    if (!encoded) return null;
    if (typeof encoded !== 'string' || encoded.length > 4096) return null;
    try {
        const parts = encoded.split('.');
        if (parts.length !== 5) return null;
        const [version, ivPart, tagPart, ciphertextPart, macPart] = parts;
        // The shape is what decides whether this is counted at all (audit L5). The
        // report noteUndecodableToken writes is the operator's signal that
        // CONFIG_SECRET changed, so it must only count strings this server could
        // really have issued: `v3.a.b.c.d` is five parts and a version prefix and
        // nothing else, and counting a scanner's guesses raised that alarm for
        // traffic that never held a token. Checked before the version, because
        // every version has written these four fields at these lengths, so a
        // genuine v2 install URL — whose user does have to reinstall — still counts.
        const iv = decodeTokenPart(ivPart, GCM_IV_BYTES);
        const tag = decodeTokenPart(tagPart, GCM_TAG_BYTES);
        const ciphertext = decodeTokenPart(ciphertextPart);
        const mac = decodeTokenPart(macPart, CONFIG_MAC_BYTES);
        if (!iv || !tag || !ciphertext || !mac) return null;
        if (version !== CONFIG_TOKEN_VERSION) {
            if (/^v\d+$/.test(version)) noteUndecodableToken('version');
            return null;
        }
        const body = [version, ivPart, tagPart, ciphertextPart].join('.');
        // The current secret first, and the previous one only when that fails, so a
        // rotation costs old install URLs one extra MAC and new ones nothing. The MAC
        // that verifies decides the decryption key: a MAC from one secret over a
        // ciphertext from the other does not open.
        const keys = timingSafeEqualString(signTokenBody(body), macPart)
            ? CURRENT_CONFIG_KEYS
            : (PREVIOUS_CONFIG_KEYS && timingSafeEqualString(signTokenBody(body, PREVIOUS_CONFIG_KEYS.mac), macPart)
                ? PREVIOUS_CONFIG_KEYS
                : null);
        if (!keys) {
            noteUndecodableToken('secret');
            return null;
        }

        // authTagLength is explicit: without it setAuthTag accepts a truncated
        // tag, and a short tag is proportionally easier to forge. Unreachable
        // today — the MAC over the same bytes is checked first, and the shape
        // check above has already refused a tag that is not 16 bytes — which is
        // why this is defence in depth rather than a fix.
        const decipher = crypto.createDecipheriv('aes-256-gcm', keys.enc, iv, { authTagLength: GCM_TAG_BYTES });
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]).toString('utf8');
        const cfg = validateConfig(JSON.parse(plaintext));
        if (cfg && keys === PREVIOUS_CONFIG_KEYS) notePreviousSecretUse();
        // Policy rather than crypto, but checked here so that no route can decode a
        // token without it. A token for an unlisted panel still decrypts — one
        // minted before ALLOWED_PANEL_HOSTS was set, or while it was empty — and a
        // route that honoured it would relay for a panel the operator never allowed.
        if (cfg && !panelHostAllowed(cfg.serverUrl)) {
            noteRefusedPanel(cfg.serverUrl);
            return null;
        }
        return cfg;
    } catch {
        return null;
    }
}

module.exports = {
    CONFIG_TOKEN_VERSION,
    RAW_CONFIG_SECRET,
    CONFIG_SECRET,
    CONFIG_SECRET_MIN_BYTES,
    IS_PRODUCTION,
    SCRYPT_PARAMS,
    deriveConfigKey,
    deriveConfigKeys,
    CONFIG_ENC_KEY,
    CONFIG_MAC_KEY,
    CURRENT_CONFIG_KEYS,
    PREVIOUS_CONFIG_KEYS,
    notePreviousSecretUse,
    UNDECODABLE_REPORT_INTERVAL_MS,
    undecodableTokens,
    noteUndecodableToken,
    HLS_ENC_KEY,
    HLS_MAC_KEY,
    GCM_IV_BYTES,
    GCM_TAG_BYTES,
    CONFIG_MAC_BYTES,
    configSecretProblems,
    enforceConfigSecretPolicy,
    validateConfig,
    signTokenBody,
    decodeTokenPart,
    timingSafeEqualString,
    encodeConfig,
    sealConfig,
    decodeConfig
};
