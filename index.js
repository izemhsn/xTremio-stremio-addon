const express = require('express');
const { Readable } = require('stream');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
// Only for the connection-level DNS pin below — outbound requests still go
// through the global fetch. See PINNED_DISPATCHER for why the two have to come
// from the same undici major.
const { Agent: UndiciAgent } = require('undici');

const app = express();
// Free stack fingerprinting for anyone who can reach the port.
app.disable('x-powered-by');
// The only form is three flat string fields. Extended parsing (qs) would build
// nested objects and arrays that asString then has to defend against.
app.use(express.urlencoded({ extended: false }));

// The Stremio addon protocol is called cross-origin by web.stremio.com, so its
// JSON resources genuinely need a wildcard. Nothing else here does: /configure
// handles plaintext credentials, and the landing page and health probe are read
// by people and orchestrators, not by scripts on other origins.
const CORS_PATH = /^\/(?:[^/]+\/)?(?:manifest\.json|catalog\/|meta\/|stream\/)/;

// The byte proxy is deliberately excluded. CORS is not what stops someone
// spending your bandwidth — a plain <video src> or a server-side fetch needs no
// CORS at all, so the token is the only real gate. Set PROXY_CORS=true if a
// player turns out to need it (an MSE-based one, or a crossorigin video element).
const PROXY_CORS = process.env.PROXY_CORS === 'true';
const PROXY_PATH = /^\/[^/]+\/proxy\//;

function corsApplies(path) {
    if (PROXY_PATH.test(path)) return PROXY_CORS;
    return CORS_PATH.test(path);
}

app.use((req, res, next) => {
    if (!corsApplies(req.path)) return next();
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ADDON_ID = 'org.xtremio.addon';
// v3, not v2: the key derivation below changed, so tokens issued by an older
// build no longer decode. That is a deliberate break — see the README.
const CONFIG_TOKEN_VERSION = 'v3';
const RAW_CONFIG_SECRET = process.env.CONFIG_SECRET || process.env.XTREMIO_CONFIG_SECRET;
const CONFIG_SECRET = RAW_CONFIG_SECRET
    ? Buffer.from(RAW_CONFIG_SECRET, 'utf8')
    : crypto.randomBytes(32);
const CONFIG_SECRET_MIN_BYTES = 32;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// scrypt rather than a bare SHA-256. Every install URL carries ciphertext and a
// MAC, which is everything an attacker needs to test candidate secrets offline;
// a single hash makes each guess essentially free, so a memorable passphrase
// falls quickly. N=32768/r=8 costs ~80 ms and 32 MB per guess, and being
// memory-hard it resists GPU parallelism too. Three derivations put ~200 ms on
// startup, paid once.
// The salts are fixed strings because the keys must be re-derivable at boot from
// the secret alone — there is nowhere to persist a random salt. That is what the
// per-purpose labels stand in for: they keep the derived keys independent.
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

// Rotation (audit S11). Every install URL is sealed under CONFIG_SECRET, so changing
// it used to break every install at once — which kept a secret that had leaked, or had
// only ever been a placeholder, in service because replacing it was worse. With the old
// secret here, install URLs sealed under it keep decoding while users reinstall at
// their own pace, and every new one is sealed under the current secret.
// Only the config-token keys are derived for it: an HLS link lives an hour at most and
// every playlist fetch mints fresh ones, so a rotation costs a live channel one reload.
// Remove it once the note below stops appearing for as long as your users take to
// reinstall.
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
// routes degrade them quietly on purpose — Stremio shows raw errors to users — which
// left the operator nothing: after a restart with a missing or changed CONFIG_SECRET,
// every install on the instance became an unconfigured manifest, and not one line
// said so. Reported in aggregate, at most once per interval, since one broken install
// fires dozens of requests; and only well-formed tokens are counted, so paths probed
// by scanners do not raise the alarm. A report is written when a refusal arrives and
// the interval has passed, carrying everything counted since the last one.
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

// The keys protecting HLS sub-resource links are separate from the config-token
// pair. Those two purposes were domain-separated only by the `hls:` prefix
// inside the signed string; a distinct key makes the separation structural, so
// no future change to either message format can make a value valid in one
// position replayable in the other.
// They come from one derivation rather than two because scrypt's cost is the
// memory-hard mixing and not the output length: 64 bytes cost the same ~65 ms as
// 32, so splitting a single output keeps boot — and the module load every test
// file pays — at three derivations rather than four.
const HLS_KEY_MATERIAL = deriveConfigKey('hls', 64);
const HLS_ENC_KEY = HLS_KEY_MATERIAL.subarray(0, 32);
const HLS_MAC_KEY = HLS_KEY_MATERIAL.subarray(32);

// GCM's standard nonce and tag sizes, shared by the config token and the HLS
// target payload. Both are named rather than inlined because the decrypt side
// has to slice by them and state the tag length explicitly.
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const ALLOW_PRIVATE_NETWORKS = process.env.ALLOW_PRIVATE_NETWORKS === 'true';
const PUBLIC_URL = process.env.PUBLIC_URL ? normalizeUrl(process.env.PUBLIC_URL) : null;

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

// Host and X-Forwarded-* are attacker-controllable unless a trusted proxy sets
// them, and the result is embedded in the install link handed out by
// /configure — a poisoned host would send users' config tokens elsewhere.
// Accept only a plain host[:port] (or bracketed IPv6); set PUBLIC_URL to pin it.
const SAFE_HOST = /^[A-Za-z0-9._~[\]:-]+$/;

// How many reverse proxies in front of this server are trusted to report on the
// client (TRUST_PROXY): `true` means one, a positive integer means that many, and
// anything else means none — in which case the forwarded headers are ignored
// entirely, because with no proxy in front every one of them was written by the
// client.
const TRUST_PROXY_HOPS = (() => {
    const raw = String(process.env.TRUST_PROXY || '').trim().toLowerCase();
    if (raw === 'true') return 1;
    const n = Number(raw);
    return Number.isInteger(n) && n > 0 ? n : 0;
})();

// The value a trusted proxy recorded in a forwarded header, or ''. Proxies
// *append* to X-Forwarded-For, so everything left of what they added came from the
// client: behind one proxy, the client wrote every entry but the last. The leftmost
// entry used to be taken, so `X-Forwarded-For: <anything>` chose the rate limiter's
// key and every request could be a fresh bucket (audit S5). Counting in from the
// right by the number of trusted hops takes the entry the outermost trusted proxy
// wrote. The same rule reads X-Forwarded-Proto and -Host: a proxy that overwrites
// them rather than appending leaves a single value, which is also the last.
// Every proxy that appends has to be counted — behind a CDN and nginx that both
// append, TRUST_PROXY=true reads nginx's entry, which names the CDN.
function forwardedValue(req, header) {
    if (!TRUST_PROXY_HOPS) return '';
    const entries = String(req.headers?.[header] || '').split(',').map(v => v.trim()).filter(Boolean);
    if (!entries.length) return '';
    return entries[Math.max(0, entries.length - TRUST_PROXY_HOPS)];
}

function getBaseUrl(req) {
    if (PUBLIC_URL) return PUBLIC_URL;
    // Only a trusted proxy's word counts (audit D4). These headers used to be
    // honoured whether or not TRUST_PROXY was on — while the rate limiter, reading
    // the same kind of header, required it — so the host an install link was minted
    // for was whatever the request claimed.
    const proto = forwardedValue(req, 'x-forwarded-proto') || req.protocol || 'http';
    const host = forwardedValue(req, 'x-forwarded-host') || req.headers.host || '';
    const safeProto = /^https?$/.test(proto) ? proto : 'http';
    const safeHost = SAFE_HOST.test(host) ? host : `localhost:${PORT}`;
    return `${safeProto}://${safeHost}`;
}

// null and undefined become '', but every other value is stringified as itself:
// `String(str || '')` silently turned 0 and false into an empty string, which
// is a trap for the next caller that interpolates a number.
function escapeHtml(str) {
    return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
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
        if (parts[0] !== CONFIG_TOKEN_VERSION) {
            if (/^v\d+$/.test(parts[0])) noteUndecodableToken('version');
            return null;
        }
        const [version, ivPart, tagPart, ciphertextPart, macPart] = parts;
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
        // today because the MAC over the same bytes is checked first, which is
        // why this is defence in depth rather than a fix.
        const decipher = crypto.createDecipheriv('aes-256-gcm', keys.enc, Buffer.from(ivPart, 'base64url'), { authTagLength: GCM_TAG_BYTES });
        decipher.setAuthTag(Buffer.from(tagPart, 'base64url'));
        const plaintext = Buffer.concat([
            decipher.update(Buffer.from(ciphertextPart, 'base64url')),
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

async function getManifest(baseUrl = `http://localhost:${PORT}`, cfg = null) {
    const catalogs = [];

    if (cfg) {
        // getCategories cannot reject — refreshCategories resolves through
        // Promise.allSettled and always returns an entry, serving stale or empty
        // lists on failure — so this catch is belt and braces rather than the
        // degraded path. It used to push a second, hand-maintained copy of the
        // catalog list that could never be reached. The real degraded case is an
        // *empty* category list, which genreExtra handles below.
        let cats = { live: [], movies: [], series: [] };
        try {
            cats = await getCategories(cfg);
        } catch (e) {
            console.error('[manifest] categories unavailable:', e.message);
        }

        const genresOf = (key) =>
            [...new Set((cats[key] || []).map(c => c.category_name).filter(Boolean))];

        // A genre is only offered when there is something to pick. Stremio reads
        // `isRequired: true` as "the client must supply one of these options",
        // so a required genre with an empty list is a catalog nobody can open —
        // strictly worse than the plain catalog it was meant to degrade into.
        const genreExtra = (genres) => (genres.length
            ? [{ name: 'genre', options: genres, isRequired: true }, { name: 'skip' }, { name: 'search' }]
            : [{ name: 'skip' }, { name: 'search' }]);

        // One row per catalog, so the rule cannot apply to some and miss others
        // — which is how the empty-options bug survived in the first place:
        // seven copies of the same `extra` literal.
        const genreCatalogs = [
            ['Live TV', 'xtremio_live', 'Live TV', 'live'],
            ['XT-Movies', 'xtremio_movies_popular', 'Popular', 'movies'],
            ['XT-Movies', 'xtremio_movies_new', 'New', 'movies'],
            ['XT-Movies', 'xtremio_movies_featured', 'Featured', 'movies'],
            ['XT-Series', 'xtremio_series_popular', 'Popular', 'series'],
            ['XT-Series', 'xtremio_series_new', 'New', 'series'],
            ['XT-Series', 'xtremio_series_featured', 'Featured', 'series']
        ];

        catalogs.push(
            ...genreCatalogs.map(([type, id, name, key]) => ({
                type,
                id,
                name,
                extra: genreExtra(genresOf(key))
            })),
            {
                type: 'XT-Movies',
                id: 'xtremio_search_movies',
                name: 'Search Movies',
                // Stremio sends only the extras a catalog declares, so without
                // `skip` a search never asks for page two and a common word stops
                // at the 100 most recently added matches.
                extra: [{ name: 'search', isRequired: true }, { name: 'skip' }],
                // Not a field the Stremio SDK defines, so no client reads it.
                // Kept because it is accurate documentation of what the search
                // route actually does — filterByName matches on `name` only —
                // and because an unknown key is inert where a mistyped known
                // one (see `config` above) is not.
                searchProperties: ['name']
            },
            {
                type: 'XT-Series',
                id: 'xtremio_search_series',
                name: 'Search Series',
                // Stremio sends only the extras a catalog declares, so without
                // `skip` a search never asks for page two and a common word stops
                // at the 100 most recently added matches.
                extra: [{ name: 'search', isRequired: true }, { name: 'skip' }],
                // Not a field the Stremio SDK defines, so no client reads it.
                // Kept because it is accurate documentation of what the search
                // route actually does — filterByName matches on `name` only —
                // and because an unknown key is inert where a mistyped known
                // one (see `config` above) is not.
                searchProperties: ['name']
            }
        );
    }

    return {
        id: ADDON_ID,
        version: '1.0.2',
        name: 'xTremio',
        description: 'xTremio addon for Stremio',
        resources: ['catalog', 'meta', 'stream'],
        types: ['Live TV', 'XT-Movies', 'XT-Series', 'series'],
        catalogs,
        idPrefixes: ['xtremio_live_', 'xtremio_movie_', 'xtremio_series_', 'xtremio_episode_'],
        // No `config` field. The Stremio spec defines it as an array of field
        // descriptors, and this addon used to emit `{ url }` — an object where a
        // client following the spec expects a list. Clients ignore it today, but
        // one that starts honouring it would be handed the wrong type, and it
        // buys nothing: `behaviorHints.configurable` is what routes the user to
        // /configure, and that already works.
        behaviorHints: {
            configurable: true,
            configurationRequired: !cfg
        }
    };
}

app.get('/manifest.json', async (req, res) => {
    res.json(await getManifest(getBaseUrl(req), null));
});

app.get('/:config/manifest.json', async (req, res) => {
    const cfg = decodeConfig(req.params.config);
    res.json(await getManifest(getBaseUrl(req), cfg));
});

// Query and body values arrive as string, array, object or undefined depending
// on what the client sent. Anything that is not a string is treated as absent
// rather than coerced: `String(['a','b'])` would silently accept "a,b".
function asString(value) {
    return typeof value === 'string' ? value : '';
}

function normalizeUrl(url) {
    url = String(url || '').trim().replace(/\/+$/, '');
    if (!url) throw new Error('serverUrl is required');
    if (!/^https?:\/\//.test(url)) url = 'http://' + url;
    return url;
}

// The hostname a host-list entry or a server URL names, or null. Forgiving about
// spelling, because an operator pastes what they have: a bare hostname, `host:port`
// and a whole URL all name the same host. A bare IPv6 address is bracketed the way
// URL writes a hostname, and URL does the lowercasing, so this compares equal to
// `new URL(x).hostname` for the same host.
function hostnameOf(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    const bareIpv6 = /^[0-9a-f:]+$/i.test(raw) && raw.split(':').length > 2;
    const candidate = bareIpv6 ? `[${raw}]` : raw;
    let hostname;
    try {
        hostname = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate) ? candidate : `http://${candidate}`).hostname;
    } catch {
        return null;
    }
    // URL accepts characters no real host has — `new URL('http://*.x.test')` parses,
    // with `*.x.test` as its hostname. Kept, a `*.provider.com` entry would look like
    // it covered every subdomain while matching nothing, which is the silent failure
    // parseHostList exists to refuse. URL has already lowercased the name and turned
    // an internationalized one into its xn-- form, so this is the whole alphabet.
    if (/^\[[0-9a-f:.]+\]$/.test(hostname) || /^[a-z0-9._-]+$/.test(hostname)) return hostname;
    return null;
}

// A comma-separated host list from the environment. An entry that names no host —
// a `*.` wildcard, say — is dropped and said so at boot, rather than quietly
// allowing nothing while looking like it allows something.
function parseHostList(value, name) {
    const hosts = new Set();
    for (const entry of String(value || '').split(',')) {
        if (!entry.trim()) continue;
        const host = hostnameOf(entry);
        if (host) hosts.add(host);
        else console.warn(`[config] ${name}: ignoring ${JSON.stringify(entry.trim())}, which names no single host`);
    }
    return hosts;
}

// Which Xtream panels this instance will serve (audit S3). Empty, the default,
// means any — the only workable setting when users bring their own providers, and
// one that leaves this server usable as a relay: anyone who can reach /configure
// can stand up a ten-line fake panel that passes the credential check, get an
// install URL for it, and have the proxy fetch and relay whatever public URL that
// panel redirects to, from this server's address. The per-account relay cap does
// not bound it, since every made-up username is a new account, and nothing
// stateless can tell such a panel from a real one. A list of the real ones can.
//
// Set, it is enforced everywhere a panel is chosen or used, because any one point
// alone leaves a way round. /configure refuses an unlisted host before making any
// request to it; a listed panel whose server_info names an unlisted origin keeps
// the URL that connected; and decodeConfig refuses a token for an unlisted host,
// so an install URL minted before the list was set — or while it was empty, which
// is exactly when a fake panel could get one — stops working.
// Matched by exact hostname, like HLS_TARGET_ALLOWED_HOSTS: one entry covers both
// schemes and any port, and a subdomain needs an entry of its own. A listed panel
// is trusted, including wherever it redirects.
const ALLOWED_PANEL_HOSTS = parseHostList(process.env.ALLOWED_PANEL_HOSTS, 'ALLOWED_PANEL_HOSTS');

function panelHostAllowed(serverUrl) {
    if (!ALLOWED_PANEL_HOSTS.size) return true;
    const host = hostnameOf(serverUrl);
    return host !== null && ALLOWED_PANEL_HOSTS.has(host);
}

// A refused token is logged once per host rather than once per request. An install
// URL that stopped working when the list was set fires every catalog, meta and
// stream request Stremio makes, and one line per host is enough to say why. Bounded,
// because the hosts come from tokens rather than from this server's configuration.
const refusedPanelHostsLogged = new Set();
const REFUSED_PANEL_LOG_MAX = 1000;

function noteRefusedPanel(serverUrl) {
    const host = hostnameOf(serverUrl) || '(unparseable)';
    if (refusedPanelHostsLogged.has(host) || refusedPanelHostsLogged.size >= REFUSED_PANEL_LOG_MAX) return;
    refusedPanelHostsLogged.add(host);
    console.warn(`[config] refusing an install URL for ${JSON.stringify(host)}, which is not in ALLOWED_PANEL_HOSTS`);
}

function buildUrl(base, pathname, params = {}) {
    const url = new URL(pathname, base);
    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
            url.searchParams.set(key, String(value));
        }
    }
    return url.toString();
}

function buildXtremioApiUrl(cfg, action, params = {}) {
    return buildUrl(normalizeUrl(cfg.serverUrl), '/player_api.php', {
        username: cfg.username,
        password: cfg.password,
        action,
        ...params
    });
}

function isNumericId(value) {
    return /^\d+$/.test(String(value || ''));
}

function getPrefixedNumericId(id, prefix) {
    if (!String(id || '').startsWith(prefix)) return null;
    const value = id.slice(prefix.length);
    return isNumericId(value) ? value : null;
}

function parseEpisodeId(id) {
    if (!String(id || '').startsWith('xtremio_episode_')) return null;
    const parts = id.slice('xtremio_episode_'.length).split(':');
    if (parts.length !== 3 || !parts.every(isNumericId)) return null;
    return { seriesId: parts[0], seasonNum: parts[1], episodeId: parts[2] };
}

// Stremio's `:type` path segment is advisory here — every route dispatches on
// the id prefix instead — but without a check a mismatched pair (say
// type=XT-Movies with a live id) is happily served under the wrong type.
// Series are declared under `XT-Series` in the manifest's catalog list yet emit
// `series` metas, so both spellings are accepted wherever a series is involved.
const ID_PREFIX_TYPES = {
    'xtremio_episode_': ['series', 'XT-Series'],
    'xtremio_series_': ['series', 'XT-Series'],
    'xtremio_movie_': ['XT-Movies'],
    'xtremio_live_': ['Live TV']
};

function typeMatchesId(type, id) {
    const str = String(id || '');
    const prefix = Object.keys(ID_PREFIX_TYPES).find(p => str.startsWith(p));
    // An id we do not recognise is left to the route, which already answers it
    // with the empty payload rather than an error.
    if (!prefix) return true;
    return ID_PREFIX_TYPES[prefix].includes(String(type));
}

// Catalog ids are not item ids and overlap their prefixes (`xtremio_series_new`
// starts with `xtremio_series_`), so catalogs are matched separately — see
// `catalogTypesFor`, which lives with the catalog table further down.

// The container the provider named, or null when it named none usable. The
// stream route needs that difference: a guessed extension must not be cached.
function statedContainerExt(ext) {
    const clean = String(ext || '').trim();
    return /^[A-Za-z0-9]+$/.test(clean) ? clean : null;
}

function normalizeContainerExt(ext) {
    return statedContainerExt(ext) || 'mp4';
}

// Per Stremio SDK: notWebReady must be true when the URL is http:// or
// the file is not an MP4 container. Without this, the player may stop
// after a short period (e.g. ~1 min) and Stremio treats it as "ended",
// returning to details (movies) or auto-advancing (series episodes).
function isNotWebReady(url, ext) {
    const isHttps = /^https:\/\//i.test(url);
    const isMp4 = String(ext || '').toLowerCase() === 'mp4';
    return !(isHttps && isMp4);
}

// Browser-like UA — many Xtream CDNs reject or shortchange non-browser UAs.
const PROXY_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// How long to wait for upstream response headers in the proxy. Applies to the
// headers only — never to the body, which is a legitimate long-lived stream.
const PROXY_HEADER_TIMEOUT_MS = Math.max(1000, Number(process.env.PROXY_HEADER_TIMEOUT_MS) || 20000);

// Separate, longer deadline for the one path that buffers a whole body before
// answering: the playlist rewrite. The streaming path must stay unbounded — a
// paused movie is a legitimately idle connection — so this is not a general
// body timeout.
const PLAYLIST_BODY_TIMEOUT_MS = Math.max(1000, Number(process.env.PLAYLIST_BODY_TIMEOUT_MS) || 30000);

// Reading the body is not the end of the work. The rewrite that follows resolves
// DNS once per distinct origin named in the playlist, and it used to run with no
// deadline at all: PLAYLIST_BODY_TIMEOUT_MS had been cleared and
// PROXY_HEADER_TIMEOUT_MS long before that. At MAX_PLAYLIST_BYTES a playlist can
// name on the order of 60,000 distinct hostnames, which held one request, its
// socket and the buffered body for tens of minutes while emitting a resolver
// query per host. Two bounds close it: a ceiling on how many distinct origins are
// worth vetting at all, and a deadline over the phase as a whole.
//
// The cap is the load-bearing one — it bounds the *number* of lookups. The
// deadline bounds the total and is the backstop for a slow resolver; it is
// checked between lookups, so a single hung resolution can still overrun it by
// that lookup's own timeout.
const MAX_PLAYLIST_ORIGINS = Math.max(1, Number(process.env.MAX_PLAYLIST_ORIGINS) || 32);
const PLAYLIST_REWRITE_TIMEOUT_MS = Math.max(1000, Number(process.env.PLAYLIST_REWRITE_TIMEOUT_MS) || 15000);

// --- HLS playlist proxying -------------------------------------------------
//
// Live channels are served as either a continuous MPEG-TS body (.ts), which
// relays byte-for-byte, or an HLS playlist (.m3u8), which does not. A playlist
// is a manifest of further URLs, and an Xtream one names segments by absolute
// URLs that embed /username/password/ themselves. Relaying such a body
// unchanged would move the credential disclosure from the URL into the body
// rather than fixing it, so playlists are rewritten: every URI inside is
// resolved and replaced with a link back through this server.
//
// Those rewritten links must not turn the proxy into an open relay for
// arbitrary URLs, so each target is HMAC-signed and the signature is checked
// before any outbound request. The MAC uses its own key (HLS_MAC_KEY) and its
// `hls:` prefix domain-separates the signed string as well, so a value valid in
// one position cannot be replayed in the other.
//
// The target itself is encrypted, not merely encoded. It used to be plain
// base64url, and the URL it names is the provider's own: for many panels that
// is /live/<username>/<password>/<id>.ts, so anyone who read the query string
// could decode working account credentials — credentials that keep working
// against the provider directly and survive a CONFIG_SECRET rotation. Query
// strings are recorded in player logs, in Stremio's history and in every
// reverse-proxy access log, which is the same disclosure /configure refuses to
// make when it declines to prefill the password back into its form.
// The config token and the expiry are the ciphertext's associated data, so the
// GCM tag covers exactly what the MAC covers: a payload minted for one account
// will not decrypt under another's token, nor under a deadline someone extended.
// A signature covers the config token and an expiry as well as the URL, so the
// capability it grants is neither transferable nor permanent. It was previously
// a pure function of the URL and the global MAC key, which meant one minted
// while rewriting user A's playlist verified under *any* user's token, forever
// — and the target it names is an Xtream segment URL with A's credentials in
// the path. Obtaining one already requires A's token, so this is durability
// rather than escalation: a link captured from a log or a shared screen stayed
// valid indefinitely, and survived the user reconfiguring.
//
// None of the three fields can contain a `:` — the config token is base64url
// with `.` separators, the expiry is digits, the payload is base64url — so
// concatenating them is unambiguous and no field can be shifted into another.
const HLS_SIGNATURE_TTL_MS = Math.max(60 * 1000, Number(process.env.HLS_SIGNATURE_TTL_MS) || 60 * 60 * 1000);

function signHlsTarget(payload, configToken = '', expiresAt = 0) {
    return crypto.createHmac('sha256', HLS_MAC_KEY)
        .update(`hls:${configToken}:${expiresAt}:${payload}`)
        .digest('base64url');
}

// The same three fields the MAC covers, in the same order, bound to the
// ciphertext instead of concatenated with it. `expiresAt` is stringified here
// because the query carries it as a string and the decrypt side must associate
// the identical bytes.
function hlsTargetAad(configToken, expiresAt) {
    return Buffer.from(`hls:${configToken}:${expiresAt}`, 'utf8');
}

// The plaintext is one kind byte and then the URL. The kind is what the
// playlist said the target was — see HLS_PLAYLIST_URI_TAGS — and the proxy route
// needs it before the body arrives: a nested playlist must be buffered and
// rewritten in turn, while a segment must keep its Range support and stream.
// It rides inside the ciphertext rather than beside it as another query field,
// so it is covered by the GCM tag and the MAC with nothing further to sign.
const HLS_KIND_PLAYLIST = 'p';
const HLS_KIND_SEGMENT = 's';

function encodeHlsTarget(absoluteUrl, configToken = '', now = Date.now(), playlist = false) {
    const expiresAt = now + HLS_SIGNATURE_TTL_MS;
    const iv = crypto.randomBytes(GCM_IV_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', HLS_ENC_KEY, iv);
    cipher.setAAD(hlsTargetAad(configToken, String(expiresAt)));
    const plaintext = (playlist ? HLS_KIND_PLAYLIST : HLS_KIND_SEGMENT) + absoluteUrl;
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    // iv | tag | ciphertext in one field: the lengths are fixed, so the decrypt
    // side slices rather than splitting, and the payload stays a single
    // separator-free base64url string the way the signed string requires.
    const payload = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
    return { u: payload, s: signHlsTarget(payload, configToken, expiresAt), e: String(expiresAt) };
}

// Returns `{ url, playlist }` only when the signature verifies for this config
// token and the expiry has not lapsed, so a caller cannot point this server at a
// host of their choosing even holding a valid config token of their own.
function decodeHlsTarget(payload, signature, expiry, configToken = '', now = Date.now()) {
    if (typeof payload !== 'string' || typeof signature !== 'string') return null;
    if (payload.length > 4096) return null;

    // Parsed strictly: `Number('12e9')` and `Number(' 12 ')` both succeed, and
    // an expiry that round-trips differently to the string that was signed
    // would verify against a value it does not equal.
    const expiresAt = typeof expiry === 'string' && /^\d{1,15}$/.test(expiry) ? Number(expiry) : NaN;
    if (!Number.isSafeInteger(expiresAt)) return null;

    // Signature first, then the clock, then the decrypt: the MAC is the cheapest
    // of the three and rejects a forged link before any key schedule is set up,
    // the same order the config token uses.
    if (!timingSafeEqualString(signHlsTarget(payload, configToken, expiry), signature)) return null;
    if (expiresAt <= now) return null;

    try {
        const raw = Buffer.from(payload, 'base64url');
        // Strictly greater: the nonce and tag alone are a well-formed payload
        // carrying an empty URL, which no minting path produces.
        if (raw.length <= GCM_IV_BYTES + GCM_TAG_BYTES) return null;
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            HLS_ENC_KEY,
            raw.subarray(0, GCM_IV_BYTES),
            { authTagLength: GCM_TAG_BYTES }
        );
        decipher.setAuthTag(raw.subarray(GCM_IV_BYTES, GCM_IV_BYTES + GCM_TAG_BYTES));
        decipher.setAAD(hlsTargetAad(configToken, expiry));
        const plaintext = Buffer.concat([
            decipher.update(raw.subarray(GCM_IV_BYTES + GCM_TAG_BYTES)),
            decipher.final()
        ]).toString('utf8');

        const kind = plaintext[0];
        if (kind !== HLS_KIND_PLAYLIST && kind !== HLS_KIND_SEGMENT) return null;

        const url = new URL(plaintext.slice(1));
        if (!['http:', 'https:'].includes(url.protocol)) return null;
        return { url: url.toString(), playlist: kind === HLS_KIND_PLAYLIST };
    } catch {
        return null;
    }
}

const HLS_CONTENT_TYPES = /^(application\/(vnd\.apple\.mpegurl|x-mpegurl)|audio\/(mpegurl|x-mpegurl))/i;

// The extension is the hint that matters: providers commonly return
// text/plain or octet-stream for a playlist, so content-type alone would miss
// them — and a missed playlist is relayed verbatim, with the provider's
// credential-bearing URLs still in the body. `hlsTargetExt` is what supplies an
// extension on the sub-resource route, where the request carries no file name.
// A body that then turns out not to be a playlist is refused rather than
// rewritten; see the EXTM3U check in relayUpstream.
function looksLikePlaylist(ext, contentType) {
    if (String(ext || '').toLowerCase() === 'm3u8') return true;
    return HLS_CONTENT_TYPES.test(String(contentType || ''));
}

// What the sub-resource route should expect of a signed target, decided before
// any of the body arrives — it has to be, because the streaming path forwards
// Range and relays bytes through untouched.
//
// Two things say "playlist" ahead of the body. The capability itself, when the
// URI sat on a tag that can only name one, is the reliable half: it comes from
// the playlist's own structure rather than from anything the provider labelled.
// A path ending in .m3u8 covers the rest — a playlist reached by a link this
// server did not mint, or one whose tag context said nothing.
//
// Sniffing the body for #EXTM3U is deliberately not a third signal here. The
// decision has to be made before reading anything, and the alternative to a
// playlist on this route is a segment that may be gigabytes; buffering one to
// find out is exactly what the streaming path exists to avoid.
const PLAYLIST_PATH_EXT = /\.m3u8?$/i;

// Every HLS playlist starts with this tag; the spec requires it on the first
// line. A byte-order mark and leading blank lines are tolerated because real
// panels emit both.
const HLS_BODY_PREFIX = /^\uFEFF?\s*#EXTM3U/;

function hlsTargetExt(target) {
    if (target.playlist) return 'm3u8';
    // Parsed by decodeHlsTarget already, so this cannot throw.
    return PLAYLIST_PATH_EXT.test(new URL(target.url).pathname) ? 'm3u8' : null;
}

// Playlists are kilobytes; anything far larger is not one. Bounded because the
// rewrite has to buffer the whole body, unlike the streaming path.
const MAX_PLAYLIST_BYTES = 4 * 1024 * 1024;

// URI="..." appears on EXT-X-KEY, EXT-X-MAP, EXT-X-MEDIA, EXT-X-PART and
// friends; those are sub-resources exactly like segment lines and leak the
// same credentials if left alone.
const HLS_URI_ATTR = /URI="([^"]*)"/gi;

// Which lines name a *playlist* rather than a segment or a key. The distinction
// is carried into the signed link, because the route that later fetches the
// target cannot recover it: a variant playlist need not end in .m3u8 and is
// routinely served as text/plain, and one relayed as if it were a segment goes
// to the player unrewritten, credentials and all.
// HLS states it unambiguously here instead. EXT-X-MEDIA and EXT-X-RENDITION-
// REPORT name Media Playlists, EXT-X-I-FRAME-STREAM-INF an I-frame playlist,
// and the URI *line* following an EXT-X-STREAM-INF is a Variant Stream's
// playlist. Every other URI — EXT-X-KEY, EXT-X-MAP, EXT-X-PART, a plain segment
// line — is a segment or a key, and must keep its Range support.
const HLS_PLAYLIST_URI_TAGS = /^#EXT-X-(MEDIA|I-FRAME-STREAM-INF|RENDITION-REPORT)[:\s]/i;
const HLS_STREAM_INF_TAG = /^#EXT-X-STREAM-INF[:\s]/i;

// `toProxyUrl` maps one absolute upstream URL to a URL on this server.
// Anything that will not resolve, or is not http(s), is left untouched rather
// than dropped: a malformed line is the provider's business, and removing it
// would silently corrupt the playlist.
// `toProxyUrl` may be async — the mapper used in production resolves DNS to
// check the target before signing it — so this is async throughout.
async function rewriteHlsPlaylist(text, baseUrl, toProxyUrl, { deadline = null } = {}) {
    const mapUri = async (raw, playlist) => {
        // Checked here rather than around the whole pass because this is the only
        // point that awaits: a timer cannot interrupt an await chain, so the loop
        // has to look. Throwing rather than emitting a partly-rewritten playlist
        // is deliberate — the un-rewritten lines are the provider's own URLs, and
        // those carry the account credentials this rewrite exists to hide.
        if (deadline !== null && Date.now() > deadline) {
            const err = new Error('playlist rewrite deadline exceeded');
            err.code = 'PLAYLIST_REWRITE_TIMEOUT';
            throw err;
        }
        const uri = String(raw).trim();
        if (!uri) return null;
        let absolute;
        try {
            absolute = new URL(uri, baseUrl);
        } catch {
            return null;
        }
        if (!['http:', 'https:'].includes(absolute.protocol)) return null;
        const mapped = await toProxyUrl(absolute.toString(), Boolean(playlist));
        if (mapped) return mapped;
        // The mapper refused this target, and leaving the line as the provider
        // wrote it is the disclosure this rewrite exists to prevent: an Xtream
        // playlist names its sub-resources by absolute URLs carrying the account's
        // credentials, so a partly rewritten playlist hands them to the player.
        // Refusing the whole playlist is the answer the deadline above gives, for
        // the same reason — and dropping the line is not a safe alternative, since
        // a dropped EXT-X-KEY URI leaves the player treating encrypted segments as
        // plaintext. The operator's remedy is HLS_TARGET_ALLOWED_HOSTS, named in
        // the warning the mapper logs.
        const err = new Error('playlist names a target this server will not proxy');
        err.code = 'PLAYLIST_TARGET_REFUSED';
        throw err;
    };

    // replace() cannot await, so URI attributes are walked by hand. The regex is
    // built per call rather than shared: awaiting mid-scan would otherwise let a
    // concurrent rewrite move lastIndex out from under this one.
    const rewriteUriAttrs = async (body, playlist) => {
        const scanner = new RegExp(HLS_URI_ATTR.source, HLS_URI_ATTR.flags);
        const parts = [];
        let cursor = 0;
        let match;
        while ((match = scanner.exec(body)) !== null) {
            const mapped = await mapUri(match[1], playlist);
            parts.push(body.slice(cursor, match.index), mapped ? `URI="${mapped}"` : match[0]);
            cursor = match.index + match[0].length;
        }
        parts.push(body.slice(cursor));
        return parts.join('');
    };

    const out = [];
    // Set by an EXT-X-STREAM-INF and consumed by the next URI line, which is the
    // one place a playlist's kind is stated by position rather than by the tag
    // the URI sits on. Not cleared by the tags and comments that may sit in
    // between: the spec says the URI line follows immediately, and erring toward
    // "playlist" costs a buffered fetch, while erring the other way relays a
    // playlist to the player with the provider's credentials still in it.
    let nextUriIsPlaylist = false;

    for (const line of text.split('\n')) {
        // Preserve CRLF exactly: some players are strict about the line ending.
        const cr = line.endsWith('\r') ? '\r' : '';
        const body = cr ? line.slice(0, -1) : line;

        if (!body.trim()) {
            out.push(line);
            continue;
        }
        if (body.startsWith('#')) {
            out.push(await rewriteUriAttrs(body, HLS_PLAYLIST_URI_TAGS.test(body)) + cr);
            if (HLS_STREAM_INF_TAG.test(body)) nextUriIsPlaylist = true;
            continue;
        }

        const mapped = await mapUri(body, nextUriIsPlaylist);
        nextUriIsPlaylist = false;
        out.push(mapped ? mapped + cr : line);
    }
    return out.join('\n');
}

function ipv4ToLong(ip) {
    return ip.split('.').reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
}

// Both families are matched as numeric CIDR prefixes. IPv6 used to be matched
// by string prefix, which is where the gaps were: `fe80:` catches only the
// first /64 of a range that spans fe80–febf, and nothing at all looked inside
// the transition formats that embed an IPv4 address.
const IPV4_PRIVATE_CIDRS = [
    ['0.0.0.0', 8],          // "this network"
    ['10.0.0.0', 8],         // RFC 1918
    ['100.64.0.0', 10],      // carrier-grade NAT
    ['127.0.0.0', 8],        // loopback
    ['169.254.0.0', 16],     // link-local, and the cloud metadata endpoint
    ['172.16.0.0', 12],      // RFC 1918
    ['192.0.0.0', 24],       // IETF protocol assignments
    ['192.168.0.0', 16],     // RFC 1918
    ['198.18.0.0', 15],      // benchmarking
    ['224.0.0.0', 3]         // multicast, reserved and broadcast, to the end
].map(([address, bits]) => ({ network: ipv4ToLong(address), mask: bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0 }));

// Expands to the full 16 bytes. `net.isIP` has already validated the syntax, so
// this only has to handle the shapes it accepts: one optional `::` run, and an
// optional trailing dotted quad standing in for the last two groups.
function ipv6ToBytes(input) {
    const ip = String(input || '').split('%')[0];   // drop any zone id
    if (net.isIP(ip) !== 6) return null;

    const halves = ip.split('::');
    const toGroups = (part) => {
        if (!part) return [];
        const groups = [];
        for (const chunk of part.split(':')) {
            if (chunk.includes('.')) {
                const quad = chunk.split('.').map(Number);
                groups.push((quad[0] << 8) | quad[1], (quad[2] << 8) | quad[3]);
            } else {
                groups.push(parseInt(chunk, 16));
            }
        }
        return groups;
    };

    const head = toGroups(halves[0]);
    const tail = halves.length === 2 ? toGroups(halves[1]) : [];
    const groups = halves.length === 2
        ? [...head, ...Array(8 - head.length - tail.length).fill(0), ...tail]
        : head;
    if (groups.length !== 8) return null;

    const bytes = Buffer.alloc(16);
    groups.forEach((group, i) => bytes.writeUInt16BE(group & 0xffff, i * 2));
    return bytes;
}

function ipv6MatchesPrefix(bytes, prefixBytes, bits) {
    const whole = bits >> 3;
    for (let i = 0; i < whole; i++) {
        if (bytes[i] !== prefixBytes[i]) return false;
    }
    const spare = bits & 7;
    if (spare === 0) return true;
    const mask = (0xff << (8 - spare)) & 0xff;
    return (bytes[whole] & mask) === (prefixBytes[whole] & mask);
}

const IPV6_PRIVATE_PREFIXES = [
    ['::', 128],             // unspecified
    ['::1', 128],            // loopback
    ['fc00::', 7],           // unique local (fc00–fdff)
    ['fe80::', 10],          // link-local (fe80–febf) — the old check saw 1/64 of this
    ['fec0::', 10],          // site-local, deprecated but still routed on some networks
    ['ff00::', 8]            // multicast
].map(([prefix, bits]) => ({ bytes: ipv6ToBytes(prefix), bits }));

// Formats that carry an IPv4 address inside an IPv6 one. Each is decided by the
// address it embeds rather than blocked outright: a 6to4 address wrapping a
// public IPv4 is itself public, and refusing those would break real providers.
// `64:ff9b::7f00:1` is the one that matters — on a NAT64 network it reaches
// 127.0.0.1, and the old check let it straight through.
const IPV6_EMBEDDED_IPV4 = [
    ['::ffff:0:0', 96, 12],  // v4-mapped
    ['64:ff9b::', 96, 12],   // NAT64 (RFC 6052)
    ['2002::', 16, 2]        // 6to4 (RFC 3056)
].map(([prefix, bits, offset]) => ({ bytes: ipv6ToBytes(prefix), bits, offset }));

function isPrivateIp(ip) {
    if (net.isIP(ip) === 4) {
        const n = ipv4ToLong(ip);
        return IPV4_PRIVATE_CIDRS.some(({ network, mask }) => ((n & mask) >>> 0) === network);
    }

    const bytes = ipv6ToBytes(ip);
    // Not an address at all. Refuse it: everything reaching here comes from
    // dns.lookup or from a literal that net.isIP already accepted, so an
    // unparseable value means something unexpected — and "unexpected" is not a
    // reason to allow an outbound connection.
    if (!bytes) return true;

    for (const { bytes: prefix, bits, offset } of IPV6_EMBEDDED_IPV4) {
        if (ipv6MatchesPrefix(bytes, prefix, bits)) {
            return isPrivateIp(Array.from(bytes.subarray(offset, offset + 4)).join('.'));
        }
    }
    return IPV6_PRIVATE_PREFIXES.some(({ bytes: prefix, bits }) => ipv6MatchesPrefix(bytes, prefix, bits));
}

// --- DNS pinning -----------------------------------------------------------
//
// Vetting an address and then calling fetch() resolves the hostname twice:
// once in assertSafeOutboundUrl, once inside the HTTP client, independently.
// A record with a near-zero TTL can answer the first lookup with a public
// address and the second with 169.254.169.254 — the check passes and the
// connection lands inside the network anyway. Since the proxy relays upstream
// bodies back to the caller, winning that race is not blind SSRF but full
// response exfiltration.
//
// So the addresses that passed the check are remembered here and handed to the
// connector, which performs no lookup of its own. The hostname itself is left
// alone in the URL and the TLS options, so SNI and certificate validation still
// happen against the real name rather than a bare IP.
const DNS_PIN_TTL_MS = 60 * 1000;
const DNS_PIN_MAX_HOSTS = 1000;
const dnsPins = new Map();

function pinResolvedAddresses(hostname, addresses) {
    const now = Date.now();
    for (const [host, entry] of dnsPins) {
        if (entry.expiresAt <= now) dnsPins.delete(host);
    }
    // Re-inserting rather than updating in place keeps insertion order equal to
    // recency, so the eviction below drops the least recently vetted host.
    dnsPins.delete(hostname);
    while (dnsPins.size >= DNS_PIN_MAX_HOSTS) {
        dnsPins.delete(dnsPins.keys().next().value);
    }
    dnsPins.set(hostname, {
        addresses: addresses.map(({ address, family }) => ({ address, family: family || net.isIP(address) })),
        expiresAt: now + DNS_PIN_TTL_MS
    });
}

function pinnedLookupError(hostname) {
    return Object.assign(new Error(`No vetted address pinned for ${hostname}`), {
        code: 'ENOTFOUND',
        hostname
    });
}

// Fails closed. An unpinned hostname means the connector is resolving something
// assertSafeOutboundUrl never approved, which is exactly the case this exists
// to stop — falling back to a real lookup here would reopen the race.
function pinnedLookup(hostname, options, callback) {
    const entry = dnsPins.get(hostname);
    if (!entry || entry.expiresAt <= Date.now()) {
        return callback(pinnedLookupError(hostname));
    }

    const wanted = options?.family;
    const matches = (wanted === 4 || wanted === 6)
        ? entry.addresses.filter((a) => a.family === wanted)
        : entry.addresses;
    if (!matches.length) return callback(pinnedLookupError(hostname));

    // Node asks for every address when happy-eyeballs is on, one otherwise.
    if (options?.all) return callback(null, matches.map(({ address, family }) => ({ address, family })));
    return callback(null, matches[0].address, matches[0].family);
}

// One agent for the process. Pooling is safe because every pinned address has
// already passed the private-address check, so a reused connection is no less
// vetted than a fresh one. Null when ALLOW_PRIVATE_NETWORKS is set: the check
// is off, so there is nothing to pin against.
const PINNED_DISPATCHER = ALLOW_PRIVATE_NETWORKS
    ? null
    : new UndiciAgent({ connect: { lookup: pinnedLookup } });

// The pinned dispatcher comes from the undici dependency while fetch() comes from the
// undici Node bundles, so the two can differ, and not every pairing works. Measured
// with this app's own pattern — a custom connect.lookup, a redirect, a streamed body
// and an abort — dispatchers from undici 6 and 7 work with the fetch bundled in Node
// 20.18.1 (undici 6.20), 22 (6.28) and 24 (7.25), in both directions, and the full
// suite passes on all three. An undici 8 dispatcher fails every request against the
// fetch in Node 22 and 24 with "invalid onRequestStart method", its handler interface
// having changed, and does not load on Node 20 at all.
// This used to compare majors and warn on any difference, so on the documented Node
// 20.18.1 floor it told the operator that every outbound request would fail, where
// every one succeeds (audit D2). It now warns only for a pairing outside the measured
// set, and says the pairing is unverified rather than broken, since only the undici 8
// direction has actually been seen to fail. The versions are parameters so the rule
// can be tested without the runtime that would exercise each branch.
const UNDICI_INTEROPERABLE_MAJORS = new Set(['6', '7']);

function warnOnUndiciMismatch(log = console, {
    pinned = Boolean(PINNED_DISPATCHER),
    bundled = process.versions.undici,
    dependency = require('undici/package.json').version
} = {}) {
    if (!pinned) return true;
    const bundledMajor = String(bundled || '').split('.')[0];
    const dependencyMajor = String(dependency || '').split('.')[0];
    if (!bundledMajor || bundledMajor === dependencyMajor) return true;
    if (UNDICI_INTEROPERABLE_MAJORS.has(bundledMajor) && UNDICI_INTEROPERABLE_MAJORS.has(dependencyMajor)) return true;
    log.warn(
        `Node bundles undici ${bundled} but this app's connection agent comes from undici ${dependency}. ` +
        'That pairing has not been verified and outbound requests may fail — an undici 8 agent used with an ' +
        'older fetch fails every request with "invalid onRequestStart method". Align the undici dependency ' +
        'with the runtime.'
    );
    return false;
}

// A refusal by policy — this scheme or address is never allowed — as opposed to a
// lookup that failed and may succeed next time. vetHlsOrigin remembers the first
// kind and retries the second.
function blockedOutbound(message) {
    return Object.assign(new Error(message), { code: 'OUTBOUND_BLOCKED' });
}

// DNS resolution for the SSRF check, with a deadline (audit S6). dns.lookup runs
// getaddrinfo on libuv's thread pool — four threads by default, uncancellable, and
// deaf to the fetch's abort signal — so a panel on a domain whose nameserver never
// answers held a pool thread for the resolver's whole timeout. Four such lookups,
// two per /configure attempt, and every proxied range request on the instance
// queued behind them: one caller's dead domain stalled everyone's playback.
// c-ares (dns.Resolver) runs off the pool and can be cancelled, and each lookup
// gets a resolver of its own, so cancelling one abandons nothing else. It does not
// read /etc/hosts, which is why localhost names are refused by name in
// assertSafeOutboundUrl rather than left to fail as unresolvable.
const DNS_TIMEOUT_MS = Math.max(500, Number(process.env.DNS_TIMEOUT_MS) || 5000);

async function resolveHostAddresses(hostname, {
    timeoutMs = DNS_TIMEOUT_MS,
    makeResolver = () => new dns.Resolver({ timeout: timeoutMs, tries: 2 })
} = {}) {
    const resolver = makeResolver();
    let timer;
    const deadline = new Promise((_, reject) => {
        timer = setTimeout(() => {
            try { resolver.cancel(); } catch {}
            reject(Object.assign(
                new Error(`DNS lookup for ${hostname} timed out after ${timeoutMs}ms`),
                { code: 'ETIMEOUT', hostname }
            ));
        }, timeoutMs);
    });
    // allSettled attaches a handler to both, so the one still pending when the
    // deadline wins cannot surface later as an unhandled rejection.
    const families = Promise.allSettled([
        resolver.resolve4(hostname).then(list => list.map(address => ({ address, family: 4 }))),
        resolver.resolve6(hostname).then(list => list.map(address => ({ address, family: 6 })))
    ]);
    try {
        const results = await Promise.race([families, deadline]);
        const addresses = results.flatMap(r => (r.status === 'fulfilled' ? r.value : []));
        if (addresses.length) return addresses;
        // Neither family answered. A host with no record of one family (ENODATA) is
        // ordinary, so the other family's error is the one that says why.
        const errors = results.map(r => r.reason).filter(Boolean);
        throw errors.find(e => e.code !== 'ENODATA') || errors[0]
            || Object.assign(new Error(`No addresses for ${hostname}`), { code: 'ENOTFOUND', hostname });
    } finally {
        clearTimeout(timer);
    }
}

async function assertSafeOutboundUrl(inputUrl, { resolve = resolveHostAddresses } = {}) {
    const url = new URL(inputUrl);
    if (!['http:', 'https:'].includes(url.protocol)) {
        throw blockedOutbound(`Blocked unsupported outbound protocol: ${url.protocol}`);
    }
    if (ALLOW_PRIVATE_NETWORKS) return url;

    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    // RFC 6761 reserves these names for loopback. The resolver above would not answer
    // for them at all, so without this they would fail as unresolvable instead of
    // being refused as what they are.
    if (/(^|\.)localhost\.?$/i.test(hostname)) {
        throw blockedOutbound(`Blocked private outbound address for ${hostname}`);
    }
    const directIp = net.isIP(hostname) ? [{ address: hostname }] : null;
    // A host vetted within the pin window is not resolved again (audit P4). Every
    // range request of a movie used to pay a fresh lookup for addresses the connector
    // was going to be held to anyway, and that reuse is what keeps the resolver off
    // the hot path S6 is about. Only vetted addresses are ever pinned, so nothing is
    // skipped but the lookup. Reuse does not extend the pin: its expiry still says
    // when the addresses were last actually looked up.
    const pinned = directIp ? null : dnsPins.get(hostname);
    if (pinned && pinned.expiresAt > Date.now()) return url;
    const addresses = directIp || await resolve(hostname);
    if (!addresses.length) throw new Error(`Could not resolve outbound host: ${hostname}`);

    for (const { address } of addresses) {
        if (isPrivateIp(address)) {
            throw blockedOutbound(`Blocked private outbound address for ${hostname}`);
        }
    }
    // A literal address needs no pin: the connector recognises it and never
    // calls lookup, so there is no second resolution to disagree with.
    if (!directIp) pinResolvedAddresses(hostname, addresses);
    return url;
}

// A response whose body is never read still owns a connection: undici keeps it
// out of the pool until the body is consumed or cancelled, so dropping one on
// the floor holds a socket until GC gets round to it. Every path that abandons
// a response goes through here. A body with a reader already attached is
// locked and cannot be cancelled — those paths abort the request instead, which
// tears the connection down rather than trying to return it to the pool.
function discardBody(res) {
    try {
        const body = res?.body;
        if (body && !body.locked) body.cancel().catch(() => {});
    } catch {}
}

// `onFinalUrl` reports the URL that actually produced the returned response,
// after any redirects. HLS playlists carry relative URIs that must be resolved
// against *that* URL, not the one we asked for — a provider's /live/... request
// typically lands on a CDN path several segments deep, so resolving against the
// original would point every segment at the wrong host. Response.url is not
// relied on here because redirects are followed manually, one fetch each.
async function safeFetch(inputUrl, options = {}, { maxRedirects = 3, onFinalUrl } = {}) {
    let url = await assertSafeOutboundUrl(inputUrl);
    for (let redirects = 0; redirects <= maxRedirects; redirects++) {
        // The dispatcher is what makes the check above binding: assertSafeOutboundUrl
        // pins the addresses it approved, and this connects to those and nothing
        // else. Every redirect hop re-checks and re-pins before its own fetch.
        const res = await fetch(url, {
            ...options,
            redirect: 'manual',
            ...(PINNED_DISPATCHER ? { dispatcher: PINNED_DISPATCHER } : {})
        });
        if (![301, 302, 303, 307, 308].includes(res.status)) {
            onFinalUrl?.(url.toString());
            return res;
        }

        const location = res.headers.get('location');
        if (!location) {
            onFinalUrl?.(url.toString());
            return res;
        }
        // The redirect's own body is never read, and every proxy request traverses
        // at least one 302, so this is the hot path for leaked connections. The
        // audit expected undici to hold that connection until GC; measured, it
        // does not — the abandoned
        // socket closed in under 10 ms with and without this call, because a
        // half-read response cannot be returned to the pool anyway. Kept as
        // explicit hygiene rather than as a fix for a leak that reproduces: it
        // states the intent at the point of abandonment instead of depending on
        // that undici behaviour continuing to hold.
        discardBody(res);
        if (redirects === maxRedirects) throw new Error('Too many redirects');

        url = await assertSafeOutboundUrl(new URL(location, url).toString());
    }
    throw new Error('Too many redirects');
}

// The upstream host is supplied by the user and reachable before any
// authentication, so an unbounded res.json() lets a hostile or broken provider
// stream until the process runs out of memory. Large providers legitimately
// return tens of MB for get_vod_streams, so the cap is generous but finite.
const MAX_UPSTREAM_BYTES = Math.max(1, Number(process.env.MAX_UPSTREAM_MB) || 64) * 1024 * 1024;

// What a JSON body will cost once parsed, estimated from its bytes as they
// arrive. The byte count alone is the wrong measure, because the parsed graph
// depends on the body's *shape*, and a hostile shape inflates by more than twenty
// times. Measured on Node 24 with 16 MB bodies, heap retained after GC:
//
//   realistic get_vod_streams     18 MB  (1.1x)      [{},{},…]    341 MB  (21x)
//   realistic get_series_info     20 MB  (1.2x)      [[],[],…]    213 MB  (13x)
//
// Nearly all of that difference is per-value overhead, and the structural bytes
// expose it: every object opens with `{`, every array with `[`, and every further
// member or element is preceded by `,`. So those three bytes are weighed by what
// the value behind them costs — an empty object 56 bytes, an array 32, a slot 8 —
// plus half a byte per body byte for string payload. Across eleven shapes the
// estimate lands within 0.78x-1.27x of measured heap for every realistic body,
// and at or above it for every hostile one (1.02x for [{},{},…]). The one shape
// it under-counts is a single long string, by half, which is harmless: that
// string costs about the body itself, and the byte cap already bounds the body.
// The three bytes are counted wherever they appear, inside strings too. A comma
// in a plot adds eight bytes that are not really there, and over-counting is the
// safe side to be wrong on — the alternative is a string-aware scanner running on
// every byte of every list.
const PARSED_WEIGHT = new Uint8Array(256);
PARSED_WEIGHT[0x7b] = 56; // {
PARSED_WEIGHT[0x5b] = 32; // [
PARSED_WEIGHT[0x2c] = 8;  // ,

// How large a body may be *estimated* to parse to, relative to its own byte cap.
// Every realistic body measured estimates at 1.0-1.3x its size, so it reaches the
// byte cap long before this one. A hostile [{},{},…] body estimates at ~22x, so
// it is refused after ~6 MB of a 64 MB allowance — mid-download, and before
// JSON.parse has built any of it. That puts the graph a single response can
// produce at about 128 MB at the defaults; the same body shape used to reach
// ~1.4 GB (341 MB measured at 16 MB, scaled to MAX_UPSTREAM_MB).
const MAX_PARSED_TO_BODY_RATIO = 2;

// The estimate each parsed payload arrived with, so the caches can weigh it from
// every byte of its body rather than from a sample. Keyed by the parsed value, so
// an entry lives exactly as long as the value does.
const parsedSizeEstimates = new WeakMap();

// `onChunk` is called once per chunk read, which is how xtremioGet's idle deadline
// knows the download is still moving.
async function readJsonCapped(res, label, maxBytes = MAX_UPSTREAM_BYTES, { onChunk = null } = {}) {
    // Trust a declared length to reject early, before reading a single byte.
    const declared = Number(res.headers?.get?.('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
        throw new Error(`${label} response too large: ${declared} bytes exceeds ${maxBytes}`);
    }
    // A stub or a body-less response has nothing to meter; fall back.
    if (!res.body || typeof res.body.getReader !== 'function') return res.json();

    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    let structural = 0;
    const maxParsedBytes = maxBytes * MAX_PARSED_TO_BODY_RATIO;
    // The count costs a few milliseconds per megabyte, and it does not spread
    // itself across the download. When a fast upstream has already buffered the
    // body, read() resolves chunk after chunk as microtasks without ever returning
    // to the event loop, so the whole count ran as one block and merged with the
    // parse that follows it: on a 25 MB list the longest event-loop stall grew from
    // 179 ms to 247 ms, on the thread that relays every video. Handing the loop
    // back once per counted megabyte keeps each slice of that work to a few
    // milliseconds, at the cost of one setImmediate hop per megabyte. Measured
    // with it, the same list's longest stall is 128 ms, against 131 ms before the
    // count existed; the count still adds ~80 ms of total time, just not in one go.
    const YIELD_EVERY_BYTES = 1024 * 1024;
    let nextYieldAt = YIELD_EVERY_BYTES;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
            // Stop pulling from the socket rather than finishing the download.
            await reader.cancel().catch(() => {});
            throw new Error(`${label} response exceeded ${maxBytes} bytes`);
        }
        // Checked per chunk, like the byte cap, so a hostile body is refused before
        // the rest of it arrives rather than after JSON.parse has inflated it.
        for (let i = 0; i < value.length; i++) structural += PARSED_WEIGHT[value[i]];
        if (structural + total / 2 > maxParsedBytes) {
            await reader.cancel().catch(() => {});
            throw new Error(
                `${label} response is shaped to parse to more than ${Math.round(maxParsedBytes / 1048576)} MB ` +
                `after ${total} bytes; refusing it before parsing`
            );
        }
        chunks.push(Buffer.from(value));
        if (onChunk) onChunk();
        if (total >= nextYieldAt) {
            nextYieldAt = total + YIELD_EVERY_BYTES;
            await new Promise((resolve) => setImmediate(resolve));
        }
    }
    // Written as four statements rather than one expression because each step
    // allocates a full copy of the body and the references are what decide how
    // many of them are alive at once. `Buffer.concat(chunks).toString()` handed
    // straight to the parser keeps `chunks` reachable through the concat *and* the
    // stringify, and the buffer through the parse, so three copies of the body are
    // alive while the parser builds the object graph — measured on a 21 MB body,
    // ~3× the body. Dropping each reference as soon as the next copy exists holds
    // that to one: the string, alongside the graph (~1×). One copy plus the parsed
    // graph is the floor for a non-incremental parser; this only stops paying for
    // the copies already spent.
    let buf = Buffer.concat(chunks);
    chunks.length = 0;
    const text = buf.toString('utf8');
    buf = null;
    const data = JSON.parse(text);
    if (data !== null && typeof data === 'object') parsedSizeEstimates.set(data, structural + total / 2);
    return data;
}

// Three deadlines for one upstream call, because they bound three different failures
// (audit R5). A single 15 s timeout used to cover the whole download, so a 25 MB list
// from a panel slower than ~1.7 MB/s could never finish, and every retry started over
// from nothing. Headers get a short deadline. The body gets an idle deadline that
// every chunk resets, so a slow download that keeps moving completes. And the whole
// call gets an overall deadline, since without one a panel sending a byte just inside
// the idle window could hold the request open for as long as it liked.
const UPSTREAM_HEADER_TIMEOUT_MS = Math.max(100, Number(process.env.UPSTREAM_HEADER_TIMEOUT_MS) || 15000);
const UPSTREAM_IDLE_TIMEOUT_MS = Math.max(100, Number(process.env.UPSTREAM_IDLE_TIMEOUT_MS) || 15000);
const UPSTREAM_BODY_TIMEOUT_MS = Math.max(100, Number(process.env.UPSTREAM_BODY_TIMEOUT_MS) || 5 * 60 * 1000);

async function xtremioGet(cfg, action, params = {}, { timeoutMs = UPSTREAM_HEADER_TIMEOUT_MS } = {}) {
    const url = buildXtremioApiUrl(cfg, action, params);
    const controller = new AbortController();
    let expired = null;
    const expire = (waitingFor, ms) => setTimeout(() => {
        expired = { waitingFor, ms };
        controller.abort();
    }, ms);
    let phaseTimer = expire('headers', timeoutMs);
    const overallTimer = expire('the whole response', UPSTREAM_BODY_TIMEOUT_MS);
    try {
        const res = await safeFetch(url, { signal: controller.signal });
        clearTimeout(phaseTimer);
        if (!res.ok) throw new Error(`xtremio ${action} failed: HTTP ${res.status}`);
        const resetIdle = () => {
            clearTimeout(phaseTimer);
            phaseTimer = expire('the next chunk', UPSTREAM_IDLE_TIMEOUT_MS);
        };
        resetIdle();
        const data = await readJsonCapped(res, `xtremio ${action}`, MAX_UPSTREAM_BYTES, { onChunk: resetIdle });

        console.log(`[xtremioGet] ${action} (${Array.isArray(data) ? data.length : '?'} items)`);

        return data;
    } catch (e) {
        // Name the deadline that fired: "aborted" alone does not tell a stalled panel
        // from a slow one, and the fix for each is a different setting.
        if (expired) {
            throw new Error(`xtremio ${action} timed out waiting for ${expired.waitingFor} after ${expired.ms} ms`, { cause: e });
        }
        throw e;
    } finally {
        clearTimeout(phaseTimer);
        clearTimeout(overallTimer);
    }
}

function toIsoDate(s) {
    if (!s) return undefined;
    const d = new Date(s);
    return isNaN(d.getTime()) ? undefined : d.toISOString();
}

// A provider's title is not reliably a string. Panels that encode with PHP's
// JSON_NUMERIC_CHECK send titles like 1917 and 300 as JSON *numbers*, and one of
// those threw out of filterByName ('s.name.toLowerCase is not a function') —
// which the catalog route's catch turned into an empty result for every search
// on that account, not just the one title. Titles also reach Stremio, where the
// SDK expects a string.
// Only strings and numbers count: a provider that put an object or an array
// there has sent no title at all, and "[object Object]" on a shelf is worse than
// the fallback every caller already has.
function titleOf(value) {
    if (typeof value === 'string') return value;
    return typeof value === 'number' && Number.isFinite(value) ? String(value) : '';
}

// Xtream providers return `cast`/`genre` as either a comma-separated string or an array.
function splitList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value.map(v => String(v).trim()).filter(Boolean);
    return String(value).split(',').map(v => v.trim()).filter(Boolean);
}

// `backdrop_path` can be an array of URLs or a single URL string.
function pickBackdrop(value) {
    if (!value) return undefined;
    if (Array.isArray(value)) return value[0] || undefined;
    return String(value) || undefined;
}

// All in-memory caches share the same TTL.
const CACHE_TTL = 30 * 60 * 1000;

// A category fetch that partly or wholly failed must not be held for the full
// TTL: one transient upstream blip would otherwise leave the user with empty
// catalogs and an empty genre list for 30 minutes, with no way to force a
// refresh. Retry those soon instead.
const CACHE_FAILURE_TTL = 60 * 1000;

// Keys must include credentials so two users on the same Xtream host don't
// share cached catalogs/streams (different accounts can see different content).
function accountCacheKey(cfg) {
    return `${cfg.serverUrl}\n${cfg.username}\n${cfg.password}`;
}

// One memory budget shared by every data cache (CACHE_MAX_MB). Each cache is also
// bounded on its own, but those bounds were set independently and only ever added
// up in prose — and four of them counted entries alone, so the sum was not a bound
// at all: a hundred per-category lists at 7 MB each is 700 MB inside
// CACHE_MAX_CATEGORY_LISTS, and an instance serving a few large providers could
// reach 1-1.5 GB inside every configured limit (audit R2). This is the number a
// container is actually sized by.
//
// It is least-recently-used across all the caches, in one order. A read in any of
// them moves that entry to the recent end, and when the total is over, the oldest
// entry anywhere goes first — which can be a stream list evicted to admit a series
// payload, because the series payload was used more recently. Entries are tracked
// by the entry object rather than by key, so two caches that happen to share a key
// string cannot collide here, and each remembers the weight it was added with, so
// the total cannot drift if an entry is mutated in place.
class CacheBudget {
    constructor(maxBytes) {
        this.maxBytes = maxBytes;
        this.totalBytes = 0;
        this.order = new Map(); // entry -> { owner, key, bytes }
    }

    add(entry, owner, key) {
        const bytes = weightOf(entry);
        this.order.set(entry, { owner, key, bytes });
        this.totalBytes += bytes;
    }

    touch(entry) {
        const ref = this.order.get(entry);
        if (!ref) return;
        this.order.delete(entry);
        this.order.set(entry, ref);
    }

    remove(entry) {
        const ref = this.order.get(entry);
        if (!ref) return;
        this.order.delete(entry);
        this.totalBytes -= ref.bytes;
    }

    // Evicts oldest-first until the total fits, never the entry just written.
    // Eviction goes through the owning cache, so its own total and its onEvict
    // report stay right; the size check afterwards is what guarantees the loop
    // ends even if an owner were ever to fail to release its entry.
    enforce(keep) {
        while (this.totalBytes > this.maxBytes) {
            let victim = null;
            for (const [entry, ref] of this.order) {
                if (entry !== keep) {
                    victim = ref;
                    break;
                }
            }
            if (!victim) break;
            const before = this.order.size;
            victim.owner.evict(victim.key, 'global budget');
            if (this.order.size === before) break;
        }
    }
}

// Every cache below was previously an unbounded Map whose TTL was only checked
// on read, so nothing was ever deleted: memory grew with every distinct account
// and every series ever opened, and never shrank when users went away.
//
// Extending Map keeps the whole existing surface (`get`/`set`/`size`/iteration)
// working unchanged. Map iterates in insertion order, so re-inserting an entry
// when it is read makes the *first* key the least recently used one — which is
// the one to drop when the cache is full.
class BoundedMap extends Map {
    // `maxBytes` weighs entries by their `bytes` field as well as counting them,
    // because entry count is a poor proxy for memory when one entry is a parsed
    // 25 MB catalog and another is a few KB of categories. `onEvict` reports
    // what was dropped and why, which is how the stream caches notice they are
    // thrashing rather than caching.
    // `ledger`, when given, is the CacheBudget this map's entries are charged to as
    // well; every production data cache passes CACHE_BUDGET. Opt-in, so a map made
    // for a test is not quietly competing with the real caches for their budget.
    constructor({ maxEntries, maxAgeMs = null, maxBytes = null, onEvict = null, ledger = null }) {
        super();
        this.maxEntries = maxEntries;
        this.maxAgeMs = maxAgeMs;
        this.maxBytes = maxBytes;
        this.onEvict = onEvict;
        this.ledger = ledger;
        this.totalBytes = 0;
    }

    get(key) {
        const entry = super.get(key);
        if (entry === undefined) return undefined;
        // Touch: delete + re-insert moves this key to the most-recent end.
        super.delete(key);
        super.set(key, entry);
        if (this.ledger) this.ledger.touch(entry);
        return entry;
    }

    // Read without disturbing LRU order. Nothing in the request path uses this —
    // it exists so tests can assert what a cache holds without the assertion
    // itself promoting the entry and changing what is evicted next. Kept
    // deliberately rather than deleted: the alternative is tests that cannot
    // observe eviction order without perturbing it.
    peek(key) {
        return super.get(key);
    }

    set(key, value) {
        // An entry the shared budget could never hold is not stored at all. The
        // rule below keeps a single entry over *this* map's budget rather than
        // refetch it on every request, and that is right for a per-cache bound. On
        // the shared one it would evict every other cache's entries — every other
        // account's data — for an entry that still did not fit, and then keep it.
        // What it would have replaced goes too: that was the caller's intent.
        if (this.ledger && weightOf(value) > this.ledger.maxBytes) {
            this.delete(key);
            console.warn(
                `[cache] not caching a ${Math.round(weightOf(value) / 1048576)} MB entry: larger than the ` +
                `whole CACHE_MAX_MB budget (${Math.round(this.ledger.maxBytes / 1048576)} MB). It will be ` +
                'fetched again on every request; raise CACHE_MAX_MB if a real provider sends lists this large'
            );
            return this;
        }

        const replaced = super.get(key);
        if (replaced) {
            this.totalBytes -= weightOf(replaced);
            if (this.ledger) this.ledger.remove(replaced);
        }
        super.delete(key);
        super.set(key, value);
        this.totalBytes += weightOf(value);
        if (this.ledger) this.ledger.add(value, this, key);

        // Never evict what was just written, even when a single entry is larger
        // than the whole budget: refusing to cache it at all would mean
        // refetching it on every request, which is worse than being over.
        while (this.size > 1 && (this.size > this.maxEntries || this.overBudget())) {
            // Map keys iterate oldest-first; the first is the LRU victim.
            const oldest = this.keys().next();
            if (oldest.done || oldest.value === key) break;
            this.evict(oldest.value, this.size > this.maxEntries ? 'entry count' : 'byte budget');
        }
        if (this.ledger) this.ledger.enforce(value);
        return this;
    }

    overBudget() {
        return this.maxBytes !== null && this.totalBytes > this.maxBytes;
    }

    evict(key, reason) {
        const entry = super.get(key);
        super.delete(key);
        this.totalBytes -= weightOf(entry);
        if (this.ledger) this.ledger.remove(entry);
        if (this.onEvict) this.onEvict(key, entry, reason);
        return entry;
    }

    delete(key) {
        if (super.has(key)) {
            const entry = super.get(key);
            this.totalBytes -= weightOf(entry);
            if (this.ledger) this.ledger.remove(entry);
        }
        return super.delete(key);
    }

    // Releases only this map's share of a shared budget, not the whole of it.
    clear() {
        if (this.ledger) for (const entry of super.values()) this.ledger.remove(entry);
        this.totalBytes = 0;
        return super.clear();
    }

    // Drops entries past maxAgeMs. Caches whose expired entries are still
    // useful (see catCache) pass a deliberately generous age, or none at all.
    sweep(now = Date.now()) {
        if (!this.maxAgeMs) return 0;
        let dropped = 0;
        for (const [key, entry] of this) {
            if (entry && typeof entry.ts === 'number' && entry.ts <= now - this.maxAgeMs) {
                super.delete(key);
                this.totalBytes -= weightOf(entry);
                if (this.ledger) this.ledger.remove(entry);
                dropped++;
            }
        }
        return dropped;
    }
}

function weightOf(entry) {
    return typeof entry?.bytes === 'number' ? entry.bytes : 0;
}

// What a cached value costs in memory — the parsed graph, not its serialized text.
// It used to be the serialized length, which is what let a hostile list through:
// `{}` serializes to two bytes and occupies 56, so a [{},{},…] list was weighed at
// a twentieth of its real size, fitted the stream budget, and was kept for half
// an hour. The weights are readJsonCapped's; see PARSED_WEIGHT.
function estimateBytes(value) {
    // A payload read from upstream was weighed from every byte of its body as it
    // arrived, which no sample can match — and a sample can be steered, because
    // its positions follow from the list's length alone.
    if (value !== null && typeof value === 'object') {
        const measured = parsedSizeEstimates.get(value);
        if (measured !== undefined) return Math.round(measured);
    }

    // Everything else is sampled rather than serialized whole: JSON.stringify over
    // a 25 MB list allocates a second 25 MB string to learn what twenty items
    // already say, and doubling peak memory to police memory would be
    // self-defeating.
    if (!Array.isArray(value)) {
        try {
            return Math.round(weighJson(JSON.stringify(value)));
        } catch {
            return 0;
        }
    }
    if (!value.length) return 0;

    const step = Math.max(1, Math.floor(value.length / 20));
    let sampled = 0;
    let counted = 0;
    for (let i = 0; i < value.length; i += step) {
        try {
            sampled += weighJson(JSON.stringify(value[i]));
        } catch {
            // A circular or unserializable item tells us nothing; skip it.
        }
        counted++;
    }
    if (!counted) return 0;
    // Plus the list's own slots, which no item's JSON includes — the separating
    // commas the streamed estimate counts. Without them the two paths disagree by
    // a sixth on exactly the list this exists to catch: [{},{},…], at 57 bytes an
    // item sampled against 65 streamed.
    return Math.round((sampled / counted) * value.length + PARSED_WEIGHT[0x2c] * value.length);
}

// The streaming estimate, applied to text already in hand.
function weighJson(text) {
    if (typeof text !== 'string') return 0;
    let structural = 0;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (c < 256) structural += PARSED_WEIGHT[c];
    }
    return structural + text.length / 2;
}

// Category lists are small (a few KB per account), so the bound here is about
// account count, not bytes.
const CACHE_MAX_ACCOUNTS = Math.max(1, Number(process.env.CACHE_MAX_ACCOUNTS) || 100);

// How many accounts' full stream lists to hold, per kind. This used to be the bound
// that capped memory, at 4 — and it was a churn cliff (audit R3): a fifth active
// account evicted a list that fitted the budget comfortably, and refetching it meant
// parsing tens of MB again on the thread that relays every video. Memory is bounded
// in bytes now (CACHE_MAX_STREAM_BYTES per kind, CACHE_MAX_BYTES across every cache),
// so this only has to stop many tiny entries accumulating, and the byte budgets
// decide what is evicted. Parsing in a worker thread was measured as the other way
// out and is worse: a 20.7 MB list blocked the main thread 81-94 ms in JSON.parse,
// and 111-153 ms when parsed in a worker, because the parsed graph comes back by
// structured clone and deserializing it runs on the main thread anyway.
const CACHE_MAX_STREAM_ACCOUNTS = Math.max(1, Number(process.env.CACHE_MAX_STREAM_ACCOUNTS) || 64);

// Counting entries is not the same as bounding memory: four accounts' worth of
// entries could be four megabytes or four hundred, and only the second one
// matters. This is a budget *per kind*, so the ceiling across live, movies and
// series is three times it, and it is measured in estimated heap — what an entry
// occupies once parsed (see estimateBytes). It was measured in serialized JSON,
// with resident cost said to run 3-10× that. Measured, a realistic list occupies
// 1.1-1.4× its text and a hostile one 21×: no single multiplier describes both,
// which is why the unit changed rather than the multiplier.
const CACHE_MAX_STREAM_BYTES = Math.max(1, Number(process.env.CACHE_MAX_STREAM_MB) || 64) * 1024 * 1024;

// One entry per series *per account* — the only dimension that grows without
// bound for a single user just browsing.
const CACHE_MAX_SERIES_INFO = Math.max(1, Number(process.env.CACHE_MAX_SERIES_INFO) || 500);

// Same dimension for movies. A vod_info payload is a single item's metadata —
// kilobytes, not megabytes — so this bound is about entry count, not size.
const CACHE_MAX_VOD_INFO = Math.max(1, Number(process.env.CACHE_MAX_VOD_INFO) || 500);

// Per-category stream lists: one entry per category per account, and the count
// grows with every genre a user opens. Each is a slice of the full list — usually
// small, but a 20k-title category is ~7 MB, and a hundred of those is what
// CACHE_MAX_MB below exists to stop.
const CACHE_MAX_CATEGORY_LISTS = Math.max(1, Number(process.env.CACHE_MAX_CATEGORY_LISTS) || 100);

// The shared ceiling across every data cache; see CacheBudget. 256 MB is about what
// the per-cache bounds were meant to add up to — three 64 MB stream budgets, plus
// room for the small caches — so a deployment that sat inside them before rarely
// meets this one, and one that did not is now held to it.
const CACHE_MAX_BYTES = Math.max(1, Number(process.env.CACHE_MAX_MB) || 256) * 1024 * 1024;
const CACHE_BUDGET = new CacheBudget(CACHE_MAX_BYTES);

// getCategories intentionally serves expired categories when a refresh fails
// (stale beats empty — see CACHE_FAILURE_TTL), so age-sweeping catCache on the
// normal TTL would destroy that fallback. This hard age only reclaims accounts
// that have genuinely stopped being used.
const CACHE_STALE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

const catCache = new BoundedMap({
    maxEntries: CACHE_MAX_ACCOUNTS,
    maxAgeMs: CACHE_STALE_MAX_AGE_MS,
    ledger: CACHE_BUDGET
});

const categoriesSingleFlight = createSingleFlight();

function getCategories(cfg) {
    const key = accountCacheKey(cfg);
    // Kept even once expired: stale categories beat empty ones if a refresh fails.
    const cached = catCache.get(key);
    if (cached && cached.ts > Date.now() - cached.ttl) return Promise.resolve(cached);
    return categoriesSingleFlight(key, () => refreshCategories(cfg, key));
}

async function refreshCategories(cfg, key) {
    const cached = catCache.get(key);
    // A concurrent flight may have refreshed it while we queued.
    if (cached && cached.ts > Date.now() - cached.ttl) return cached;

    const results = await Promise.allSettled([
        xtremioGet(cfg, 'get_live_categories'),
        xtremioGet(cfg, 'get_vod_categories'),
        xtremioGet(cfg, 'get_series_categories')
    ]);
    const pick = (r, stale) => (r.status === 'fulfilled' && Array.isArray(r.value)) ? r.value : (stale || []);
    results.forEach((r, i) => {
        if (r.status === 'rejected') {
            console.error(`[getCategories] source ${i} failed:`, r.reason?.message || r.reason);
        }
    });

    const failed = results.some(r => r.status !== 'fulfilled' || !Array.isArray(r.value));
    const entry = {
        live: pick(results[0], cached?.live),
        movies: pick(results[1], cached?.movies),
        series: pick(results[2], cached?.series),
        ts: Date.now(),
        ttl: failed ? CACHE_FAILURE_TTL : CACHE_TTL
    };
    // Weighed by its three lists. A failed refresh reuses the stale arrays, but the
    // entry it writes replaces the one that held them, so they are never counted
    // twice.
    entry.bytes = estimateBytes(entry.live) + estimateBytes(entry.movies) + estimateBytes(entry.series);
    if (failed) {
        console.warn(`[getCategories] partial or total failure; serving ${cached ? 'stale' : 'empty'} data, retrying in ${CACHE_FAILURE_TTL / 1000}s`);
    }
    catCache.set(key, entry);
    return entry;
}

// Deduplicates concurrent misses for the same key. Stremio opens many catalog
// requests in parallel on install, and without this each one fires its own
// multi-megabyte upstream fetch for a list the others are already loading.
function createSingleFlight() {
    const pending = new Map();
    return function singleFlight(key, fn) {
        const existing = pending.get(key);
        if (existing) return existing;
        // Errors are not cached: the entry is dropped either way, so the next
        // caller retries rather than inheriting a stale rejection.
        const promise = Promise.resolve().then(fn).finally(() => pending.delete(key));
        pending.set(key, promise);
        return promise;
    };
}

// Stream list caches - populated on first fetch, reused for catalogs, search and meta
function createStreamListCache() {
    // Expired entries here are never served as a fallback (`get` returns null
    // once past the TTL), so they can be swept on the normal TTL — and these
    // are by far the largest entries, so reclaiming them matters most.
    const map = new BoundedMap({
        maxEntries: CACHE_MAX_STREAM_ACCOUNTS,
        maxAgeMs: CACHE_TTL,
        maxBytes: CACHE_MAX_STREAM_BYTES,
        ledger: CACHE_BUDGET,
        // Evicting an entry that has not expired means the bounds are too tight
        // for the load: that account's next request refetches 10-50 MB, and
        // nothing else would say so. An expired entry leaving is routine and
        // silent. The advice names the bound that actually did it — raising the
        // per-kind budget does nothing when the shared one is the tight one.
        onEvict(key, entry, reason) {
            if (entry && entry.ts > Date.now() - CACHE_TTL) {
                const knob = reason === 'global budget'
                    ? 'CACHE_MAX_MB'
                    : 'CACHE_MAX_STREAM_ACCOUNTS or CACHE_MAX_STREAM_MB';
                console.warn(
                    `[cache] evicted a live stream list on ${reason} ` +
                    `(${Math.round((entry.bytes || 0) / 1024 / 1024)} MB); ` +
                    `raise ${knob} if this repeats`
                );
            }
        }
    });
    const singleFlight = createSingleFlight();
    return {
        map,
        get(cfg) {
            const cached = map.get(accountCacheKey(cfg));
            // Per-entry ttl: a stale entry being served through an outage carries
            // a short one, so it is retried in a minute rather than in half an hour.
            if (cached && cached.ts > Date.now() - (cached.ttl || CACHE_TTL)) return cached.data;
            return null;
        },
        set(cfg, items) {
            // An empty list is a legitimate answer, but a real provider also returns
            // one transiently. Held for the full TTL it left search empty for half an
            // hour after one bad answer; held for CACHE_FAILURE_TTL it is still a hit
            // for the burst of requests that arrive together, and is asked again a
            // minute later.
            map.set(accountCacheKey(cfg), {
                data: items,
                ts: Date.now(),
                ttl: items.length ? CACHE_TTL : CACHE_FAILURE_TTL,
                bytes: estimateBytes(items)
            });
        },
        // Cache-aside read: serves a warm entry, otherwise runs `fetcher` once
        // no matter how many callers arrive while it is in flight.
        load(cfg, fetcher) {
            const cached = this.get(cfg);
            if (cached) return Promise.resolve(cached);
            const key = accountCacheKey(cfg);
            return singleFlight(key, async () => {
                // Re-check: a concurrent flight may have populated it already.
                const warm = this.get(cfg);
                if (warm) return warm;
                try {
                    const items = await fetcher();
                    this.set(cfg, items);
                    return items;
                } catch (e) {
                    // A list we already have beats no list at all — the caller's
                    // only other answer is an empty shelf. `ts` is deliberately
                    // *not* re-stamped: the entry keeps its true age, so the
                    // ordinary age sweep still reclaims it and stale data is
                    // served for minutes rather than indefinitely. Only the ttl
                    // moves, which is what schedules the retry.
                    const stale = map.get(key);
                    if (!stale || !Array.isArray(stale.data) || !stale.data.length) throw e;
                    stale.ttl = (Date.now() - stale.ts) + CACHE_FAILURE_TTL;
                    console.warn(
                        `[cache] upstream list failed (${e.message}); serving ${stale.data.length} ` +
                        `stale items, retrying in ${CACHE_FAILURE_TTL / 1000}s`
                    );
                    return stale.data;
                }
            });
        }
    };
}

// Cache-aside read with single-flight over a BoundedMap of `{ data, ts }`.
// The full-list caches above and the series-info cache below each predate this
// and carry behaviour of their own — per-entry TTLs, negative caching, a stale
// fallback — so they keep their bespoke forms. This is the plain case, and both
// caches added for the per-item and per-category paths are exactly it.
// `ttlFor(data)` shortens one entry's lifetime. It is capped at `ttl`, which is
// also the age the sweeper reclaims entries at.
// `ledger` weighs each entry and charges it to that CacheBudget; the production
// caches pass CACHE_BUDGET. Without one, entries carry no weight, as before.
function createKeyedCache({ maxEntries, ttl = CACHE_TTL, ttlFor = null, ledger = null }) {
    const map = new BoundedMap({ maxEntries, maxAgeMs: ttl, ledger });
    const singleFlight = createSingleFlight();
    // Returns the entry, not the value: a legitimately null payload must still
    // read as a hit rather than sending every caller back upstream.
    const liveEntry = (key) => {
        const entry = map.get(key);
        return entry && entry.ts > Date.now() - (entry.ttl ?? ttl) ? entry : null;
    };
    return {
        map,
        get(key) {
            const entry = liveEntry(key);
            return entry ? entry.data : null;
        },
        load(key, fetcher) {
            const hit = liveEntry(key);
            if (hit) return Promise.resolve(hit.data);
            return singleFlight(key, async () => {
                // Re-check: a concurrent flight may have populated it already.
                const warm = liveEntry(key);
                if (warm) return warm.data;
                const data = await fetcher();
                map.set(key, {
                    data,
                    ts: Date.now(),
                    ttl: ttlFor ? Math.min(ttl, ttlFor(data)) : ttl,
                    ...(ledger ? { bytes: estimateBytes(data) } : {})
                });
                return data;
            });
        }
    };
}

const liveStreamsCache = createStreamListCache();
const vodStreamsCache = createStreamListCache();
const seriesStreamsCache = createStreamListCache();

// Sorted catalog views, memoised so that paginating a shelf does not re-sort the
// whole list for every page. `[...items].sort(comparator)` copied and sorted up
// to 50,000 records to keep 100 of them, on every request, and Stremio fires
// several catalog requests in parallel on install — 50-100 ms of blocking work
// on the single thread that is also relaying video.
//
// Validity is decided by *identity*, not by a second TTL: an entry is reused
// only when the array it was derived from is still the very array the list cache
// hands back. Cached lists keep their identity until they are refetched, so a
// refetch invalidates the sorted view in the same instant, with no window in
// which the two could disagree. A TTL of its own could only be wrong in one
// direction or the other.
//
// That identity is also what the views are keyed by — a WeakMap from the source
// array — so a view lives exactly as long as the list it was sorted from. This
// was a BoundedMap of its own, and an entry holding `source` kept a list
// reachable after the stream cache had evicted it to stay within its budget:
// with CACHE_MAX_STREAM_ACCOUNTS=1, six accounts opening one shelf each held
// ~94 MB the stream cache had already let go of. It needs no count, TTL or sweep
// of its own, because the list caches already bound the lists, and a view adds
// one machine word per item it holds. Each source maps to `{ day, views }`; see
// sortedCatalogItems.
const sortedCatalogViews = new WeakMap();

// Signing-time vetting of the origins named in an HLS playlist. This was memoised
// per rewrite pass, which helped within one playlist and not at all across them —
// and a live playlist is re-fetched every few seconds, so the same CDN host was
// re-resolved for the life of the channel. Only OS-level DNS caching hid it.
//
// The TTL is the DNS pin's on purpose: a decision about a hostname must not
// outlive the window in which that hostname's addresses are treated as fixed.
// Caching this is safe because it is *not* the check that guards the fetch —
// safeFetch re-runs assertSafeOutboundUrl, and re-pins, on every segment request.
// This one only decides whether a URI is worth signing.
const HLS_ORIGIN_VET_TTL_MS = DNS_PIN_TTL_MS;
const HLS_ORIGIN_VET_MAX = 512;
const hlsOriginVetCache = new BoundedMap({
    maxEntries: HLS_ORIGIN_VET_MAX,
    maxAgeMs: HLS_ORIGIN_VET_TTL_MS
});

// Returns a promise for whether this origin may be signed. The promise itself is
// cached, so concurrent rewrites naming the same host share one resolution
// instead of racing. It never rejects.
function vetHlsOrigin(absolute, origin) {
    const cached = hlsOriginVetCache.get(origin);
    if (cached && cached.ts > Date.now() - HLS_ORIGIN_VET_TTL_MS) return cached.ok;
    const ok = assertSafeOutboundUrl(absolute).then(() => true, (e) => {
        // Only a policy refusal is a verdict worth keeping. A resolver blip is
        // not: remembered as "refused" it made every rewrite naming this origin
        // fail for the rest of the window, and a refused origin now costs the
        // whole playlist rather than leaking the provider's own URL.
        // Checked by identity so a newer entry set after this one is left alone.
        if (e?.code !== 'OUTBOUND_BLOCKED' && hlsOriginVetCache.peek(origin)?.ok === ok) {
            hlsOriginVetCache.delete(origin);
        }
        return false;
    });
    hlsOriginVetCache.set(origin, { ok, ts: Date.now() });
    return ok;
}

function getAllVodStreams(cfg) {
    return vodStreamsCache.load(cfg, () => getStreams(cfg, 'get_vod_streams'));
}

function getAllSeriesStreams(cfg) {
    return seriesStreamsCache.load(cfg, () => getStreams(cfg, 'get_series'));
}

function getAllLiveStreams(cfg) {
    return liveStreamsCache.load(cfg, () => getStreams(cfg, 'get_live_streams'));
}

// The keys this addon declares in its manifest `extra` blocks. Nothing else is
// a pair separator's right-hand side, which is what makes the split below safe.
const EXTRA_KEYS = ['skip', 'genre', 'search'];

// A pair boundary is a separator followed by one of those keys and its '='. A
// '&' anywhere else belongs to a value and is kept: category names like
// "SLOVAKIA & Czechia" and "Kids & Family" are common, and splitting on every
// '&' cut them in half, so the manifest advertised a genre whose shelf could
// never open. Anchoring on a declared key is what makes that decidable — the
// previous code could not tell a separator from a value byte, because Express
// percent-decodes a route param before any handler sees it, turning %26 into the
// very character the parser split on.
//
// Both the separator and the '=' are matched raw or escaped, because how much of
// the segment is escaped is the client's choice: some send `genre=A%20%26%20B`,
// others escape the whole pair as `genre%3DA%2520%2526%2520B`.
const EXTRA_KEY_ALT = EXTRA_KEYS.join('|');
const EXTRA_PAIR_SPLIT = new RegExp(`(?:&|%26)(?=(?:${EXTRA_KEY_ALT})(?:=|%3D))`, 'i');
const EXTRA_KEY_HEAD = new RegExp(`^(${EXTRA_KEY_ALT})(?:=|%3D)`, 'i');

// decodeURIComponent throws on a malformed escape, and "100%" is a legitimate
// search term, so a part that will not decode is kept verbatim. Decoding here is
// only correct because the input is the *raw* segment (see rawExtraSegment); on
// an already-decoded param this would be a second decode and would corrupt it.
function decodeExtraPart(part) {
    try {
        return decodeURIComponent(part);
    } catch {
        return part;
    }
}

function parseExtra(extra) {
    const params = {};
    if (!extra) return params;

    for (const pair of extra.split(EXTRA_PAIR_SPLIT)) {
        const head = EXTRA_KEY_HEAD.exec(pair);
        if (head) {
            params[head[1].toLowerCase()] = decodeExtraPart(pair.slice(head[0].length));
            continue;
        }
        // Not a key this addon declares. Kept rather than dropped, on the first
        // literal '=', so an extra added to the manifest without being added to
        // EXTRA_KEYS still arrives instead of vanishing silently.
        const i = pair.indexOf('=');
        const [k, v] = i === -1 ? [pair, ''] : [pair.slice(0, i), pair.slice(i + 1)];
        params[decodeExtraPart(k)] = decodeExtraPart(v);
    }
    return params;
}

// The still-encoded :extra segment, or undefined when the request matched the
// route pattern that has no extra. `originalUrl` is the one place the escapes
// survive; `req.params.extra` has already lost them.
function rawExtraSegment(req) {
    if (req.params.extra === undefined) return undefined;
    const path = req.originalUrl.split('?')[0];
    return path.slice(path.lastIndexOf('/') + 1).replace(/\.json$/i, '');
}

const PAGE_SIZE = 100;

// `cacheMaxAge` and `staleRevalidate` are body fields, and in
// stremio-addon-sdk's serveHTTP they are what the SDK *converts into* a
// Cache-Control header. This addon is hand-rolled, so it emitted the fields and
// no header at all: nothing downstream had anything to act on, and the 86400 on
// movie meta was inert. This sets the header the fields were always describing,
// and keeps the fields — they are harmless, documentary, and read directly by
// some clients.
//
// `private` rather than `public` because every one of these responses is
// account-specific and the path carries a bearer token. A shared cache keys on
// the whole URL, so `public` would not leak between accounts, but it would put
// credentialed content in intermediaries the operator does not control — and the
// caching that actually matters here is the client's.
function withCacheHints(res, cacheMaxAge, staleRevalidate) {
    const directives = ['private', `max-age=${cacheMaxAge}`];
    if (staleRevalidate) directives.push(`stale-while-revalidate=${staleRevalidate}`);
    res.setHeader('Cache-Control', directives.join(', '));
    return staleRevalidate === undefined ? { cacheMaxAge } : { cacheMaxAge, staleRevalidate };
}

// A payload that is not an array is a provider failure, not an empty catalog:
// an overloaded Xtream panel answers `get_vod_streams` with an error object or a
// bare `{}`. Coercing that to [] made it indistinguishable from a genuinely
// empty account, and the empty list was then cached *positively* for the full 30
// minutes — every movie shelf and every movie search blank until it expired, off
// one blip, with no retry. Throwing keeps it out of the cache, because rejections
// are not cached, so the next request tries again. Same lesson as
// `isUsableSeriesInfo`: accepting less than the caller needs turns a flaky call
// into a sticky one.
async function getStreams(cfg, action, params = {}) {
    const data = await xtremioGet(cfg, action, params);
    if (!Array.isArray(data)) {
        throw new Error(`${action} returned ${data === null ? 'null' : typeof data}, not a list`);
    }
    // Without this the symptom is a search that finds nothing and no trace of why.
    if (!data.length && params.category_id === undefined) {
        console.warn(
            `[getStreams] ${action} returned an empty list; retrying in ${CACHE_FAILURE_TTL / 1000}s. ` +
            'Genre shelves use per-category fetches meanwhile, but search has nothing to search.'
        );
    }
    return data;
}

// The per-category fetch is what `selectCatalogGenre` falls back to when the
// full list is cold — which is precisely when Stremio's parallel catalog
// requests arrive, and it was neither cached nor single-flighted. Paginating a
// genre re-pulled the whole category from upstream on every page, and four
// sequential loads of one genre cost four upstream calls.
// An empty category is asked again within a minute: a real provider has answered
// a category that served 500 items with an empty list on a later load.
const categoryStreamsCache = createKeyedCache({
    maxEntries: CACHE_MAX_CATEGORY_LISTS,
    ledger: CACHE_BUDGET,
    ttlFor: list => (list.length ? CACHE_TTL : CACHE_FAILURE_TTL)
});

function categoryStreamsCacheKey(cfg, action, categoryId) {
    return `${accountCacheKey(cfg)}\n${action}\n${categoryId}`;
}

function getCategoryStreams(cfg, action, categoryId) {
    return categoryStreamsCache.load(
        categoryStreamsCacheKey(cfg, action, categoryId),
        () => getStreams(cfg, action, { category_id: categoryId })
    );
}

function parseYear(s) {
    if (!s) return undefined;
    const m = String(s).match(/\d{4}/);
    return m ? parseInt(m[0]) : undefined;
}

// "Usable" has to mean the same thing here as it does at the point of use, or
// the two disagree and the disagreement is cached. A payload carrying only
// `info.cover` (or a plot, or a genre) counted as usable, was cached
// *positively* for the full 30 minutes, and then failed the meta route's own
// `hasContent` check — which requires a name or episodes — so the series
// rendered as `meta: null` for half an hour with no retry. Accepting less than
// the caller needs is worse than a retry: it turns a flaky call into a
// sticky one.
// This is the predicate for *answering* with a payload, and it still mirrors
// `hasContent` exactly. What may be cached for half an hour is the stricter
// `hasSeriesEpisodes` below.
function isUsableSeriesInfo(info) {
    if (!info || typeof info !== 'object') return false;
    const hasName = info.info && typeof info.info === 'object' && info.info.name;
    return Boolean(hasName || hasSeriesEpisodes(info));
}

// What a payload needs before it is worth keeping for the full 30 minutes, and
// it is a stricter test than the one above: episodes. A series with a name and
// nothing to play is a page the user opens and leaves, and `get_series_info` is
// flaky enough that an episodes-less answer is far more likely a bad call than a
// real series with no episodes in it. Such a payload is still *returned* — the
// meta route renders the name rather than nothing — but it is remembered under
// SERIES_INFO_NEGATIVE_TTL, so the next request after a few minutes asks again
// instead of being pinned to it for half an hour.
// A season whose list is empty does not count. `{ episodes: { 1: [] } }` passed
// the old key-count check while the meta route, which iterates only arrays,
// built no videos from it at all — the same disagreement one level down.
function hasSeriesEpisodes(info) {
    if (!info || typeof info !== 'object') return false;
    const eps = info.episodes;
    if (!eps || typeof eps !== 'object') return false;
    return Object.values(eps).some(list => Array.isArray(list) && list.length > 0);
}

const SERIES_INFO_MAX_ATTEMPTS = 3;
const SERIES_INFO_BACKOFF_MS = 500;

// A series that never returns usable data costs 3 sequential upstream calls
// plus 1.5 s of backoff — and, uncached, pays that on *every* request. Single
// flight collapses concurrent callers but does nothing for sequential ones, so
// remember the failure briefly.
//
// Longer than CACHE_FAILURE_TTL (the category equivalent) because that case is
// three parallel calls with no backoff, while this one is sequential and sleeps;
// far shorter than the 30-minute positive TTL so a provider-side fix is picked
// up soon rather than being pinned for half an hour.
const SERIES_INFO_NEGATIVE_TTL = Math.max(1000, Number(process.env.SERIES_INFO_NEGATIVE_TTL_MS) || 5 * 60 * 1000);

const seriesInfoCache = new BoundedMap({
    maxEntries: CACHE_MAX_SERIES_INFO,
    maxAgeMs: CACHE_TTL,
    ledger: CACHE_BUDGET
});

// The LRU bound caps the worst case, but on its own it only reclaims memory
// when something new arrives. An instance whose users have all gone away would
// hold its last entries forever, so sweep on a timer too.
const CACHE_SWEEP_INTERVAL_MS = Math.max(30 * 1000, Number(process.env.CACHE_SWEEP_INTERVAL_MS) || 5 * 60 * 1000);

function sweepCaches(now = Date.now()) {
    return catCache.sweep(now)
        + seriesInfoCache.sweep(now)
        + vodInfoCache.map.sweep(now)
        + categoryStreamsCache.map.sweep(now)
        + liveStreamsCache.map.sweep(now)
        + vodStreamsCache.map.sweep(now)
        + seriesStreamsCache.map.sweep(now)
        + hlsOriginVetCache.sweep(now);
}

function startCacheSweeper() {
    const timer = setInterval(() => {
        const dropped = sweepCaches();
        if (dropped) console.log(`[cache] swept ${dropped} expired entr${dropped === 1 ? 'y' : 'ies'}`);
    }, CACHE_SWEEP_INTERVAL_MS);
    // Never hold the process open for a cache sweep.
    timer.unref();
    return timer;
}

function seriesInfoCacheKey(cfg, seriesId) {
    return `${cfg.serverUrl}\n${cfg.username}\n${cfg.password}\n${seriesId}`;
}

// Entries carry their own ttl (as catCache's do) because a remembered failure
// must expire far sooner than a good payload.
function readSeriesInfoEntry(cfg, seriesId) {
    const entry = seriesInfoCache.get(seriesInfoCacheKey(cfg, seriesId));
    if (!entry) return null;
    const ttl = typeof entry.ttl === 'number' ? entry.ttl : CACHE_TTL;
    return entry.ts > Date.now() - ttl ? entry : null;
}

function getCachedSeriesInfo(cfg, seriesId) {
    const entry = readSeriesInfoEntry(cfg, seriesId);
    // Only a good payload is a "hit" here; negative entries are replayed by
    // fetchSeriesInfo, which knows how to reproduce the original outcome.
    return entry && !entry.negative ? entry.data : null;
}

function setCachedSeriesInfo(cfg, seriesId, data) {
    seriesInfoCache.set(seriesInfoCacheKey(cfg, seriesId), {
        data,
        ts: Date.now(),
        ttl: CACHE_TTL,
        bytes: estimateBytes(data)
    });
}

// Remembers *how* the series failed, so a cached failure reproduces exactly what
// an uncached one would have returned: an unusable-but-present payload is
// replayed, and a total failure re-throws.
function setNegativeSeriesInfo(cfg, seriesId, { data, error }) {
    seriesInfoCache.set(seriesInfoCacheKey(cfg, seriesId), {
        data,
        error,
        negative: true,
        ts: Date.now(),
        ttl: SERIES_INFO_NEGATIVE_TTL,
        bytes: estimateBytes(data)
    });
}

const seriesInfoSingleFlight = createSingleFlight();

// Opening a series fires meta and stream requests that both land here, and a
// miss costs up to 3 upstream attempts with backoff — worth deduplicating.
function getSeriesInfo(cfg, seriesId) {
    const hit = getCachedSeriesInfo(cfg, seriesId);
    if (hit) return Promise.resolve(hit);
    return seriesInfoSingleFlight(
        seriesInfoCacheKey(cfg, seriesId),
        () => fetchSeriesInfo(cfg, seriesId)
    );
}

async function fetchSeriesInfo(cfg, seriesId) {
    const cached = readSeriesInfoEntry(cfg, seriesId);
    if (cached) {
        if (!cached.negative) return cached.data;
        console.log(`[getSeriesInfo] series ${seriesId} failed recently; skipping ${SERIES_INFO_MAX_ATTEMPTS} retries`);
        if (cached.data !== null) return cached.data;
        throw new Error(cached.error);
    }

    let lastInfo = null;
    let lastError = null;
    for (let attempt = 1; attempt <= SERIES_INFO_MAX_ATTEMPTS; attempt++) {
        try {
            const info = await xtremioGet(cfg, 'get_series_info', { series_id: seriesId }, { timeoutMs: 8000 });
            if (hasSeriesEpisodes(info)) {
                setCachedSeriesInfo(cfg, seriesId, info);
                return info;
            }
            lastInfo = info;
            const shape = isUsableSeriesInfo(info) ? 'a series with no episodes' : 'unusable data';
            console.warn(`[getSeriesInfo] attempt ${attempt}/${SERIES_INFO_MAX_ATTEMPTS} for series ${seriesId} returned ${shape}`);
        } catch (e) {
            lastError = e;
            const causeMsg = e.cause ? ` (cause: ${e.cause.code || e.cause.message || e.cause})` : '';
            console.warn(`[getSeriesInfo] attempt ${attempt}/${SERIES_INFO_MAX_ATTEMPTS} for series ${seriesId} failed: ${e.message}${causeMsg}`);
        }
        if (attempt < SERIES_INFO_MAX_ATTEMPTS) {
            await new Promise(r => setTimeout(r, SERIES_INFO_BACKOFF_MS * attempt));
        }
    }
    const failure = lastError || new Error(`get_series_info failed for series ${seriesId}`);

    setNegativeSeriesInfo(cfg, seriesId, {
        data: lastInfo,
        error: failure.message
    });

    if (lastInfo !== null) return lastInfo;
    throw failure;
}

// Movies get the same treatment as series, minus the retries and the negative
// cache — `get_vod_info` is not flaky the way `get_series_info` is. Opening one
// movie called it twice, once from the meta route and once from the stream
// route, and re-opening the same movie paid both again: nothing cached it.
const vodInfoCache = createKeyedCache({ maxEntries: CACHE_MAX_VOD_INFO, ledger: CACHE_BUDGET });

function vodInfoCacheKey(cfg, vodId) {
    return `${accountCacheKey(cfg)}\n${vodId}`;
}

// The rule isUsableSeriesInfo states for series, for the same reason: the meta
// route needs a name and the stream route a container. A payload with neither
// was cached for 30 minutes and rendered as a movie called "Unknown" with a
// playable-looking mp4 stream — measured against a real account with a movie id
// that does not exist. Some panels put the fields at the root, which is why the
// meta route reads `info?.info ?? info` and why this does too.
function isUsableVodInfo(payload) {
    const isObject = v => Boolean(v) && typeof v === 'object' && !Array.isArray(v);
    if (!isObject(payload)) return false;
    const movie = isObject(payload.info) ? payload.info : payload;
    const named = Boolean(movie.name || movie.o_name);
    const data = payload.movie_data;
    const playable = isObject(data) && Boolean(data.stream_id || data.container_extension);
    return named || playable;
}

function getVodInfo(cfg, vodId) {
    return vodInfoCache.load(vodInfoCacheKey(cfg, vodId), async () => {
        const info = await xtremioGet(cfg, 'get_vod_info', { vod_id: vodId });
        // Thrown rather than returned because rejections are not cached, so a
        // movie the provider fills in later is picked up on the next request.
        if (!isUsableVodInfo(info)) throw new Error(`get_vod_info returned no usable data for movie ${vodId}`);
        return info;
    });
}

function schemeOf(url) {
    return String(url || '').startsWith('https:') ? 'https' : 'http';
}

// A downgrade can arrive by two routes, and both end up baked into the config
// token permanently: the https attempt failing and the http retry succeeding,
// or the provider's own server_info naming http. Neither used to be visible to
// the user, so credentials could travel in cleartext forever because https
// hiccuped once during setup.
function describeDowngrade(requested, finalUrl, source) {
    if (schemeOf(requested) !== 'https' || schemeOf(finalUrl) !== 'http') return null;
    return { from: 'https', to: 'http', source };
}

// The URL a provider names for itself in `server_info`, or null when those fields
// do not make one. They are provider-controlled and used to be concatenated
// unchecked: a `url` that already carried its port gave `http://host:8080:8080`,
// which does not parse, and one with a trailing slash gave `http://host/:8080`,
// which parses but has lost its port. Both reported "Connected!" and minted an
// install link whose every catalog was empty. Only a bare http(s) origin is
// accepted; the caller keeps the URL that just worked otherwise.
function serverInfoOrigin(si) {
    if (!si || !si.url) return null;
    const proto = si.server_protocol || 'http';
    // An https server_info names its port in https_port. Borrowing `port` when that
    // is empty gave https://host:80 — TLS spoken to the http port, which never
    // connects (audit S8). With no https_port, https means its default port.
    const port = proto === 'https' ? si.https_port : si.port;
    let parsed;
    try {
        parsed = new URL(port ? `${proto}://${si.url}:${port}` : `${proto}://${si.url}`);
    } catch {
        return null;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password) return null;
    return parsed.origin;
}

// Whether these credentials work at `origin`: the same player_api call the check
// below makes, answered with auth=1. Never throws — any failure, a refusal by the
// SSRF guard included, is simply "no".
async function credentialsWorkAt(origin, username, password) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
        const res = await safeFetch(buildUrl(origin, '/player_api.php', { username, password }), { signal: controller.signal });
        const json = await readJsonCapped(res, 'credential check', 1024 * 1024);
        return json?.user_info?.auth === 1;
    } catch {
        return false;
    } finally {
        clearTimeout(timer);
    }
}

async function validateXtremioCredentials(serverUrl, username, password) {
    const base = normalizeUrl(serverUrl);
    // Someone who typed https:// asked for https and is never moved off it
    // automatically (audit S7). Any failure of the https attempt — a TLS reset, a
    // non-JSON 5xx page, a reset on port 443 from someone on the path — used to
    // trigger an http retry that sent the password in cleartext before the page could
    // warn anyone. Without a scheme, or with http://, the fallback only ever tries
    // https, which costs nothing.
    const askedForHttps = schemeOf(base) === 'https';
    const urls = askedForHttps ? [base] : [base, base.replace(/^http:/, 'https:')];

    for (const url of urls) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 15000);
        try {
            const apiUrl = buildUrl(url, '/player_api.php', { username, password });
            const res = await safeFetch(apiUrl, { signal: controller.signal });
            // Unauthenticated entry point against a user-supplied host: a small
            // cap here, since an auth response is tiny and anything large is abuse.
            const json = await readJsonCapped(res, 'credential check', 1024 * 1024);

            // `?.`: a panel answering a literal `null` threw here, and the catch
            // reported it as "Cannot reach that server", which it plainly could.
            if (!json?.user_info) return { valid: false, error: 'Not a valid xTremio server' };
            if (json.user_info.auth !== 1) return { valid: false, error: 'Invalid username or password' };
            if (json.user_info.status !== 'Active') return { valid: false, error: `Account is ${json.user_info.status || 'inactive'}` };

            const expDate = parseInt(json.user_info.exp_date, 10);
            if (expDate && expDate < Math.floor(Date.now() / 1000)) {
                return { valid: false, error: 'Account has expired' };
            }

            const si = json.server_info;
            let named = serverInfoOrigin(si);
            if (si && si.url && !named) {
                console.warn('[configure] provider server_info does not form a usable URL; keeping the one that connected');
            }
            // A listed panel does not get to move the install URL to a host that is
            // not listed. server_info is provider data, and adopting an unlisted
            // origin would bake it into the token — which decodeConfig then refuses,
            // leaving a "Connected!" page whose install link never works.
            if (named && !panelHostAllowed(named)) {
                console.warn(
                    `[configure] provider server_info names ${JSON.stringify(hostnameOf(named))}, ` +
                    'which is not in ALLOWED_PANEL_HOSTS; keeping the one that connected'
                );
                named = null;
            }
            // Nor does the panel's own configuration move someone who asked for https
            // onto http. server_info routinely names http, and following it baked
            // cleartext into the install URL for a user who had typed https.
            if (named && askedForHttps && schemeOf(named) === 'http') {
                console.warn(
                    `[configure] provider server_info names http for ${JSON.stringify(hostnameOf(named))}; ` +
                    'keeping the https URL that connected'
                );
                named = null;
            }
            // And whatever origin survives is adopted only once these credentials have
            // worked there too (audit S8). It used to replace the URL that connected
            // untested, so a panel reporting its internal address — a common
            // misconfiguration — got "Connected!" and an install link whose every
            // catalog was empty, because the SSRF guard refused every request to it.
            // Checked last, so a host already refused above is never contacted, and
            // skipped for the origin that just answered, which proves nothing new.
            if (named && new URL(named).origin !== new URL(url).origin
                && !await credentialsWorkAt(named, username, password)) {
                console.warn(
                    `[configure] provider server_info names ${JSON.stringify(hostnameOf(named))}, ` +
                    'where these credentials did not work; keeping the one that connected'
                );
                named = null;
            }
            const finalUrl = named || url;
            // Attribute the downgrade to whichever step actually caused it: the
            // http retry, or the provider overriding a scheme that just worked.
            const downgrade = describeDowngrade(base, url, 'fallback')
                || describeDowngrade(url, finalUrl, 'provider');
            if (downgrade) {
                console.warn(`[configure] ${new URL(finalUrl).host}: https→http downgrade (${downgrade.source}); credentials will travel in cleartext`);
            }

            return {
                valid: true,
                userInfo: json.user_info,
                resolvedUrl: finalUrl,
                downgrade
            };
        } catch (e) {
            if (url === urls[0] && urls.length > 1) continue;
            // Distinguishing ECONNREFUSED / ENOTFOUND / timeout back to an
            // unauthenticated caller turns this page into a port scanner: the
            // reply says whether an arbitrary host:port is closed, nonexistent,
            // or filtered. The operator still gets the detail in the log.
            console.warn(`[configure] connection to ${new URL(url).host} failed: ${e.name === 'AbortError' ? 'timeout' : e.cause?.code || e.message}`);
            return {
                valid: false,
                error: askedForHttps
                    ? 'Cannot reach that server over https — check the URL and port. If your provider only supports http, enter the address starting with http:// instead.'
                    : 'Cannot reach that server — check the URL and port.'
            };
        } finally {
            clearTimeout(timer);
        }
    }
    return { valid: false, error: 'Cannot connect to server' };
}

// `nonce` comes from setPrivateHeaders and is the only thing that lets this
// page's one script run under its CSP. Rendering without one (a caller that
// forgot, or a test) still produces a working page — only the click-to-copy
// convenience goes quiet, since the link is selectable text either way.
function renderConfigPage({ serverUrl = '', username = '', password = '', status = null, baseUrl = `http://localhost:${PORT}`, nonce = '' }) {
    // Base64 contains nothing escapeHtml touches, so this is identical to the
    // value in the header — it just keeps the rule that every interpolation on
    // this page goes through escapeHtml, with no exception to remember.
    const safeNonce = escapeHtml(nonce);
    const safeServerUrl = escapeHtml(serverUrl);
    const safeUsername = escapeHtml(username);
    const safePassword = escapeHtml(password);
    let statusHtml = '';
    if (status) {
        if (status.valid) {
            const encoded = encodeConfig({ serverUrl, username, password });
            const installUrl = escapeHtml(`stremio://${baseUrl.replace(/^https?:\/\//, '')}/${encoded}/manifest.json`);
            const httpUrl = escapeHtml(`${baseUrl}/${encoded}/manifest.json`);
            // The connection was downgraded to http and that choice is now baked
            // into the install token, so say so plainly rather than letting the
            // green "Connected!" banner imply everything is fine.
            const downgradeHtml = status.downgrade ? `
                    <div class="status-banner status-warning">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                        <span class="status-text">
                            <strong>Connected over http, not https.</strong>
                            ${status.downgrade.source === 'fallback'
                                ? 'The https connection failed, so http was used instead.'
                                : 'Your provider asked for http even though https worked.'}
                            Your username and password will be sent in cleartext on every request, and this choice is saved into the install link below.
                            ${status.downgrade.source === 'fallback'
                                ? 'If your provider does support https, fix the URL and configure again.'
                                : ''}
                        </span>
                    </div>` : '';
            statusHtml = `
                <div class="status-section">
                    <div class="status-banner status-success">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
                        <span class="status-text">Connected! Welcome, ${escapeHtml(status.userInfo.username || username)}</span>
                    </div>${downgradeHtml}
                    <a href="${installUrl}" class="btn full install-link">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                        Install in Stremio
                    </a>
                    <div class="copy-block">
                        <p id="copy-label" class="copy-label" data-idle="Or copy this link to install:">Or copy this link to install:</p>
                        <input type="text" id="copy-input" class="copy-input" value="${httpUrl}" readonly title="Click to copy install link" />
                    </div>
                </div>
                <script nonce="${safeNonce}">
                (function () {
                    var input = document.getElementById('copy-input');
                    var label = document.getElementById('copy-label');
                    if (!input || !label) return;
                    var timer = null;

                    function report(copied) {
                        label.textContent = copied ? '✓ Copied to clipboard!' : 'Press Ctrl+C to copy';
                        label.style.color = copied ? '#2e7d32' : '#555';
                        clearTimeout(timer);
                        timer = setTimeout(function () {
                            label.textContent = label.dataset.idle;
                            label.style.color = '#555';
                        }, 2000);
                    }

                    function copyViaSelection() {
                        // execCommand is deprecated but stays as the fallback rather
                        // than the other way round: navigator.clipboard exists only on
                        // secure origins, and this addon is most often reached over
                        // plain http on a LAN, where it is undefined.
                        try { return document.execCommand('copy'); } catch (e) { return false; }
                    }

                    input.addEventListener('click', function () {
                        input.select();
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            navigator.clipboard.writeText(input.value).then(function () {
                                report(true);
                            }, function () {
                                report(copyViaSelection());
                            });
                        } else {
                            report(copyViaSelection());
                        }
                    });
                })();
                </script>`;
        } else {
            statusHtml = `
                <div class="status-section">
                    <div class="status-banner status-error">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M6 18L18 6M6 6l12 12"/></svg>
                        <span class="status-text">${escapeHtml(status.error)}</span>
                    </div>
                </div>`;
        }
    }

    return `<!DOCTYPE html>
    <html><head>
        <title>xTremio Configuration</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                min-height: 100vh; display: flex; align-items: center; justify-content: center;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                padding: 20px;
            }
            .card {
                background: #fff; border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 420px; width: 100%; overflow: hidden;
            }
            .header {
                background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
                padding: 30px; text-align: center;
            }
            .header h1 { color: #fff; font-size: 24px; font-weight: 600; }
            .header p { color: rgba(255,255,255,0.8); font-size: 14px; margin-top: 8px; }
            .btn {
                display: inline-flex; align-items: center; gap: 10px;
                padding: 14px 32px;
                background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
                color: #fff; text-decoration: none; border: none;
                border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(124,77,255,0.4); }
            .btn:active { transform: translateY(0); }
            .btn svg { width: 20px; height: 20px; }
            .form-container { padding: 30px; }
            .input-group { margin-bottom: 20px; }
            .input-group label { display: block; font-size: 13px; font-weight: 600; color: #333; margin-bottom: 8px; }
            .input-wrapper { position: relative; }
            .input-wrapper svg { position: absolute; left: 14px; top: 50%; transform: translateY(-50%); width: 18px; height: 18px; color: #999; }
            .input-wrapper input { width: 100%; padding: 14px 14px 14px 44px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 15px; transition: border-color 0.2s, box-shadow 0.2s; }
            .input-wrapper input:focus { outline: none; border-color: #7c4dff; box-shadow: 0 0 0 3px rgba(124,77,255,0.1); }
            .input-wrapper input::placeholder { color: #aaa; }
            .btn.full { width: 100%; justify-content: center; }
            .status-section { padding: 0 30px 30px; text-align: center; }
            .status-banner { padding: 16px; border-radius: 10px; display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
            .status-banner svg { width: 22px; height: 22px; flex-shrink: 0; }
            .status-banner .status-text { font-size: 14px; font-weight: 500; text-align: left; }
            .status-success { background: #e8f5e9; color: #2e7d32; }
            .status-error { background: #ffebee; color: #c62828; }
            .status-warning { background: #fff8e1; color: #8a5a00; }
            .status-warning .status-text { line-height: 1.5; }
            .install-link { margin-top: 4px; }
            .copy-block { margin-top: 16px; }
            .copy-label { font-size: 13px; color: #555; margin-bottom: 8px; font-weight: 600; text-align: left; }
            .copy-input { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 14px; color: #333; background: #f9f9f9; cursor: pointer; text-align: center; transition: border-color 0.2s; }
            .copy-input:hover { border-color: #7c4dff; }
            .disclaimer {
                background: #fff8e1;
                border: 1px solid #ffe082;
                color: #5d4037;
                border-radius: 10px;
                padding: 12px 14px;
                font-size: 12px;
                line-height: 1.5;
                margin-bottom: 22px;
            }
            .disclaimer strong { color: #ef6c00; display: block; margin-bottom: 4px; font-size: 13px; }
            .disclaimer ul { margin: 6px 0 0 18px; padding: 0; }
            .disclaimer li { margin-bottom: 3px; }
        </style>
    </head><body>
        <div class="card">
            <div class="header">
                <h1>xTremio Addon</h1>
                <p>Configure your credentials</p>
            </div>
            <div class="form-container">
                <div class="disclaimer">
                    <strong>⚠ Disclaimer</strong>
                    This addon is a technical gateway only. It does <b>not</b> host, store, or provide any media content.
                    <ul>
                        <li>You must have a valid, legally obtained Xtream Codes account.</li>
                        <li>You are solely responsible for the content accessed through your provider.</li>
                        <li>Credentials are encrypted into your install URL &mdash; keep it private, do not share it.</li>
                    </ul>
                </div>
                <form method="POST" action="/configure">
                    <div class="input-group">
                        <label>Server URL</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>
                            <input type="url" name="serverUrl" value="${safeServerUrl}" placeholder="http://example.com:port" required />
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Username</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
                            <input type="text" name="username" value="${safeUsername}" placeholder="Enter username" required />
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Password</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                            <input type="password" name="password" value="${safePassword}" placeholder="Enter password" required />
                        </div>
                    </div>
                    <button type="submit" class="btn full">Save & Install</button>
                </form>
            </div>
            ${statusHtml}
        </div>
    </body></html>`;
}

// The configure page echoes back a submitted password and embeds the install token.
// Keep it out of shared caches, browser history, and outbound Referer headers.
//
// The framing and CSP headers are the backstop behind the escapeHtml discipline
// in renderConfigPage, not a replacement for it. Framing is the one with a live
// attack behind it: this is the only page with a submit button that sends
// plaintext credentials, so a framed copy of it is a clickjacking target, and
// both frame-ancestors and X-Frame-Options are sent because the latter is all
// an older client understands.
//
// The policy can be nearly `default-src 'none'` because the page loads nothing
// external — no fonts, no stylesheets, no scripts, and its icons are inline
// <svg> rather than images.
// Scripts run only under a per-response nonce, which is what forced the copy
// handler out of an onclick attribute and into a real script block: an inline
// handler would need script-src 'unsafe-inline', which would give back exactly
// the injected-script execution the policy exists to deny. style-src keeps
// 'unsafe-inline' because the page's <style> block and its remaining style="…"
// attributes both need it, and a style nonce does not cover attributes.
// Returns the nonce, which the caller must pass to renderConfigPage.
function setPrivateHeaders(res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');

    const nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader('Content-Security-Policy', [
        "default-src 'none'",
        `script-src 'nonce-${nonce}'`,
        "style-src 'unsafe-inline'",
        // form-action does not fall back to default-src, so the page's own POST
        // has to be allowed explicitly or the form silently stops submitting.
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'"
    ].join('; '));
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return nonce;
}

// POST /configure makes an outbound request to a host the caller chooses, with
// credentials the caller chooses, before any authentication. Unmetered, that
// makes the instance a port scanner and a credential-stuffing relay running on
// this server's IP. A handful of attempts per minute is far more than a human
// configuring an addon needs.
const CONFIGURE_RATE_LIMIT = Math.max(1, Number(process.env.CONFIGURE_RATE_LIMIT) || 10);
const CONFIGURE_RATE_WINDOW_MS = Math.max(1000, Number(process.env.CONFIGURE_RATE_WINDOW_MS) || 60 * 1000);
// Bound the map so the limiter cannot itself become a memory-exhaustion vector.
// Once full, the oldest bucket makes room for the new one. It used to let every
// new client through instead, which meant that 10,000 addresses in one window —
// cheap in IPv6 before /64 bucketing — switched the limiter off for everyone.
const CONFIGURE_RATE_MAX_CLIENTS = 10000;
const configureAttempts = new Map();

// The key a client is limited by — for /configure attempts and for concurrent
// relays alike. Its address, or the one a trusted proxy reported for it (see
// forwardedValue); a forwarded value that is not an address falls back to the
// socket, since a garbage key is a free bucket.
function clientKey(req) {
    const forwarded = forwardedValue(req, 'x-forwarded-for');
    const address = net.isIP(forwarded) ? forwarded : (req.socket?.remoteAddress || '');
    return addressBucket(address) || 'unknown';
}

// An IPv6 client is keyed by its /64. One home or mobile connection is routinely
// assigned a whole /64, so keying by the full address handed each subscriber 2^64
// fresh buckets. A v4-mapped address — how a dual-stack socket reports an IPv4
// client — is keyed as the IPv4 address it is, so the same client is one bucket
// whichever way it arrived.
function addressBucket(address) {
    const family = net.isIP(address);
    if (family === 4) return address;
    if (family !== 6) return '';
    const bytes = ipv6ToBytes(address);
    if (!bytes) return '';
    const mapped = IPV6_EMBEDDED_IPV4[0];
    if (ipv6MatchesPrefix(bytes, mapped.bytes, mapped.bits)) {
        return Array.from(bytes.subarray(mapped.offset, mapped.offset + 4)).join('.');
    }
    const hextets = [];
    for (let i = 0; i < 8; i += 2) hextets.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    return `${hextets.join(':')}::/64`;
}

// Fixed window: on the first hit of a window the count resets. Sweeping expired
// entries on each call keeps the map proportional to *active* clients.
function rateLimitConfigure(req) {
    const now = Date.now();
    for (const [key, entry] of configureAttempts) {
        if (entry.resetAt <= now) configureAttempts.delete(key);
    }

    const key = clientKey(req);
    const entry = configureAttempts.get(key);
    if (!entry) {
        while (configureAttempts.size >= CONFIGURE_RATE_MAX_CLIENTS) {
            configureAttempts.delete(configureAttempts.keys().next().value);
        }
        configureAttempts.set(key, { count: 1, resetAt: now + CONFIGURE_RATE_WINDOW_MS });
        return { allowed: true, retryAfter: 0 };
    }

    entry.count += 1;
    if (entry.count > CONFIGURE_RATE_LIMIT) {
        return { allowed: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    return { allowed: true, retryAfter: 0 };
}

// Prefill comes from an encrypted `config` token and nothing else. The route
// used to accept serverUrl, username and password as loose query parameters
// too. They were escaped, so it was never XSS — but it invited a URL with a
// plaintext password into browser history, referrer chains, proxy logs and
// anything that shoulder-surfs an address bar.
//
// Even from a token, only the server URL and username are prefilled. The token
// is the install URL Stremio stores and syncs, and rendering its password into
// the form made this page decrypt it for whoever held one — handing out a
// password that works against the provider directly, bypasses this server and
// survives a CONFIG_SECRET rotation. Reconfiguring costs retyping one field.
function sendConfigurePage(req, res, token) {
    const nonce = setPrivateHeaders(res);
    const existing = decodeConfig(token) || {};
    res.send(renderConfigPage({
        serverUrl: existing.serverUrl || '',
        username: existing.username || '',
        baseUrl: getBaseUrl(req),
        nonce
    }));
}

app.get('/configure', (req, res) => sendConfigurePage(req, res, req.query.config));

// Stremio's Configure button on an installed addon swaps manifest.json for
// `configure` in the transport URL, so it lands here and not on /configure. An
// undecodable token renders the empty form, as the bare route does. The form
// names /configure as its action because a bare POST from this path would go to
// /<token>/configure, which has no handler.
app.get('/:config/configure', (req, res) => sendConfigurePage(req, res, req.params.config));

app.post('/configure', async (req, res) => {
    const nonce = setPrivateHeaders(res);
    // req.body is undefined when nothing parsed the body (no Content-Type, or a
    // JSON one), and extended urlencoded turns `serverUrl[]=a&serverUrl[]=b` or
    // `serverUrl[a]=1` into an array or an object. Either way the fields are not
    // guaranteed to be strings, and this runs before the try below, so calling
    // .trim() on one was an unauthenticated 500.
    const body = req.body || {};
    const rawServerUrl = asString(body.serverUrl).trim().replace(/\/+$/, '');
    const username = asString(body.username);
    const password = asString(body.password);

    const limit = rateLimitConfigure(req);
    if (!limit.allowed) {
        res.status(429);
        res.setHeader('Retry-After', String(limit.retryAfter));
        return res.send(renderConfigPage({
            serverUrl: rawServerUrl,
            username,
            password,
            status: { valid: false, error: `Too many attempts. Try again in ${limit.retryAfter} second${limit.retryAfter === 1 ? '' : 's'}.` },
            baseUrl: getBaseUrl(req),
            nonce
        }));
    }

    // An empty serverUrl made normalizeUrl throw, which the catch below reported
    // as the generic "Something went wrong" — true, but silent about which field
    // is at fault. The browser's `required` attributes normally prevent this, so
    // it is only reachable by a direct POST, but the field still deserves an
    // answer it can act on.
    const missing = [
        !rawServerUrl && 'server URL',
        !username && 'username',
        !password && 'password'
    ].filter(Boolean);
    if (missing.length) {
        const named = missing.length === 1
            ? missing[0]
            : `${missing.slice(0, -1).join(', ')} and ${missing[missing.length - 1]}`;
        return res.send(renderConfigPage({
            serverUrl: rawServerUrl,
            username,
            password,
            status: { valid: false, error: `Please enter your ${named}.` },
            baseUrl: getBaseUrl(req),
            nonce
        }));
    }

    // Before any request is made to the host: the credential check is itself an
    // outbound fetch to a URL the caller chose. The reply does not list the hosts
    // that are allowed — whether to publish that is the operator's decision.
    if (!panelHostAllowed(rawServerUrl)) {
        console.warn(
            `[configure] refused ${JSON.stringify(hostnameOf(rawServerUrl) || rawServerUrl.slice(0, 100))}: ` +
            'not in ALLOWED_PANEL_HOSTS'
        );
        return res.send(renderConfigPage({
            serverUrl: rawServerUrl,
            username,
            password,
            status: { valid: false, error: 'This instance only accepts accounts from specific providers, and that server is not one of them.' },
            baseUrl: getBaseUrl(req),
            nonce
        }));
    }

    try {
        const validation = await validateXtremioCredentials(rawServerUrl, username, password);
        const finalServerUrl = validation.valid
            ? (validation.resolvedUrl || normalizeUrl(rawServerUrl))
            : rawServerUrl;

        res.send(renderConfigPage({
            serverUrl: finalServerUrl,
            username,
            password,
            status: validation,
            baseUrl: getBaseUrl(req),
            nonce
        }));
    } catch (e) {
        res.send(renderConfigPage({
            serverUrl: rawServerUrl,
            username,
            password,
            status: { valid: false, error: 'Something went wrong. Please try again.' },
            baseUrl: getBaseUrl(req),
            nonce
        }));
    }
});

// Route failures are answered quietly — an empty shelf, a null meta — because Stremio
// shows raw errors to users, so the log is the only place one failure can be told
// from another. It used to print e.message for everything, and a bug in this file read
// exactly like a provider outage: C1's "s.name.toLowerCase is not a function" emptied
// every search on an account and looked like a flaky panel (audit R6). An error this
// code raised by mistake now keeps its stack; provider and network failures stay one
// line, since they are expected and their stacks say nothing. Stacks rather than error
// objects, for the reason terminalErrorHandler gives.
function isProgrammingError(e) {
    if (e instanceof ReferenceError || e instanceof RangeError) return true;
    // fetch reports a network failure as TypeError('fetch failed') with a cause.
    return e instanceof TypeError && !e.cause && e.message !== 'fetch failed';
}

function logRouteError(route, e) {
    if (isProgrammingError(e)) console.error(`[${route}] unexpected error: ${e.stack}`);
    else console.error(`[${route}] Error:`, e?.message);
}

// --- Catalogs ---
// The three catalog kinds differ only in the fields below. Everything else —
// genre resolution, the search filter, sorting, pagination and the meta shape —
// is one code path, so a change to any of it cannot apply to movies and quietly
// miss series.
const CATALOG_KINDS = {
    live: {
        catalogTypes: ['Live TV'],
        categoryKey: 'live',
        loadAll: getAllLiveStreams,
        listCache: liveStreamsCache,
        // get_live_streams items may carry category_id, category_name, or neither,
        // so live also matches on the category name.
        matchCategoryName: true,
        // Live always loads the full list first; this is only for a category that
        // list has nothing for (see selectCatalogSource).
        categoryAction: 'get_live_streams',
        idField: 'stream_id',
        idPrefix: 'xtremio_live_',
        metaType: 'Live TV',
        posterField: 'stream_icon',
        posterShape: 'square',
        recencyField: null
    },
    movies: {
        catalogTypes: ['XT-Movies'],
        categoryKey: 'movies',
        loadAll: getAllVodStreams,
        listCache: vodStreamsCache,
        categoryAction: 'get_vod_streams',
        idField: 'stream_id',
        idPrefix: 'xtremio_movie_',
        metaType: 'XT-Movies',
        posterField: 'stream_icon',
        posterShape: 'poster',
        recencyField: 'added'
    },
    series: {
        // Declared under XT-Series in the manifest, but the metas are `series`
        // because that is the built-in type that gives episodes their UI.
        catalogTypes: ['XT-Series', 'series'],
        categoryKey: 'series',
        loadAll: getAllSeriesStreams,
        listCache: seriesStreamsCache,
        categoryAction: 'get_series',
        idField: 'series_id',
        idPrefix: 'xtremio_series_',
        metaType: 'series',
        posterField: 'cover',
        posterShape: 'poster',
        recencyField: 'last_modified'
    }
};

// Which kind a catalog id belongs to, and which variant of it. Note the overlap
// with item id prefixes: `xtremio_series_new` is a catalog id that starts with
// the item prefix `xtremio_series_`, which is why item ids are matched by
// `typeMatchesId` and never by this.
// The three variants the manifest actually declares. Anything else has to be
// rejected rather than resolved: an unknown suffix used to yield a real kind
// with `variant: 'bogus'`, which gives a null comparator, so the catalog was
// served *unsorted* instead of 404ing. A silently wrong order is harder to
// notice than a missing shelf.
const CATALOG_VARIANTS = new Set(['new', 'popular', 'featured']);

function parseCatalogId(id) {
    const str = String(id || '');
    if (str === 'xtremio_live') return { kind: 'live', variant: null, search: false };
    if (str === 'xtremio_search_movies') return { kind: 'movies', variant: null, search: true };
    if (str === 'xtremio_search_series') return { kind: 'series', variant: null, search: true };
    for (const kind of ['movies', 'series']) {
        const prefix = `xtremio_${kind}_`;
        if (!str.startsWith(prefix)) continue;
        const variant = str.slice(prefix.length);
        return CATALOG_VARIANTS.has(variant) ? { kind, variant, search: false } : null;
    }
    return null;
}

function catalogTypesFor(id) {
    const route = parseCatalogId(id);
    return route ? CATALOG_KINDS[route.kind].catalogTypes : null;
}

// Every comparator ends in the item id, making each sort a *total* order. Without
// that, two items with the same rating keep whatever order the source happened to
// produce — and the same catalog has two sources (the warm full list or a
// per-category fetch), so the page you got depended on cache state. That was the
// audit's L3.
// `now` is a parameter only so the featured shuffle can be tested across days
// without moving the system clock. Production always takes the default.
function catalogComparator(kind, variant, now = Date.now()) {
    const idOf = s => parseInt(s[kind.idField]) || 0;
    const byId = (a, b) => idOf(a) - idOf(b);

    if (variant === 'new' && kind.recencyField) {
        return (a, b) => ((parseInt(b[kind.recencyField]) || 0) - (parseInt(a[kind.recencyField]) || 0)) || byId(a, b);
    }
    if (variant === 'popular') {
        return (a, b) => ((parseFloat(b.rating) || 0) - (parseFloat(a.rating) || 0)) || byId(a, b);
    }
    if (variant === 'featured') {
        // Seeded on the day so the shuffle holds still while the user paginates
        // and changes when the day does. The seed has to enter the hash *before*
        // the multiply. It used to be added after (`id * C + daySeed`), and
        // adding a constant is order-preserving except for the single item that
        // wraps 2^31 — with tens of thousands of items spread over that range the
        // mean gap is tens of thousands, so the rotation took tens of thousands of
        // days to cross one item boundary. "Featured" was a fixed permutation:
        // measured identical at day+1, +30, +365 and +3650.
        const daySeed = Math.floor(now / 86400000);
        // Spread the day across the whole word first, so consecutive days are not
        // near-identical keys.
        const dayKey = Math.imul(daySeed, 0x9e3779b1);
        // XOR is a permutation of the id space and 2654435761 is odd, so this
        // stays a bijection modulo 2^31 exactly as the previous hash was: two
        // distinct ids still cannot collide, which is what the injectivity test
        // below relies on.
        const hash = s => (Math.imul(idOf(s) ^ dayKey, 2654435761) & 0x7fffffff);
        return (a, b) => (hash(a) - hash(b)) || byId(a, b);
    }
    return null;
}

function filterByName(items, search) {
    if (!search) return items;
    const q = search.toLowerCase();
    return items.filter(s => titleOf(s.name).toLowerCase().includes(q));
}

function toCatalogMetas(items, kind) {
    return items.map(s => ({
        id: `${kind.idPrefix}${s[kind.idField]}`,
        type: kind.metaType,
        // `|| undefined` so an item with no title still omits the key rather
        // than shipping an empty string, which is what it did before.
        name: titleOf(s.name) || undefined,
        poster: s[kind.posterField] || undefined,
        posterShape: kind.posterShape
    }));
}

// Which categories an item is filed under. Xtream items carry a primary
// `category_id`, and many panels list every category in `category_ids` as well. The
// per-category upstream call returns an item for each of them, so matching the cached
// full list on `category_id` alone kept a multi-category item off all but one shelf
// once the list was warm, while the same shelf cold showed it (audit C4): what a
// shelf held depended on whether a search had happened to fill the cache.
function hasCategoryIds(item) {
    return (item.category_id != null && item.category_id !== '')
        || (Array.isArray(item.category_ids) && item.category_ids.length > 0);
}

function inCategories(item, ids) {
    if (item.category_id != null && item.category_id !== '' && ids.has(String(item.category_id))) return true;
    return Array.isArray(item.category_ids) && item.category_ids.some(id => ids.has(String(id)));
}

// Items merged from several category lists, each once, first occurrence kept: an
// item filed under two categories of the same name is in both of their lists.
function uniqueById(items, idField) {
    const seen = new Set();
    return items.filter((item) => {
        const id = String(item?.[idField]);
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
    });
}

// Resolves a genre to its items *and* to the cached array they were derived
// from, or to null when the genre does not resolve to a category. The second half is what lets the sorted view be invalidated by
// identity: a genre shelf is usually a fresh `.filter()` of the full list, so
// the items array is new on every request and says nothing about whether the
// underlying data changed — but the array it was filtered from is the one the
// list cache holds, and that is replaced only by a refetch.
//
// `selection` names which subset of `source` the items are, as resolved here:
// 'all', or the categories — every one that shares the genre's name. The sorted
// view is keyed on it rather than on the genre the request carried, because the
// no-categories path ignores that genre.
//
// `selectCatalogGenre` below is the plain-items form, kept because it is the
// exported surface and the shape the rest of the file describes.
async function selectCatalogSource(cfg, kind, genre) {
    const cats = await getCategories(cfg);
    const categories = cats[kind.categoryKey] || [];

    // No categories at all — the degraded case the manifest reflects by dropping
    // the genre extra. Without this the shelf is empty either way, because there
    // is no category for the genre to resolve to; the full list is the honest
    // answer, and it is the same list search already uses.
    if (!categories.length) {
        console.warn(`[catalog] no ${kind.categoryKey} categories; serving the full list`);
        const all = await kind.loadAll(cfg);
        return { items: all, source: all, selection: 'all' };
    }
    // Stremio marks genre required, but a bare catalog request still falls back
    // to the first category rather than showing an empty shelf.
    const selectedGenre = genre || (categories[0] && categories[0].category_name);
    // Every category with that name, not the first (audit C3). The manifest offers
    // each name once, so two "Action" categories are one genre to the user — but the
    // shelf resolved the name to the first of them alone, and the second one's titles
    // could not be reached from anywhere in the addon.
    const ids = [...new Set(categories
        .filter(c => c.category_name === selectedGenre)
        .map(c => String(c.category_id)))];
    if (!ids.length) return null;
    const idSet = new Set(ids);

    // Unambiguous for any ids, and exactly the old `category:<id>` for one numeric id.
    const selection = `category:${ids.map(encodeURIComponent).sort().join(',')}`;

    // A full list is a shortcut for the per-category fetch, and either one can be
    // wrong: a real provider has answered the unscoped get_vod_streams with an
    // empty list while its category_id calls worked, and on another load answered
    // a category_id call with an empty list while the full list worked. Any cached
    // array used to count as warm — `[]` is truthy — so one search cached the empty
    // full list and blanked every movie shelf for its whole TTL. The full list now
    // serves a genre only when it has something for it; otherwise the category is
    // asked directly. Both caches hold an empty answer for a minute, not thirty.
    if (kind.matchCategoryName) {
        const genreLower = String(selectedGenre || '').toLowerCase();
        const all = await kind.loadAll(cfg);
        // An item with any category id is matched by id; only one with none at all
        // falls back to its category name.
        const items = all.filter(s => (hasCategoryIds(s)
            ? inCategories(s, idSet)
            : Boolean(genreLower) && String(s.category_name || '').toLowerCase() === genreLower));
        // The name takes part in this filter, so it takes part in the selection.
        if (items.length) return { items, source: all, selection: `${selection}\n${genreLower}` };
    } else {
        // Reuse the warm full list when there is one; otherwise a per-category
        // fetch beats pulling 10-50 MB just to filter it down.
        const fullList = kind.listCache.get(cfg);
        if (fullList) {
            const items = fullList.filter(s => inCategories(s, idSet));
            if (items.length) return { items, source: fullList, selection };
        }
    }

    // The per-category lists are themselves cached, so one is its own identity token,
    // as before. Several are merged into an array that is new on every request, so its
    // sorted view is computed per request and collected with it — a sort paid only on
    // the cold path, and only by an account whose provider duplicates a name.
    const lists = await Promise.all(ids.map(id => getCategoryStreams(cfg, kind.categoryAction, id)));
    if (lists.length === 1) return { items: lists[0], source: lists[0], selection };
    const merged = uniqueById(lists.flat(), kind.idField);
    return { items: merged, source: merged, selection };
}

async function selectCatalogGenre(cfg, kind, genre) {
    const selected = await selectCatalogSource(cfg, kind, genre);
    return selected && selected.items;
}

// The sorted view of one shelf, memoised against the identity of the list it was
// derived from (see sortedCatalogViews). Returns `items` untouched when the
// variant has no comparator — the live shelf and any unsorted kind — so nothing
// is cached for a shelf whose order was never computed in the first place.
//
// Under one source, a view is keyed by the variant and by `selection`, the subset
// selectCatalogSource resolved — never by the genre string the request carried.
// Search and a kind with no categories ignore the genre, so keying on it let
// every distinct string mint a fresh sort of the same list, and while the views
// shared one LRU across accounts, one token holder could evict everyone else's.
// Keyed by what was selected, the views a source can have are bounded by its own
// account's categories, and a search shares its view with the no-categories
// shelf, which is the same list sorted the same way.
//
// Account and kind are not in the key because the source already implies them:
// every list cache is keyed by account, and each kind has its own.
function sortedCatalogItems(kind, route, { items, source, selection }, now = Date.now()) {
    const variant = route.search ? 'new' : route.variant;
    const comparator = catalogComparator(kind, variant, now);
    if (!comparator) return items;

    // The featured order is seeded on the day, and a list that stays cached
    // across midnight must not keep yesterday's views alongside today's.
    const day = Math.floor(now / 86400000);
    let entry = sortedCatalogViews.get(source);
    if (!entry || entry.day !== day) {
        entry = { day, views: new Map() };
        sortedCatalogViews.set(source, entry);
    }

    // `variant` never contains a newline, so the selection cannot shift into it.
    const key = `${variant}\n${selection}`;
    const hit = entry.views.get(key);
    if (hit) return hit;

    const sorted = [...items].sort(comparator);
    entry.views.set(key, sorted);
    return sorted;
}

app.get(['/:config/catalog/:type/:id.json', '/:config/catalog/:type/:id/:extra.json'], async (req, res) => {
    // Degraded answers are the default: every early return below is an empty
    // shelf or a null meta produced by a failure, and a client or intermediary
    // applying heuristic caching to one would pin a transient fault for as long
    // as it liked. withCacheHints overwrites this on the paths that succeeded.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ metas: [] });

    const { id, type } = req.params;

    // Asked of catalogTypesFor rather than re-derived here. The route used to
    // inline the equivalent lookup, which left the function with no production
    // caller at all and its six assertions testing something that never ran —
    // exactly the shape that lets a check and its test drift apart.
    const types = catalogTypesFor(id);
    if (!types) return res.json({ metas: [] });
    if (!types.includes(type)) {
        console.warn(`[catalog] type/id mismatch: type=${type} id=${id}`);
        return res.json({ metas: [] });
    }

    const route = parseCatalogId(id);
    const kind = CATALOG_KINDS[route.kind];

    try {
        const extra = parseExtra(rawExtraSegment(req));
        const skip = Math.max(0, parseInt(extra.skip) || 0);

        let selected;
        if (route.search) {
            // Global search: one full-list fetch per account (cached), then an
            // in-memory filter. This is what makes search cheap.
            if (!extra.search) return res.json({ metas: [] });
            const all = await kind.loadAll(cfg);
            selected = { items: all, source: all, selection: 'all' };
        } else {
            selected = await selectCatalogSource(cfg, kind, extra.genre);
            if (!selected) return res.json({ metas: [] });
        }

        // Both branches sort, and they did not used to. A search catalog has no
        // variant, so it got no comparator and was served in whatever order the
        // provider happened to return — which is stable only for as long as one
        // cached list survives. Across a TTL refetch an upstream reordering moves
        // the page boundaries, and the reader sees an item twice or not at all.
        // `new` is the variant chosen for search because it is a total order (it
        // ends in the item id, like every comparator here) and "most recently
        // added first" is the most useful ranking available behind a substring
        // match, which carries no relevance signal of its own.
        //
        // The sort now runs *before* the search filter rather than after it. The
        // two commute — a filter preserves relative order, and every comparator
        // here is a total order, so filtering a sorted list gives exactly the
        // list a sort of the filtered items would — and doing it in this order
        // means the sorted array depends only on the shelf, not on the search
        // term, which is what makes it memoisable at all. Keying a cache by a
        // caller-supplied search string would be an unbounded key space.
        const items = filterByName(
            sortedCatalogItems(kind, route, selected),
            extra.search
        );

        const metas = toCatalogMetas(items.slice(skip, skip + PAGE_SIZE), kind);
        // An empty page stays no-store, like the degraded answers above. Real
        // providers return empty lists transiently and the server-side caches
        // retry those within a minute, but a client told to keep the page for
        // 300 s plus 600 s stale would pin the blank shelf long after the server
        // had recovered. Recomputing an empty page costs nothing.
        if (!metas.length) return res.json({ metas });
        return res.json({ metas, ...withCacheHints(res, 300, 600) });
    } catch (e) {
        logRouteError('catalog', e);
        res.json({ metas: [] });
    }
});

app.get('/:config/meta/:type/:id.json', async (req, res) => {
    // Degraded answers are the default: every early return below is an empty
    // shelf or a null meta produced by a failure, and a client or intermediary
    // applying heuristic caching to one would pin a transient fault for as long
    // as it liked. withCacheHints overwrites this on the paths that succeeded.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ meta: null });
    const { id, type } = req.params;
    console.log(`[meta] type=${type} id=${id}`);

    if (!typeMatchesId(type, id)) {
        console.warn(`[meta] type/id mismatch: type=${type} id=${id}`);
        return res.status(404).json({ meta: null });
    }

    try {
        if (id.startsWith('xtremio_live_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_live_');
            if (!streamId) return res.status(400).json({ meta: null });
            const allLive = await getAllLiveStreams(cfg);
            let s = allLive.find(i => String(i.stream_id) === streamId);

            if (!s) return res.json({ meta: null });
            const meta = {
                id: `xtremio_live_${s.stream_id}`,
                type: 'Live TV',
                name: titleOf(s.name) || undefined,
                poster: s.stream_icon || undefined,
                posterShape: 'square',
                genres: s.category_name ? [s.category_name] : [],
                description: titleOf(s.name) || undefined
            };
            return res.json({ meta, ...withCacheHints(res, 300) });
        }

        if (id.startsWith('xtremio_movie_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_movie_');
            if (!streamId) return res.status(400).json({ meta: null });
            const info = await getVodInfo(cfg, streamId);
            const movie = info?.info ?? info ?? {};
            const cast = splitList(movie.cast);
            const backdrop = pickBackdrop(movie.backdrop_path);

            const meta = {
                id: `xtremio_movie_${streamId}`,
                type: 'XT-Movies',
                name: titleOf(movie.name || movie.o_name || info?.movie_data?.name) || 'Unknown',
                poster: movie.cover_big || movie.movie_image || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: movie.plot || movie.description || undefined,
                releaseInfo: movie.releasedate ? String(movie.releasedate) : undefined,
                genres: splitList(movie.genre),
                runtime: movie.duration ? String(movie.duration) + ' min' : (movie.episode_run_time ? String(movie.episode_run_time) + ' min' : undefined),
                director: movie.director || undefined,
                cast,
                imdbRating: movie.rating ? String(movie.rating) : undefined,
                year: parseYear(movie.releasedate),
                country: movie.country || undefined,
                trailer: movie.youtube_trailer || undefined
            };
            return res.json({ meta, ...withCacheHints(res, 86400) });
        }

        if (id.startsWith('xtremio_series_')) {
            const seriesId = getPrefixedNumericId(id, 'xtremio_series_');
            if (!seriesId) return res.status(400).json({ meta: null });
            let info = null;
            try {
                info = await getSeriesInfo(cfg, seriesId);
            } catch (e) {
                const causeMsg = e.cause ? ` (cause: ${e.cause.code || e.cause.message || e.cause})` : '';
                console.warn(`[meta] getSeriesInfo(${seriesId}) failed after retries: ${e.message}${causeMsg}`);
            }
            const series = info?.info ?? info ?? {};

            const videos = [];
            const episodes = info?.episodes ?? {};
            let skippedEpisodes = 0;
            for (const [seasonNum, eps] of Object.entries(episodes)) {
                if (!Array.isArray(eps)) continue;
                // parseEpisodeId requires all three components to be numeric, so an
                // episode built from a non-numeric season key or episode id would
                // render in the UI and then 400 on play. Drop it here instead.
                if (!isNumericId(seasonNum)) {
                    skippedEpisodes += eps.length;
                    continue;
                }
                for (const ep of eps) {
                    if (!isNumericId(ep?.id)) {
                        skippedEpisodes++;
                        continue;
                    }
                    // `|| 1` turned a legitimate episode 0 into episode 1, and
                    // providers do number specials, pilots and recaps 0 — so the
                    // episode was relabelled and collided with the real episode 1
                    // of the same season. Only a value that will not parse falls
                    // back now.
                    const parsedEpisode = parseInt(ep.episode_num);
                    const episodeNum = Number.isInteger(parsedEpisode) ? parsedEpisode : 1;
                    videos.push({
                        id: `xtremio_episode_${seriesId}:${seasonNum}:${ep.id}`,
                        // Built from the resolved number, so a missing episode_num
                        // reads "Episode 1" rather than "Episode undefined".
                        title: titleOf(ep.title) || `Episode ${episodeNum}`,
                        season: parseInt(seasonNum),
                        episode: episodeNum,
                        // Omitted rather than epoch-defaulted: Stremio renders a
                        // date it is given, so the old fallback printed "1970"
                        // next to every episode whose provider sent no date.
                        released: toIsoDate(ep.info?.releasedate) || undefined,
                        overview: ep.info?.plot || undefined,
                        thumbnail: ep.info?.movie_image || undefined
                    });
                }
            }
            if (skippedEpisodes) {
                console.warn(`[meta] series ${seriesId}: skipped ${skippedEpisodes} episode(s) with non-numeric season/episode ids`);
            }

            const hasContent = Boolean(series.name || videos.length);
            if (!hasContent) {
                console.warn(`[meta] no usable data for series ${seriesId}`);
                return res.json({ meta: null });
            }

            const cast = splitList(series.cast);
            const backdrop = pickBackdrop(series.backdrop_path);

            const meta = {
                id: `xtremio_series_${seriesId}`,
                type: 'series',
                name: titleOf(series.name) || 'Unknown',
                poster: series.cover || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: series.plot || undefined,
                releaseInfo: series.releaseDate ? String(series.releaseDate) : undefined,
                genres: splitList(series.genre),
                runtime: series.episode_run_time ? String(series.episode_run_time) + ' min' : undefined,
                director: series.director || undefined,
                cast,
                imdbRating: series.rating ? String(series.rating) : undefined,
                year: parseYear(series.releaseDate),
                videos
            };
            return res.json({ meta, ...withCacheHints(res, 3600) });
        }

        res.json({ meta: null });
    } catch (e) {
        logRouteError('meta', e);
        res.json({ meta: null });
    }
});

app.get('/:config/stream/:type/:id.json', async (req, res) => {
    // Degraded answers are the default: every early return below is an empty
    // shelf or a null meta produced by a failure, and a client or intermediary
    // applying heuristic caching to one would pin a transient fault for as long
    // as it liked. withCacheHints overwrites this on the paths that succeeded.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ streams: [] });
    const { id, type } = req.params;
    console.log(`[stream] type=${type} id=${id}`);

    if (!typeMatchesId(type, id)) {
        console.warn(`[stream] type/id mismatch: type=${type} id=${id}`);
        return res.status(404).json({ streams: [] });
    }

    try {
        // No credentials are read here any more: every stream this route hands
        // out is a proxy URL on this server, and the proxy is what holds them.

        // --- Handle xTremio's own IDs ---
        if (id.startsWith('xtremio_live_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_live_');
            if (!streamId) return res.status(400).json({ streams: [] });
            // Live goes through the proxy for the same reason movies and
            // episodes do, plus one of its own: the upstream URL embeds the
            // account username and password, and handing it to Stremio put
            // those in client logs and — for the http-only providers that are
            // the norm — in cleartext on the wire. Neither format is MP4, so
            // both are notWebReady; isNotWebReady is used rather than a
            // hardcoded true so the rule stays stated in one place.
            const proxyBase = `${getBaseUrl(req)}/${req.params.config}/proxy/live/${streamId}`;
            const variants = [
                { ext: 'm3u8', title: 'HLS' },
                { ext: 'ts', title: 'MPEG-TS' }
            ];
            return res.json({
                streams: variants.map(({ ext, title }) => {
                    const url = `${proxyBase}.${ext}`;
                    return {
                        url,
                        title,
                        behaviorHints: {
                            notWebReady: isNotWebReady(url, ext),
                            bingeGroup: `xtremio-live-${ext}`
                        }
                    };
                }),
                ...withCacheHints(res, 3600)
            });
        }

        if (id.startsWith('xtremio_movie_')) {
            const streamId = getPrefixedNumericId(id, 'xtremio_movie_');
            if (!streamId) return res.status(400).json({ streams: [] });
            const info = await getVodInfo(cfg, streamId);
            const rawExt = info?.movie_data?.container_extension;
            const ext = normalizeContainerExt(rawExt);
            const extStated = statedContainerExt(rawExt) !== null;
            const proxyUrl = `${getBaseUrl(req)}/${req.params.config}/proxy/movie/${streamId}.${ext}`;
            // Cacheable like the live answer: the proxy URL is stable for a
            // given title, because it is the proxy that re-resolves the
            // provider's short-lived token on every playback, not this response.
            // Only when the provider named the container, though: a guessed mp4
            // held by the client for an hour outlives any fix to the provider's
            // data.
            return res.json({
                streams: [
                    {
                        url: proxyUrl,
                        title: '▶ Play',
                        behaviorHints: {
                            notWebReady: isNotWebReady(proxyUrl, ext),
                            bingeGroup: `xtremio-movie-${ext}`
                        }
                    }
                ],
                ...(extStated ? withCacheHints(res, 3600) : {})
            });
        }

        if (id.startsWith('xtremio_episode_')) {
            // Format: xtremio_episode_{seriesId}:{season}:{episodeId}
            const parsed = parseEpisodeId(id);
            if (!parsed) return res.status(400).json({ streams: [] });
            const { seriesId, seasonNum, episodeId } = parsed;

            const findEpisode = (data) => {
                const eps = (data?.episodes ?? {})[seasonNum];
                return Array.isArray(eps) ? eps.find(e => String(e.id) === episodeId) || null : null;
            };

            const info = await getSeriesInfo(cfg, seriesId);
            const rawExt = findEpisode(info)?.container_extension;
            // Not cached when guessed, for the same reason as the movie branch.
            const extStated = statedContainerExt(rawExt) !== null;
            if (!extStated) {
                console.warn(`[stream] episode ${episodeId} is missing from series ${seriesId} info or names no container; defaulting to mp4`);
            }
            const ext = normalizeContainerExt(rawExt);

            const proxyUrl = `${getBaseUrl(req)}/${req.params.config}/proxy/series/${episodeId}.${ext}`;
            return res.json({
                streams: [
                    {
                        url: proxyUrl,
                        title: '▶ Play',
                        behaviorHints: {
                            notWebReady: isNotWebReady(proxyUrl, ext),
                            bingeGroup: `xtremio-series-${seriesId}-${ext}`
                        }
                    }
                ],
                ...(extStated ? withCacheHints(res, 3600) : {})
            });
        }

        res.json({ streams: [] });
    } catch (e) {
        logRouteError('stream', e);
        res.json({ streams: [] });
    }
});

// Read a capped body for rewriting. Unlike the streaming path this has to hold
// the whole thing in memory, so an upstream that mislabels a video as a
// playlist must not be allowed to fill the heap.
async function readTextCapped(body, maxBytes) {
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
            await reader.cancel().catch(() => {});
            throw new Error(`playlist exceeded ${maxBytes} bytes`);
        }
        chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks).toString('utf8');
}

// The shared body of both proxy routes: resolve the upstream, forward the
// headers that matter for playback, and either rewrite a playlist or stream
// the bytes through. Both routes need identical abort, timeout and
// header-forwarding behaviour, so it lives in one place — the difference
// between them is only how the upstream URL is arrived at.
//
// `rewriteFor` is called with the response's final URL and content type; it
// returns a mapper for playlist URIs, or null to stream the body untouched.
// RFC 9110 §14.3: Accept-Ranges carries a range-*unit* — `bytes` or `none` —
// not a range. A real provider answers a ranged movie request with
// `accept-ranges: 0-3328437858`, which this proxy relayed verbatim; a strict
// player that cannot parse the unit may conclude ranges are unsupported and
// disable seeking, or fall back to pulling a 3.3 GB file linearly.
//
// The opposite mistake lived here too: whenever upstream omitted the header the
// proxy asserted `bytes`, and an origin that *ignores* Range answers 200 with
// the whole body. Measured against the real provider, a player asking for 2 KB
// of an HLS segment was told ranges work and handed 3,675,400 bytes — and in
// that exchange upstream's own `accept-ranges: bytes` was the lie, so trusting
// a well-formed value is not enough either.
//
// So the header is decided by what the exchange actually demonstrated, in that
// order of confidence, rather than by what either side claims.
const RANGE_UNIT = /^(?:bytes|none)$/i;

function normalizeAcceptRanges({ status, upstreamValue, sentRange, sentIfRange }) {
    // A 206 is proof: the origin honoured a byte range in this very exchange.
    if (status === 206) return 'bytes';

    // We asked for a range and did not get a partial body, so the origin
    // ignored it. An If-Range that failed to match legitimately produces a
    // whole 200 and proves nothing, so that case falls through instead.
    if (sentRange && !sentIfRange) return null;

    // No evidence from this exchange: trust a well-formed unit from upstream.
    const unit = String(upstreamValue || '').trim();
    if (RANGE_UNIT.test(unit)) return unit.toLowerCase();

    // Nothing usable either way. Stay optimistic, as before: plenty of Xtream
    // CDNs serve ranges without advertising them, and nothing here contradicts
    // that. Never relay a malformed value — omitting beats lying, and this
    // returns a valid unit or nothing at all.
    return 'bytes';
}

async function relayUpstream(req, res, { upstreamUrl, label, ext, rewriteFor }) {
    const headers = { 'User-Agent': PROXY_USER_AGENT };
    // A Range on a playlist would yield a partial body that cannot be parsed or
    // rewritten. Players do not range-request playlists; skip it when we already
    // know from the extension that one is coming.
    const expectPlaylist = String(ext || '').toLowerCase() === 'm3u8';
    if (!expectPlaylist) {
        // Left unset, undici's fetch offers gzip/deflate. An origin that honours
        // that on a byte relay answers a Range with a Content-Range in
        // *compressed* offsets, which no longer describe the decompressed bytes
        // relayed — and decompressing video spends CPU on the relaying thread.
        // Playlists keep the default: they are text and rewritten whole.
        headers['Accept-Encoding'] = 'identity';
        if (req.headers.range) headers['Range'] = req.headers.range;
        if (req.headers['if-range']) headers['If-Range'] = req.headers['if-range'];
    }
    // What we asked for is half the evidence normalizeAcceptRanges needs below.
    const sentRange = Boolean(headers['Range']);
    const sentIfRange = Boolean(headers['If-Range']);

    const controller = new AbortController();
    const abort = () => {
        if (!controller.signal.aborted) {
            try { controller.abort(); } catch {}
        }
    };
    req.on('close', abort);
    req.on('aborted', abort);

    const isAbortErr = (e) => e && (e.name === 'AbortError' || e.code === 'ABORT_ERR' || controller.signal.aborted);

    let upstream;
    let finalUrl = upstreamUrl;
    // Bound the wait for response *headers* only. An upstream that accepts the
    // connection and then stalls would otherwise pin this request and its
    // socket forever. The timer is cleared as soon as headers arrive so the
    // body itself can stream for as long as playback needs.
    let headersTimedOut = false;
    const headerTimer = setTimeout(() => { headersTimedOut = true; abort(); }, PROXY_HEADER_TIMEOUT_MS);
    try {
        // A HEAD from the player used to become a GET upstream whose body was
        // then dropped unread, spending a buffer window of the provider's
        // bandwidth — bounded by undici's backpressure, but wasted, and a movie
        // here is routinely 3 GB. So the method is passed through.
        //
        // But HEAD cannot be trusted to work, and the failure is not tidy.
        // Measured against a real Xtream account: the panel answers HEAD with
        // **502 and no redirect at all**, and the CDN behind its 302 drops the
        // connection outright, so `fetch` *throws* rather than returning a
        // status. An earlier version of this fell back only on 405/501 and
        // turned every real HEAD into a 502 — the regression this shape exists
        // to prevent. Anything short of a usable response therefore falls back
        // to the GET that has always worked: one wasted round trip on providers
        // that reject HEAD, against a whole body saved on those that honour it.
        if (req.method === 'HEAD') {
            try {
                const head = await safeFetch(upstreamUrl, {
                    method: 'HEAD',
                    headers,
                    signal: controller.signal
                }, { onFinalUrl: (u) => { finalUrl = u; } });
                if (head.status < 400) upstream = head;
                else discardBody(head);
            } catch (e) {
                // A timeout or a client disconnect is not a statement about HEAD
                // support, and retrying would paper over it.
                if (headersTimedOut || isAbortErr(e)) throw e;
            }
        }

        if (!upstream) {
            upstream = await safeFetch(upstreamUrl, {
                method: 'GET',
                headers,
                signal: controller.signal
            }, { onFinalUrl: (u) => { finalUrl = u; } });
        }
    } catch (e) {
        if (headersTimedOut) {
            console.warn(`[proxy] upstream headers timed out after ${PROXY_HEADER_TIMEOUT_MS}ms for ${label}`);
            if (!res.headersSent) res.status(504).end('upstream timeout');
            return;
        }
        if (!isAbortErr(e)) {
            console.warn(`[proxy] upstream fetch failed for ${label}: ${e.message}`);
        }
        if (!res.headersSent) res.status(502).end('upstream fetch failed');
        return;
    } finally {
        clearTimeout(headerTimer);
    }

    const contentType = upstream.headers.get('content-type');
    // Only a complete 200 body is rewritable; a 206 is a fragment, and an error
    // body is not a playlist whatever the extension says. A successful HEAD has
    // no body at all, but still needs to know a GET would be rewritten, so its
    // headers do not describe the provider's unrewritten body.
    const mapper = (upstream.status === 200 && (upstream.body || req.method === 'HEAD') && rewriteFor)
        ? rewriteFor(finalUrl, contentType)
        : null;

    // Fail closed on a playlist we cannot rewrite. The sub-resource route has
    // to forward Range, because EXT-X-BYTERANGE segments depend on it, so a
    // ranged request for a nested playlist would come back 206 and skip the
    // rewrite above — relaying the provider's credential-bearing URIs verbatim,
    // which is the one thing this whole path exists to prevent. Players do not
    // range-request playlists, so refusing costs nothing real.
    if (!mapper && upstream.status === 206 && looksLikePlaylist(ext, contentType)) {
        console.warn(`[proxy] refusing to relay a partial playlist for ${label}`);
        discardBody(upstream);
        if (!res.headersSent) res.status(502).end('partial playlist');
        return;
    }

    if (mapper && req.method !== 'HEAD') {
        let text;
        // The header timer is gone by now — correct for the streaming path,
        // where a long body is the point, but this branch buffers the whole
        // thing before answering. An upstream that sends headers and then
        // trickles one byte a minute would otherwise hold the request, its
        // socket and up to MAX_PLAYLIST_BYTES of buffer indefinitely;
        // REQUEST_TIMEOUT_MS does not help, since that bounds receiving the
        // *request*. A playlist is kilobytes, so this deadline is generous.
        let bodyTimedOut = false;
        const bodyTimer = setTimeout(() => { bodyTimedOut = true; abort(); }, PLAYLIST_BODY_TIMEOUT_MS);
        try {
            text = await readTextCapped(upstream.body, MAX_PLAYLIST_BYTES);
        } catch (e) {
            if (bodyTimedOut) {
                console.warn(`[proxy] playlist body timed out after ${PLAYLIST_BODY_TIMEOUT_MS}ms for ${label}`);
                if (!res.headersSent) res.status(504).end('upstream timeout');
                return;
            }
            if (!isAbortErr(e)) console.warn(`[proxy] playlist read failed for ${label}: ${e.message}`);
            // readTextCapped holds a reader, so the body is locked and cannot be
            // cancelled — abort the request instead of leaving the socket half-read.
            abort();
            if (!res.headersSent) res.status(502).end('bad playlist');
            return;
        } finally {
            clearTimeout(bodyTimer);
        }

        // The body settles what the headers could only suggest. Whether to take
        // this branch has to be decided before a byte arrives — the alternative
        // is a segment that must not be buffered — so a target that says .m3u8
        // and is really a video stream gets this far, and parsing one as a
        // playlist would hand the player a mangled body.
        // Refused rather than relayed: if this *is* a playlist whose first line
        // went missing, relaying it verbatim is the credential disclosure the
        // rewrite exists to prevent, and a player rejects a playlist with no
        // #EXTM3U either way.
        if (!HLS_BODY_PREFIX.test(text)) {
            console.warn(`[proxy] expected a playlist for ${label} but the body does not start with #EXTM3U; refusing`);
            if (!res.headersSent) res.status(502).end('bad playlist');
            return;
        }

        // The two timers above are both cleared by now, so this phase carries its
        // own deadline. See PLAYLIST_REWRITE_TIMEOUT_MS.
        let rewritten;
        try {
            rewritten = await rewriteHlsPlaylist(text, finalUrl, mapper, {
                deadline: Date.now() + PLAYLIST_REWRITE_TIMEOUT_MS
            });
        } catch (e) {
            const timedOut = e.code === 'PLAYLIST_REWRITE_TIMEOUT';
            const refused = e.code === 'PLAYLIST_TARGET_REFUSED';
            const how = timedOut
                ? `timed out after ${PLAYLIST_REWRITE_TIMEOUT_MS}ms`
                : (refused ? 'refused a target' : 'failed');
            console.warn(
                `[proxy] playlist rewrite ${how} for ${label}${timedOut ? '' : `: ${e.message}`}`
            );
            if (!res.headersSent) {
                res.status(timedOut ? 504 : 502)
                    .end(timedOut ? 'upstream timeout' : (refused ? 'playlist target refused' : 'bad playlist'));
            }
            return;
        }
        res.status(upstream.status);
        // Deliberately not forwarding content-length: the rewritten body is a
        // different size. Nor accept-ranges — a playlist is not seekable.
        if (contentType) res.setHeader('Content-Type', contentType);
        res.setHeader('Cache-Control', 'no-store');
        return res.end(Buffer.from(rewritten, 'utf8'));
    }

    res.status(upstream.status);

    // Forward headers relevant for seekable playback.
    // accept-ranges is deliberately absent: it is the one header here that is a
    // claim about the origin rather than a fact about this body, so it is
    // derived below instead of relayed.
    const forward = [
        'content-type',
        'content-length',
        'content-range',
        'last-modified',
        'etag'
    ];
    // undici decompresses transparently, so on a content-encoded response the
    // body handed to us is longer than the content-length that came with it.
    // Forwarding that number makes the client stop short or hang waiting for
    // bytes that already arrived. Unlikely for media, plausible for a playlist
    // or an error page, and the length is optional — Express falls back to
    // chunked encoding without it.
    const encoded = Boolean(upstream.headers.get('content-encoding'));
    // Only a HEAD reaches here with a mapper. The GET it previews is rewritten,
    // so upstream's length is the wrong body's, and a playlist is not seekable —
    // the same two headers the rewrite branch above leaves out.
    const previewsRewrite = Boolean(mapper);
    for (const h of forward) {
        if ((encoded || previewsRewrite) && h === 'content-length') continue;
        const v = upstream.headers.get(h);
        if (v) res.setHeader(h, v);
    }

    const acceptRanges = previewsRewrite ? null : normalizeAcceptRanges({
        status: upstream.status,
        upstreamValue: upstream.headers.get('accept-ranges'),
        sentRange,
        sentIfRange
    });
    if (acceptRanges) res.setHeader('Accept-Ranges', acceptRanges);
    res.setHeader('Cache-Control', 'no-store');

    if (req.method === 'HEAD' || !upstream.body) {
        // A HEAD that fell back to GET above still has a body nobody will read.
        discardBody(upstream);
        return res.end();
    }

    const nodeStream = Readable.fromWeb(upstream.body);
    nodeStream.on('error', (e) => {
        if (!isAbortErr(e)) {
            console.warn(`[proxy] stream error for ${label}: ${e.message}`);
        }
        // The client is already gone, or the response already finished.
        if (res.destroyed || res.writableEnded) return;
        // Once bytes are on the wire the status and length are promised, and a
        // dead connection is the only honest signal left. Ending the response
        // instead left a keep-alive socket open with the client waiting for the
        // bytes its Content-Length still promised — measured against this relay:
        // 500 of 1,000 bytes, socket still open 8 s later, until keepAliveTimeout.
        // A closed connection is what makes a player retry with a Range request.
        if (res.headersSent) return res.destroy();
        // Nothing sent yet, but the headers set above describe the upstream body,
        // not a 502: sent as they were, the 502 promised the movie's full length
        // and delivered nothing. The length is set again explicitly because
        // removing it tells Node the response has none, and it falls back to
        // chunked encoding.
        for (const h of [...forward, 'accept-ranges']) res.removeHeader(h);
        const body = 'upstream stream failed';
        res.status(502);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Content-Length', String(Buffer.byteLength(body)));
        res.end(body);
    });
    res.on('error', () => abort());
    res.on('close', () => {
        abort();
        nodeStream.destroy();
    });
    nodeStream.pipe(res);
}

// Stream proxy. Xtream providers 302-redirect to a CDN URL that carries
// a short-lived signed token (~60s). Handing that URL directly to
// Stremio causes "playback error" after ~1 minute when the token
// expires. By proxying every range request through the addon, we
// re-resolve the origin URL (and get a fresh token) for each request.
//
// It also keeps the account credentials on the server: the upstream path
// embeds username and password, and this is what stops that URL reaching the
// player. Live channels use it for the same reason (see the stream route).
// Signing a target hands out a capability, and the URIs come from the provider,
// not from us — a hostile or compromised panel can put any absolute URL in its
// playlist. Signing one the server would refuse to fetch is the wrong default,
// so the same check runs here. A target that cannot be signed is not left in the
// playlist verbatim: those lines are the provider's own credential-bearing URLs,
// so rewriteHlsPlaylist refuses the playlist instead (502) and the warnings below
// name the setting that would admit the host.
// This is defence in depth over the fetch-time check, not a replacement for it.
// Escape hatch for a provider that genuinely fans segments out beyond the panel
// and the playlist's own origin. Hostnames rather than origins, so a provider
// serving the playlist over http and its segments over https needs one entry, not
// two. Empty by default — the two derived origins cover every real provider seen
// so far, and every entry here is a host this server will fetch from on request.
// Parsed by the same parseHostList as ALLOWED_PANEL_HOSTS, so an entry written as
// `host:port` or as a URL names its host here too, rather than never matching.
const HLS_TARGET_ALLOWED_HOSTS = parseHostList(process.env.HLS_TARGET_ALLOWED_HOSTS, 'HLS_TARGET_ALLOWED_HOSTS');

// The origins a playlist is allowed to name. The account's own panel is not
// enough on its own: real providers 302 the playlist to a CDN on a different
// host — one live account here serves its segments from a bare IP that is not the
// panel hostname at all — so the origin the playlist was *finally* fetched from
// has to be in the set too, alongside the one it was requested from.
// normalizeUrl throws on an empty serverUrl, and a config that decoded is not a
// guarantee of a usable one. A panel with no origin simply contributes nothing to
// the allowed set rather than taking the request down.
function panelOrigin(cfg) {
    try {
        return normalizeUrl(cfg.serverUrl);
    } catch {
        return null;
    }
}

function hlsTargetOrigins(...candidates) {
    const origins = new Set();
    for (const candidate of candidates) {
        if (!candidate) continue;
        try {
            origins.add(new URL(candidate).origin);
        } catch { /* not a usable origin; simply contributes nothing */ }
    }
    return origins;
}

// `allowedOrigins` is required and there is deliberately no permissive default:
// a caller that forgets it signs nothing, which fails closed and shows up
// immediately, rather than quietly restoring the playlist relay this closes.
// Closes it for playlists from an honest panel, that is (audit D1): a malicious
// panel's own origin and final URL are in the set by construction. That case is
// S3, closed by ALLOWED_PANEL_HOSTS and otherwise bounded by the relay caps.
function makeHlsProxyMapper(base, configToken, allowedOrigins) {
    // Playlists name hundreds of segments on one host, so vetting is per origin —
    // one DNS resolution rather than hundreds, and now shared across passes via
    // hlsOriginVetCache rather than only within one.
    //
    // Distinct origins are capped per playlist because each new one costs a
    // resolution and a real playlist names one or two. Past the cap nothing more
    // is signed and no further lookups are made, which refuses the playlist —
    // a playlist naming more hosts than the cap is hostile or broken either way.
    const seen = new Set();
    let warned = false;
    let refusedOrigin = false;
    return async (absolute, playlist = false) => {
        let url;
        try {
            url = new URL(absolute);
        } catch {
            return null;
        }
        const origin = url.origin;

        // Checked before the cap and before any DNS work, so a playlist naming
        // hosts this account has no business fetching costs nothing at all.
        // assertSafeOutboundUrl below only refuses *private* targets, which left
        // every public host a playlist named signable — and therefore fetchable and
        // relayable from the operator's address. This bounds what a compromised or
        // misbehaving playlist can reach; it cannot bound a panel that is itself
        // hostile, whose own hosts are the allowed ones (audit D1, and see S3).
        if (!(allowedOrigins && allowedOrigins.has(origin))
            && !HLS_TARGET_ALLOWED_HOSTS.has(url.hostname.toLowerCase())) {
            if (!refusedOrigin) {
                refusedOrigin = true;
                console.warn(
                    `[proxy] playlist names ${origin}, which is neither the account's panel nor the ` +
                    'origin the playlist came from; refusing the playlist ' +
                    '(add it to HLS_TARGET_ALLOWED_HOSTS if the provider legitimately uses it)'
                );
            }
            return null;
        }

        if (!seen.has(origin)) {
            if (seen.size >= MAX_PLAYLIST_ORIGINS) {
                if (!warned) {
                    warned = true;
                    console.warn(
                        `[proxy] playlist names more than ${MAX_PLAYLIST_ORIGINS} distinct origins; ` +
                        'refusing the playlist (raise MAX_PLAYLIST_ORIGINS if a provider legitimately fans out)'
                    );
                }
                return null;
            }
            seen.add(origin);
        }

        if (!await vetHlsOrigin(absolute, origin)) return null;

        const { u, s, e } = encodeHlsTarget(absolute, configToken, Date.now(), playlist);
        return `${base}/${configToken}/proxy/hls?u=${u}&s=${s}&e=${e}`;
    };
}

// An install URL is a bearer credential, and one that leaks or is deliberately
// shared can open as many simultaneous relays as the sharers have players — each
// one a full-rate video stream out of this server's egress, paid for by the
// operator. Nothing else here bounds that: the caches bound memory and the
// timeouts bound stalled requests, but a thousand healthy concurrent relays look
// exactly like a popular household.
//
// The counter is keyed by *account* rather than by the token string, even though
// the limit is named for the token: `/configure` will mint a fresh token for the
// same credentials on demand (the IV is random, so the ciphertext differs every
// time), and a budget that a new install URL resets is not a budget. Two people
// legitimately sharing one account share one allowance, which is the same thing
// the provider's own connection limit already does.
//
// Set to 0 to disable, for an operator whose reverse proxy already does this.
// The default is generous on purpose — a single player keeps one or two relays
// open, a live HLS channel two or three, and a household with several devices
// still lands far below it — so reaching it means something is wrong rather than
// something is popular.
//
// Parsed by hand rather than with the `Number(x) || default` the cache bounds
// use, because 0 is a *meaningful* value here and that idiom would quietly turn
// the documented way to disable the limit into the default. An empty or
// unparseable setting is treated as unset.
function relayLimitFromEnv(name, fallback) {
    const raw = process.env[name];
    if (typeof raw !== 'string' || !raw.trim()) return fallback;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

const PROXY_MAX_CONCURRENT_PER_TOKEN = relayLimitFromEnv('PROXY_MAX_CONCURRENT_PER_TOKEN', 16);

// Two more budgets over the same relays, because the one above is keyed by account
// and an account is free. /configure mints one for any panel that passes the
// credential check, so a caller with a panel of their own — or many made-up
// usernames on one — gets a fresh per-account allowance each time (audit S3). On
// an instance where anyone may bring any provider, nothing about the account can be
// relied on to bound the traffic.
//
// Per client, because addresses are not free: keyed by clientKey, so an IPv6 client
// counts by its /64 and a proxied one by the address TRUST_PROXY vouches for. The
// default sits well above a household — several players at two or three relays
// each — and is generous on purpose, since carrier NAT puts many unrelated users
// behind one address.
// And in total, because a caller with many addresses is still bounded by the
// server's own capacity. That one is the operator's to size to their bandwidth; the
// default is a ceiling a small host should lower, not a recommendation.
// Both are parsed like the per-token limit, where 0 disables.
const PROXY_MAX_CONCURRENT_PER_CLIENT = relayLimitFromEnv('PROXY_MAX_CONCURRENT_PER_CLIENT', 32);
const PROXY_MAX_CONCURRENT_TOTAL = relayLimitFromEnv('PROXY_MAX_CONCURRENT_TOTAL', 256);

const proxyInFlight = new Map();          // relays per account
const proxyInFlightByClient = new Map();  // relays per client bucket
const proxyRelays = { total: 0 };         // an object, so an importer sees it change

function releaseCount(map, key) {
    const left = (map.get(key) || 1) - 1;
    // Delete at zero: the key space is every account and address that ever
    // streamed, and an idle one must not cost an entry.
    if (left > 0) map.set(key, left);
    else map.delete(key);
}

// Takes a slot for the life of this response, or returns the limit that refused it
// ({ scope }) for rejectOverCap. Null means the relay may go ahead. All three limits
// are checked before any is counted, so a refused request holds nothing.
// The release is bound to the response's `close` event rather than to the end of
// the handler: `relayUpstream` returns as soon as the body is piped, while the
// relay it started may run for hours. `close` fires exactly once, on a finished
// response and on a dropped connection alike, which is what keeps the counts from
// drifting upward until a cap locks a caller out permanently.
function acquireProxySlot(cfg, req, res) {
    if (!PROXY_MAX_CONCURRENT_PER_TOKEN && !PROXY_MAX_CONCURRENT_PER_CLIENT && !PROXY_MAX_CONCURRENT_TOTAL) {
        return null;
    }
    const account = accountCacheKey(cfg);
    const client = clientKey(req);
    const byAccount = proxyInFlight.get(account) || 0;
    const byClient = proxyInFlightByClient.get(client) || 0;

    if (PROXY_MAX_CONCURRENT_PER_TOKEN && byAccount >= PROXY_MAX_CONCURRENT_PER_TOKEN) {
        console.warn(
            `[proxy] per-account concurrency cap reached (${byAccount}/${PROXY_MAX_CONCURRENT_PER_TOKEN}); ` +
            'raise PROXY_MAX_CONCURRENT_PER_TOKEN if this is legitimate traffic'
        );
        return { scope: 'account' };
    }
    if (PROXY_MAX_CONCURRENT_PER_CLIENT && byClient >= PROXY_MAX_CONCURRENT_PER_CLIENT) {
        console.warn(
            `[proxy] per-client concurrency cap reached for ${client} (${byClient}/${PROXY_MAX_CONCURRENT_PER_CLIENT}); ` +
            'raise PROXY_MAX_CONCURRENT_PER_CLIENT if this is legitimate traffic, or check TRUST_PROXY if every client shares one address'
        );
        return { scope: 'client' };
    }
    if (PROXY_MAX_CONCURRENT_TOTAL && proxyRelays.total >= PROXY_MAX_CONCURRENT_TOTAL) {
        console.warn(
            `[proxy] total concurrency cap reached (${proxyRelays.total}/${PROXY_MAX_CONCURRENT_TOTAL}); ` +
            'raise PROXY_MAX_CONCURRENT_TOTAL if the host has the bandwidth'
        );
        return { scope: 'total' };
    }

    if (PROXY_MAX_CONCURRENT_PER_TOKEN) proxyInFlight.set(account, byAccount + 1);
    if (PROXY_MAX_CONCURRENT_PER_CLIENT) proxyInFlightByClient.set(client, byClient + 1);
    if (PROXY_MAX_CONCURRENT_TOTAL) proxyRelays.total += 1;
    let released = false;
    res.once('close', () => {
        if (released) return;
        released = true;
        if (PROXY_MAX_CONCURRENT_PER_TOKEN) releaseCount(proxyInFlight, account);
        if (PROXY_MAX_CONCURRENT_PER_CLIENT) releaseCount(proxyInFlightByClient, client);
        if (PROXY_MAX_CONCURRENT_TOTAL) proxyRelays.total = Math.max(0, proxyRelays.total - 1);
    });
    return null;
}

// A caller over its own budget gets 429: the limit is a property of its usage, not
// of the server's health, and Retry-After tells a player to come back for the
// segment rather than treating it as the end of the stream. The total limit is the
// server's capacity, which is what 503 says, with a longer wait since a slot there
// frees only when someone else's stream ends.
function rejectOverCap(res, refused = { scope: 'account' }) {
    if (refused.scope === 'total') {
        res.setHeader('Retry-After', '5');
        return res.status(503).end('server at stream capacity');
    }
    res.setHeader('Retry-After', '1');
    return res.status(429).end('too many concurrent streams');
}

app.all('/:config/proxy/:kind/:file', async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).end('method not allowed');
    }
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.status(401).end('unauthorized');
    const refused = acquireProxySlot(cfg, req, res);
    if (refused) return rejectOverCap(res, refused);

    const { kind, file } = req.params;
    if (!['movie', 'series', 'live'].includes(kind)) {
        return res.status(400).end('bad kind');
    }
    const match = /^([^./]+)\.([A-Za-z0-9]+)$/.exec(file);
    if (!match) return res.status(400).end('bad file');
    const [, streamId, ext] = match;
    if (!isNumericId(streamId)) return res.status(400).end('bad stream id');

    // A token minted before server_info was validated can hold a server URL that
    // does not parse. Node puts the rejected input on the TypeError, and here that
    // input is this path — username and password included — so the failure is
    // answered on the spot rather than thrown to the terminal handler's log.
    let serverUrl;
    let upstreamUrl;
    try {
        serverUrl = normalizeUrl(cfg.serverUrl);
        upstreamUrl = new URL(
            `/${kind}/${encodeURIComponent(cfg.username)}/${encodeURIComponent(cfg.password)}/${streamId}.${ext}`,
            serverUrl
        ).toString();
    } catch {
        console.warn('[proxy] the configured server URL does not parse; the account needs reconfiguring');
        return res.status(502).end('bad upstream');
    }

    const base = getBaseUrl(req);
    await relayUpstream(req, res, {
        upstreamUrl,
        label: `${kind}/${streamId}.${ext}`,
        ext,
        rewriteFor: (finalUrl, contentType) => {
            if (!looksLikePlaylist(ext, contentType)) return null;
            return makeHlsProxyMapper(
                base,
                req.params.config,
                hlsTargetOrigins(serverUrl, upstreamUrl, finalUrl)
            );
        }
    });
});

// Sub-resources of a proxied playlist: variant playlists, segments and keys.
// Reached only through URLs this server generated and signed, so the target is
// not caller-chosen despite being carried in the query string. A nested
// playlist is rewritten in turn, which is what makes master playlists work.
app.all('/:config/proxy/hls', async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).end('method not allowed');
    }
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.status(401).end('unauthorized');
    const refused = acquireProxySlot(cfg, req, res);
    if (refused) return rejectOverCap(res, refused);

    // Bound to this config token: a signature minted for another account's
    // playlist does not verify here, even though the keys are shared by every
    // account on this instance.
    const target = decodeHlsTarget(req.query.u, req.query.s, req.query.e, req.params.config);
    if (!target) return res.status(400).end('bad target');

    const upstreamUrl = target.url;
    // What the playlist said this target was, or what its path says. Content
    // type alone used to decide it here, which missed every variant playlist a
    // provider labelled text/plain: the body was then relayed untouched, with
    // the credential-bearing URIs the rewrite exists to remove still in it.
    // Supplying the extension also withholds Range, so the response cannot come
    // back a 206 that skips the rewrite.
    const ext = hlsTargetExt(target);

    const base = getBaseUrl(req);
    await relayUpstream(req, res, {
        upstreamUrl,
        label: 'hls sub-resource',
        ext,
        rewriteFor: (finalUrl, contentType) => {
            if (!looksLikePlaylist(ext, contentType)) return null;
            // A nested playlist keeps the same rule. `upstreamUrl` is included as
            // well as `finalUrl` because a variant playlist that redirects may
            // still name its segments back on the host it was fetched from.
            return makeHlsProxyMapper(
                base,
                req.params.config,
                hlsTargetOrigins(panelOrigin(cfg), upstreamUrl, finalUrl)
            );
        }
    });
});

app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>xTremio &mdash; Stremio Addon</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Stremio addon that exposes any Xtream Codes IPTV provider as Live TV, Movies and Series.">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #fff;
            padding: 20px;
            text-align: center;
        }
        .wrap { max-width: 560px; width: 100%; }
        .logo {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 72px; height: 72px;
            background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
            border-radius: 20px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(124,77,255,0.4);
        }
        .logo svg { width: 38px; height: 38px; color: #fff; }
        h1 { font-size: 36px; font-weight: 700; margin-bottom: 12px; letter-spacing: -0.5px; }
        .tagline { font-size: 17px; color: rgba(255,255,255,0.75); margin-bottom: 36px; line-height: 1.5; }
        .features {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 36px;
        }
        .feature {
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 16px 10px;
            font-size: 13px;
            color: rgba(255,255,255,0.85);
        }
        .feature b { display: block; color: #fff; font-size: 14px; margin-bottom: 4px; }
        .btn {
            display: inline-flex; align-items: center; gap: 10px;
            padding: 16px 36px;
            background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
            color: #fff; text-decoration: none;
            border-radius: 12px;
            font-size: 16px; font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 8px 20px rgba(124,77,255,0.3);
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 12px 30px rgba(124,77,255,0.5); }
        .btn svg { width: 20px; height: 20px; }
        .links {
            margin-top: 28px;
            font-size: 14px;
            color: rgba(255,255,255,0.6);
        }
        .links a {
            color: rgba(255,255,255,0.85);
            text-decoration: none;
            border-bottom: 1px solid rgba(255,255,255,0.3);
            padding-bottom: 1px;
        }
        .links a:hover { color: #fff; border-bottom-color: #fff; }
        .footer {
            margin-top: 40px;
            font-size: 12px;
            color: rgba(255,255,255,0.4);
            line-height: 1.6;
        }
        @media (max-width: 520px) {
            h1 { font-size: 28px; }
            .features { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="logo">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </div>
        <h1>xTremio</h1>
        <p class="tagline">A Stremio addon that turns your Xtream Codes IPTV provider into browseable Live TV, Movies, and Series catalogs.</p>

        <div class="features">
            <div class="feature"><b>Live TV</b>Watch your channels</div>
            <div class="feature"><b>Movies &amp; Series</b>Full VOD catalog</div>
            <div class="feature"><b>Global Search</b>Across everything</div>
        </div>

        <a href="/configure" class="btn">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
            Install Addon
        </a>

        <div class="links">
            <a href="https://github.com/izemhsn/xTremio-stremio-addon" target="_blank" rel="noopener">View on GitHub</a>
        </div>

        <div class="footer">
            This is a self-hosted technical gateway. No media is hosted here.<br>
            You must supply your own legally obtained Xtream Codes account.
        </div>
    </div>
</body>
</html>`);
});

// --- Server lifecycle ---
// This process is a streaming proxy, not a plain JSON API: a single request can
// hold a socket open for the length of a movie. That changes what the right
// timeout and shutdown behaviour are, so both are stated explicitly rather than
// left on Node's defaults.

const SHUTDOWN_TIMEOUT_MS = Math.max(1000, Number(process.env.SHUTDOWN_TIMEOUT_MS) || 10000);
// Deliberately longer than the 60 s idle timeout most load balancers use, so the
// balancer is always the side that closes an idle connection. If we closed first
// there is a race where a request arrives on a socket we have just torn down,
// which the balancer reports to the user as a 502.
const KEEPALIVE_TIMEOUT_MS = Math.max(1000, Number(process.env.KEEPALIVE_TIMEOUT_MS) || 65000);
// Must exceed keepAliveTimeout, or a socket idling between keep-alive requests
// is killed as if it were a slow header write.
const HEADERS_TIMEOUT_MS = Math.max(KEEPALIVE_TIMEOUT_MS + 1000, Number(process.env.HEADERS_TIMEOUT_MS) || 66000);
// Caps how long we will spend receiving a *request*. The response body is not
// affected, so a proxied stream may still run for hours.
const REQUEST_TIMEOUT_MS = Math.max(HEADERS_TIMEOUT_MS, Number(process.env.REQUEST_TIMEOUT_MS) || 120000);

let shuttingDown = false;
function isShuttingDown() { return shuttingDown; }
// Test-only: the flag is process-wide, so a test that exercises the drain path
// needs a way back.
function setShuttingDown(value) { shuttingDown = Boolean(value); }

function applyServerTimeouts(server) {
    server.keepAliveTimeout = KEEPALIVE_TIMEOUT_MS;
    server.headersTimeout = HEADERS_TIMEOUT_MS;
    server.requestTimeout = REQUEST_TIMEOUT_MS;
    // Already Node's default, but stated because a non-zero socket inactivity
    // timeout here would kill a paused or slow-buffering stream mid-playback.
    server.timeout = 0;
    return server;
}

function createShutdownHandler(server, { timeoutMs = SHUTDOWN_TIMEOUT_MS, exit = (code) => process.exit(code), log = console } = {}) {
    let started = false;
    return function shutdown(signal) {
        if (started) return;
        started = true;
        setShuttingDown(true);   // /health starts failing, so a balancer drains us
        log.log(`${signal} received, shutting down...`);

        // An in-flight movie stream can hold its socket for hours, so server.close()
        // on its own waits until the platform loses patience and SIGKILLs us
        // mid-write. Give real requests a window, then leave regardless.
        const forced = setTimeout(() => {
            log.warn(`Shutdown still pending after ${timeoutMs} ms, forcing exit.`);
            exit(1);
        }, timeoutMs);
        if (typeof forced.unref === 'function') forced.unref();

        server.close(() => {
            clearTimeout(forced);
            exit(0);
        });
        // Sockets parked between keep-alive requests have nothing to drain, but
        // would still make close() wait out the full window.
        if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
    };
}

app.get('/health', (req, res) => {
    // Reporting unhealthy while draining is the point: it takes this instance out
    // of the load balancer pool before the process actually goes away, instead of
    // letting it keep receiving requests it is about to drop.
    const draining = isShuttingDown();
    res.status(draining ? 503 : 200)
        .set('Cache-Control', 'no-store')
        .json({ status: draining ? 'shutting_down' : 'ok', uptime: process.uptime() });
});

// A path begins with the config token, which is a bearer credential: it
// decrypts to the account's password. Logging one would put working install
// URLs in the log file, so the first segment is dropped when it is long enough
// to be a token rather than a route name.
function redactConfigInPath(path) {
    return String(path).replace(/^\/[^/]{24,}/, '/<config>');
}

// Unknown paths, so Express's default HTML 404 (which names the method and the
// path) never reaches a client.
app.use((req, res) => {
    res.status(404).type('text/plain').end('not found');
});

// Terminal error handler. Express's default one writes the stack into the
// response whenever NODE_ENV is not exactly 'production' — absolute filesystem
// paths, this file's line numbers and the dependency tree, to anyone who can
// reach the port. Two routes into it were reachable unauthenticated: a
// non-string field on POST /configure, and a malformed percent-escape anywhere
// in a path, which throws a URIError out of the router *before* any handler
// runs. Nothing a handler does can catch the second one — only this can.
//
// Registered last because Express matches middleware in order, and an error
// handler only sees throws from what was registered before it. The four
// parameters are what identify it as one, so `next` stays whether or not every
// path uses it.
function terminalErrorHandler(err, req, res, next) {
    // A URIError from decodeParam means the client sent a bad path, not that
    // the server broke; anything carrying its own status (body-parser and
    // friends) is trusted to have set a sensible one — but only inside the
    // error range, since res.status() will send whatever it is given.
    const claimed = Number(err?.status || err?.statusCode);
    const status = err instanceof URIError
        ? 400
        : (claimed >= 400 && claimed <= 599 ? claimed : 500);

    const where = `${req.method} ${redactConfigInPath(req.originalUrl || req.url)} -> ${status}`;
    // A 4xx is the client's mistake and arrives as often as someone cares to
    // send one; a stack per malformed path would be a log flood with no
    // information in it. A 5xx is ours, and the stack is the whole point.
    //
    // The stack, not the error object: printing an object prints its own
    // properties too, and some carry request data. A failed `new URL()` holds its
    // rejected input, which on the proxy route was a path with the account's
    // username and password in it. redactConfigInPath covers the request path;
    // nothing could cover properties it never sees.
    if (status >= 500) console.error(`[error] ${where}:`, err?.stack || String(err));
    else console.warn(`[error] ${where}: ${err?.message}`);

    // Once the body has started there is no status left to set, and the
    // response is already half-written; hand back to Express, which closes the
    // connection rather than appending a stack to a partial body.
    if (res.headersSent) return next(err);

    res.status(status).type('text/plain').end(status < 500 ? 'bad request' : 'internal error');
}

app.use(terminalErrorHandler);

// Only bind the port and install process-wide handlers when run directly, so
// `require('./index.js')` from a test can exercise the internals below without
// starting a server or hijacking the test runner's exception handling.
if (require.main === module) {
    // Before binding a port: a production deploy with a weak or absent secret
    // should fail loudly at startup, not quietly issue forgeable install URLs.
    enforceConfigSecretPolicy();
    warnOnUndiciMismatch();

    // Only when actually serving: importing this module for tests should not
    // leave a timer running.
    startCacheSweeper();

    const server = applyServerTimeouts(app.listen(PORT, HOST, () => {
        console.log(`Addon running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
        console.log(`Configure: http://localhost:${PORT}/configure`);
    }));

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`Port ${PORT} is already in use. Kill the existing process or use a different port: PORT=3001 npm start`);
        } else {
            console.error('Server error:', err.message);
        }
        process.exit(1);
    });

    const shutdown = createShutdownHandler(server);
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    // No AbortError exemption. Client disconnects are handled where they happen —
    // the proxy route aborts its own upstream fetch and filters the resulting
    // errors at each failure point — so an abort reaching here would mean a real
    // gap, and swallowing it would hide exactly the `write after end` class of bug
    // this handler exists to catch.
    process.on('uncaughtException', (err) => {
        // Process state is undefined after an uncaught throw. Exiting lets the
        // platform restart us; staying up serves requests from a wedged process
        // that /health would still report as healthy.
        console.error('Uncaught exception, exiting:', err);
        process.exit(1);
    });
    // Same treatment as an uncaught throw, and for the same reason: a rejection
    // nobody handled leaves the process in exactly the undefined state the
    // handler above exists to escape, while /health cheerfully keeps answering
    // 200. Logging and continuing also diverged from Node's own default, which
    // has been to exit since v15. Express 5 forwards async route errors to the
    // terminal error handler, so anything reaching here is a genuine bug rather
    // than routine traffic — including a client disconnect, which the proxy
    // handles locally and which is covered by a test that kills a socket
    // mid-stream and asserts the process survives.
    process.on('unhandledRejection', (err) => {
        console.error('Unhandled rejection, exiting:', err);
        process.exit(1);
    });
}

// Exported for the test suite only — nothing here is a public API.
module.exports = {
    app,
    getManifest,
    encodeConfig,
    decodeConfig,
    xtremioGet,
    UPSTREAM_HEADER_TIMEOUT_MS,
    UPSTREAM_IDLE_TIMEOUT_MS,
    UPSTREAM_BODY_TIMEOUT_MS,
    isProgrammingError,
    noteUndecodableToken,
    undecodableTokens,
    UNDECODABLE_REPORT_INTERVAL_MS,
    validateConfig,
    configSecretProblems,
    enforceConfigSecretPolicy,
    corsApplies,
    deriveConfigKey,
    CONFIG_TOKEN_VERSION,
    CONFIG_SECRET_MIN_BYTES,
    SCRYPT_PARAMS,
    getBaseUrl,
    escapeHtml,
    normalizeUrl,
    serverInfoOrigin,
    hostnameOf,
    sealConfig,
    deriveConfigKeys,
    resolveHostAddresses,
    DNS_TIMEOUT_MS,
    parseHostList,
    panelHostAllowed,
    ALLOWED_PANEL_HOSTS,
    terminalErrorHandler,
    buildUrl,
    buildXtremioApiUrl,
    isNumericId,
    getPrefixedNumericId,
    parseEpisodeId,
    typeMatchesId,
    catalogTypesFor,
    withCacheHints,
    parseCatalogId,
    CATALOG_KINDS,
    catalogComparator,
    filterByName,
    titleOf,
    toCatalogMetas,
    selectCatalogGenre,
    selectCatalogSource,
    sortedCatalogItems,
    sortedCatalogViews,
    normalizeContainerExt,
    statedContainerExt,
    isNotWebReady,
    normalizeAcceptRanges,
    estimateBytes,
    CACHE_MAX_STREAM_BYTES,
    PLAYLIST_BODY_TIMEOUT_MS,
    PLAYLIST_REWRITE_TIMEOUT_MS,
    MAX_PLAYLIST_ORIGINS,
    signTokenBody,
    rewriteHlsPlaylist,
    looksLikePlaylist,
    encodeHlsTarget,
    decodeHlsTarget,
    signHlsTarget,
    HLS_SIGNATURE_TTL_MS,
    MAX_PLAYLIST_BYTES,
    isPrivateIp,
    readJsonCapped,
    MAX_UPSTREAM_BYTES,
    MAX_PARSED_TO_BODY_RATIO,
    weighJson,
    assertSafeOutboundUrl,
    discardBody,
    acquireProxySlot,
    proxyInFlight,
    PROXY_MAX_CONCURRENT_PER_TOKEN,
    PROXY_MAX_CONCURRENT_PER_CLIENT,
    PROXY_MAX_CONCURRENT_TOTAL,
    proxyInFlightByClient,
    proxyRelays,
    makeHlsProxyMapper,
    hlsTargetOrigins,
    HLS_TARGET_ALLOWED_HOSTS,
    hlsOriginVetCache,
    HLS_ORIGIN_VET_TTL_MS,
    asString,
    redactConfigInPath,
    pinnedLookup,
    pinResolvedAddresses,
    dnsPins,
    PINNED_DISPATCHER,
    DNS_PIN_TTL_MS,
    warnOnUndiciMismatch,
    parseExtra,
    rawExtraSegment,
    parseYear,
    toIsoDate,
    splitList,
    pickBackdrop,
    isUsableSeriesInfo,
    isUsableVodInfo,
    getCategories,
    getAllVodStreams,
    getAllSeriesStreams,
    getAllLiveStreams,
    getSeriesInfo,
    getVodInfo,
    getCategoryStreams,
    createSingleFlight,
    createKeyedCache,
    accountCacheKey,
    catCache,
    vodStreamsCache,
    seriesStreamsCache,
    liveStreamsCache,
    seriesInfoCache,
    vodInfoCache,
    categoryStreamsCache,
    CACHE_TTL,
    CACHE_FAILURE_TTL,
    PAGE_SIZE,
    BoundedMap,
    sweepCaches,
    startCacheSweeper,
    CACHE_MAX_ACCOUNTS,
    CACHE_MAX_STREAM_ACCOUNTS,
    CACHE_MAX_SERIES_INFO,
    CACHE_MAX_VOD_INFO,
    CACHE_MAX_CATEGORY_LISTS,
    CACHE_MAX_BYTES,
    CACHE_BUDGET,
    CacheBudget,
    CACHE_STALE_MAX_AGE_MS,
    readSeriesInfoEntry,
    setNegativeSeriesInfo,
    getCachedSeriesInfo,
    setCachedSeriesInfo,
    fetchSeriesInfo,
    SERIES_INFO_NEGATIVE_TTL,
    SERIES_INFO_MAX_ATTEMPTS,
    validateXtremioCredentials,
    describeDowngrade,
    schemeOf,
    renderConfigPage,
    rateLimitConfigure,
    configureAttempts,
    clientKey,
    addressBucket,
    forwardedValue,
    TRUST_PROXY_HOPS,
    CONFIGURE_RATE_LIMIT,
    CONFIGURE_RATE_WINDOW_MS,
    CONFIGURE_RATE_MAX_CLIENTS,
    applyServerTimeouts,
    createShutdownHandler,
    isShuttingDown,
    setShuttingDown,
    SHUTDOWN_TIMEOUT_MS,
    KEEPALIVE_TIMEOUT_MS,
    HEADERS_TIMEOUT_MS,
    REQUEST_TIMEOUT_MS
};