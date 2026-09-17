// The SSRF guard: what this server is willing to connect to, and the DNS pinning
// that makes the answer binding.
//
// The two halves are one module because separating them would misdescribe how
// they work. assertSafeOutboundUrl vets a hostname's addresses and records them
// in dnsPins; PINNED_DISPATCHER connects to those and nothing else. Resolve twice
// — once to check, once to connect — and a near-zero-TTL record can differ
// between the two, which is the rebinding hole the pin closes. Nothing outside
// assertSafeOutboundUrl may write to dnsPins.
const dns = require('node:dns').promises;
const net = require('node:net');
const { Agent: UndiciAgent } = require('undici');

const { isPrivateIp } = require('./private-ip.js');

// Disables the guard for local Xtream panels during development. It also makes
// PINNED_DISPATCHER null, since pinning an address that was never checked would
// claim a vetting that did not happen.
const ALLOW_PRIVATE_NETWORKS = process.env.ALLOW_PRIVATE_NETWORKS === 'true';

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
    // Every pin is (re-)inserted with the same TTL, so insertion order is expiry
    // order and the sweep can stop at the first live one. A pin expired out of
    // order is still refused on read by pinnedLookup.
    for (const [host, entry] of dnsPins) {
        if (entry.expiresAt > now) break;
        dnsPins.delete(host);
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

// The pinned dispatcher comes from the undici dependency and fetch() from Node's
// bundled undici, and not every pairing works. Measured: 6 and 7 interoperate with
// the fetch in Node 20.18.1, 22 and 24; an undici 8 dispatcher fails every request
// on 22 and 24. Only pairings outside the measured set warn (audit D2). The versions
// are parameters so each branch can be tested.
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

// DNS resolution for the SSRF check, with a deadline (audit S6). dns.lookup runs on
// libuv's four-thread pool and cannot be cancelled, so one dead nameserver stalled
// everyone's relays. c-ares runs off the pool, one resolver per lookup, cancelled
// at the deadline. It does not read /etc/hosts, hence the localhost check in
// assertSafeOutboundUrl.
const DNS_TIMEOUT_MS = Math.max(500, Number(process.env.DNS_TIMEOUT_MS) || 5000);

// c-ares reads the nameserver list itself and can get it wrong where the OS works
// (one Windows host gave it only 127.0.0.1). These codes mean the resolver itself is
// unusable, so only they fall back to the OS resolver, under the same deadline. A
// timeout never falls back: that is the stall S6 removed.
const DNS_RESOLVER_UNUSABLE = new Set(['ECONNREFUSED', 'ELOADIPHLPAPI', 'EADDRGETNETWORKPARAMS']);
const dnsFallback = { warned: false };  // an object, so a test can reset it

// The operator's way to hand c-ares the nameservers the OS is using, for the host
// above where it works one out for itself and gets it wrong. Validated by c-ares
// itself rather than by a regular expression of our own: setServers accepts an
// address, `address:port` and `[v6]:port`, and throws ERR_INVALID_IP_ADDRESS on
// anything else, which is exactly the rule we want and not one worth restating.
// A bad entry is dropped with a warning at boot rather than taken silently or
// made fatal — an unreachable nameserver in a list of three should not stop the
// server, and a typo that quietly disabled the setting would be worse than both.
function parseDnsServers(value, name = 'DNS_SERVERS', log = console) {
    const servers = [];
    for (const entry of String(value || '').split(',')) {
        const trimmed = entry.trim();
        if (!trimmed) continue;
        try {
            new dns.Resolver().setServers([trimmed]);
            servers.push(trimmed);
        } catch {
            log.warn(`[config] ${name}: ignoring ${JSON.stringify(trimmed)}, which is not an IP address`);
        }
    }
    return servers;
}

const DNS_SERVERS = parseDnsServers(process.env.DNS_SERVERS);

// Every resolver this module makes, so setting DNS_SERVERS cannot reach some
// lookups and miss others. An empty list leaves c-ares to its own discovery,
// which is the default and works on most hosts.
function makeDnsResolver(timeoutMs = DNS_TIMEOUT_MS, servers = DNS_SERVERS) {
    const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 2 });
    if (servers.length) resolver.setServers(servers);
    return resolver;
}

async function resolveHostAddresses(hostname, {
    timeoutMs = DNS_TIMEOUT_MS,
    makeResolver = () => makeDnsResolver(timeoutMs),
    lookup = (host) => dns.lookup(host, { all: true, verbatim: true }),
    log = console
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
        const failure = errors.find(e => e.code !== 'ENODATA') || errors[0]
            || Object.assign(new Error(`No addresses for ${hostname}`), { code: 'ENOTFOUND', hostname });
        if (!DNS_RESOLVER_UNUSABLE.has(failure.code)) throw failure;

        if (!dnsFallback.warned) {
            dnsFallback.warned = true;
            let servers = '';
            try { servers = ` (it was configured with ${resolver.getServers().join(', ') || 'no servers'})`; } catch {}
            log.warn(
                `[dns] the built-in resolver cannot reach its nameservers: ${failure.code}${servers}. ` +
                'Falling back to the operating system resolver, which works but cannot be cancelled, ' +
                'so a slow nameserver can delay other requests. Fix the host DNS configuration to restore it.'
            );
        }
        return await Promise.race([lookup(hostname), deadline]);
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
    // A host vetted within the pin window is not resolved again (audit P4), which
    // keeps the resolver off the relay hot path. Only vetted addresses are pinned,
    // and reuse does not extend the pin.
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
        // The redirect's own body is never read. Explicit hygiene: undici was
        // measured closing the abandoned socket either way, but this states the
        // intent instead of depending on that behaviour.
        discardBody(res);
        if (redirects === maxRedirects) throw new Error('Too many redirects');

        url = await assertSafeOutboundUrl(new URL(location, url).toString());
    }
}

module.exports = {
    ALLOW_PRIVATE_NETWORKS,
    DNS_TIMEOUT_MS,
    DNS_PIN_TTL_MS,
    DNS_PIN_MAX_HOSTS,
    DNS_RESOLVER_UNUSABLE,
    DNS_SERVERS,
    parseDnsServers,
    makeDnsResolver,
    dnsFallback,
    dnsPins,
    resolveHostAddresses,
    pinResolvedAddresses,
    pinnedLookup,
    pinnedLookupError,
    PINNED_DISPATCHER,
    UNDICI_INTEROPERABLE_MAJORS,
    warnOnUndiciMismatch,
    blockedOutbound,
    assertSafeOutboundUrl,
    discardBody,
    safeFetch
};
