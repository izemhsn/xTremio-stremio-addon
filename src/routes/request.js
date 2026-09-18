// Who a request is from, and what URL this server is reachable at.
//
// Both answers come from headers a client can set, so both depend on TRUST_PROXY.
// A proxy *appends* the address it saw, which is why forwardedValue counts in from
// the right: the leftmost X-Forwarded-For entry used to be the rate limiter's key,
// and `X-Forwarded-For: <anything>` minted a fresh bucket per request (audit S5).
// With TRUST_PROXY off every forwarded header is ignored and the socket decides.
const net = require('node:net');

const { normalizeUrl } = require('../helpers.js');
const { ipv6ToBytes, ipv6MatchesPrefix, IPV6_V4_MAPPED } = require('../net/private-ip.js');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Pins the origin install links are built from. Without it SAFE_HOST checks only
// the *shape* of the Host header, so any hostname an attacker controls and points
// at this instance mints install links carrying that hostname (audit L7) —
// warnOnUnpinnedBaseUrl says so at boot in production.
const PUBLIC_URL = process.env.PUBLIC_URL ? normalizeUrl(process.env.PUBLIC_URL) : null;

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

// The value a trusted proxy recorded in a forwarded header, or ''. Proxies *append*,
// so everything left of their entries was written by the client (audit S5): the
// value is read from the right, TRUST_PROXY_HOPS entries in. A proxy that
// overwrites instead leaves a single value, which is also the last.
function forwardedValue(req, header) {
    if (!TRUST_PROXY_HOPS) return '';
    const entries = String(req.headers?.[header] || '').split(',').map(v => v.trim()).filter(Boolean);
    if (!entries.length) return '';
    return entries[Math.max(0, entries.length - TRUST_PROXY_HOPS)];
}

function getBaseUrl(req) {
    if (PUBLIC_URL) return PUBLIC_URL;
    // Only a trusted proxy's word counts (audit D4).
    const proto = forwardedValue(req, 'x-forwarded-proto') || req.protocol || 'http';
    const host = forwardedValue(req, 'x-forwarded-host') || req.headers.host || '';
    const safeProto = /^https?$/.test(proto) ? proto : 'http';
    const safeHost = SAFE_HOST.test(host) ? host : `localhost:${PORT}`;
    return `${safeProto}://${safeHost}`;
}

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
    if (ipv6MatchesPrefix(bytes, IPV6_V4_MAPPED.bytes, IPV6_V4_MAPPED.bits)) {
        return Array.from(bytes.subarray(IPV6_V4_MAPPED.offset, IPV6_V4_MAPPED.offset + 4)).join('.');
    }
    const hextets = [];
    for (let i = 0; i < 8; i += 2) hextets.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    return `${hextets.join(':')}::/64`;
}

module.exports = {
    PORT,
    HOST,
    PUBLIC_URL,
    SAFE_HOST,
    TRUST_PROXY_HOPS,
    forwardedValue,
    getBaseUrl,
    clientKey,
    addressBucket
};
