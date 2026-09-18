// Which addresses the SSRF guard refuses. Kept apart from the guard itself
// because it is pure: no DNS, no sockets, no configuration. test/private-ip.test.js
// pins both what is blocked and what must stay reachable — blocking a provider's
// real address is a worse and quieter bug than the gap being closed.
const net = require('node:net');

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
    // ::/96 covers the unspecified address, loopback, and the deprecated
    // IPv4-compatible form (audit L4). Unlike the wrappers below it is blocked
    // whole rather than judged by the IPv4 it embeds: RFC 4291 deprecated the
    // format outright, so nothing legitimate is reached through it, while
    // `::127.0.0.1` is loopback on any host that still accepts one.
    ['::', 96],
    ['64:ff9b:1::', 48],     // local-use NAT64 (RFC 8215) — local by definition
    ['2001::', 32],          // Teredo, a tunnel into someone else's network
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
//
// The IPv4-translated form is the same gap one prefix over (audit F4):
// `::ffff:0:7f00:1` is 127.0.0.1 and `::ffff:0:a9fe:a9fe` is the cloud metadata
// address, and both read as public while the row was missing. It is only
// reachable behind a stateless translator, which is why it went unnoticed, but
// that is a property of the network this server happens to sit on.
const IPV6_EMBEDDED_IPV4 = [
    ['::ffff:0:0', 96, 12],    // v4-mapped
    ['::ffff:0:0:0', 96, 12],  // IPv4-translated (RFC 2765/6145)
    ['64:ff9b::', 96, 12],     // NAT64 (RFC 6052)
    ['2002::', 16, 2]          // 6to4 (RFC 3056)
].map(([prefix, bits, offset]) => ({ prefix, bytes: ipv6ToBytes(prefix), bits, offset }));

// addressBucket needs the v4-mapped entry in particular, so that a dual-stack
// socket reporting an IPv4 client gets the same rate-limit bucket the client
// would get over IPv4. It used to reach into the table at [0]: a row added in
// the wrong place would have rekeyed every IPv4 client silently, which is the
// kind of thing adding a row here is otherwise free of.
const IPV6_V4_MAPPED = IPV6_EMBEDDED_IPV4.find(e => e.prefix === '::ffff:0:0');

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

module.exports = {
    isPrivateIp,
    ipv6ToBytes,
    ipv6MatchesPrefix,
    IPV4_PRIVATE_CIDRS,
    IPV6_PRIVATE_PREFIXES,
    IPV6_EMBEDDED_IPV4,
    IPV6_V4_MAPPED
};
