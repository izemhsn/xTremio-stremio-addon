// M-6 — isPrivateIp matched IPv6 by string prefix, and the prefixes were wrong.
//
// `fe80:` catches only the first 1/64 of fe80::/10, which spans fe80–febf, so
// fe90:: through febf:: went straight through. Nothing looked inside the
// transition formats that embed an IPv4 address either: `64:ff9b::7f00:1`
// reaches 127.0.0.1 on a NAT64 network, and `2002:7f00:1::1` is 6to4 for the
// same. Two IPv4 ranges were missing as well.
//
// This matters more since the DNS pin landed. The pin makes whatever this
// function approves the literal address the connection goes to, with no second
// resolution that might have caught the mistake — so this is now the only
// filter between a hostile provider and the internal network.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const { isPrivateIp } = require('../index.js');

// --- what must be blocked --------------------------------------------------

test('IPv4 ranges that never belong on the public internet', () => {
    const blocked = [
        ['0.0.0.0', 'this network'],
        ['0.255.255.255', 'top of 0.0.0.0/8'],
        ['10.0.0.5', 'RFC 1918'],
        ['100.64.0.1', 'carrier-grade NAT'],
        ['100.127.255.255', 'top of the CGNAT range'],
        ['127.0.0.1', 'loopback'],
        ['169.254.169.254', 'cloud metadata — the target that matters most'],
        ['172.16.0.1', 'RFC 1918'],
        ['172.31.255.255', 'top of 172.16.0.0/12'],
        ['192.168.1.1', 'RFC 1918'],
        ['224.0.0.1', 'multicast'],
        ['255.255.255.255', 'broadcast']
    ];
    for (const [ip, what] of blocked) {
        assert.equal(isPrivateIp(ip), true, `${ip} (${what}) must be blocked`);
    }
});

test('the two IPv4 ranges the old check missed', () => {
    // 192.0.0.0/24 is IETF protocol assignments; 198.18.0.0/15 is benchmarking.
    // Neither routes to anything a user's provider legitimately lives on.
    for (const ip of ['192.0.0.1', '192.0.0.255', '198.18.0.1', '198.19.255.255']) {
        assert.equal(isPrivateIp(ip), true, `${ip} must be blocked`);
    }
    // The neighbours stay reachable, so the new masks are not too wide.
    for (const ip of ['192.0.1.1', '198.17.255.255', '198.20.0.1']) {
        assert.equal(isPrivateIp(ip), false, `${ip} must stay reachable`);
    }
});

test('the whole of fe80::/10, not just its first /64', () => {
    // The exact gap: the old string check tested for "fe80:".
    for (const ip of ['fe80::1', 'fe90::1', 'fea0::1', 'feaf::1', 'febf::ffff']) {
        assert.equal(isPrivateIp(ip), true, `${ip} is link-local and must be blocked`);
    }
    // fec0::/10 (site-local, deprecated) is a separate range and also blocked.
    assert.equal(isPrivateIp('fec0::1'), true);
    assert.equal(isPrivateIp('feff::1'), true);
});

test('other IPv6 ranges that must not be reachable', () => {
    const blocked = [
        ['::', 'unspecified'],
        ['::1', 'loopback'],
        ['fc00::1', 'unique local, bottom of fc00::/7'],
        ['fd00::1', 'unique local'],
        ['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'top of fc00::/7'],
        ['ff02::1', 'link-local all-nodes multicast'],
        ['ff00::', 'bottom of the multicast range']
    ];
    for (const [ip, what] of blocked) {
        assert.equal(isPrivateIp(ip), true, `${ip} (${what}) must be blocked`);
    }
});

test('IPv6 formats that embed an IPv4 address are judged by that address', () => {
    // The NAT64 row is the one with real teeth: on such a network this reaches
    // 127.0.0.1, and the old check let it through untouched.
    const blocked = [
        ['::ffff:127.0.0.1', 'v4-mapped loopback'],
        ['::ffff:169.254.169.254', 'v4-mapped metadata endpoint'],
        ['::ffff:10.0.0.1', 'v4-mapped RFC 1918'],
        ['64:ff9b::7f00:1', 'NAT64 to 127.0.0.1'],
        ['64:ff9b::a9fe:a9fe', 'NAT64 to 169.254.169.254'],
        ['2002:7f00:1::1', '6to4 to 127.0.0.1'],
        ['2002:a9fe:a9fe::1', '6to4 to 169.254.169.254']
    ];
    for (const [ip, what] of blocked) {
        assert.equal(isPrivateIp(ip), true, `${ip} (${what}) must be blocked`);
    }
});

// --- what must stay reachable ----------------------------------------------

test('public addresses are not caught by the widened ranges', () => {
    // A guard against overcorrection: blocking a provider's real address would
    // be a worse bug than the one being fixed here, and silent.
    const allowed = [
        ['1.1.1.1', 'public v4'],
        ['8.8.8.8', 'public v4'],
        ['93.184.216.34', 'public v4'],
        ['172.15.255.255', 'just below the RFC 1918 /12'],
        ['172.32.0.1', 'just above it'],
        ['100.63.255.255', 'just below the CGNAT /10'],
        ['100.128.0.1', 'just above it'],
        ['223.255.255.255', 'just below the multicast /3'],
        ['2606:4700::1111', 'public v6'],
        ['2001:4860:4860::8888', 'public v6'],
        ['fbff::1', 'just below fc00::/7'],
        ['fe7f::1', 'just below fe80::/10']
    ];
    for (const [ip, what] of allowed) {
        assert.equal(isPrivateIp(ip), false, `${ip} (${what}) must stay reachable`);
    }
});

test('an embedded public IPv4 stays reachable in every wrapper', () => {
    // These formats are decided by what they embed, not blocked wholesale: a
    // 6to4 address wrapping a public address is itself public.
    assert.equal(isPrivateIp('::ffff:93.184.216.34'), false);
    assert.equal(isPrivateIp('2002:5db8:d822::1'), false, '6to4 wrapping 93.184.216.34');
    assert.equal(isPrivateIp('64:ff9b::5db8:d822'), false, 'NAT64 wrapping 93.184.216.34');
});

// --- parsing and failure mode ----------------------------------------------

test('the compressed and mixed notations all expand correctly', () => {
    // Same address written four ways; the matcher works on bytes, so all four
    // have to agree or the prefixes are being applied to the wrong offsets.
    for (const ip of ['::ffff:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:7f00:1', '0:0:0:0:0:ffff:127.0.0.1']) {
        assert.equal(isPrivateIp(ip), true, `${ip} must expand to v4-mapped loopback`);
    }
    for (const ip of ['fe80:0:0:0:0:0:0:1', 'fe80::1', 'FE80::1']) {
        assert.equal(isPrivateIp(ip), true, `${ip} must be link-local`);
    }
});

test('a zone id does not smuggle an address past the check', () => {
    assert.equal(isPrivateIp('fe80::1%eth0'), true);
    assert.equal(isPrivateIp('fe90::1%25'), true);
});

test('anything unparseable is refused rather than allowed', () => {
    // Fail closed. Nothing should reach here that is not an address — the
    // callers pass dns.lookup results or a literal net.isIP already accepted —
    // so an unrecognised value means something unexpected, and that is not a
    // reason to permit an outbound connection.
    for (const value of ['', null, undefined, 'localhost', 'not-an-ip', '999.999.999.999', '::gg', {}, 42]) {
        assert.equal(isPrivateIp(value), true, `${JSON.stringify(value)} must not be treated as public`);
    }
});

// --- L4 — three ranges that still read as public ---------------------------
//
// The audit found the numeric rewrite above had closed the string-prefix gaps
// but left three holes: RFC 8215's local-use NAT64 prefix, the deprecated
// IPv4-compatible form, and Teredo. Each is a way to name an internal address
// in a spelling the table did not recognise.

test('local-use NAT64 (64:ff9b:1::/48) is blocked whole', () => {
    // RFC 8215 set this prefix aside for translation inside a single network,
    // so it is local by definition — unlike the well-known 64:ff9b::/96 above,
    // there is no embedded public address worth letting through. The /48 is
    // also why it cannot be decided by the embedded IPv4: where that address
    // sits depends on the translation prefix length.
    const blocked = [
        ['64:ff9b:1::a9fe:a9fe', 'the metadata endpoint, translated locally'],
        ['64:ff9b:1::7f00:1', 'loopback, translated locally'],
        ['64:ff9b:1::', 'bottom of the prefix'],
        ['64:ff9b:1:ffff:ffff:ffff:ffff:ffff', 'top of the /48'],
        ['64:ff9b:1:0:8.8.8.8::', 'a public IPv4 inside it is still local-use']
    ];
    for (const [ip, what] of blocked) {
        assert.equal(isPrivateIp(ip), true, `${ip} (${what}) must be blocked`);
    }
    // The well-known prefix keeps its embedded-address rule, and the neighbours
    // of the /48 stay reachable.
    assert.equal(isPrivateIp('64:ff9b::8.8.8.8'), false, 'NAT64 to a public address stays reachable');
    assert.equal(isPrivateIp('64:ff9b:2::1'), false, 'just above the local-use /48');
});

test('IPv4-compatible addresses (::/96) are blocked whole', () => {
    // RFC 4291 deprecated the format outright, so nothing legitimate is reached
    // through it — while `::127.0.0.1` is still loopback to anything that
    // accepts one. Blocked rather than judged by the address it embeds, which
    // is the one place this table departs from the wrapper rule.
    const blocked = [
        ['::127.0.0.1', 'loopback, IPv4-compatible'],
        ['::169.254.169.254', 'the metadata endpoint, IPv4-compatible'],
        ['::8.8.8.8', 'a public address in a deprecated wrapper is still refused'],
        ['::', 'unspecified, now covered by the /96'],
        ['::1', 'loopback, now covered by the /96'],
        ['::ffff', 'top of the first /112']
    ];
    for (const [ip, what] of blocked) {
        assert.equal(isPrivateIp(ip), true, `${ip} (${what}) must be blocked`);
    }
    // v4-mapped sits at ::ffff:0:0/96 and is unaffected: it is still decided by
    // the IPv4 it carries, so a real provider reached that way stays reachable.
    assert.equal(isPrivateIp('::ffff:8.8.8.8'), false, 'v4-mapped public must stay reachable');
    assert.equal(isPrivateIp('::ffff:127.0.0.1'), true, 'v4-mapped loopback must stay blocked');
    assert.equal(isPrivateIp('::1:0:0'), false, 'just above ::/96');
});

test('Teredo (2001::/32) is blocked, and its neighbours are not', () => {
    // A Teredo address is a tunnel endpoint inside someone else's network, and
    // the IPv4 it carries is obfuscated rather than plainly embedded.
    for (const ip of ['2001::1', '2001:0:5ef5:79fb:8000:1:ac10:1', '2001:0:ffff:ffff:ffff:ffff:ffff:ffff']) {
        assert.equal(isPrivateIp(ip), true, `${ip} is Teredo and must be blocked`);
    }
    // The /32 is narrow on purpose: 2001::/23 holds real allocations, and
    // blocking a provider's address would be the worse and quieter bug.
    for (const ip of ['2001:1::1', '2001:4860:4860::8888', '2001:db8::1', '2000::1']) {
        assert.equal(isPrivateIp(ip), false, `${ip} must stay reachable`);
    }
});
