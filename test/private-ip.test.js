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
