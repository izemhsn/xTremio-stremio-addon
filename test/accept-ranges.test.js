// LIVE-3 and L-2 — the proxy made two opposite false claims about range support.
//
//   LIVE-3: the real provider answers a ranged movie request with
//   `accept-ranges: 0-3328437858` — a byte range where RFC 9110 §14.3 permits
//   only a range-unit token. It was in the blind forward list, so it reached
//   the player verbatim.
//
//   L-2: whenever upstream omitted the header the proxy asserted `bytes`. An
//   origin that ignores Range answers 200 with the whole body, so a player
//   asking for 2 KB of an HLS segment was told ranges work and handed
//   3,675,400 bytes. Measured on the provider's channel 28939, where upstream
//   sent `accept-ranges: bytes` *and* ignored the range — so forwarding a
//   well-formed value would have preserved the lie.
//
// Both values below are the ones observed on the wire, not invented.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const http = require('node:http');

const { app, encodeConfig, normalizeAcceptRanges } = require('./support/internals.js');

const realFetch = global.fetch;
const MALFORMED = '0-3328437858';

// --- the decision itself ---------------------------------------------------

test('a 206 is proof, whatever upstream claims', () => {
    // The origin honoured a byte range in this very exchange; nothing it says
    // about itself outranks that.
    for (const upstreamValue of [MALFORMED, 'none', null, 'bytes', 'seconds']) {
        expect(
            normalizeAcceptRanges({ status: 206, upstreamValue, sentRange: true }),
            `206 with upstream ${JSON.stringify(upstreamValue)}`
        ).toBe('bytes');
    }
});

test('a range we asked for that came back whole means the origin ignores ranges', () => {
    // L-2 exactly: upstream says bytes, upstream ignored the range. Omitting is
    // the only honest answer — asserting either unit would be a guess.
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: 'bytes', sentRange: true })).toBeNull();
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: null, sentRange: true })).toBeNull();
    // 416 is a refusal, not a demonstration of support.
    expect(normalizeAcceptRanges({ status: 416, upstreamValue: 'bytes', sentRange: true })).toBeNull();
});

test('a failed If-Range legitimately returns a whole body, so it proves nothing', () => {
    // The one 200-to-a-ranged-request that is not evidence of anything: the
    // validator did not match, so the origin correctly sent the whole entity.
    expect(
        normalizeAcceptRanges({ status: 200, upstreamValue: 'bytes', sentRange: true, sentIfRange: true })
    ).toBe('bytes');
    expect(
        normalizeAcceptRanges({ status: 200, upstreamValue: MALFORMED, sentRange: true, sentIfRange: true })
    ).toBe('bytes');
});

test('with no range requested, a well-formed unit is trusted and a malformed one is not', () => {
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: 'bytes' })).toBe('bytes');
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: 'none' })).toBe('none');
    expect(
        normalizeAcceptRanges({ status: 200, upstreamValue: 'BYTES' }),
        'the token is case-insensitive'
    ).toBe('bytes');
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: ' bytes ' })).toBe('bytes');

    // LIVE-3: never relayed, and the optimistic default stands in instead.
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: MALFORMED })).toBe('bytes');
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: 'seconds' })).toBe('bytes');
    expect(normalizeAcceptRanges({ status: 200, upstreamValue: null })).toBe('bytes');
});

test('the result is always a valid range-unit or nothing', () => {
    // The property that matters: no input produces a header a player cannot
    // parse. Includes the shapes a hostile or broken provider might send.
    const inputs = [MALFORMED, 'bytes', 'none', '', null, undefined, 'bytes, seconds', '<script>', '0-1', 'BYTES'];
    for (const upstreamValue of inputs) {
        for (const status of [200, 206, 416, 502]) {
            for (const sentRange of [true, false]) {
                const out = normalizeAcceptRanges({ status, upstreamValue, sentRange });
                expect(
                    out === null || out === 'bytes' || out === 'none',
                    `status=${status} sentRange=${sentRange} upstream=${JSON.stringify(upstreamValue)} produced ${JSON.stringify(out)}`
                ).toBeTruthy();
            }
        }
    }
});

// --- end to end through the proxy ------------------------------------------

let provider;
let server;
let base;
let cfgToken;

// Answers the way the two real cases did, keyed by the requested path.
function providerHandler(req, res) {
    const body = Buffer.alloc(4096, 0x47);

    if (req.url.includes('/honours-ranges')) {
        // The movie case: honours the range, but describes itself with a range
        // instead of a unit.
        const [, start, end] = /bytes=(\d+)-(\d+)/.exec(req.headers.range || '') || [];
        if (start !== undefined) {
            res.writeHead(206, {
                'Content-Type': 'video/mp4',
                'Content-Range': `bytes ${start}-${end}/${body.length}`,
                'Accept-Ranges': `0-${body.length}`
            });
            return res.end(body.subarray(Number(start), Number(end) + 1));
        }
        res.writeHead(200, { 'Content-Type': 'video/mp4', 'Accept-Ranges': `0-${body.length}` });
        return res.end(body);
    }

    // The segment case: advertises bytes, ignores the range, sends everything.
    res.writeHead(200, { 'Content-Type': 'video/mp2t', 'Accept-Ranges': 'bytes' });
    return res.end(body);
}

beforeAll(async () => {
    provider = await new Promise((resolve) => {
        const s = http.createServer(providerHandler);
        s.listen(0, '127.0.0.1', () => resolve(s));
    });
    server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    base = `http://127.0.0.1:${server.address().port}`;
    cfgToken = encodeConfig({
        serverUrl: `http://127.0.0.1:${provider.address().port}`,
        username: 'honours-ranges',
        password: 'p'
    });
});

afterAll(async () => {
    global.fetch = realFetch;
    await new Promise(r => server.close(r));
    await new Promise(r => provider.close(r));
});

test('a malformed unit never reaches the player', async () => {
    const res = await realFetch(`${base}/${cfgToken}/proxy/movie/1.mp4`, {
        headers: { Range: 'bytes=0-99' }
    });
    await res.arrayBuffer();

    expect(res.status).toBe(206);
    expect(res.headers.get('accept-ranges'), 'a 206 proves ranges work').toBe('bytes');
    expect(res.headers.get('accept-ranges')).not.toBe(MALFORMED);
    // Ranges still work end to end — the point is the header, not the body.
    expect(res.headers.get('content-range')).toBe('bytes 0-99/4096');
});

test('an origin that ignores the range is not advertised as supporting it', async () => {
    const ignoring = encodeConfig({
        serverUrl: `http://127.0.0.1:${provider.address().port}`,
        username: 'ignores-ranges',
        password: 'p'
    });
    const res = await realFetch(`${base}/${ignoring}/proxy/movie/2.ts`, {
        headers: { Range: 'bytes=0-2047' }
    });
    const body = await res.arrayBuffer();

    expect(res.status).toBe(200);
    expect(body.byteLength, 'the origin sent the whole body, as observed live').toBe(4096);
    expect(
        res.headers.get('accept-ranges'),
        'upstream said bytes and ignored the range; relaying that is the L-2 lie'
    ).toBeNull();
});

test('a plain request still gets the optimistic default', async () => {
    // No range asked, upstream's own value malformed: no evidence either way,
    // so the pre-existing default stands rather than a header being dropped.
    const res = await realFetch(`${base}/${cfgToken}/proxy/movie/3.mp4`);
    await res.arrayBuffer();

    expect(res.status).toBe(200);
    expect(res.headers.get('accept-ranges')).toBe('bytes');
});
