// A relay whose upstream dies part-way must fail visibly, not go quiet.
//
// The stream error handler used to end the response. Measured against the real
// relay with a local upstream that declared 1,000 bytes and died after 500: the
// client got a 200 and 500 bytes, and its keep-alive socket was still open 8 s
// later, waiting for the rest until keepAliveTimeout closed it. An upstream that
// died before its first body byte produced a 502 carrying the upstream's
// Content-Length: 1000 and no body, with the same wait. A player sees either as a
// frozen stream rather than a failure it can retry.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const http = require('node:http');
const net = require('node:net');

const { app, encodeConfig, applyServerTimeouts, proxyInFlight } = require('./support/internals.js');

let provider;
let server;
let CFG;

// Declares a 1,000-byte movie, then dies: after 500 bytes for stream 1, before
// any body byte for stream 2. The delay lets the relay take what was sent.
function providerHandler(req, res) {
    res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '1000' });
    if (req.url.endsWith('/1.mp4')) res.write(Buffer.alloc(500, 1));
    else res.flushHeaders();
    setTimeout(() => res.socket.destroy(), 100);
}

beforeAll(async () => {
    provider = http.createServer(providerHandler);
    await new Promise(resolve => provider.listen(0, '127.0.0.1', resolve));
    CFG = encodeConfig({
        serverUrl: `http://127.0.0.1:${provider.address().port}`,
        username: 'u',
        password: 'p'
    });

    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    // Production timeouts: with Node's 5 s default keep-alive the old hang would
    // end on its own soon after the window below, and the test would say less.
    applyServerTimeouts(server);
});

afterAll(async () => {
    await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => provider.close(resolve));
});

// A raw socket rather than fetch: what matters is what the connection itself
// does, and a client library would hide an unfinished response behind its own
// timeout.
function rawGet(path, waitMs) {
    return new Promise((resolve) => {
        let buf = Buffer.alloc(0);
        let settled = false;
        const parse = () => {
            const split = buf.indexOf('\r\n\r\n');
            const head = split === -1 ? '' : buf.subarray(0, split).toString('latin1');
            const body = split === -1 ? Buffer.alloc(0) : buf.subarray(split + 4);
            const declared = /\r\ncontent-length: *(\d+)/i.exec(head);
            return { head, body, declared: declared ? Number(declared[1]) : null };
        };
        const finish = (how) => {
            if (settled) return;
            settled = true;
            sock.destroy();
            resolve({ how, ...parse() });
        };
        const sock = net.connect(server.address().port, '127.0.0.1', () => {
            sock.write(`GET ${path} HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n\r\n`);
        });
        sock.on('data', (chunk) => {
            buf = Buffer.concat([buf, chunk]);
            const { head, body, declared } = parse();
            if (head && declared !== null && body.length >= declared) finish('complete');
        });
        sock.on('close', () => finish('closed'));
        sock.on('error', () => finish('closed'));
        setTimeout(() => finish('still open'), waitMs);
    });
}

test('an upstream that dies mid-body closes the client connection', async () => {
    const r = await rawGet(`/${CFG}/proxy/movie/1.mp4`, 3000);
    expect(r.head).toMatch(/^HTTP\/1\.1 200/);
    expect(r.body.length, `sent ${r.body.length} of the 1,000 bytes promised`).toBeLessThan(1000);
    expect(r.how, 'the connection stayed open with the response unfinished').toBe('closed');

    // The destroyed response still releases its concurrency slot.
    await new Promise(resolve => setImmediate(resolve));
    expect(proxyInFlight.size, 'a destroyed relay kept its slot').toBe(0);
});

test('an upstream that dies before its first byte gets a complete 502', async () => {
    const r = await rawGet(`/${CFG}/proxy/movie/2.mp4`, 3000);
    expect(r.head).toMatch(/^HTTP\/1\.1 502/);
    expect(r.how, 'the 502 never finished').toBe('complete');
    expect(r.declared, 'the 502 promised a length it did not deliver').toBe(r.body.length);
    expect(r.head, "the 502 kept the movie's content type").not.toMatch(/content-type: *video\/mp4/i);
});
