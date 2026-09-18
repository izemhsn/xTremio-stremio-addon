// The upstream host is user-supplied and reachable before authentication, so
// an unbounded JSON read lets a hostile or broken provider exhaust memory.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const { readJsonCapped, estimateBytes, MAX_UPSTREAM_BYTES, MAX_PARSED_TO_BODY_RATIO } = require('../index.js');

// Builds a fetch-like Response whose body streams `chunkCount` chunks of
// `chunkSize` bytes, and records whether the reader was cancelled early.
function streamingResponse({ chunkSize, chunkCount, contentLength = null, payload = null }) {
    const state = { cancelled: false, chunksRead: 0 };
    let emitted = 0;

    const body = {
        getReader() {
            return {
                async read() {
                    if (payload) {
                        if (emitted++ > 0) return { done: true, value: undefined };
                        state.chunksRead++;
                        return { done: false, value: Buffer.from(payload, 'utf8') };
                    }
                    if (emitted >= chunkCount) return { done: true, value: undefined };
                    emitted++;
                    state.chunksRead++;
                    return { done: false, value: Buffer.alloc(chunkSize, 0x61) };
                },
                async cancel() { state.cancelled = true; }
            };
        }
    };

    return {
        state,
        res: {
            ok: true,
            status: 200,
            headers: { get: (h) => (h === 'content-length' ? contentLength : null) },
            body,
            json: async () => { throw new Error('json() should not be used when a body is present'); }
        }
    };
}

test('a declared content-length over the cap is rejected before reading', async () => {
    const { res, state } = streamingResponse({ chunkSize: 10, chunkCount: 1, contentLength: '999999' });
    await assert.rejects(
        () => readJsonCapped(res, 'test', 1000),
        /too large: 999999 bytes exceeds 1000/
    );
    assert.strictEqual(state.chunksRead, 0, 'must not read the body at all');
});

test('a body that exceeds the cap mid-stream is aborted', async () => {
    // 10 chunks of 100 bytes against a 250-byte cap: should stop after 3.
    const { res, state } = streamingResponse({ chunkSize: 100, chunkCount: 10 });
    await assert.rejects(() => readJsonCapped(res, 'test', 250), /exceeded 250 bytes/);
    assert.ok(state.cancelled, 'must cancel the reader rather than drain the socket');
    assert.ok(state.chunksRead < 10, `should stop early, read ${state.chunksRead} of 10 chunks`);
});

test('a lying content-length does not bypass the streamed check', async () => {
    // Claims to be small, actually streams far more.
    const { res, state } = streamingResponse({ chunkSize: 100, chunkCount: 50, contentLength: '10' });
    await assert.rejects(() => readJsonCapped(res, 'test', 250), /exceeded 250 bytes/);
    assert.ok(state.cancelled);
});

test('a body within the cap parses normally', async () => {
    const { res } = streamingResponse({ payload: JSON.stringify([{ a: 1 }, { b: 2 }]) });
    assert.deepStrictEqual(await readJsonCapped(res, 'test', 1000), [{ a: 1 }, { b: 2 }]);
});

test('a body exactly at the cap is allowed', async () => {
    const payload = JSON.stringify('x'.repeat(20));
    const { res } = streamingResponse({ payload });
    const size = Buffer.byteLength(payload);
    assert.strictEqual(await readJsonCapped(res, 'test', size), 'x'.repeat(20));
});

test('invalid JSON inside the cap still raises a parse error', async () => {
    const { res } = streamingResponse({ payload: '{not json' });
    await assert.rejects(() => readJsonCapped(res, 'test', 1000), SyntaxError);
});

test('a response with no readable body falls back to json()', async () => {
    // Covers stubs and any runtime that hands back a body-less response.
    const res = {
        ok: true,
        status: 200,
        headers: { get: () => null },
        json: async () => ({ fallback: true })
    };
    assert.deepStrictEqual(await readJsonCapped(res, 'test', 1000), { fallback: true });
});

test('the default cap is generous enough for a large real provider', () => {
    // A 50k-title VOD list at ~500 bytes each is ~25MB; the cap must clear that
    // comfortably or legitimate providers break.
    assert.ok(MAX_UPSTREAM_BYTES >= 32 * 1024 * 1024, `cap is ${MAX_UPSTREAM_BYTES}`);
});

// --- transient peak while parsing (audit L-5) -------------------------------
//
// `JSON.parse(Buffer.concat(chunks).toString('utf8'))` reads as one step but
// allocates three full copies of the body, and writing it as one expression
// keeps every one of them reachable until the last returns: `chunks` is live
// through both the concat and the stringify, and the concatenated buffer is live
// through the parse. At MAX_UPSTREAM_BYTES that is a ~256 MB peak for a 64 MB
// catalog — the spike that OOMs a small container, which no steady-state budget
// describes.

// Streams a body as several chunks, so the concat has something real to join.
function chunkedResponse(text, chunkSize) {
    const buf = Buffer.from(text, 'utf8');
    let offset = 0;
    return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: {
            getReader: () => ({
                async read() {
                    if (offset >= buf.length) return { done: true, value: undefined };
                    const value = buf.subarray(offset, offset + chunkSize);
                    offset += chunkSize;
                    return { done: false, value };
                },
                async cancel() {}
            })
        },
        json: async () => { throw new Error('json() should not be used when a body is present'); }
    };
}

test('a body split across many chunks parses to exactly the same value', async () => {
    // Releasing the chunk array must not disturb what was read from it. Split at
    // 7 bytes so boundaries land inside tokens rather than between them.
    const value = Array.from({ length: 200 }, (_, i) => ({ stream_id: i, name: `Title ${i}` }));
    const res = chunkedResponse(JSON.stringify(value), 7);
    assert.deepStrictEqual(await readJsonCapped(res, 'test', 1024 * 1024), value);
});

test('a multi-byte character split across a chunk boundary survives', async () => {
    // Decoding per chunk rather than after the concat would corrupt this. The
    // release only moves references; it must not move the decode.
    const value = { name: '✪ CANAL+ SPORT — Ω' };
    const text = JSON.stringify(value);
    for (let chunkSize = 1; chunkSize <= 4; chunkSize++) {
        const res = chunkedResponse(text, chunkSize);
        assert.deepStrictEqual(await readJsonCapped(res, 'test', 1024), value, `chunk size ${chunkSize}`);
    }
});

test('each copy of the body is released before the next is allocated', () => {
    // Asserted on the source, because the property is about *reachability* and
    // nothing observable from outside the function can distinguish one copy of the
    // body alive at parse time from three — a GC that happens not to run leaves the same
    // heap either way. The shape is the guarantee, so the shape is what is
    // pinned: chunks emptied before the stringify, buffer dropped before the
    // parse. Written as one expression again, this would silently regress.
    // Source-level, because nothing observable from outside the function can tell
    // the two shapes apart — a GC that happens not to run leaves the same heap
    // either way. So it has to read the file readJsonCapped is written in.
    const src = require('node:fs').readFileSync(require.resolve('../src/upstream/read-capped.js'), 'utf8');
    const body = src.slice(src.indexOf('async function readJsonCapped'));
    const fn = body.slice(0, body.indexOf('\n}\n'));

    const concat = fn.indexOf('Buffer.concat(chunks)');
    const drop = fn.indexOf('chunks.length = 0');
    const stringify = fn.indexOf(".toString('utf8')");
    const release = fn.indexOf('buf = null');
    const parse = fn.indexOf('JSON.parse(');

    assert.ok(concat > 0 && drop > 0 && stringify > 0 && release > 0 && parse > 0,
        'readJsonCapped no longer has the staged shape this test describes');
    assert.ok(drop > concat && drop < stringify, 'chunks must be released between the concat and the stringify');
    assert.ok(release > stringify && release < parse, 'the buffer must be released between the stringify and the parse');
    assert.ok(!/JSON\.parse\(Buffer\.concat/.test(fn), 'the one-expression form keeps every copy alive');
});

// --- what a body parses to (audit S4) ----------------------------------------
//
// The byte cap bounds the body, not what JSON.parse builds from it, and the two
// differ by shape. A 16 MB [{},{},…] body retained 341 MB of heap after GC — 21x
// its size — and blocked for about a second while it was built. At the default
// MAX_UPSTREAM_MB that is ~1.4 GB from one response, and every byte of it was
// inside the byte cap.

// Streams `text` in chunks and records what the reader was asked for.
function trackedResponse(text, chunkSize) {
    const buf = Buffer.from(text, 'utf8');
    const state = { chunksRead: 0, cancelled: false, totalChunks: Math.ceil(buf.length / chunkSize) };
    let offset = 0;
    return {
        state,
        res: {
            ok: true,
            status: 200,
            headers: { get: () => null },
            body: {
                getReader: () => ({
                    async read() {
                        if (offset >= buf.length) return { done: true, value: undefined };
                        const value = buf.subarray(offset, offset + chunkSize);
                        offset += chunkSize;
                        state.chunksRead++;
                        return { done: false, value };
                    },
                    async cancel() { state.cancelled = true; }
                })
            },
            json: async () => { throw new Error('json() should not be used when a body is present'); }
        }
    };
}

const MB = 1024 * 1024;

test('a body shaped to inflate is refused mid-stream, inside its byte cap', async () => {
    // 1 MB of [{},{},…] against a 1 MB byte cap, so the byte cap never trips. It
    // estimates at ~22 MB parsed, so it is refused after roughly a tenth of the
    // body. Stopping early is also the proof that it was never parsed: JSON.parse
    // runs only once the read loop has finished.
    const text = '[' + new Array(Math.floor((MB - 2) / 3)).fill('{}').join(',') + ']';
    assert.ok(Buffer.byteLength(text) <= MB);
    const { res, state } = trackedResponse(text, 16 * 1024);

    const allowedMb = MAX_PARSED_TO_BODY_RATIO;
    await assert.rejects(
        () => readJsonCapped(res, 'test', MB),
        new RegExp(`shaped to parse to more than ${allowedMb} MB`)
    );
    assert.ok(state.cancelled, 'the socket is released rather than drained');
    assert.ok(
        state.chunksRead < state.totalChunks / 4,
        `stopped after ${state.chunksRead} of ${state.totalChunks} chunks`
    );
});

test('a realistic list up to its byte cap is never refused by the shape check', async () => {
    // The other side of the ratio. Every real list must reach its byte cap before
    // this check, or a large provider's catalog is turned away by a guard meant for
    // hostile ones. These are the three list shapes an Xtream panel serves; live
    // estimates highest of the three, at ~1.3x its size.
    const shapes = {
        vod: (i) => ({
            num: i, name: `Some Movie Title ${i} (2019)`, stream_type: 'movie', stream_id: 100000 + i,
            stream_icon: `http://img.example.com/posters/p${i}.jpg`, rating: '6.5', rating_5based: 3.25,
            added: '1577836800', is_adult: '0', category_id: '20', category_ids: [20],
            container_extension: 'mkv', custom_sid: '', direct_source: ''
        }),
        live: (i) => ({
            num: i, name: `CH ${i}`, stream_type: 'live', stream_id: i, stream_icon: '', epg_channel_id: '',
            added: '1577836800', is_adult: 0, category_id: '1', category_ids: [1], custom_sid: '',
            tv_archive: 0, direct_source: '', tv_archive_duration: 0
        }),
        series: (i) => ({
            num: i, name: `Series ${i}`, series_id: 5000 + i, cover: `http://img.example.com/c/${i}.jpg`,
            plot: 'A family, torn apart by war, must find its way home, against all odds, in a land, far away.',
            cast: 'Actor One, Actor Two, Actor Three', genre: 'Drama, Action', rating_5based: 3.5,
            backdrop_path: [`http://img.example.com/b/${i}.jpg`], category_id: '30', category_ids: [30]
        })
    };
    for (const [kind, make] of Object.entries(shapes)) {
        const items = Array.from({ length: 2000 }, (_, i) => make(i));
        const text = JSON.stringify(items);
        const { res } = trackedResponse(text, 16 * 1024);
        // The byte cap is the body's exact size: as close to refusal as a real list gets.
        const parsed = await readJsonCapped(res, 'test', Buffer.byteLength(text));
        assert.equal(parsed.length, items.length, `${kind} list parsed whole`);
    }
});

test('a parsed payload is weighed from its whole body, not from a sample', async () => {
    // A sample can be steered: its positions follow from the list length, so a list
    // whose sampled items are empty and whose others are deeply nested is weighed
    // far below its real cost. The body the reader already counted cannot be.
    const nested = { a: { b: { c: { d: {} } } } };
    // 2000 items sample every 100th, and every 100th is the empty one.
    const items = Array.from({ length: 2000 }, (_, i) => (i % 100 === 0 ? {} : nested));
    const text = JSON.stringify(items);
    const { res } = trackedResponse(text, 4096);

    const fromBody = estimateBytes(await readJsonCapped(res, 'test', MB));
    const fromSample = estimateBytes(JSON.parse(text));
    assert.ok(fromBody > 3 * fromSample, `whole body weighed ${fromBody}, the steered sample ${fromSample}`);
});
