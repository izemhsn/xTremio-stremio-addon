// The upstream host is user-supplied and reachable before authentication, so
// an unbounded JSON read lets a hostile or broken provider exhaust memory.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const { readJsonCapped, MAX_UPSTREAM_BYTES } = require('../index.js');

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
