// Audit F3 — two exits abandoned a response without cancelling its body.
//
// undici keeps the connection behind an unread body out of its pool until the
// response is garbage collected, so a path that throws while the body is still
// pending leaks a socket for as long as the GC takes to notice. Two did:
//
//   * xtremioGet threw on any non-2xx without touching the body, and a panel
//     answering every call with a 5xx HTML error page is exactly the case where
//     that path runs on every request.
//   * readJsonCapped refuses an over-cap `content-length` before reading a
//     single byte, which is the one exit it has that never goes through the
//     reader — the two streamed caps below it already cancel through one.
//
// The rest of the app already follows the rule that every abandoned response is
// cancelled, through discardBody; these are the two places that missed it. The
// assertions are about the body being cancelled, not about socket counts, since
// the pooling behaviour is undici's and not this server's to pin.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const { xtremioGet, readJsonCapped } = require('../index.js');

const realFetch = global.fetch;
test.after(() => { global.fetch = realFetch; });

// A response whose body records whether it was cancelled, and never yields any
// data: a test that read it would be testing something else.
function unreadResponse({ status = 200, contentLength = null } = {}) {
    const state = { cancelled: false };
    return {
        state,
        res: {
            ok: status >= 200 && status < 300,
            status,
            headers: { get: (h) => (h === 'content-length' ? contentLength : null) },
            body: {
                locked: false,
                async cancel() { state.cancelled = true; },
                getReader() { throw new Error('the body must not be read on this path'); }
            },
            json: async () => { throw new Error('the body must not be read on this path'); }
        }
    };
}

const cfg = { serverUrl: 'http://panel.test', username: 'u', password: 'p' };

test('a non-2xx panel response has its body cancelled', async () => {
    const { res, state } = unreadResponse({ status: 502 });
    global.fetch = async () => res;

    await assert.rejects(
        () => xtremioGet(cfg, 'get_vod_streams'),
        /get_vod_streams failed: HTTP 502/
    );
    assert.ok(state.cancelled, 'the error body must be cancelled, not left pending');
});

test('an over-cap content-length has its body cancelled', async () => {
    const { res, state } = unreadResponse({ contentLength: '999999' });

    await assert.rejects(
        () => readJsonCapped(res, 'test', 1000),
        /too large: 999999 bytes exceeds 1000/
    );
    assert.ok(state.cancelled, 'refusing before the first byte still has to release the socket');
});

test('the same refusal through a panel call cancels the body too', async () => {
    // The cap is reached through xtremioGet in production, and the deadline
    // timers it arms must not keep the process alive after the refusal either.
    const { res, state } = unreadResponse({ contentLength: String(1024 * 1024 * 1024) });
    global.fetch = async () => res;

    await assert.rejects(() => xtremioGet(cfg, 'get_vod_streams'), /too large/);
    assert.ok(state.cancelled);
});

test('a body already locked by a reader is left alone', async () => {
    // discardBody must not call cancel() on a locked stream: that throws, and on
    // the playlist path the reader is mid-read. Nothing here should throw.
    const { res, state } = unreadResponse({ status: 502 });
    res.body.locked = true;
    global.fetch = async () => res;

    await assert.rejects(() => xtremioGet(cfg, 'get_vod_streams'), /HTTP 502/);
    assert.strictEqual(state.cancelled, false, 'a locked body is the reader\'s to cancel');
});
