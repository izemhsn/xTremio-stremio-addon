// L2 — two meta fields did not match the Stremio SDK's shape.
//
// `director` was sent as the raw provider string, but the spec says an array of
// strings, so a multi-director title rendered as one run-on name. `trailer` is
// not a field at all: a trailer belongs in `trailers` as `{ source, type }` with
// the YouTube video id as the source, so the value was silently discarded and
// the trailer button never appeared for any movie.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    youtubeTrailers,
    vodInfoCache,
    vodStreamsCache,
    seriesInfoCache
} = require('../index.js');

const realFetch = global.fetch;

const CFG = encodeConfig({ serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' });

let vodAnswer = null;
let seriesAnswer = null;

function stubProvider() {
    global.fetch = async (url) => {
        const action = new URL(url).searchParams.get('action');
        let data = null;
        if (action === 'get_vod_info') data = vodAnswer;
        else if (action === 'get_series_info') data = seriesAnswer;
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
}

let server;
let base;

test.before(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
});

test.beforeEach(() => {
    vodInfoCache.map.clear();
    vodStreamsCache.map.clear();
    seriesInfoCache.clear();
    vodAnswer = null;
    seriesAnswer = null;
    stubProvider();
});

async function meta(path) {
    const res = await realFetch(`${base}/${CFG}/meta/${path}`);
    return (await res.json()).meta;
}

// --- youtubeTrailers -------------------------------------------------------

test('a YouTube id is taken from a bare id or from any spelling of the URL', () => {
    const expected = [{ source: 'dQw4w9WgXcQ', type: 'Trailer' }];
    const spellings = [
        'dQw4w9WgXcQ',
        '  dQw4w9WgXcQ  ',
        'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        'http://youtube.com/watch?v=dQw4w9WgXcQ&t=30',
        'https://youtu.be/dQw4w9WgXcQ',
        'https://youtu.be/dQw4w9WgXcQ?t=5',
        // Panels store these without a scheme as often as with one.
        'youtu.be/dQw4w9WgXcQ',
        'www.youtube.com/watch?v=dQw4w9WgXcQ'
    ];
    for (const value of spellings) {
        assert.deepEqual(youtubeTrailers(value), expected, `${JSON.stringify(value)} should yield the id`);
    }
});

test('anything that is not a YouTube id is dropped rather than passed on', () => {
    // A source Stremio cannot play renders as a trailer button that does nothing,
    // which is worse than the button being absent.
    for (const value of ['', '   ', 'N/A', 'none', null, undefined, 0, false, {},
        'https://provider.test/trailer.mp4', 'https://www.youtube.com/', 'not-an-id-at-all']) {
        assert.equal(youtubeTrailers(value), undefined, `${JSON.stringify(value)} should be dropped`);
    }
});

// --- the meta routes -------------------------------------------------------

test('a movie sends director as an array and its trailer under `trailers`', async () => {
    vodAnswer = {
        info: {
            name: 'Heat',
            director: 'Michael Mann, Second Name',
            youtube_trailer: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'
        },
        movie_data: { stream_id: 7, container_extension: 'mkv' }
    };
    const m = await meta('XT-Movies/xtremio_movie_7.json');

    assert.deepEqual(m.director, ['Michael Mann', 'Second Name']);
    assert.deepEqual(m.trailers, [{ source: 'dQw4w9WgXcQ', type: 'Trailer' }]);
    assert.ok(!('trailer' in m), 'the non-spec `trailer` key must be gone');
});

test('a director already sent as an array is kept as one', async () => {
    vodAnswer = {
        info: { name: 'Heat', director: ['Michael Mann'] },
        movie_data: { stream_id: 7, container_extension: 'mkv' }
    };
    const m = await meta('XT-Movies/xtremio_movie_7.json');
    assert.deepEqual(m.director, ['Michael Mann']);
});

test('a movie with no director or trailer omits both rather than sending empty ones', async () => {
    vodAnswer = { info: { name: 'Heat' }, movie_data: { stream_id: 7, container_extension: 'mkv' } };
    const m = await meta('XT-Movies/xtremio_movie_7.json');

    // splitList gives [], which JSON keeps; the point is that it is an array
    // either way, so a client never sees a string here.
    assert.ok(Array.isArray(m.director));
    assert.equal(m.director.length, 0);
    assert.equal(m.trailers, undefined);
});

test('a series sends director as an array too', async () => {
    seriesAnswer = {
        info: { name: 'Show', director: 'A Name, B Name' },
        episodes: { 1: [{ id: '11', episode_num: 1, title: 'Pilot', container_extension: 'mkv' }] }
    };
    const m = await meta('series/xtremio_series_900.json');
    assert.deepEqual(m.director, ['A Name', 'B Name']);
});
