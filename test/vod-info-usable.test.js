// get_vod_info was cached whatever it returned, and a guessed container was
// cached with it.
//
// Measured against a real account: a movie id that does not exist was served as
// meta named "Unknown" with max-age=86400 and an mp4 stream with max-age=3600,
// and repeat requests came from the server cache in 3 ms. isUsableSeriesInfo
// already encodes the lesson for series: accepting less than the caller needs
// turns a bad answer into a sticky one.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    isUsableVodInfo,
    statedContainerExt,
    normalizeContainerExt,
    vodInfoCache,
    seriesInfoCache
} = require('../index.js');

const realFetch = global.fetch;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);

const HEAT = { info: { name: 'Heat' }, movie_data: { stream_id: 7, container_extension: 'mkv' } };

// get_vod_info answers these in order, repeating the last one.
let vodAnswers = [];
let seriesAnswer = null;
let calls = [];

function stubProvider() {
    calls = [];
    global.fetch = async (url) => {
        const action = new URL(url).searchParams.get('action');
        calls.push(action);
        let data = null;
        if (action === 'get_vod_info') data = vodAnswers.length > 1 ? vodAnswers.shift() : vodAnswers[0];
        else if (action === 'get_series_info') data = seriesAnswer;
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
}

const countOf = action => calls.filter(c => c === action).length;

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
    seriesInfoCache.clear();
    vodAnswers = [HEAT];
    seriesAnswer = null;
    stubProvider();
});

// realFetch, not the global: stubProvider replaces the same global the test
// client would otherwise use to reach the server.
async function get(path) {
    const res = await realFetch(`${base}/${CFG}${path}`);
    return { headers: res.headers, body: await res.json() };
}

test('isUsableVodInfo wants a name or movie data, not an empty shell', () => {
    assert.ok(isUsableVodInfo(HEAT));
    assert.ok(isUsableVodInfo({ info: { o_name: 'Heat' } }));
    assert.ok(isUsableVodInfo({ info: [], movie_data: { stream_id: 7 } }));
    assert.ok(isUsableVodInfo({ name: 'Heat' }), 'some panels put the fields at the root');
    for (const bad of [{ info: [], movie_data: [] }, {}, { info: {} }, { info: { cover_big: 'x.jpg' } }, null, [], 'error', 42]) {
        assert.equal(isUsableVodInfo(bad), false, `${JSON.stringify(bad)} is not usable`);
    }
});

test('statedContainerExt tells a named container from a guess', () => {
    assert.equal(statedContainerExt('mkv'), 'mkv');
    assert.equal(statedContainerExt(' mp4 '), 'mp4');
    for (const bad of [undefined, null, '', '  ', 'a.b', '../x']) {
        assert.equal(statedContainerExt(bad), null, `${JSON.stringify(bad)} names no container`);
    }
    // normalizeContainerExt keeps its contract on top of it.
    assert.equal(normalizeContainerExt(undefined), 'mp4');
    assert.equal(normalizeContainerExt('mkv'), 'mkv');
});

test('a movie the provider has no data for gets no meta and no stream, and nothing is cached', async () => {
    vodAnswers = [{ info: [], movie_data: [] }];

    const meta = await get('/meta/XT-Movies/xtremio_movie_999999992.json');
    assert.deepEqual(meta.body, { meta: null });
    assert.equal(meta.headers.get('cache-control'), 'no-store');

    const stream = await get('/stream/XT-Movies/xtremio_movie_999999992.json');
    assert.deepEqual(stream.body, { streams: [] });
    assert.equal(stream.headers.get('cache-control'), 'no-store');

    assert.equal(vodInfoCache.map.size, 0, 'an unusable payload must not be cached');
    assert.equal(countOf('get_vod_info'), 2, 'each request asks the provider again');
});

test('a movie whose data arrives later is served on the next request', async () => {
    vodAnswers = [{}, HEAT];
    assert.deepEqual((await get('/meta/XT-Movies/xtremio_movie_7.json')).body, { meta: null });

    const meta = await get('/meta/XT-Movies/xtremio_movie_7.json');
    assert.equal(meta.body.meta.name, 'Heat');
    assert.match(meta.headers.get('cache-control'), /max-age=86400/);
});

test('a movie stream with a guessed container is served but not cacheable', async () => {
    vodAnswers = [{ info: { name: 'Heat' }, movie_data: [] }];
    const guessed = await get('/stream/XT-Movies/xtremio_movie_7.json');
    assert.match(guessed.body.streams[0].url, /\/proxy\/movie\/7\.mp4$/);
    assert.equal(guessed.headers.get('cache-control'), 'no-store');
    assert.equal(guessed.body.cacheMaxAge, undefined);

    vodInfoCache.map.clear();
    vodAnswers = [HEAT];
    const stated = await get('/stream/XT-Movies/xtremio_movie_7.json');
    assert.match(stated.body.streams[0].url, /\/proxy\/movie\/7\.mkv$/);
    assert.equal(stated.headers.get('cache-control'), 'private, max-age=3600');
});

test('an episode stream with a guessed container is served but not cacheable', async () => {
    seriesAnswer = {
        info: { name: 'Show' },
        episodes: { 1: [{ id: '501', episode_num: 1 }, { id: '502', episode_num: 2, container_extension: 'mkv' }] }
    };

    const guessed = await get('/stream/series/xtremio_episode_900:1:501.json');
    assert.match(guessed.body.streams[0].url, /\/proxy\/series\/501\.mp4$/);
    assert.equal(guessed.headers.get('cache-control'), 'no-store');

    const missing = await get('/stream/series/xtremio_episode_900:1:999.json');
    assert.equal(missing.headers.get('cache-control'), 'no-store', 'an episode missing from the info is a guess too');

    const stated = await get('/stream/series/xtremio_episode_900:1:502.json');
    assert.match(stated.body.streams[0].url, /\/proxy\/series\/502\.mkv$/);
    assert.equal(stated.headers.get('cache-control'), 'private, max-age=3600');
});
