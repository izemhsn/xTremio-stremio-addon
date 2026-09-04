// Two route-level defects from the audit:
//
//   L5 — a series whose provider used a non-numeric season key or episode id
//        produced episode ids that parseEpisodeId later rejects, so the episode
//        rendered in the UI and then 400'd the moment you pressed play.
//   L6 — the `:type` path segment was never checked. Every route dispatches on
//        the id prefix, so /meta/XT-Movies/xtremio_live_5.json served a live
//        channel as a movie.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const test = require('node:test');
const assert = require('node:assert');

const {
    app,
    encodeConfig,
    parseEpisodeId,
    typeMatchesId,
    catalogTypesFor,
    catCache
} = require('../index.js');

const realFetch = global.fetch;

const CFG = encodeConfig({
    serverUrl: 'http://provider.test:8080',
    username: 'alice',
    password: 'secret'
});

let server;
let base;

// Counts upstream calls so a route that was rejected early (0 calls) can be told
// apart from one that ran and merely returned an empty payload.
let upstreamCalls = 0;
function stubUpstream(payload) {
    upstreamCalls = 0;
    // Categories are cached per account, so without this a later catalog request
    // would make no upstream call and look identical to one that was rejected.
    catCache.clear();
    global.fetch = async () => {
        upstreamCalls++;
        return {
            ok: true,
            status: 200,
            headers: { get: () => null },
            json: async () => payload
        };
    };
}

test.before(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
});

// realFetch, not the global: stubUpstream replaces global.fetch to intercept the
// server's outbound calls, and the test client must not go through that stub.
function get(path) {
    return realFetch(`${base}/${CFG}${path}`);
}

// --- the pure helpers ------------------------------------------------------

test('typeMatchesId pairs each id prefix with the type that owns it', () => {
    assert.ok(typeMatchesId('Live TV', 'xtremio_live_5'));
    assert.ok(typeMatchesId('XT-Movies', 'xtremio_movie_5'));
    assert.ok(!typeMatchesId('XT-Movies', 'xtremio_live_5'));
    assert.ok(!typeMatchesId('Live TV', 'xtremio_movie_5'));
    assert.ok(!typeMatchesId('series', 'xtremio_movie_5'));
});

test('series and episode ids accept both XT-Series and series', () => {
    // The manifest declares the catalog under XT-Series but emits `series` metas,
    // so a client legitimately uses either spelling.
    for (const id of ['xtremio_series_9', 'xtremio_episode_9:1:2']) {
        assert.ok(typeMatchesId('series', id), `series/${id}`);
        assert.ok(typeMatchesId('XT-Series', id), `XT-Series/${id}`);
        assert.ok(!typeMatchesId('XT-Movies', id), `XT-Movies/${id}`);
    }
});

test('an unrecognised id is left for the route to answer', () => {
    // Not our id space; the route already replies with the empty payload and the
    // type check must not turn that into a hard rejection.
    assert.ok(typeMatchesId('movie', 'tt1234567'));
    assert.ok(typeMatchesId('anything', ''));
});

test('catalog ids are mapped separately from item ids', () => {
    // The trap this guards: 'xtremio_series_new' starts with the item prefix
    // 'xtremio_series_', so running a catalog id through typeMatchesId would
    // demand a `series` type for a catalog declared as XT-Series.
    assert.ok('xtremio_series_new'.startsWith('xtremio_series_'));
    assert.deepEqual(catalogTypesFor('xtremio_live'), ['Live TV']);
    assert.deepEqual(catalogTypesFor('xtremio_movies_new'), ['XT-Movies']);
    assert.deepEqual(catalogTypesFor('xtremio_search_movies'), ['XT-Movies']);
    assert.deepEqual(catalogTypesFor('xtremio_series_featured'), ['XT-Series', 'series']);
    assert.deepEqual(catalogTypesFor('xtremio_search_series'), ['XT-Series', 'series']);
    assert.equal(catalogTypesFor('something_else'), null);
});

// --- L6, on the wire -------------------------------------------------------

test('a catalog requested under the wrong type returns empty without calling upstream', async () => {
    stubUpstream([]);
    const res = await get('/catalog/XT-Movies/xtremio_live.json');
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { metas: [] });
    assert.equal(upstreamCalls, 0, 'the mismatch must be caught before any outbound request');
});

test('a catalog requested under its declared type still runs', async () => {
    stubUpstream([]);
    const res = await get('/catalog/Live%20TV/xtremio_live.json');
    assert.equal(res.status, 200);
    assert.ok(upstreamCalls > 0, 'the matching type must reach the catalog body');
});

test('a series catalog is accepted under either XT-Series or series', async () => {
    for (const type of ['XT-Series', 'series']) {
        stubUpstream([]);
        await get(`/catalog/${type}/xtremio_series_new.json`);
        assert.ok(upstreamCalls > 0, `${type} must be accepted`);
    }
    stubUpstream([]);
    await get('/catalog/XT-Movies/xtremio_series_new.json');
    assert.equal(upstreamCalls, 0, 'XT-Movies must not reach a series catalog');
});

test('meta rejects a type/id mismatch with 404 and no upstream call', async () => {
    stubUpstream({});
    const res = await get('/meta/XT-Movies/xtremio_live_5.json');
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), { meta: null });
    assert.equal(upstreamCalls, 0);
});

test('meta accepts every legitimate type/id pairing', async () => {
    // Each series test uses its own id: getSeriesInfo caches per (account, series),
    // so a shared id would let one test's stub answer the next test's request.
    for (const [type, id] of [['Live%20TV', 'xtremio_live_5'], ['XT-Movies', 'xtremio_movie_5'], ['series', 'xtremio_series_900'], ['XT-Series', 'xtremio_series_900']]) {
        stubUpstream({ info: { name: 'x' }, episodes: {} });
        const res = await get(`/meta/${type}/${id}.json`);
        assert.notEqual(res.status, 404, `${type}/${id} must not be rejected`);
    }
});

test('stream rejects a type/id mismatch with 404 and no upstream call', async () => {
    stubUpstream({});
    const res = await get('/stream/Live%20TV/xtremio_episode_1:1:2.json');
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), { streams: [] });
    assert.equal(upstreamCalls, 0);
});

test('stream accepts an episode id under series', async () => {
    stubUpstream({ info: { name: 'x' }, episodes: { 1: [{ id: '2', episode_num: 1, container_extension: 'mp4' }] } });
    const res = await get('/stream/series/xtremio_episode_1:1:2.json');
    assert.notEqual(res.status, 404);
});

// --- L5, on the wire -------------------------------------------------------

test('episodes with non-numeric season keys or ids are dropped from the meta', async () => {
    stubUpstream({
        info: { name: 'Show' },
        episodes: {
            // A numeric season holding one good and one unusable episode.
            1: [
                { id: '10', episode_num: 1, title: 'Good' },
                { id: 'abc', episode_num: 2, title: 'Bad id' }
            ],
            // Providers really do label a season like this.
            Specials: [{ id: '20', episode_num: 1, title: 'Whole season unusable' }]
        }
    });

    const res = await get('/meta/series/xtremio_series_101.json');
    assert.equal(res.status, 200);
    const { meta } = await res.json();

    assert.deepEqual(meta.videos.map(v => v.id), ['xtremio_episode_101:1:10']);
    // The real invariant: anything we hand Stremio must survive the parse that
    // the stream route will run on it when the user presses play.
    for (const v of meta.videos) {
        assert.ok(parseEpisodeId(v.id), `${v.id} must round-trip through parseEpisodeId`);
    }
});

test('a series whose episodes are all unusable still returns its meta', async () => {
    stubUpstream({
        info: { name: 'Show' },
        episodes: { Specials: [{ id: 'x', episode_num: 1 }] }
    });
    const res = await get('/meta/series/xtremio_series_102.json');
    const { meta } = await res.json();
    // The name is real content, so the page is worth showing with no episodes —
    // better than a dead entry, and better than episodes that 400 on play.
    assert.equal(meta.name, 'Show');
    assert.deepEqual(meta.videos, []);
});

test('season 0 is kept — it is numeric and providers use it for specials', async () => {
    stubUpstream({
        info: { name: 'Show' },
        episodes: { 0: [{ id: '7', episode_num: 1 }] }
    });
    const res = await get('/meta/series/xtremio_series_103.json');
    const { meta } = await res.json();
    assert.deepEqual(meta.videos.map(v => v.id), ['xtremio_episode_103:0:7']);
    assert.equal(meta.videos[0].season, 0);
});
