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

const {
    app,
    encodeConfig,
    parseEpisodeId,
    typeMatchesId,
    catalogTypesFor,
    catCache
} = require('./support/internals.js');

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

beforeAll(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
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
    expect(typeMatchesId('Live TV', 'xtremio_live_5')).toBeTruthy();
    expect(typeMatchesId('XT-Movies', 'xtremio_movie_5')).toBeTruthy();
    expect(typeMatchesId('XT-Movies', 'xtremio_live_5')).toBeFalsy();
    expect(typeMatchesId('Live TV', 'xtremio_movie_5')).toBeFalsy();
    expect(typeMatchesId('series', 'xtremio_movie_5')).toBeFalsy();
});

test('series and episode ids accept both XT-Series and series', () => {
    // The manifest declares the catalog under XT-Series but emits `series` metas,
    // so a client legitimately uses either spelling.
    for (const id of ['xtremio_series_9', 'xtremio_episode_9:1:2']) {
        expect(typeMatchesId('series', id), `series/${id}`).toBeTruthy();
        expect(typeMatchesId('XT-Series', id), `XT-Series/${id}`).toBeTruthy();
        expect(typeMatchesId('XT-Movies', id), `XT-Movies/${id}`).toBeFalsy();
    }
});

test('an unrecognised id is left for the route to answer', () => {
    // Not our id space; the route already replies with the empty payload and the
    // type check must not turn that into a hard rejection.
    expect(typeMatchesId('movie', 'tt1234567')).toBeTruthy();
    expect(typeMatchesId('anything', '')).toBeTruthy();
});

test('catalog ids are mapped separately from item ids', () => {
    // The trap this guards: 'xtremio_series_new' starts with the item prefix
    // 'xtremio_series_', so running a catalog id through typeMatchesId would
    // demand a `series` type for a catalog declared as XT-Series.
    expect('xtremio_series_new'.startsWith('xtremio_series_')).toBeTruthy();
    expect(catalogTypesFor('xtremio_live')).toStrictEqual(['Live TV']);
    expect(catalogTypesFor('xtremio_movies_new')).toStrictEqual(['XT-Movies']);
    expect(catalogTypesFor('xtremio_search_movies')).toStrictEqual(['XT-Movies']);
    expect(catalogTypesFor('xtremio_series_featured')).toStrictEqual(['XT-Series', 'series']);
    expect(catalogTypesFor('xtremio_search_series')).toStrictEqual(['XT-Series', 'series']);
    expect(catalogTypesFor('something_else')).toBeNull();
});

// --- L6, on the wire -------------------------------------------------------

test('a catalog requested under the wrong type returns empty without calling upstream', async () => {
    stubUpstream([]);
    const res = await get('/catalog/XT-Movies/xtremio_live.json');
    expect(res.status).toBe(200);
    expect(await res.json()).toStrictEqual({ metas: [] });
    expect(upstreamCalls, 'the mismatch must be caught before any outbound request').toBe(0);
});

test('a catalog requested under its declared type still runs', async () => {
    stubUpstream([]);
    const res = await get('/catalog/Live%20TV/xtremio_live.json');
    expect(res.status).toBe(200);
    expect(upstreamCalls, 'the matching type must reach the catalog body').toBeGreaterThan(0);
});

test('a series catalog is accepted under either XT-Series or series', async () => {
    for (const type of ['XT-Series', 'series']) {
        stubUpstream([]);
        await get(`/catalog/${type}/xtremio_series_new.json`);
        expect(upstreamCalls, `${type} must be accepted`).toBeGreaterThan(0);
    }
    stubUpstream([]);
    await get('/catalog/XT-Movies/xtremio_series_new.json');
    expect(upstreamCalls, 'XT-Movies must not reach a series catalog').toBe(0);
});

test('meta rejects a type/id mismatch with 404 and no upstream call', async () => {
    stubUpstream({});
    const res = await get('/meta/XT-Movies/xtremio_live_5.json');
    expect(res.status).toBe(404);
    expect(await res.json()).toStrictEqual({ meta: null });
    expect(upstreamCalls).toBe(0);
});

test('meta accepts every legitimate type/id pairing', async () => {
    // Each series test uses its own id: getSeriesInfo caches per (account, series),
    // so a shared id would let one test's stub answer the next test's request.
    for (const [type, id] of [['Live%20TV', 'xtremio_live_5'], ['XT-Movies', 'xtremio_movie_5'], ['series', 'xtremio_series_900'], ['XT-Series', 'xtremio_series_900']]) {
        stubUpstream({ info: { name: 'x' }, episodes: {} });
        const res = await get(`/meta/${type}/${id}.json`);
        expect(res.status, `${type}/${id} must not be rejected`).not.toBe(404);
    }
});

test('stream rejects a type/id mismatch with 404 and no upstream call', async () => {
    stubUpstream({});
    const res = await get('/stream/Live%20TV/xtremio_episode_1:1:2.json');
    expect(res.status).toBe(404);
    expect(await res.json()).toStrictEqual({ streams: [] });
    expect(upstreamCalls).toBe(0);
});

test('stream accepts an episode id under series', async () => {
    stubUpstream({ info: { name: 'x' }, episodes: { 1: [{ id: '2', episode_num: 1, container_extension: 'mp4' }] } });
    const res = await get('/stream/series/xtremio_episode_1:1:2.json');
    expect(res.status).not.toBe(404);
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
    expect(res.status).toBe(200);
    const { meta } = await res.json();

    expect(meta.videos.map(v => v.id)).toStrictEqual(['xtremio_episode_101:1:10']);
    // The real invariant: anything we hand Stremio must survive the parse that
    // the stream route will run on it when the user presses play.
    for (const v of meta.videos) {
        expect(parseEpisodeId(v.id), `${v.id} must round-trip through parseEpisodeId`).toBeTruthy();
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
    expect(meta.name).toBe('Show');
    expect(meta.videos).toStrictEqual([]);
});

test('season 0 is kept — it is numeric and providers use it for specials', async () => {
    stubUpstream({
        info: { name: 'Show' },
        episodes: { 0: [{ id: '7', episode_num: 1 }] }
    });
    const res = await get('/meta/series/xtremio_series_103.json');
    const { meta } = await res.json();
    expect(meta.videos.map(v => v.id)).toStrictEqual(['xtremio_episode_103:0:7']);
    expect(meta.videos[0].season).toBe(0);
});

test('episode 0 is kept too, for the same reason season 0 is', async () => {
    // `parseInt(ep.episode_num) || 1` relabelled a legitimate episode 0 as
    // episode 1, where it collided with the season's real episode 1 — two
    // entries claiming the same slot, one of them wrong.
    stubUpstream({
        info: { name: 'Show' },
        episodes: { 1: [
            { id: '7', episode_num: 0, title: 'Pilot' },
            { id: '8', episode_num: 1, title: 'First' }
        ] }
    });
    const res = await get('/meta/series/xtremio_series_104.json');
    const { meta } = await res.json();

    expect(meta.videos.map(v => v.episode)).toStrictEqual([0, 1]);
    expect(meta.videos.map(v => v.title)).toStrictEqual(['Pilot', 'First']);
});

test('an unparseable episode number still falls back, and says so readably', async () => {
    // The fallback is what the `|| 1` was there for; only the 0 case was wrong.
    stubUpstream({
        info: { name: 'Show' },
        episodes: { 1: [
            { id: '9' },
            { id: '10', episode_num: 'not a number' }
        ] }
    });
    const res = await get('/meta/series/xtremio_series_105.json');
    const { meta } = await res.json();

    expect(meta.videos.map(v => v.episode)).toStrictEqual([1, 1]);
    // And the generated title reads from the resolved number rather than the raw
    // field, which used to render "Episode undefined".
    expect(meta.videos.map(v => v.title)).toStrictEqual(['Episode 1', 'Episode 1']);
});

test('the catalog route dispatches through catalogTypesFor, not a copy of it', () => {
    // The route used to inline the equivalent lookup, so the tested function had
    // no production caller and the assertions above proved nothing about what
    // actually runs. Asserting on the source is crude, but it is the only thing
    // that catches the two drifting apart again — the behaviour is identical
    // either way, which is precisely why the duplication survived unnoticed.
    const src = require('fs').readFileSync(require.resolve('../src/routes/catalog.js'), 'utf8');
    const route = src.slice(src.indexOf("router.get(['/:config/catalog/"));
    const body = route.slice(0, route.indexOf('\n});'));

    expect(body, 'the catalog route must call catalogTypesFor').toContain('catalogTypesFor(id)');
    expect(
        body,
        'the catalog route still re-derives the type list instead of asking catalogTypesFor'
    ).not.toContain('.catalogTypes.includes(');
});
