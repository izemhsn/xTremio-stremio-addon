// L1 and L6 — two ways the log stopped being a reliable record.
//
// L1: the catalog, meta and stream routes interpolated `:type` and `:id`
// straight from the path into a warning, so `%0A` in the type segment wrote a
// second, forged line. A log an unauthenticated caller can write lines into is
// no longer evidence of anything.
//
// L6: `no <kind> categories; serving the full list` was written on every
// catalog request. An account whose category calls are failing produced dozens
// of identical lines per client refresh, burying everything around them.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';
process.env.LOG_REQUESTS = 'true';

const {
    app,
    encodeConfig,
    noteDegradedCatalog,
    degradedCatalogLogged,
    DEGRADED_CATALOG_LOG_INTERVAL_MS
} = require('./support/internals.js');

const realFetch = global.fetch;

const CFG_ARGS = { serverUrl: 'http://provider.test:8080', username: 'alice', password: 'secret' };
const CFG = encodeConfig(CFG_ARGS);

let server;
let base;

beforeAll(async () => {
    await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
    base = `http://127.0.0.1:${server.address().port}`;
});

afterAll(async () => {
    global.fetch = realFetch;
    await new Promise(resolve => server.close(resolve));
});

// Every console channel the routes use, captured as the strings that would have
// been written — one array entry per call, so an injected newline is visible.
function captureConsole(fn) {
    const lines = [];
    const real = { warn: console.warn, error: console.error, log: console.log };
    const grab = (...args) => lines.push(args.map(a => (typeof a === 'string' ? a : String(a))).join(' '));
    console.warn = grab;
    console.error = grab;
    console.log = grab;
    return Promise.resolve()
        .then(fn)
        .finally(() => Object.assign(console, real))
        .then(() => lines);
}

// --- L1 --------------------------------------------------------------------

// A line that would look like this addon's own output if it appeared on its own.
const FORGED = '\n[error] GET /admin -> 500 relaying credentials';

test('a newline in :type cannot write its own log line', async () => {
    const cases = [
        // The catalog route reaches its mismatch warning through catalogTypesFor.
        `/catalog/${encodeURIComponent('Live TV' + FORGED)}/xtremio_movies_new.json`,
        `/meta/${encodeURIComponent('series' + FORGED)}/xtremio_movie_7.json`,
        `/stream/${encodeURIComponent('series' + FORGED)}/xtremio_movie_7.json`
    ];

    for (const path of cases) {
        const lines = await captureConsole(() => realFetch(`${base}/${CFG}${path}`));
        expect(lines.length, `${path} logged nothing, so the test proves nothing`).toBeTruthy();
        for (const line of lines) {
            expect(
                line,
                `a raw newline reached the log for ${path}:\n${JSON.stringify(line)}`
            ).not.toContain('\n');
        }
        // The value is still readable, just quoted — the point is escaping, not
        // dropping information the operator needs.
        expect(
            lines.some(l => l.includes(JSON.stringify(FORGED).slice(1, -1))),
            `the injected text should survive escaped, got:\n${JSON.stringify(lines)}`
        ).toBeTruthy();
    }
});

test('a newline in :id cannot write its own log line either', async () => {
    const id = 'xtremio_movie_7' + FORGED;
    const lines = await captureConsole(
        () => realFetch(`${base}/${CFG}/meta/series/${encodeURIComponent(id)}.json`)
    );
    expect(lines.length).toBeTruthy();
    for (const line of lines) {
        expect(line, `a raw newline reached the log:\n${JSON.stringify(line)}`).not.toContain('\n');
    }
});

// --- L6 --------------------------------------------------------------------

test('the degraded-catalog warning is written once per account and kind per interval', () => {
    degradedCatalogLogged.clear();
    const t0 = 1_000_000;

    expect(noteDegradedCatalog(CFG_ARGS, 'movie', t0), 'the first one must be written').toBe(true);
    expect(noteDegradedCatalog(CFG_ARGS, 'movie', t0 + 1), 'the next request must be quiet').toBe(false);
    expect(
        noteDegradedCatalog(CFG_ARGS, 'movie', t0 + DEGRADED_CATALOG_LOG_INTERVAL_MS - 1),
        'still inside the interval'
    ).toBe(false);
    expect(
        noteDegradedCatalog(CFG_ARGS, 'movie', t0 + DEGRADED_CATALOG_LOG_INTERVAL_MS),
        'the operator hears about an outage that is still going'
    ).toBe(true);

    // A different kind, and a different account, are separate facts.
    expect(noteDegradedCatalog(CFG_ARGS, 'series', t0 + 1)).toBe(true);
    expect(noteDegradedCatalog({ ...CFG_ARGS, username: 'bob' }, 'movie', t0 + 1)).toBe(true);
});

test('the warning keys are bounded, and eviction only re-arms a warning', () => {
    degradedCatalogLogged.clear();
    const t0 = 2_000_000;

    // The accounts come from install URLs, so the map must not grow with them.
    for (let i = 0; i < 1200; i++) {
        noteDegradedCatalog({ ...CFG_ARGS, username: `u${i}` }, 'movie', t0 + i);
    }
    expect(
        degradedCatalogLogged.size,
        `unbounded: ${degradedCatalogLogged.size} keys`
    ).toBeLessThanOrEqual(1000);

    // Evicting the oldest means the most recently warned accounts stay quiet,
    // which is the direction that matters: a dropped key warns again, it never
    // silences one.
    expect(noteDegradedCatalog({ ...CFG_ARGS, username: 'u1199' }, 'movie', t0 + 1200)).toBe(false);
});

test('the catalog route no longer warns once per request', async () => {
    // get_live_categories answers empty, which is what a failed category call
    // looks like; the route then serves the full list on every request.
    global.fetch = async (url) => {
        const action = new URL(url).searchParams.get('action');
        const data = action === 'get_live_streams' ? [] : [];
        return { ok: true, status: 200, headers: { get: () => null }, json: async () => data };
    };
    degradedCatalogLogged.clear();

    const lines = await captureConsole(async () => {
        for (let i = 0; i < 4; i++) {
            await realFetch(`${base}/${CFG}/catalog/Live TV/xtremio_live/skip=${i * 100}.json`);
        }
    });

    const degraded = lines.filter(l => l.includes('categories for this account'));
    expect(
        degraded.length,
        `expected one line across four requests, got:\n${degraded.join('\n')}`
    ).toBe(1);
    global.fetch = realFetch;
});
