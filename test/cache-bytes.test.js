// M-4 — cache bounds counted entries, not bytes.
//
// BoundedMap capped entry count, and the stream caches hold 4 accounts × 3
// kinds = 12 entries, each a parsed array of up to MAX_UPSTREAM_MB of JSON
// *text*. A parsed graph of many small objects runs 3-10× its serialized size,
// so the real ceiling was on the order of a gigabyte — not the "10-50 MB per
// account per kind" the README implied. On a 512 MB container that is an OOM.
//
// The second half of the finding: 4 stream accounts is a thrashing cliff for
// the multi-user deployment the README advertises. With 5+ active accounts
// every catalog request could evict and refetch a full list, and nothing logged
// that it was happening.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';
process.env.ALLOW_PRIVATE_NETWORKS = 'true';

const {
    BoundedMap,
    estimateBytes,
    weighJson,
    vodStreamsCache,
    CACHE_TTL,
    CACHE_MAX_STREAM_BYTES,
    CACHE_MAX_STREAM_ACCOUNTS
} = require('./support/internals.js');

const entry = (bytes, extra = {}) => ({ data: null, bytes, ...extra });

// --- the byte budget -------------------------------------------------------

test('entries are evicted on total bytes, not just entry count', () => {
    const map = new BoundedMap({ maxEntries: 100, maxBytes: 1000 });
    map.set('a', entry(400));
    map.set('b', entry(400));
    expect(map.size, 'under budget, both stay').toBe(2);

    map.set('c', entry(400));
    expect(map.size, 'the oldest went to get back under 1000 bytes').toBe(2);
    expect(map.has('a')).toBeFalsy();
    expect(map.has('b') && map.has('c')).toBeTruthy();
    expect(map.totalBytes).toBe(800);
});

test('the entry-count bound still applies on its own', () => {
    const map = new BoundedMap({ maxEntries: 2, maxBytes: 10 ** 9 });
    map.set('a', entry(1));
    map.set('b', entry(1));
    map.set('c', entry(1));
    expect([...map.keys()]).toStrictEqual(['b', 'c']);
});

test('an entry larger than the whole budget is still cached', () => {
    // Refusing it would mean refetching 50 MB on every request — worse than
    // being over budget with one entry.
    const map = new BoundedMap({ maxEntries: 10, maxBytes: 1000 });
    map.set('huge', entry(5000));
    expect(map.size).toBe(1);
    expect(map.get('huge').bytes).toBe(5000);
    expect(map.overBudget(), 'and it reports being over rather than pretending').toBeTruthy();
});

test('the byte total tracks replacement, deletion, sweeping and clearing', () => {
    // If the total drifts, the budget silently becomes either useless or a
    // cache that evicts everything.
    const map = new BoundedMap({ maxEntries: 10, maxBytes: 10 ** 9, maxAgeMs: 1000 });
    map.set('a', entry(100, { ts: Date.now() }));
    map.set('b', entry(200, { ts: Date.now() - 5000 }));
    expect(map.totalBytes).toBe(300);

    map.set('a', entry(50, { ts: Date.now() }));
    expect(map.totalBytes, 'replacing an entry replaces its weight').toBe(250);

    expect(map.sweep(), 'b was past maxAgeMs').toBe(1);
    expect(map.totalBytes).toBe(50);

    map.delete('a');
    expect(map.totalBytes).toBe(0);

    map.set('c', entry(70, { ts: Date.now() }));
    map.clear();
    expect(map.totalBytes).toBe(0);
    expect(map.size).toBe(0);
});

test('an LRU touch does not disturb the byte total', () => {
    // get() re-inserts to move the key to the recent end; doing that through
    // set() would double-count.
    const map = new BoundedMap({ maxEntries: 10, maxBytes: 10 ** 9 });
    map.set('a', entry(100));
    map.set('b', entry(200));
    map.get('a');
    map.get('a');
    expect(map.totalBytes).toBe(300);
    expect([...map.keys()], 'and the touch still reorders').toStrictEqual(['b', 'a']);
});

// --- the thrashing signal --------------------------------------------------

test('evicting a live entry warns; evicting an expired one does not', () => {
    const warnings = [];
    const map = new BoundedMap({
        maxEntries: 1,
        maxAgeMs: CACHE_TTL,
        onEvict: (key, dropped, reason) => warnings.push({ key, reason, ts: dropped.ts })
    });

    map.set('fresh', entry(1, { ts: Date.now() }));
    map.set('next', entry(1, { ts: Date.now() }));
    expect(warnings.length, 'a within-TTL eviction is the "bounds too tight" signal').toBe(1);
    expect(warnings[0].key).toBe('fresh');
    expect(warnings[0].reason).toBe('entry count');

    // And the real cache's own handler, not a copy of its rule: an entry
    // already past its TTL leaving is routine and must stay silent.
    const logged = [];
    const realWarn = console.warn;
    console.warn = (msg) => logged.push(msg);
    try {
        vodStreamsCache.map.onEvict('k', { ts: Date.now() - CACHE_TTL - 1, bytes: 1 }, 'entry count');
        expect(logged, 'an expired entry leaving is not a problem to report').toStrictEqual([]);

        vodStreamsCache.map.onEvict('k', { ts: Date.now(), bytes: 12 * 1024 * 1024 }, 'byte budget');
        expect(logged.length).toBe(1);
        expect(logged[0]).toMatch(/evicted a live stream list on byte budget \(12 MB\)/);
        expect(logged[0], 'says what to raise').toMatch(/CACHE_MAX_STREAM_ACCOUNTS|CACHE_MAX_STREAM_MB/);
    } finally {
        console.warn = realWarn;
    }
});

test('onEvict reports which bound did it', () => {
    const reasons = [];
    const map = new BoundedMap({
        maxEntries: 10,
        maxBytes: 100,
        onEvict: (key, dropped, reason) => reasons.push(reason)
    });
    map.set('a', entry(60));
    map.set('b', entry(60));
    expect(reasons).toStrictEqual(['byte budget']);
});

test('the real stream cache is wired to both bounds', () => {
    expect(vodStreamsCache.map.maxEntries).toBe(CACHE_MAX_STREAM_ACCOUNTS);
    expect(vodStreamsCache.map.maxBytes).toBe(CACHE_MAX_STREAM_BYTES);
    expect(typeof vodStreamsCache.map.onEvict).toBe('function');
});

test('a cached stream list is weighed when it is stored', () => {
    // The end of the chain: without this the budget above never sees anything.
    vodStreamsCache.map.clear();
    const cfg = { serverUrl: 'http://provider.test', username: 'u', password: 'p' };
    const items = Array.from({ length: 500 }, (_, i) => ({ stream_id: i, name: `Movie ${i}`, category_id: 20 }));

    vodStreamsCache.set(cfg, items);
    const stored = [...vodStreamsCache.map.values()][0];
    expect(stored.bytes, `expected a real weight, got ${stored.bytes}`).toBeGreaterThan(1000);
    expect(vodStreamsCache.map.totalBytes).toBe(stored.bytes);
    vodStreamsCache.map.clear();
});

// --- the estimator ---------------------------------------------------------

test('estimateBytes samples a list to within a few percent of weighing all of it', () => {
    // Sampled, so it must be near — not exact — for the homogeneous lists this
    // actually meters. This used to compare against the serialized length, which
    // is what the estimator measured; it now measures the parsed graph (see the
    // next test), so the reference is the same weighing applied to the whole list.
    const items = Array.from({ length: 5000 }, (_, i) => ({
        stream_id: i, name: `Channel ${i}`, stream_icon: `http://cdn.test/${i}.png`, category_id: 7
    }));
    const whole = weighJson(JSON.stringify(items));
    const estimated = estimateBytes(items);
    const error = Math.abs(estimated - whole) / whole;
    expect(
        error,
        `estimate ${estimated} vs whole list ${Math.round(whole)} (${(error * 100).toFixed(1)}% off)`
    ).toBeLessThan(0.05);
});

test('a list of empty objects is weighed by what it occupies, not what it serializes to', () => {
    // Audit S4. `{}` serializes to two bytes and occupies 56 once parsed. Weighing
    // the text let a hostile [{},{},…] list fit the stream budget at a twentieth of
    // its real size and stay cached for half an hour; measured, 16 MB of that body
    // retained 341 MB of heap — 21x.
    const items = Array.from({ length: 100000 }, () => ({}));
    const serialized = JSON.stringify(items).length;
    const weighed = estimateBytes(items);
    expect(weighed, `weighed ${weighed} for ${serialized} bytes of text`).toBeGreaterThanOrEqual(20 * serialized);
});

test('estimateBytes handles the shapes that are not a big homogeneous list', () => {
    expect(estimateBytes([])).toBe(0);
    // Was 4, the length of "null". Weighed as a graph it is four characters of
    // text at half a byte each, and no structure.
    expect(estimateBytes(null)).toBe(2);
    expect(estimateBytes({ a: 'x'.repeat(100) })).toBeGreaterThan(100);

    // A circular item cannot be measured; it must not throw or poison the total.
    const circular = { name: 'x' };
    circular.self = circular;
    expect(typeof estimateBytes([circular])).toBe('number');
    expect(typeof estimateBytes(circular)).toBe('number');
});

test('estimateBytes is cheap on a large list', () => {
    // The reason it samples: measuring exactly would allocate a second copy of
    // the whole payload. Twenty samples must not scale with the list.
    const big = Array.from({ length: 200000 }, (_, i) => ({ stream_id: i, name: `Movie ${i}` }));
    const started = process.hrtime.bigint();
    estimateBytes(big);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    expect(ms, `estimating took ${ms.toFixed(1)}ms`).toBeLessThan(50);
});
