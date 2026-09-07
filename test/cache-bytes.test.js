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

const test = require('node:test');
const assert = require('node:assert');

const {
    BoundedMap,
    estimateBytes,
    vodStreamsCache,
    CACHE_TTL,
    CACHE_MAX_STREAM_BYTES,
    CACHE_MAX_STREAM_ACCOUNTS
} = require('../index.js');

const entry = (bytes, extra = {}) => ({ data: null, bytes, ...extra });

// --- the byte budget -------------------------------------------------------

test('entries are evicted on total bytes, not just entry count', () => {
    const map = new BoundedMap({ maxEntries: 100, maxBytes: 1000 });
    map.set('a', entry(400));
    map.set('b', entry(400));
    assert.equal(map.size, 2, 'under budget, both stay');

    map.set('c', entry(400));
    assert.equal(map.size, 2, 'the oldest went to get back under 1000 bytes');
    assert.ok(!map.has('a'));
    assert.ok(map.has('b') && map.has('c'));
    assert.equal(map.totalBytes, 800);
});

test('the entry-count bound still applies on its own', () => {
    const map = new BoundedMap({ maxEntries: 2, maxBytes: 10 ** 9 });
    map.set('a', entry(1));
    map.set('b', entry(1));
    map.set('c', entry(1));
    assert.deepEqual([...map.keys()], ['b', 'c']);
});

test('an entry larger than the whole budget is still cached', () => {
    // Refusing it would mean refetching 50 MB on every request — worse than
    // being over budget with one entry.
    const map = new BoundedMap({ maxEntries: 10, maxBytes: 1000 });
    map.set('huge', entry(5000));
    assert.equal(map.size, 1);
    assert.equal(map.get('huge').bytes, 5000);
    assert.ok(map.overBudget(), 'and it reports being over rather than pretending');
});

test('the byte total tracks replacement, deletion, sweeping and clearing', () => {
    // If the total drifts, the budget silently becomes either useless or a
    // cache that evicts everything.
    const map = new BoundedMap({ maxEntries: 10, maxBytes: 10 ** 9, maxAgeMs: 1000 });
    map.set('a', entry(100, { ts: Date.now() }));
    map.set('b', entry(200, { ts: Date.now() - 5000 }));
    assert.equal(map.totalBytes, 300);

    map.set('a', entry(50, { ts: Date.now() }));
    assert.equal(map.totalBytes, 250, 'replacing an entry replaces its weight');

    assert.equal(map.sweep(), 1, 'b was past maxAgeMs');
    assert.equal(map.totalBytes, 50);

    map.delete('a');
    assert.equal(map.totalBytes, 0);

    map.set('c', entry(70, { ts: Date.now() }));
    map.clear();
    assert.equal(map.totalBytes, 0);
    assert.equal(map.size, 0);
});

test('an LRU touch does not disturb the byte total', () => {
    // get() re-inserts to move the key to the recent end; doing that through
    // set() would double-count.
    const map = new BoundedMap({ maxEntries: 10, maxBytes: 10 ** 9 });
    map.set('a', entry(100));
    map.set('b', entry(200));
    map.get('a');
    map.get('a');
    assert.equal(map.totalBytes, 300);
    assert.deepEqual([...map.keys()], ['b', 'a'], 'and the touch still reorders');
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
    assert.equal(warnings.length, 1, 'a within-TTL eviction is the "bounds too tight" signal');
    assert.equal(warnings[0].key, 'fresh');
    assert.equal(warnings[0].reason, 'entry count');

    // And the real cache's own handler, not a copy of its rule: an entry
    // already past its TTL leaving is routine and must stay silent.
    const logged = [];
    const realWarn = console.warn;
    console.warn = (msg) => logged.push(msg);
    try {
        vodStreamsCache.map.onEvict('k', { ts: Date.now() - CACHE_TTL - 1, bytes: 1 }, 'entry count');
        assert.deepEqual(logged, [], 'an expired entry leaving is not a problem to report');

        vodStreamsCache.map.onEvict('k', { ts: Date.now(), bytes: 12 * 1024 * 1024 }, 'byte budget');
        assert.equal(logged.length, 1);
        assert.match(logged[0], /evicted a live stream list on byte budget \(12 MB\)/);
        assert.match(logged[0], /CACHE_MAX_STREAM_ACCOUNTS|CACHE_MAX_STREAM_MB/, 'says what to raise');
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
    assert.deepEqual(reasons, ['byte budget']);
});

test('the real stream cache is wired to both bounds', () => {
    assert.equal(vodStreamsCache.map.maxEntries, CACHE_MAX_STREAM_ACCOUNTS);
    assert.equal(vodStreamsCache.map.maxBytes, CACHE_MAX_STREAM_BYTES);
    assert.equal(typeof vodStreamsCache.map.onEvict, 'function');
});

test('a cached stream list is weighed when it is stored', () => {
    // The end of the chain: without this the budget above never sees anything.
    vodStreamsCache.map.clear();
    const cfg = { serverUrl: 'http://provider.test', username: 'u', password: 'p' };
    const items = Array.from({ length: 500 }, (_, i) => ({ stream_id: i, name: `Movie ${i}`, category_id: 20 }));

    vodStreamsCache.set(cfg, items);
    const stored = [...vodStreamsCache.map.values()][0];
    assert.ok(stored.bytes > 1000, `expected a real weight, got ${stored.bytes}`);
    assert.equal(vodStreamsCache.map.totalBytes, stored.bytes);
    vodStreamsCache.map.clear();
});

// --- the estimator ---------------------------------------------------------

test('estimateBytes lands close to the real serialized size', () => {
    // Sampled, so it must be near — not exact — for the homogeneous lists this
    // actually meters.
    const items = Array.from({ length: 5000 }, (_, i) => ({
        stream_id: i, name: `Channel ${i}`, stream_icon: `http://cdn.test/${i}.png`, category_id: 7
    }));
    const actual = JSON.stringify(items).length;
    const estimated = estimateBytes(items);
    const error = Math.abs(estimated - actual) / actual;
    assert.ok(error < 0.05, `estimate ${estimated} vs actual ${actual} (${(error * 100).toFixed(1)}% off)`);
});

test('estimateBytes handles the shapes that are not a big homogeneous list', () => {
    assert.equal(estimateBytes([]), 0);
    assert.equal(estimateBytes(null), 4, 'JSON.stringify(null) is "null"');
    assert.ok(estimateBytes({ a: 'x'.repeat(100) }) > 100);

    // A circular item cannot be measured; it must not throw or poison the total.
    const circular = { name: 'x' };
    circular.self = circular;
    assert.equal(typeof estimateBytes([circular]), 'number');
    assert.equal(typeof estimateBytes(circular), 'number');
});

test('estimateBytes is cheap on a large list', () => {
    // The reason it samples: measuring exactly would allocate a second copy of
    // the whole payload. Twenty samples must not scale with the list.
    const big = Array.from({ length: 200000 }, (_, i) => ({ stream_id: i, name: `Movie ${i}` }));
    const started = process.hrtime.bigint();
    estimateBytes(big);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(ms < 50, `estimating took ${ms.toFixed(1)}ms`);
});
