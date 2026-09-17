// The caches were unbounded Maps whose TTL was only checked on read, so nothing
// was ever deleted: memory grew with every distinct account and every series
// ever opened, and never shrank when users went away.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const {
    BoundedMap,
    sweepCaches,
    startCacheSweeper,
    catCache,
    seriesInfoCache,
    vodStreamsCache,
    liveStreamsCache,
    seriesStreamsCache,
    hlsOriginVetCache,
    vodInfoCache,
    categoryStreamsCache,
    accountCacheKey,
    CACHE_TTL,
    CACHE_MAX_ACCOUNTS,
    CACHE_MAX_STREAM_ACCOUNTS,
    CACHE_MAX_SERIES_INFO,
    CACHE_STALE_MAX_AGE_MS
} = require('../index.js');

function cfgFor(user) {
    return { serverUrl: 'http://provider.test', username: user, password: 'p' };
}

test.beforeEach(() => {
    catCache.clear();
    seriesInfoCache.clear();
    vodStreamsCache.map.clear();
    liveStreamsCache.map.clear();
    seriesStreamsCache.map.clear();
});

// --- BoundedMap itself -----------------------------------------------------

test('entries beyond the bound evict the least recently used', () => {
    const m = new BoundedMap({ maxEntries: 3 });
    m.set('a', { ts: Date.now() });
    m.set('b', { ts: Date.now() });
    m.set('c', { ts: Date.now() });
    m.set('d', { ts: Date.now() });

    assert.strictEqual(m.size, 3, 'the bound holds');
    assert.strictEqual(m.has('a'), false, 'the oldest was evicted');
    assert.deepStrictEqual([...m.keys()], ['b', 'c', 'd']);
});

test('reading an entry renews it, so it is not the next victim', () => {
    const m = new BoundedMap({ maxEntries: 3 });
    m.set('a', { ts: 1 });
    m.set('b', { ts: 2 });
    m.set('c', { ts: 3 });

    m.get('a');            // 'a' is now the most recently used
    m.set('d', { ts: 4 });

    assert.strictEqual(m.has('a'), true, 'the touched key survived');
    assert.strictEqual(m.has('b'), false, 'the untouched oldest went instead');
});

test('peek reads without disturbing LRU order', () => {
    const m = new BoundedMap({ maxEntries: 2 });
    m.set('a', { ts: 1 });
    m.set('b', { ts: 2 });

    assert.deepStrictEqual(m.peek('a'), { ts: 1 }, 'peek still returns the value');
    m.set('c', { ts: 3 });

    assert.strictEqual(m.has('a'), false, 'peek did not rescue it');
});

test('overwriting an existing key updates in place without growing', () => {
    const m = new BoundedMap({ maxEntries: 2 });
    m.set('a', { ts: 1 });
    m.set('b', { ts: 2 });
    m.set('a', { ts: 99 });

    assert.strictEqual(m.size, 2);
    assert.deepStrictEqual(m.peek('a'), { ts: 99 });
    assert.strictEqual(m.has('b'), true, 'an update is not an eviction');
});

test('sweep drops entries past the age and keeps fresh ones', () => {
    const now = Date.now();
    const m = new BoundedMap({ maxEntries: 100, maxAgeMs: 1000 });
    m.set('old', { ts: now - 5000 });
    m.set('fresh', { ts: now - 100 });

    assert.strictEqual(m.sweep(now), 1, 'one entry reported dropped');
    assert.strictEqual(m.has('old'), false);
    assert.strictEqual(m.has('fresh'), true);
});

test('sweep is a no-op without a configured age', () => {
    const m = new BoundedMap({ maxEntries: 10 });
    m.set('ancient', { ts: 0 });

    assert.strictEqual(m.sweep(Date.now()), 0);
    assert.strictEqual(m.has('ancient'), true, 'age-less caches are bounded by count only');
});

test('sweep tolerates entries with no usable timestamp', () => {
    const m = new BoundedMap({ maxEntries: 10, maxAgeMs: 1000 });
    m.set('shaped', { ts: 0 });
    m.set('odd', { noTimestamp: true });
    m.set('nullish', null);

    assert.doesNotThrow(() => m.sweep(Date.now()));
    assert.strictEqual(m.has('odd'), true, 'unrecognised entries are left alone, not dropped');
    assert.strictEqual(m.has('shaped'), false);
});

// --- the real caches are wired to it ---------------------------------------

test('the stream list caches are bounded per account', () => {
    for (let i = 0; i < CACHE_MAX_STREAM_ACCOUNTS + 2; i++) {
        vodStreamsCache.set(cfgFor(`user${i}`), [{ stream_id: i }]);
    }
    assert.strictEqual(vodStreamsCache.map.size, CACHE_MAX_STREAM_ACCOUNTS);
    assert.strictEqual(
        vodStreamsCache.get(cfgFor('user0')),
        null,
        'the earliest account was evicted rather than held forever'
    );
    assert.deepStrictEqual(
        vodStreamsCache.get(cfgFor(`user${CACHE_MAX_STREAM_ACCOUNTS + 1}`)),
        [{ stream_id: CACHE_MAX_STREAM_ACCOUNTS + 1 }],
        'the newest is still served'
    );
});

test('seriesInfoCache is bounded, so browsing many series cannot grow forever', () => {
    for (let i = 0; i < CACHE_MAX_SERIES_INFO + 25; i++) {
        seriesInfoCache.set(`key-${i}`, { data: {}, ts: Date.now() });
    }
    assert.strictEqual(seriesInfoCache.size, CACHE_MAX_SERIES_INFO);
});

test('catCache is bounded by account count', () => {
    for (let i = 0; i < CACHE_MAX_ACCOUNTS + 5; i++) {
        catCache.set(`account-${i}`, { live: [], movies: [], series: [], ts: Date.now(), ttl: CACHE_TTL });
    }
    assert.strictEqual(catCache.size, CACHE_MAX_ACCOUNTS);
});

// This is the interaction that makes catCache different from the others: M2
// deliberately serves *expired* categories when a refresh fails, because stale
// beats empty. Sweeping it on the normal TTL would silently undo that.
test('an expired catCache entry survives a sweep, preserving the stale fallback', () => {
    const now = Date.now();
    catCache.set('acct', {
        live: [{ category_id: '1' }], movies: [], series: [],
        ts: now - (CACHE_TTL * 2),   // long expired
        ttl: CACHE_TTL
    });

    sweepCaches(now);

    const kept = catCache.peek('acct');
    assert.ok(kept, 'the expired entry is still there to fall back on');
    assert.deepStrictEqual(kept.live, [{ category_id: '1' }]);
});

test('catCache entries are reclaimed once genuinely abandoned', () => {
    const now = Date.now();
    catCache.set('abandoned', { live: [], movies: [], series: [], ts: now - CACHE_STALE_MAX_AGE_MS - 1, ttl: CACHE_TTL });

    sweepCaches(now);
    assert.strictEqual(catCache.has('abandoned'), false);
});

test('sweepCaches reclaims expired entries across every cache', () => {
    const now = Date.now();
    const stale = now - CACHE_TTL - 1;

    seriesInfoCache.set('s1', { data: {}, ts: stale });
    vodStreamsCache.map.set(accountCacheKey(cfgFor('a')), { data: [], ts: stale });
    liveStreamsCache.map.set(accountCacheKey(cfgFor('b')), { data: [], ts: stale });
    seriesStreamsCache.map.set(accountCacheKey(cfgFor('c')), { data: [], ts: stale });

    assert.strictEqual(sweepCaches(now), 4, 'all four reported');
    assert.strictEqual(seriesInfoCache.size, 0);
    assert.strictEqual(vodStreamsCache.map.size, 0);
    assert.strictEqual(liveStreamsCache.map.size, 0);
    assert.strictEqual(seriesStreamsCache.map.size, 0);
});

// sweepCaches used to name all eight caches in a hand-written sum. A cache left
// off it was not a visible bug: the map still evicted on write, so it only failed
// to reclaim memory while nothing new arrived — a leak with no symptom until the
// process was large. Registration at construction is what replaced that, and this
// is the assertion the old shape could not have.
test('every live cache is swept, without sweepCaches naming any of them', () => {
    const live = [
        ['catCache', catCache],
        ['seriesInfoCache', seriesInfoCache],
        ['hlsOriginVetCache', hlsOriginVetCache],
        ['vodInfoCache', vodInfoCache.map],
        ['categoryStreamsCache', categoryStreamsCache.map],
        ['liveStreamsCache', liveStreamsCache.map],
        ['vodStreamsCache', vodStreamsCache.map],
        ['seriesStreamsCache', seriesStreamsCache.map]
    ];

    // Each one gets an entry old enough for its own rule — catCache sweeps on the
    // 24-hour stale window, not the TTL — and the sweep must account for all of
    // them in one call.
    const now = Date.now();
    const ancient = now - CACHE_STALE_MAX_AGE_MS - 1;
    for (const [, map] of live) map.set('sweep-probe', { data: null, ts: ancient });

    const dropped = sweepCaches(now);
    assert.ok(dropped >= live.length, `swept ${dropped}, expected at least ${live.length}`);
    for (const [name, map] of live) {
        assert.equal(map.has('sweep-probe'), false, `${name} was not visited by the sweep`);
    }

    // And the sum is gone from the source: a list that names caches is exactly the
    // thing a new cache gets left out of.
    const src = require('node:fs').readFileSync(require.resolve('../index.js'), 'utf8');
    const body = src.slice(src.indexOf('function sweepCaches'), src.indexOf('function startCacheSweeper'));
    assert.equal((body.match(/Cache\.sweep\(|Cache\.map\.sweep\(/g) || []).length, 0,
        'sweepCaches is naming caches again');
});

test('a fresh entry is left alone by the sweeper', () => {
    const now = Date.now();
    vodStreamsCache.set(cfgFor('active'), [{ stream_id: 1 }]);

    assert.strictEqual(sweepCaches(now), 0);
    assert.deepStrictEqual(vodStreamsCache.get(cfgFor('active')), [{ stream_id: 1 }]);
});

test('the sweep timer never holds the process open', () => {
    const timer = startCacheSweeper();
    assert.strictEqual(typeof timer.unref, 'function');
    // hasRef() is the observable proof; an un-unref'd interval would keep
    // `npm test` itself from exiting.
    assert.strictEqual(timer.hasRef(), false);
    clearInterval(timer);
});
