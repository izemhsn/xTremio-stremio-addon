// The two bounding primitives every data cache is built on, and nothing else:
// no TTLs, no upstream calls, no knowledge of what is being cached. BoundedMap
// bounds one map by entry count and by estimated bytes; CacheBudget is the single
// LRU order shared across all of them, so the per-cache bounds add up to a figure
// of memory rather than to nothing.
//
// An entry's weight is its own `bytes` field, set by the caller from
// estimateBytes — the weighing lives with the reader that counted the body, in
// src/upstream/read-capped.js, and only the number arrives here.


// One memory budget shared by every data cache (CACHE_MAX_MB, audit R2): the
// per-cache bounds do not add up to any figure of memory. LRU across all caches in
// one order. Entries are tracked by object identity, so caches sharing a key string
// cannot collide, and by the weight they were added with, so the total cannot drift.
class CacheBudget {
    constructor(maxBytes) {
        this.maxBytes = maxBytes;
        this.totalBytes = 0;
        this.order = new Map(); // entry -> { owner, key, bytes }
    }

    add(entry, owner, key) {
        const bytes = weightOf(entry);
        this.order.set(entry, { owner, key, bytes });
        this.totalBytes += bytes;
    }

    touch(entry) {
        const ref = this.order.get(entry);
        if (!ref) return;
        this.order.delete(entry);
        this.order.set(entry, ref);
    }

    remove(entry) {
        const ref = this.order.get(entry);
        if (!ref) return;
        this.order.delete(entry);
        this.totalBytes -= ref.bytes;
    }

    // Evicts oldest-first until the total fits, never the entry just written.
    // Eviction goes through the owning cache, so its own total and its onEvict
    // report stay right; the size check afterwards is what guarantees the loop
    // ends even if an owner were ever to fail to release its entry.
    enforce(keep) {
        while (this.totalBytes > this.maxBytes) {
            let victim = null;
            for (const [entry, ref] of this.order) {
                if (entry !== keep) {
                    victim = ref;
                    break;
                }
            }
            if (!victim) break;
            const before = this.order.size;
            victim.owner.evict(victim.key, 'global budget');
            if (this.order.size === before) break;
        }
    }
}

// An LRU Map bounded by entry count, optionally by weight (`maxBytes`, from each
// entry's `bytes`) and by age (`sweep`). Map iterates in insertion order, so
// re-inserting on read makes the first key the least recently used. `onEvict`
// reports what was dropped and why. `ledger` charges entries to a shared
// CacheBudget; opt-in, so a test's map does not compete with the real caches.
class BoundedMap extends Map {
    constructor({ maxEntries, maxAgeMs = null, maxBytes = null, onEvict = null, ledger = null }) {
        super();
        this.maxEntries = maxEntries;
        this.maxAgeMs = maxAgeMs;
        this.maxBytes = maxBytes;
        this.onEvict = onEvict;
        this.ledger = ledger;
        this.totalBytes = 0;
    }

    get(key) {
        const entry = super.get(key);
        if (entry === undefined) return undefined;
        // Touch: delete + re-insert moves this key to the most-recent end.
        super.delete(key);
        super.set(key, entry);
        if (this.ledger) this.ledger.touch(entry);
        return entry;
    }

    // Read without disturbing LRU order. vetHlsOrigin uses it to check an entry
    // is still the one it wrote, and tests use it to inspect a cache without
    // changing what is evicted next.
    peek(key) {
        return super.get(key);
    }

    set(key, value) {
        // An entry larger than the whole shared budget is not stored at all:
        // keeping it would evict every other account's data and still not fit.
        // What it would have replaced goes too.
        if (this.ledger && weightOf(value) > this.ledger.maxBytes) {
            this.delete(key);
            console.warn(
                `[cache] not caching a ${Math.round(weightOf(value) / 1048576)} MB entry: larger than the ` +
                `whole CACHE_MAX_MB budget (${Math.round(this.ledger.maxBytes / 1048576)} MB). It will be ` +
                'fetched again on every request; raise CACHE_MAX_MB if a real provider sends lists this large'
            );
            return this;
        }

        const replaced = super.get(key);
        if (replaced) {
            this.totalBytes -= weightOf(replaced);
            if (this.ledger) this.ledger.remove(replaced);
        }
        super.delete(key);
        super.set(key, value);
        this.totalBytes += weightOf(value);
        if (this.ledger) this.ledger.add(value, this, key);

        // Never evict what was just written, even when a single entry is larger
        // than the whole budget: refusing to cache it at all would mean
        // refetching it on every request, which is worse than being over.
        while (this.size > 1 && (this.size > this.maxEntries || this.overBudget())) {
            // Map keys iterate oldest-first; the first is the LRU victim.
            const oldest = this.keys().next();
            if (oldest.done || oldest.value === key) break;
            this.evict(oldest.value, this.size > this.maxEntries ? 'entry count' : 'byte budget');
        }
        if (this.ledger) this.ledger.enforce(value);
        return this;
    }

    overBudget() {
        return this.maxBytes !== null && this.totalBytes > this.maxBytes;
    }

    evict(key, reason) {
        const entry = super.get(key);
        super.delete(key);
        this.totalBytes -= weightOf(entry);
        if (this.ledger) this.ledger.remove(entry);
        if (this.onEvict) this.onEvict(key, entry, reason);
        return entry;
    }

    delete(key) {
        if (super.has(key)) {
            const entry = super.get(key);
            this.totalBytes -= weightOf(entry);
            if (this.ledger) this.ledger.remove(entry);
        }
        return super.delete(key);
    }

    // Releases only this map's share of a shared budget, not the whole of it.
    clear() {
        if (this.ledger) for (const entry of super.values()) this.ledger.remove(entry);
        this.totalBytes = 0;
        return super.clear();
    }

    // Drops entries past maxAgeMs. Caches whose expired entries are still
    // useful (see catCache) pass a deliberately generous age, or none at all.
    //
    // An entry carrying its own ttl longer than maxAgeMs is reclaimed on that
    // instead: the stale-on-failure path extends one deliberately so the list
    // keeps being served through an outage, and sweeping it on the map's age
    // silently undid that a few minutes later (audit L3). A *shorter* per-entry
    // ttl never shortens the sweep — those entries stop being served on their
    // own ttl and are reclaimed here on the map's, exactly as before — so this
    // only ever keeps an entry that something deliberately asked to keep.
    sweep(now = Date.now()) {
        if (!this.maxAgeMs) return 0;
        let dropped = 0;
        for (const [key, entry] of this) {
            const maxAge = Math.max(this.maxAgeMs, typeof entry?.ttl === 'number' ? entry.ttl : 0);
            if (entry && typeof entry.ts === 'number' && entry.ts <= now - maxAge) {
                super.delete(key);
                this.totalBytes -= weightOf(entry);
                if (this.ledger) this.ledger.remove(entry);
                dropped++;
            }
        }
        return dropped;
    }
}

function weightOf(entry) {
    return typeof entry?.bytes === 'number' ? entry.bytes : 0;
}

module.exports = { BoundedMap, CacheBudget, weightOf };
