// A per-client rate limit for POST /configure.
//
// POST /configure makes an outbound request to a host the caller chooses, with
// credentials the caller chooses, before any authentication. Without a limit,
// that turns this server into a port scanner and a credential-stuffing relay
// running on its IP. A handful of attempts per minute is far more than a human
// configuring an addon needs.
const { clientKey } = require('../routes/request.js');

const CONFIGURE_RATE_LIMIT = Math.max(1, Number(process.env.CONFIGURE_RATE_LIMIT) || 10);
const CONFIGURE_RATE_WINDOW_MS = Math.max(1000, Number(process.env.CONFIGURE_RATE_WINDOW_MS) || 60 * 1000);
// Bounded; once full, the oldest client's bucket makes room rather than letting
// new clients through untracked.
const CONFIGURE_RATE_MAX_CLIENTS = 10000;

// client key -> { count, resetAt }
const configureAttempts = new Map();

// A fixed window: a client's count resets on its first attempt after the window
// ends.
//
// Expired buckets are swept on every call, which keeps the map proportional to
// *active* clients. A Map iterates in insertion order, a bucket is only ever
// inserted at the start of its window, and every window is the same length — so
// the oldest bucket always expires first, and the sweep can stop at the first
// one that is still live.
function rateLimitConfigure(req) {
    const now = Date.now();
    for (const [key, entry] of configureAttempts) {
        if (entry.resetAt > now) break;
        configureAttempts.delete(key);
    }

    const key = clientKey(req);
    let entry = configureAttempts.get(key);
    if (entry && entry.resetAt <= now) {
        configureAttempts.delete(key);
        entry = undefined;
    }
    if (!entry) {
        while (configureAttempts.size >= CONFIGURE_RATE_MAX_CLIENTS) {
            configureAttempts.delete(configureAttempts.keys().next().value);
        }
        configureAttempts.set(key, { count: 1, resetAt: now + CONFIGURE_RATE_WINDOW_MS });
        return { allowed: true, retryAfter: 0 };
    }

    entry.count += 1;
    if (entry.count > CONFIGURE_RATE_LIMIT) {
        return { allowed: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
    }
    return { allowed: true, retryAfter: 0 };
}

module.exports = {
    CONFIGURE_RATE_LIMIT,
    CONFIGURE_RATE_WINDOW_MS,
    CONFIGURE_RATE_MAX_CLIENTS,
    configureAttempts,
    rateLimitConfigure
};
