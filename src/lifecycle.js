// Starting and stopping the server cleanly.
//
// The four timeouts are ordered, not independent: headersTimeout must exceed
// keepAliveTimeout or a socket can be closed between requests while a request is
// arriving on it, and requestTimeout must exceed headersTimeout. Each Math.max
// enforces its own floor, so raising one by configuration cannot invert the pair.
//
// The shutdown handler raises the drain signal as it begins rather than when
// close() finishes: the point is to leave the load balancer's pool before this
// instance stops serving, which is what /health reports.
// hold a socket open for the length of a movie. That changes what the right
// timeout and shutdown behaviour are, so both are stated explicitly rather than
// left on Node's defaults.

const SHUTDOWN_TIMEOUT_MS = Math.max(1000, Number(process.env.SHUTDOWN_TIMEOUT_MS) || 10000);
// Deliberately longer than the 60 s idle timeout most load balancers use, so the
// balancer is always the side that closes an idle connection. If we closed first
// there is a race where a request arrives on a socket we have just torn down,
// which the balancer reports to the user as a 502.
const KEEPALIVE_TIMEOUT_MS = Math.max(1000, Number(process.env.KEEPALIVE_TIMEOUT_MS) || 65000);
// Must exceed keepAliveTimeout, or a socket idling between keep-alive requests
// is killed as if it were a slow header write.
const HEADERS_TIMEOUT_MS = Math.max(KEEPALIVE_TIMEOUT_MS + 1000, Number(process.env.HEADERS_TIMEOUT_MS) || 66000);
// Caps how long we will spend receiving a *request*. The response body is not
// affected, so a proxied stream may still run for hours.
const REQUEST_TIMEOUT_MS = Math.max(HEADERS_TIMEOUT_MS, Number(process.env.REQUEST_TIMEOUT_MS) || 120000);

let shuttingDown = false;
function isShuttingDown() { return shuttingDown; }
// Test-only: the flag is process-wide, so a test that exercises the drain path
// needs a way back.
function setShuttingDown(value) { shuttingDown = Boolean(value); }

function applyServerTimeouts(server) {
    server.keepAliveTimeout = KEEPALIVE_TIMEOUT_MS;
    server.headersTimeout = HEADERS_TIMEOUT_MS;
    server.requestTimeout = REQUEST_TIMEOUT_MS;
    // Already Node's default, but stated because a non-zero socket inactivity
    // timeout here would kill a paused or slow-buffering stream mid-playback.
    server.timeout = 0;
    return server;
}

function createShutdownHandler(server, { timeoutMs = SHUTDOWN_TIMEOUT_MS, exit = (code) => process.exit(code), log = console } = {}) {
    let started = false;
    return function shutdown(signal) {
        if (started) return;
        started = true;
        setShuttingDown(true);   // /health starts failing, so a balancer drains us
        log.log(`${signal} received, shutting down...`);

        // An in-flight movie stream can hold its socket for hours, so server.close()
        // on its own waits until the platform loses patience and SIGKILLs us
        // mid-write. Give real requests a window, then leave regardless.
        const forced = setTimeout(() => {
            log.warn(`Shutdown still pending after ${timeoutMs} ms, forcing exit.`);
            exit(1);
        }, timeoutMs);
        if (typeof forced.unref === 'function') forced.unref();

        server.close(() => {
            clearTimeout(forced);
            exit(0);
        });
        // Sockets parked between keep-alive requests have nothing to drain, but
        // would still make close() wait out the full window.
        if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
    };
}

module.exports = {
    SHUTDOWN_TIMEOUT_MS,
    KEEPALIVE_TIMEOUT_MS,
    HEADERS_TIMEOUT_MS,
    REQUEST_TIMEOUT_MS,
    isShuttingDown,
    setShuttingDown,
    applyServerTimeouts,
    createShutdownHandler
};
