// Three audit findings about how this process lives and dies (L10, L11, L12).
// They matter more here than in a typical JSON service because the stream proxy
// holds a socket open for the length of a movie:
//
//   L10 — SIGTERM called server.close() with no deadline, so one active stream
//         blocked shutdown until the platform SIGKILLed us mid-write.
//   L11 — /health returned 200 unconditionally, so a draining (or wedged)
//         instance stayed in the load balancer pool.
//   L12 — no headersTimeout / requestTimeout / keepAliveTimeout tuning.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const http = require('node:http');

const {
    app,
    applyServerTimeouts,
    createShutdownHandler,
    isShuttingDown,
    setShuttingDown,
    KEEPALIVE_TIMEOUT_MS,
    HEADERS_TIMEOUT_MS,
    REQUEST_TIMEOUT_MS,
    HEALTH_MAX_EVENT_LOOP_LAG_MS
} = require('./support/internals.js');

const quietLog = { log() {}, warn() {} };

// A server stub whose close() never completes, standing in for the case that
// motivates the whole fix: a long-lived proxy stream keeping a socket alive.
function stuckServer() {
    return {
        closeCalls: 0,
        idleClosed: 0,
        close() { this.closeCalls++; },
        closeIdleConnections() { this.idleClosed++; }
    };
}

// --- L12: timeouts ---------------------------------------------------------

test('applyServerTimeouts sets all three connection timeouts', () => {
    const server = http.createServer();
    applyServerTimeouts(server);
    expect(server.keepAliveTimeout).toBe(KEEPALIVE_TIMEOUT_MS);
    expect(server.headersTimeout).toBe(HEADERS_TIMEOUT_MS);
    expect(server.requestTimeout).toBe(REQUEST_TIMEOUT_MS);
});

test('the socket inactivity timeout stays off', () => {
    const server = http.createServer();
    applyServerTimeouts(server);
    // A non-zero server.timeout kills a socket that goes quiet, which is exactly
    // what a paused or slow-buffering video stream looks like.
    expect(server.timeout).toBe(0);
});

test('headersTimeout exceeds keepAliveTimeout', () => {
    // Otherwise a socket merely idling between keep-alive requests is torn down
    // as though it were a slow header write.
    expect(
        HEADERS_TIMEOUT_MS,
        `headers ${HEADERS_TIMEOUT_MS} must exceed keepAlive ${KEEPALIVE_TIMEOUT_MS}`
    ).toBeGreaterThan(KEEPALIVE_TIMEOUT_MS);
    expect(REQUEST_TIMEOUT_MS).toBeGreaterThanOrEqual(HEADERS_TIMEOUT_MS);
});

test('keepAliveTimeout outlasts the usual 60s balancer idle timeout', () => {
    // We want the balancer to be the side that closes an idle socket. If we close
    // first, a request can land on a socket we just tore down and the user sees a
    // 502 from the balancer.
    expect(KEEPALIVE_TIMEOUT_MS, `${KEEPALIVE_TIMEOUT_MS} must be over 60000`).toBeGreaterThan(60000);
});

test('the timeouts are env-tunable and clamped into a valid ordering', () => {
    // Reloaded in a child env so the module-load-time reads are exercised.
    const { execFileSync } = require('node:child_process');
    const out = execFileSync(process.execPath, ['-e', `
        const m = require(${JSON.stringify(require.resolve('./support/internals.js'))});
        console.log(JSON.stringify([m.KEEPALIVE_TIMEOUT_MS, m.HEADERS_TIMEOUT_MS, m.REQUEST_TIMEOUT_MS]));
    `], {
        env: { ...process.env, CONFIG_SECRET: 'x', KEEPALIVE_TIMEOUT_MS: '90000', HEADERS_TIMEOUT_MS: '1000', REQUEST_TIMEOUT_MS: '1' },
        encoding: 'utf8'
    });
    const [keepAlive, headers, request] = JSON.parse(out.trim().split('\n').pop());
    expect(keepAlive).toBe(90000);
    // Nonsensical values are raised rather than accepted: the ordering invariant
    // holds no matter what the operator sets.
    expect(headers, `headers ${headers} > keepAlive ${keepAlive}`).toBeGreaterThan(keepAlive);
    expect(request, `request ${request} >= headers ${headers}`).toBeGreaterThanOrEqual(headers);
});

// --- L10: shutdown ---------------------------------------------------------

test('a clean close exits 0 and cancels the force-exit timer', async () => {
    const exits = [];
    const server = {
        close(cb) { setTimeout(cb, 5); },
        closeIdleConnections() {}
    };
    const shutdown = createShutdownHandler(server, { timeoutMs: 200, exit: c => exits.push(c), log: quietLog });
    shutdown('SIGTERM');

    await new Promise(r => setTimeout(r, 60));
    expect(exits).toStrictEqual([0]);
    // Well past the close, still well before the deadline: the timer must be gone.
    await new Promise(r => setTimeout(r, 200));
    expect(exits, 'the force-exit timer must have been cleared').toStrictEqual([0]);
    setShuttingDown(false);
});

test('a stream that will not drain is force-exited instead of hanging', async () => {
    const exits = [];
    const server = stuckServer();
    const shutdown = createShutdownHandler(server, { timeoutMs: 40, exit: c => exits.push(c), log: quietLog });
    shutdown('SIGTERM');

    expect(exits, 'must not exit before the deadline').toStrictEqual([]);
    await new Promise(r => setTimeout(r, 120));
    // Exit code 1: this is an ungraceful shutdown and the platform should know.
    expect(exits).toStrictEqual([1]);
    setShuttingDown(false);
});

test('idle keep-alive sockets are closed so they do not hold up the drain', async () => {
    const server = stuckServer();
    const shutdown = createShutdownHandler(server, { timeoutMs: 5000, exit() {}, log: quietLog });
    shutdown('SIGTERM');
    expect(server.idleClosed).toBe(1);
    setShuttingDown(false);
});

test('a real server with a live connection is force-exited, not left hanging', async () => {
    // The stub above proves the timer logic; this proves the premise. A real
    // http.Server with a request in progress genuinely does not finish close(),
    // which is the situation an in-flight movie stream creates.
    const net = require('node:net');
    const inflight = [];
    const server = http.createServer((req, res) => { inflight.push(res); /* never responds */ });
    await new Promise(r => server.listen(0, '127.0.0.1', r));

    const sock = net.connect(server.address().port, '127.0.0.1');
    await new Promise(r => sock.on('connect', r));
    sock.write('GET / HTTP/1.1\r\nHost: x\r\n\r\n');
    await new Promise(r => setTimeout(r, 50));

    const exits = [];
    let closed = false;
    server.on('close', () => { closed = true; });
    const shutdown = createShutdownHandler(server, { timeoutMs: 60, exit: c => exits.push(c), log: quietLog });
    shutdown('SIGTERM');

    await new Promise(r => setTimeout(r, 200));
    expect(closed, 'close() must still be pending — that is the bug being guarded').toBe(false);
    expect(exits, 'the deadline must fire rather than waiting for SIGKILL').toStrictEqual([1]);

    onTestFinished(() => {
        setShuttingDown(false);
        sock.destroy();
        for (const res of inflight) res.destroy();
        server.close();
    });
});

test('a second signal does not restart the shutdown', async () => {
    const server = stuckServer();
    const shutdown = createShutdownHandler(server, { timeoutMs: 5000, exit() {}, log: quietLog });
    shutdown('SIGTERM');
    shutdown('SIGINT');
    shutdown('SIGTERM');
    expect(server.closeCalls).toBe(1);
    setShuttingDown(false);
});

// --- L11: /health ----------------------------------------------------------

test('/health reports ok, then unhealthy once draining', async () => {
    const server = await new Promise(resolve => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    onTestFinished(async () => {
        setShuttingDown(false);
        await new Promise(r => server.close(r));
    });

    // /health reports the worst event-loop stall since the previous reading, and
    // the first reading also covers loading the app (synchronous scrypt key
    // derivation), which can pass the 1 s threshold on a machine busy running
    // the other test files in parallel. One discarded reading starts a clean
    // window, so what follows measures this test only.
    await (await fetch(`${base}/health`)).arrayBuffer();

    let res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    let body = await res.json();
    expect(body.status).toBe('ok');
    expect(typeof body.uptime).toBe('number');
    // A cached 200 would keep a drained instance looking healthy.
    expect(res.headers.get('cache-control')).toBe('no-store');

    setShuttingDown(true);
    res = await fetch(`${base}/health`);
    expect(res.status, 'a draining instance must fail its health check').toBe(503);
    body = await res.json();
    expect(body.status).toBe('shutting_down');
});

// Liveness alone said only that the process was running, which on this server is
// nearly always true and nearly never the question: the thread that answers this
// route is the thread that parses catalogs and relays video.
test('/health reports event-loop lag, and a stalled loop fails the check', async () => {
    const server = await new Promise(resolve => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    onTestFinished(async () => { await new Promise(r => server.close(r)); });
    // Start a clean measurement window; see the test above.
    await (await fetch(`${base}/health`)).arrayBuffer();

    // A healthy instance reports a number and stays healthy. The idle floor is the
    // platform's timer granularity — 15.6 ms on Windows — so this asserts a
    // plausible reading rather than a small one.
    let body = await (await fetch(`${base}/health`)).json();
    expect(typeof body.eventLoopLagMs, 'the reading must be reported').toBe('number');
    expect(typeof body.eventLoopLagMeanMs).toBe('number');
    expect(
        body.eventLoopLagMs >= 0 && body.eventLoopLagMs < HEALTH_MAX_EVENT_LOOP_LAG_MS,
        `an idle instance reported ${body.eventLoopLagMs}ms of lag`
    ).toBeTruthy();

    // Block the loop for longer than the threshold. Deferred by a timer so the
    // block lands in its own tick: run inline, it would finish before the
    // histogram's timer re-armed and go unrecorded, which is how the first
    // attempt at this test measured nothing at all.
    await new Promise(resolve => setTimeout(resolve, 20));
    await new Promise(resolve => {
        setTimeout(() => {
            const until = Date.now() + HEALTH_MAX_EVENT_LOOP_LAG_MS + 300;
            while (Date.now() < until) { /* deliberately blocking */ }
            resolve();
        }, 20);
    });

    const res = await fetch(`${base}/health`);
    expect(res.status, 'a loop blocked past the threshold is not ready').toBe(503);
    body = await res.json();
    expect(body.status).toBe('stalled');
    expect(
        body.eventLoopLagMs,
        `reported ${body.eventLoopLagMs}ms after blocking for longer than that`
    ).toBeGreaterThan(HEALTH_MAX_EVENT_LOOP_LAG_MS);

    // The window is reset per read, so the next probe is healthy again rather than
    // pinned by a spike that has passed.
    const after = await fetch(`${base}/health`);
    expect(after.status, 'the stall must not persist once it is over').toBe(200);
    expect((await after.json()).status).toBe('ok');
});

test('the shutdown handler is what flips /health', () => {
    expect(isShuttingDown()).toBe(false);
    const shutdown = createShutdownHandler(stuckServer(), { timeoutMs: 5000, exit() {}, log: quietLog });
    shutdown('SIGTERM');
    // The drain signal must be raised as the shutdown begins, not once close()
    // finishes — the point is to leave the pool before we stop serving.
    expect(isShuttingDown()).toBe(true);
    setShuttingDown(false);
});
