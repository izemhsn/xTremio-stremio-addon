// GET /health — for load balancers and orchestrators.
//
// "The process is running" is nearly always true and rarely the useful
// question. The thread that answers /health is the same one that parses large
// catalogs and relays video, so this server fails by being too busy to answer
// in time. Event-loop delay measures exactly that.
//
// The delay histogram is reset on every read, so each probe reports the time
// since the previous probe. Concurrent probes therefore split the window between
// them, and a long gap between probes widens it. Both are fine for a load
// balancer polling on a fixed interval, and neither can hide a stall.
const { monitorEventLoopDelay } = require('node:perf_hooks');
const express = require('express');

const { isShuttingDown } = require('../lifecycle.js');

// Its timer does not keep the process alive, so it does not delay shutdown.
const eventLoopDelay = monitorEventLoopDelay({ resolution: 10 });
eventLoopDelay.enable();

// Deliberately far above anything healthy. Idle delay is the platform's timer
// granularity (about 15.6 ms on Windows), and parsing a 25 MB catalog — the
// largest blocking work this server does on purpose — takes about 128 ms. A
// readiness check that flaps under ordinary load pulls a busy-but-working
// instance out of the pool and moves its traffic onto the others, which is how
// one slow instance becomes an outage.
const HEALTH_MAX_EVENT_LOOP_LAG_MS = 1000;

// Nanoseconds -> milliseconds, rounded to one decimal place. An empty window
// (two probes too close together to measure anything) reports NaN; nothing was
// measured, so that reads as 0.
function nsToMs(ns) {
    return Number.isFinite(ns) ? Math.round((ns / 1e6) * 10) / 10 : 0;
}

const router = express.Router();

router.get('/health', (req, res) => {
    // Failing while shutting down is the point: it takes this instance out of
    // the load balancer's pool before the process actually exits.
    const draining = isShuttingDown();
    const lagMs = nsToMs(eventLoopDelay.max);
    const meanLagMs = nsToMs(eventLoopDelay.mean);
    eventLoopDelay.reset();

    const stalled = lagMs > HEALTH_MAX_EVENT_LOOP_LAG_MS;
    const status = draining ? 'shutting_down' : (stalled ? 'stalled' : 'ok');
    res.status(draining || stalled ? 503 : 200)
        .set('Cache-Control', 'no-store')
        .json({
            status,
            uptime: process.uptime(),
            eventLoopLagMs: lagMs,
            eventLoopLagMeanMs: meanLagMs
        });
});

module.exports = { router, HEALTH_MAX_EVENT_LOOP_LAG_MS };
