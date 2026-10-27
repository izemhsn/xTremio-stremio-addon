// Entry point: `npm start` runs this file.
//
// It checks the configuration, starts the HTTP server, and installs the
// process-wide handlers for signals and crashes. The app itself — every route
// and middleware — is built in src/app.js. To find your way around the code,
// start with docs/ARCHITECTURE.md.
const { app } = require('./src/app.js');
const { enforceConfigSecretPolicy } = require('./src/config-token.js');
const { warnOnUndiciMismatch } = require('./src/net/safe-fetch.js');
const { startCacheSweeper } = require('./src/cache/layers.js');
const { PORT, HOST, warnOnUnpinnedBaseUrl } = require('./src/routes/request.js');
const { applyServerTimeouts, createShutdownHandler } = require('./src/lifecycle.js');

// Before binding a port: a production deploy with a weak or missing secret
// should fail loudly at startup, not quietly issue forgeable install URLs.
enforceConfigSecretPolicy();
warnOnUnpinnedBaseUrl();
warnOnUndiciMismatch();

// Periodically drops expired cache entries.
startCacheSweeper();

const server = applyServerTimeouts(app.listen(PORT, HOST, () => {
    console.log(`Addon running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    console.log(`Configure: http://localhost:${PORT}/configure`);
}));

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Kill the existing process or use a different port: PORT=3001 npm start`);
    } else {
        console.error('Server error:', err.message);
    }
    process.exit(1);
});

const shutdown = createShutdownHandler(server);
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// After an uncaught error the process is in an unknown state, so it exits and
// lets the process manager restart it. Client disconnects are handled where
// they happen, so one reaching here is a real bug too.
process.on('uncaughtException', (err) => {
    console.error('Uncaught exception, exiting:', err);
    process.exit(1);
});
// Express 5 already sends errors from async routes to the error handler, so an
// unhandled rejection here is a bug as well.
process.on('unhandledRejection', (err) => {
    console.error('Unhandled rejection, exiting:', err);
    process.exit(1);
});
