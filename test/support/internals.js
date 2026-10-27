// Every module's exports in one object, for the test suite only.
//
// Tests import from here so that each one does not have to know which file a
// function lives in. Application code never imports this file: it requires the
// module it needs directly.
//
// Every name is unique across these modules, so spreading them together loses
// nothing. index.js is deliberately absent — requiring it starts the server.
module.exports = {
    ...require('../../src/helpers.js'),
    ...require('../../src/html.js'),
    ...require('../../src/config-token.js'),
    ...require('../../src/panel-allowlist.js'),
    ...require('../../src/lifecycle.js'),
    ...require('../../src/manifest.js'),
    ...require('../../src/cache/bounded-map.js'),
    ...require('../../src/cache/layers.js'),
    ...require('../../src/catalog/kinds.js'),
    ...require('../../src/catalog/shelf.js'),
    ...require('../../src/configure/validate.js'),
    ...require('../../src/configure/rate-limit.js'),
    ...require('../../src/hls/playlist.js'),
    ...require('../../src/net/private-ip.js'),
    ...require('../../src/net/safe-fetch.js'),
    ...require('../../src/proxy/relay.js'),
    ...require('../../src/routes/cors.js'),
    ...require('../../src/routes/errors.js'),
    ...require('../../src/routes/extras.js'),
    ...require('../../src/routes/request.js'),
    ...require('../../src/upstream/read-capped.js'),
    ...require('../../src/xtream/client.js'),
    ...require('../../src/xtream/data.js'),
    ...require('../../src/pages/configure.js'),
    ...require('../../src/pages/landing.js'),
    HEALTH_MAX_EVENT_LOOP_LAG_MS: require('../../src/routes/health.js').HEALTH_MAX_EVENT_LOOP_LAG_MS,
    app: require('../../src/app.js').app
};
