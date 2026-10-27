// The Express app: middleware, every route, and the error handlers, in the
// order Express runs them. Starting the server is index.js's job; building the
// app is kept separate so the tests can use it without opening a port.
//
// Every route that serves an account starts with `/:config`, an encrypted token
// holding that account's provider URL, username and password (see
// src/config/token.js). That token is the install URL the user pastes into
// Stremio, so this server stores nothing about its users.
const express = require('express');

const { corsMiddleware } = require('./http/cors.js');
const { router: manifestRoutes } = require('./routes/manifest.js');
const { router: configureRoutes } = require('./routes/configure.js');
const { router: catalogRoutes } = require('./routes/catalog.js');
const { router: metaRoutes } = require('./routes/meta.js');
const { router: streamRoutes } = require('./routes/stream.js');
const { router: proxyRoutes } = require('./routes/proxy.js');
const { router: healthRoutes } = require('./routes/health.js');
const { notFound, terminalErrorHandler } = require('./http/errors.js');
const { renderLandingPage } = require('./pages/landing.js');

const app = express();
// Do not tell every visitor which framework is running.
app.disable('x-powered-by');

app.use(corsMiddleware);

// The landing page, and the setup form that produces an install URL.
app.get('/', (req, res) => res.send(renderLandingPage()));
app.use(configureRoutes);

// The Stremio addon protocol: manifest -> catalog -> meta -> stream.
app.use(manifestRoutes);
app.use(catalogRoutes);
app.use(metaRoutes);
app.use(streamRoutes);

// The playback URLs handed out by the stream route.
app.use(proxyRoutes);

app.use(healthRoutes);

// Registered last: anything no route answered.
app.use(notFound);
app.use(terminalErrorHandler);

module.exports = { app };
