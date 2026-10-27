// Error handling shared by every route.
//
// The Stremio routes answer failures quietly — an empty list rather than an
// error page — so the log is the only place an operator can see what went wrong.
// logRouteError makes a bug look different from a provider outage there: a
// programming error keeps its stack, a provider or network failure is one line.

function isProgrammingError(e) {
    if (e instanceof ReferenceError || e instanceof RangeError) return true;
    // fetch reports a network failure as TypeError('fetch failed') with a cause.
    return e instanceof TypeError && !e.cause && e.message !== 'fetch failed';
}

function logRouteError(route, e) {
    if (isProgrammingError(e)) console.error(`[${route}] unexpected error: ${e.stack}`);
    else console.error(`[${route}] Error:`, e?.message);
}

// A path begins with the config token, which is a bearer credential: it
// decrypts to the account's password. Logging one would put working install
// URLs in the log file, so the first segment is dropped when it is long enough
// to be a token rather than a route name.
//
// /configure also takes a token as a `config` query parameter, so the path and
// the query string are redacted separately.
function redactConfigInPath(path) {
    const raw = String(path);
    const cut = raw.indexOf('?');
    const pathname = cut === -1 ? raw : raw.slice(0, cut);
    const query = cut === -1 ? '' : raw.slice(cut);
    return pathname.replace(/^\/[^/]{24,}/, '/<config>')
        + query.replace(/([?&]config=)[^&]*/gi, '$1<config>');
}

// Unknown paths, so Express's default HTML 404 (which names the method and the
// path) never reaches a client.
function notFound(req, res) {
    res.status(404).type('text/plain').end('not found');
}

// Terminal error handler: Express's default writes stacks into responses. A
// malformed percent-escape throws a URIError out of the router before any handler
// runs, so only this can catch it. Registered last; the four parameters are what
// mark it as an error handler to Express.
function terminalErrorHandler(err, req, res, next) {
    // A URIError means the client sent a bad path, not that the server broke.
    // Anything carrying its own status (body-parser and friends) is trusted to
    // have set a sensible one — but only inside the error range, since
    // res.status() will send whatever it is given.
    const claimed = Number(err?.status || err?.statusCode);
    const status = err instanceof URIError
        ? 400
        : (claimed >= 400 && claimed <= 599 ? claimed : 500);

    const where = `${req.method} ${redactConfigInPath(req.originalUrl || req.url)} -> ${status}`;
    // A 5xx logs its stack; a 4xx one line. The stack, never the error object,
    // whose properties can carry request data (a failed `new URL()` holds its
    // input, which can include credentials).
    if (status >= 500) console.error(`[error] ${where}:`, err?.stack || String(err));
    else console.warn(`[error] ${where}: ${err?.message}`);

    // Once the body has started there is no status left to set, and the
    // response is already half-written; hand back to Express, which closes the
    // connection rather than appending a stack to a partial body.
    if (res.headersSent) return next(err);

    res.status(status).type('text/plain').end(status < 500 ? 'bad request' : 'internal error');
}

module.exports = {
    isProgrammingError,
    logRouteError,
    redactConfigInPath,
    notFound,
    terminalErrorHandler
};
