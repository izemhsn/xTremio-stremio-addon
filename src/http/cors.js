// Which responses may be read by scripts on other websites (CORS).
//
// The Stremio addon protocol is called cross-origin by web.stremio.com, so its
// JSON resources need a wildcard. Nothing else does: /configure handles
// plaintext credentials, and the landing page and health probe are read by
// people and load balancers, not by scripts on other origins.
const CORS_PATH = /^\/(?:[^/]+\/)?(?:manifest\.json|catalog\/|meta\/|stream\/)/;

// The byte proxy is excluded by default. CORS does not protect your bandwidth —
// a plain <video src> or a server-side fetch needs no CORS at all, so the config
// token is the only real gate. Set PROXY_CORS=true if a player turns out to need
// it (an MSE-based one, or a crossorigin video element).
const PROXY_CORS = process.env.PROXY_CORS === 'true';
const PROXY_PATH = /^\/[^/]+\/proxy\//;

function corsApplies(path) {
    if (PROXY_PATH.test(path)) return PROXY_CORS;
    return CORS_PATH.test(path);
}

function corsMiddleware(req, res, next) {
    if (!corsApplies(req.path)) return next();
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
}

module.exports = { corsApplies, corsMiddleware };
