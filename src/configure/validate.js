// Does this panel exist, and do these credentials work there?
//
// Three rules here are about not sending a password somewhere it should not go.
// A typed `https://` is never moved onto http (audit S7): there is no http retry
// when https fails, and a `server_info` naming http is ignored for that
// connection. No scheme at all means https is tried *first* (audit L9), because
// normalizeUrl assumes http and the old order put the password on the wire in
// cleartext before anything had tried the panel's TLS port. And the attempt at a
// scheme the user did not type is a guess, so it carries the shorter probe
// deadline — most panels are http-only, and one behind a firewalled 443 would
// otherwise make every scheme-less /configure wait the full deadline.
//
// A `server_info` origin is adopted only after credentialsWorkAt confirms the
// credentials there (audit S8). A panel reporting its internal address used to
// get "Connected!" and an install link whose every catalog was empty.
const { normalizeUrl, buildUrl } = require('../helpers.js');
const { safeFetch } = require('../net/safe-fetch.js');
const { readJsonCapped } = require('../upstream/read-capped.js');
const { panelHostAllowed, hostnameOf } = require('../panel-allowlist.js');

function schemeOf(url) {
    return String(url || '').startsWith('https:') ? 'https' : 'http';
}

// How long /configure waits for a panel to answer. The probe deadline covers an
// attempt at a scheme the user did not type, which is a guess and must not cost
// the whole wait; see validateXtremioCredentials.
const CONFIGURE_TIMEOUT_MS = 15000;
const CONFIGURE_PROBE_TIMEOUT_MS = 6000;

// An https -> http move is baked into the token, so it is reported to the user.
function describeDowngrade(requested, finalUrl, source) {
    if (schemeOf(requested) !== 'https' || schemeOf(finalUrl) !== 'http') return null;
    return { from: 'https', to: 'http', source };
}

// The URL a provider names for itself in `server_info`, or null unless the fields
// form a bare http(s) origin; they have arrived with the port already in `url`, or
// a trailing slash.
function serverInfoOrigin(si) {
    if (!si || !si.url) return null;
    const proto = si.server_protocol || 'http';
    // https takes its port from https_port alone; borrowing `port` gave
    // https://host:80 (audit S8).
    const port = proto === 'https' ? si.https_port : si.port;
    let parsed;
    try {
        parsed = new URL(port ? `${proto}://${si.url}:${port}` : `${proto}://${si.url}`);
    } catch {
        return null;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password) return null;
    return parsed.origin;
}

// Whether these credentials work at `origin`: the same player_api call the check
// below makes, answered with auth=1. Never throws — any failure, a refusal by the
// SSRF guard included, is simply "no".
async function credentialsWorkAt(origin, username, password) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
        const res = await safeFetch(buildUrl(origin, '/player_api.php', { username, password }), { signal: controller.signal });
        const json = await readJsonCapped(res, 'credential check', 1024 * 1024);
        return json?.user_info?.auth === 1;
    } catch {
        return false;
    } finally {
        clearTimeout(timer);
    }
}

async function validateXtremioCredentials(serverUrl, username, password) {
    const base = normalizeUrl(serverUrl);
    // normalizeUrl assumes http for a URL with no scheme, so the normalized value
    // cannot tell a typed `http://` from no scheme at all — and the two deserve
    // different orders.
    const typed = String(serverUrl || '').trim().toLowerCase();
    const typedScheme = typed.startsWith('http://') || typed.startsWith('https://');
    // Someone who typed https:// is never moved onto http (audit S7). Someone who
    // typed http:// asked for it, so that is tried first and https is the upgrade.
    // With no scheme at all, https goes first: the old order put the password on
    // the wire in cleartext before anything had tried the panel's TLS port, and no
    // warning afterwards takes a sent password back (audit L9).
    const askedForHttps = schemeOf(base) === 'https';
    const httpsBase = base.replace(/^http:/, 'https:');
    // A scheme the user did not type is a guess, and a guess must not cost the
    // whole deadline: an http-only panel behind a firewalled 443 would otherwise
    // make every scheme-less /configure wait CONFIGURE_TIMEOUT_MS before trying
    // what works. Only the attempt the user actually asked for gets the full one.
    const attempts = [];
    if (askedForHttps) {
        attempts.push({ url: base, timeoutMs: CONFIGURE_TIMEOUT_MS });
    } else if (typedScheme) {
        attempts.push({ url: base, timeoutMs: CONFIGURE_TIMEOUT_MS });
        attempts.push({ url: httpsBase, timeoutMs: CONFIGURE_PROBE_TIMEOUT_MS });
    } else {
        attempts.push({ url: httpsBase, timeoutMs: CONFIGURE_PROBE_TIMEOUT_MS });
        attempts.push({ url: base, timeoutMs: CONFIGURE_TIMEOUT_MS });
    }
    // Whether any attempt got an HTTP response at all: a server that answered is
    // reachable, and the error should say the URL is wrong, not the network.
    let anyAnswered = false;

    for (let i = 0; i < attempts.length; i++) {
        const { url, timeoutMs } = attempts[i];
        const next = attempts[i + 1] || null;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let answered = false;
        try {
            const apiUrl = buildUrl(url, '/player_api.php', { username, password });
            const res = await safeFetch(apiUrl, { signal: controller.signal });
            answered = true;
            anyAnswered = true;
            // Unauthenticated entry point against a user-supplied host: a small
            // cap here, since an auth response is tiny and anything large is abuse.
            const json = await readJsonCapped(res, 'credential check', 1024 * 1024);

            // `?.`: a panel answering a literal `null` threw here, and the catch
            // reported it as "Cannot reach that server", which it plainly could.
            if (!json?.user_info) return { valid: false, error: 'Not a valid xTremio server' };
            if (json.user_info.auth !== 1) return { valid: false, error: 'Invalid username or password' };
            if (json.user_info.status !== 'Active') return { valid: false, error: `Account is ${json.user_info.status || 'inactive'}` };

            const expDate = parseInt(json.user_info.exp_date, 10);
            if (expDate && expDate < Math.floor(Date.now() / 1000)) {
                return { valid: false, error: 'Account has expired' };
            }

            const si = json.server_info;
            let named = serverInfoOrigin(si);
            if (si && si.url && !named) {
                console.warn('[configure] provider server_info does not form a usable URL; keeping the one that connected');
            }
            // server_info cannot move the install URL to an unlisted host, which
            // decodeConfig would then refuse.
            if (named && !panelHostAllowed(named)) {
                console.warn(
                    `[configure] provider server_info names ${JSON.stringify(hostnameOf(named))}, ` +
                    'which is not in ALLOWED_PANEL_HOSTS; keeping the one that connected'
                );
                named = null;
            }
            // Nor onto http for someone who asked for https.
            if (named && askedForHttps && schemeOf(named) === 'http') {
                console.warn(
                    `[configure] provider server_info names http for ${JSON.stringify(hostnameOf(named))}; ` +
                    'keeping the https URL that connected'
                );
                named = null;
            }
            // And a surviving origin is adopted only once the credentials work there
            // (audit S8). Checked last, so a refused host is never contacted, and
            // skipped for the origin that just answered.
            if (named && new URL(named).origin !== new URL(url).origin
                && !await credentialsWorkAt(named, username, password)) {
                console.warn(
                    `[configure] provider server_info names ${JSON.stringify(hostnameOf(named))}, ` +
                    'where these credentials did not work; keeping the one that connected'
                );
                named = null;
            }
            const finalUrl = named || url;
            // Attribute the downgrade to whichever step actually caused it: the
            // http retry, or the provider overriding a scheme that just worked.
            const downgrade = describeDowngrade(base, url, 'fallback')
                || describeDowngrade(url, finalUrl, 'provider');
            if (downgrade) {
                console.warn(`[configure] ${new URL(finalUrl).host}: https→http downgrade (${downgrade.source}); credentials will travel in cleartext`);
            }

            return {
                valid: true,
                userInfo: json.user_info,
                resolvedUrl: finalUrl,
                downgrade
            };
        } catch (e) {
            // The caller gets no detail about why (that would make this page a port
            // scanner); the operator gets it in the log for every attempt.
            const reason = e.name === 'AbortError' ? 'timeout' : e.cause?.code || e.message;
            // Names the scheme actually coming next, which is no longer always https.
            console.warn(
                `[configure] connection to ${new URL(url).origin} ${answered ? 'answered, but not as a panel' : 'failed'}: ` +
                `${reason}${next ? `; trying ${schemeOf(next.url)}` : ''}`
            );
            if (next) continue;
            if (anyAnswered) return { valid: false, error: 'Not a valid xTremio server' };
            return {
                valid: false,
                error: askedForHttps
                    ? 'Cannot reach that server over https — check the URL and port. If your provider only supports http, enter the address starting with http:// instead.'
                    : 'Cannot reach that server — check the URL and port.'
            };
        } finally {
            clearTimeout(timer);
        }
    }
}

module.exports = {
    CONFIGURE_TIMEOUT_MS,
    CONFIGURE_PROBE_TIMEOUT_MS,
    schemeOf,
    describeDowngrade,
    serverInfoOrigin,
    credentialsWorkAt,
    validateXtremioCredentials
};
