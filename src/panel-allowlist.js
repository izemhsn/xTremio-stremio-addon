// Which hosts this instance will talk to, and how a host is named. Kept as its own
// module because two separate policies read it — ALLOWED_PANEL_HOSTS here and
// HLS_TARGET_ALLOWED_HOSTS in the HLS code — and because decodeConfig depends on it:
// the panel check is enforced inside the token decode so that no route can reach a
// token without it (audit S3), which makes this a dependency of the crypto rather
// than the other way round.

// The hostname a host-list entry or a server URL names, or null. Forgiving about
// spelling, because an operator pastes what they have: a bare hostname, `host:port`
// and a whole URL all name the same host. A bare IPv6 address is bracketed the way
// URL writes a hostname, and URL does the lowercasing, so this compares equal to
// `new URL(x).hostname` for the same host.
function hostnameOf(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    const bareIpv6 = /^[0-9a-f:]+$/i.test(raw) && raw.split(':').length > 2;
    const candidate = bareIpv6 ? `[${raw}]` : raw;
    let hostname;
    try {
        hostname = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate) ? candidate : `http://${candidate}`).hostname;
    } catch {
        return null;
    }
    // URL accepts characters no real host has — `new URL('http://*.x.test')` parses,
    // with `*.x.test` as its hostname. Kept, a `*.provider.com` entry would look like
    // it covered every subdomain while matching nothing, which is the silent failure
    // parseHostList exists to refuse. URL has already lowercased the name and turned
    // an internationalized one into its xn-- form, so this is the whole alphabet.
    if (/^\[[0-9a-f:.]+\]$/.test(hostname) || /^[a-z0-9._-]+$/.test(hostname)) return hostname;
    return null;
}

// A comma-separated host list from the environment. An entry that names no host —
// a `*.` wildcard, say — is dropped and said so at boot, rather than quietly
// allowing nothing while looking like it allows something.
function parseHostList(value, name) {
    const hosts = new Set();
    for (const entry of String(value || '').split(',')) {
        if (!entry.trim()) continue;
        const host = hostnameOf(entry);
        if (host) hosts.add(host);
        else console.warn(`[config] ${name}: ignoring ${JSON.stringify(entry.trim())}, which names no single host`);
    }
    return hosts;
}

// Which Xtream panels this instance will serve (audit S3). Empty means any, which
// leaves the server usable as a relay through a fake panel; nothing stateless can
// tell such a panel from a real one, but a list of the real ones can. Set, it is
// enforced at /configure, on server_info origins and in decodeConfig, since any one
// point alone leaves a way round. Matched by exact hostname; a listed panel is
// trusted, including wherever it redirects.
const ALLOWED_PANEL_HOSTS = parseHostList(process.env.ALLOWED_PANEL_HOSTS, 'ALLOWED_PANEL_HOSTS');

function panelHostAllowed(serverUrl) {
    if (!ALLOWED_PANEL_HOSTS.size) return true;
    const host = hostnameOf(serverUrl);
    return host !== null && ALLOWED_PANEL_HOSTS.has(host);
}

// A refused token is logged once per host rather than once per request. An install
// URL that stopped working when the list was set fires every catalog, meta and
// stream request Stremio makes, and one line per host is enough to say why. Bounded,
// because the hosts come from tokens rather than from this server's configuration.
const refusedPanelHostsLogged = new Set();
const REFUSED_PANEL_LOG_MAX = 1000;

function noteRefusedPanel(serverUrl) {
    const host = hostnameOf(serverUrl) || '(unparseable)';
    if (refusedPanelHostsLogged.has(host) || refusedPanelHostsLogged.size >= REFUSED_PANEL_LOG_MAX) return;
    refusedPanelHostsLogged.add(host);
    console.warn(`[config] refusing an install URL for ${JSON.stringify(host)}, which is not in ALLOWED_PANEL_HOSTS`);
}

module.exports = {
    hostnameOf,
    parseHostList,
    panelHostAllowed,
    noteRefusedPanel,
    ALLOWED_PANEL_HOSTS,
    refusedPanelHostsLogged,
    REFUSED_PANEL_LOG_MAX
};
