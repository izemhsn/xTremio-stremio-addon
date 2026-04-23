const express = require('express');
const { Readable } = require('stream');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ADDON_ID = 'org.xtremio.addon';

function getBaseUrl(req) {
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
    return `${proto}://${host}`;
}

function escapeHtml(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function encodeConfig(cfg) {
    return Buffer.from(JSON.stringify({
        serverUrl: cfg.serverUrl,
        username: cfg.username,
        password: cfg.password
    })).toString('base64url');
}

function decodeConfig(encoded) {
    if (!encoded) return null;
    try {
        const cfg = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
        if (!cfg || typeof cfg !== 'object') return null;
        if (!cfg.serverUrl || !cfg.username || !cfg.password) return null;
        return cfg;
    } catch {
        return null;
    }
}

async function getManifest(baseUrl = `http://localhost:${PORT}`, cfg = null) {
    const catalogs = [];

    if (cfg) {
        try {
            const cats = await getCategories(cfg);
            const movieGenres = [...new Set(cats.movies.map(c => c.category_name).filter(Boolean))];
            const seriesGenres = [...new Set(cats.series.map(c => c.category_name).filter(Boolean))];
            const liveGenres = [...new Set(cats.live.map(c => c.category_name).filter(Boolean))];

            catalogs.push(
                {
                    type: 'Live TV',
                    id: 'xtremio_live',
                    name: 'Live TV',
                    extra: [
                        { name: 'genre', options: liveGenres, isRequired: true },
                        { name: 'skip' },
                        { name: 'search' }
                    ]
                },
                {
                    type: 'XT-Movies',
                    id: 'xtremio_movies_popular',
                    name: 'Popular',
                    extra: [
                        { name: 'genre', options: movieGenres, isRequired: true },
                        { name: 'skip' },
                        { name: 'search' }
                    ]
                },
                {
                    type: 'XT-Movies',
                    id: 'xtremio_movies_new',
                    name: 'New',
                    extra: [
                        { name: 'genre', options: movieGenres, isRequired: true },
                        { name: 'skip' },
                        { name: 'search' }
                    ]
                },
                {
                    type: 'XT-Movies',
                    id: 'xtremio_movies_featured',
                    name: 'Featured',
                    extra: [
                        { name: 'genre', options: movieGenres, isRequired: true },
                        { name: 'skip' },
                        { name: 'search' }
                    ]
                },
                {
                    type: 'XT-Series',
                    id: 'xtremio_series_popular',
                    name: 'Popular',
                    extra: [
                        { name: 'genre', options: seriesGenres, isRequired: true },
                        { name: 'skip' },
                        { name: 'search' }
                    ]
                },
                {
                    type: 'XT-Series',
                    id: 'xtremio_series_new',
                    name: 'New',
                    extra: [
                        { name: 'genre', options: seriesGenres, isRequired: true },
                        { name: 'skip' },
                        { name: 'search' }
                    ]
                },
                {
                    type: 'XT-Series',
                    id: 'xtremio_series_featured',
                    name: 'Featured',
                    extra: [
                        { name: 'genre', options: seriesGenres, isRequired: true },
                        { name: 'skip' },
                        { name: 'search' }
                    ]
                },
                {
                    type: 'XT-Movies',
                    id: 'xtremio_search_movies',
                    name: 'Search Movies',
                    extra: [{ name: 'search', isRequired: true }],
                    searchProperties: ['name']
                },
                {
                    type: 'XT-Series',
                    id: 'xtremio_search_series',
                    name: 'Search Series',
                    extra: [{ name: 'search', isRequired: true }],
                    searchProperties: ['name']
                }
            );
        } catch (e) {
            catalogs.push(
                { type: 'Live TV', id: 'xtremio_live', name: 'Live TV' },
                { type: 'XT-Movies', id: 'xtremio_movies_popular', name: 'Popular' },
                { type: 'XT-Movies', id: 'xtremio_movies_new', name: 'New' },
                { type: 'XT-Movies', id: 'xtremio_movies_featured', name: 'Featured' },
                { type: 'XT-Series', id: 'xtremio_series_popular', name: 'Popular' },
                { type: 'XT-Series', id: 'xtremio_series_new', name: 'New' },
                { type: 'XT-Series', id: 'xtremio_series_featured', name: 'Featured' },
                { type: 'XT-Movies', id: 'xtremio_search_movies', name: 'Search Movies', extra: [{ name: 'search', isRequired: true }], searchProperties: ['name'] },
                { type: 'XT-Series', id: 'xtremio_search_series', name: 'Search Series', extra: [{ name: 'search', isRequired: true }], searchProperties: ['name'] }
            );
        }
    }

    return {
        id: ADDON_ID,
        version: '1.0.2',
        name: 'xTremio',
        description: 'xTremio addon for Stremio',
        resources: ['catalog', 'meta', 'stream'],
        types: ['Live TV', 'XT-Movies', 'XT-Series', 'series'],
        catalogs,
        idPrefixes: ['xtremio_live_', 'xtremio_movie_', 'xtremio_series_', 'xtremio_episode_'],
        behaviorHints: {
            configurable: true,
            configurationRequired: !cfg
        },
        config: { url: `${baseUrl}/configure` }
    };
}

app.get('/manifest.json', async (req, res) => {
    res.json(await getManifest(getBaseUrl(req), null));
});

app.get('/:config/manifest.json', async (req, res) => {
    const cfg = decodeConfig(req.params.config);
    res.json(await getManifest(getBaseUrl(req), cfg));
});

function normalizeUrl(url) {
    url = url.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//.test(url)) url = 'http://' + url;
    return url;
}

// Per Stremio SDK: notWebReady must be true when the URL is http:// or
// the file is not an MP4 container. Without this, the player may stop
// after a short period (e.g. ~1 min) and Stremio treats it as "ended",
// returning to details (movies) or auto-advancing (series episodes).
function isNotWebReady(url, ext) {
    const isHttps = /^https:\/\//i.test(url);
    const isMp4 = String(ext || '').toLowerCase() === 'mp4';
    return !(isHttps && isMp4);
}

// Browser-like UA — many Xtream CDNs reject or shortchange non-browser UAs.
const PROXY_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

async function xtremioGet(cfg, action, extraParams = '', { timeoutMs = 15000 } = {}) {
    const base = normalizeUrl(cfg.serverUrl);
    const url = `${base}/player_api.php?username=${encodeURIComponent(cfg.username)}&password=${encodeURIComponent(cfg.password)}&action=${action}${extraParams}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, { signal: controller.signal, redirect: 'follow' });
        if (!res.ok) throw new Error(`xtremio ${action} failed: HTTP ${res.status}`);
        const data = await res.json();

        console.log(`[xtremioGet] ${action} (${Array.isArray(data) ? data.length : '?'} items)`);

        return data;
    } finally {
        clearTimeout(timer);
    }
}

function toIsoDate(s) {
    if (!s) return undefined;
    const d = new Date(s);
    return isNaN(d.getTime()) ? undefined : d.toISOString();
}

// Xtream providers return `cast`/`genre` as either a comma-separated string or an array.
function splitList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value.map(v => String(v).trim()).filter(Boolean);
    return String(value).split(',').map(v => v.trim()).filter(Boolean);
}

// `backdrop_path` can be an array of URLs or a single URL string.
function pickBackdrop(value) {
    if (!value) return undefined;
    if (Array.isArray(value)) return value[0] || undefined;
    return String(value) || undefined;
}

// All in-memory caches share the same TTL.
const CACHE_TTL = 30 * 60 * 1000;

const catCache = new Map();

async function getCategories(cfg) {
    const cached = catCache.get(cfg.serverUrl);
    if (cached && cached.ts > Date.now() - CACHE_TTL) return cached;
    const results = await Promise.allSettled([
        xtremioGet(cfg, 'get_live_categories'),
        xtremioGet(cfg, 'get_vod_categories'),
        xtremioGet(cfg, 'get_series_categories')
    ]);
    const pick = r => (r.status === 'fulfilled' && Array.isArray(r.value)) ? r.value : [];
    results.forEach((r, i) => {
        if (r.status === 'rejected') {
            console.error(`[getCategories] source ${i} failed:`, r.reason?.message || r.reason);
        }
    });
    const entry = {
        live: pick(results[0]),
        movies: pick(results[1]),
        series: pick(results[2]),
        ts: Date.now()
    };
    catCache.set(cfg.serverUrl, entry);
    return entry;
}

// Stream list caches - populated on first fetch, reused for catalogs, search and meta
function createStreamListCache() {
    const map = new Map();
    return {
        get(cfg) {
            const cached = map.get(cfg.serverUrl);
            if (cached && cached.ts > Date.now() - CACHE_TTL) return cached.data;
            return null;
        },
        set(cfg, items) {
            map.set(cfg.serverUrl, { data: items, ts: Date.now() });
        }
    };
}

const liveStreamsCache = createStreamListCache();
const vodStreamsCache = createStreamListCache();
const seriesStreamsCache = createStreamListCache();

async function getAllVodStreams(cfg) {
    let items = vodStreamsCache.get(cfg);
    if (!items) {
        items = await getStreams(cfg, 'get_vod_streams', '');
        vodStreamsCache.set(cfg, items);
    }
    return items;
}

async function getAllSeriesStreams(cfg) {
    let items = seriesStreamsCache.get(cfg);
    if (!items) {
        items = await getStreams(cfg, 'get_series', '');
        seriesStreamsCache.set(cfg, items);
    }
    return items;
}

async function getAllLiveStreams(cfg) {
    let items = liveStreamsCache.get(cfg);
    if (!items) {
        items = await getStreams(cfg, 'get_live_streams', '');
        liveStreamsCache.set(cfg, items);
    }
    return items;
}

function parseExtra(extra) {
    const params = {};
    if (extra) {
        extra.split('&').forEach(p => {
            const [k, ...rest] = p.split('=');
            params[decodeURIComponent(k)] = decodeURIComponent(rest.join('='));
        });
    }
    return params;
}

const PAGE_SIZE = 100;

async function getStreams(cfg, action, catParam = '') {
    const data = await xtremioGet(cfg, action, catParam);
    return Array.isArray(data) ? data : [];
}

function parseYear(s) {
    if (!s) return undefined;
    const m = String(s).match(/\d{4}/);
    return m ? parseInt(m[0]) : undefined;
}

function isUsableSeriesInfo(info) {
    if (!info || typeof info !== 'object') return false;
    const hasInfo = info.info && typeof info.info === 'object'
        && (info.info.name || info.info.plot || info.info.genre || info.info.cover);
    const eps = info.episodes;
    const hasEpisodes = eps && typeof eps === 'object' && Object.keys(eps).length > 0;
    return Boolean(hasInfo || hasEpisodes);
}

const SERIES_INFO_MAX_ATTEMPTS = 3;
const SERIES_INFO_BACKOFF_MS = 500;

const seriesInfoCache = new Map();

function seriesInfoCacheKey(cfg, seriesId) {
    return `${cfg.serverUrl}\n${cfg.username}\n${cfg.password}\n${seriesId}`;
}

function getCachedSeriesInfo(cfg, seriesId) {
    const entry = seriesInfoCache.get(seriesInfoCacheKey(cfg, seriesId));
    if (entry && entry.ts > Date.now() - CACHE_TTL) return entry.data;
    return null;
}

function setCachedSeriesInfo(cfg, seriesId, data) {
    seriesInfoCache.set(seriesInfoCacheKey(cfg, seriesId), { data, ts: Date.now() });
}

async function getSeriesInfo(cfg, seriesId) {
    const hit = getCachedSeriesInfo(cfg, seriesId);
    if (hit) return hit;

    let lastInfo = null;
    let lastError = null;
    for (let attempt = 1; attempt <= SERIES_INFO_MAX_ATTEMPTS; attempt++) {
        try {
            const info = await xtremioGet(cfg, 'get_series_info', `&series_id=${seriesId}`, { timeoutMs: 8000 });
            if (isUsableSeriesInfo(info)) {
                setCachedSeriesInfo(cfg, seriesId, info);
                return info;
            }
            lastInfo = info;
            console.warn(`[getSeriesInfo] attempt ${attempt}/${SERIES_INFO_MAX_ATTEMPTS} for series ${seriesId} returned unusable data`);
        } catch (e) {
            lastError = e;
            const causeMsg = e.cause ? ` (cause: ${e.cause.code || e.cause.message || e.cause})` : '';
            console.warn(`[getSeriesInfo] attempt ${attempt}/${SERIES_INFO_MAX_ATTEMPTS} for series ${seriesId} failed: ${e.message}${causeMsg}`);
        }
        if (attempt < SERIES_INFO_MAX_ATTEMPTS) {
            await new Promise(r => setTimeout(r, SERIES_INFO_BACKOFF_MS * attempt));
        }
    }
    if (lastInfo !== null) return lastInfo;
    throw lastError || new Error(`get_series_info failed for series ${seriesId}`);
}

async function validateXtremioCredentials(serverUrl, username, password) {
    const base = normalizeUrl(serverUrl);
    const path = `/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`;
    const urls = [base, base.replace(/^https?/, m => m === 'https' ? 'http' : 'https')];

    for (const url of urls) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 15000);
        try {
            const res = await fetch(url + path, { signal: controller.signal, redirect: 'follow' });
            const json = await res.json();

            if (!json.user_info) return { valid: false, error: 'Not a valid xTremio server' };
            if (json.user_info.auth !== 1) return { valid: false, error: 'Invalid username or password' };
            if (json.user_info.status !== 'Active') return { valid: false, error: `Account is ${json.user_info.status || 'inactive'}` };

            const expDate = parseInt(json.user_info.exp_date, 10);
            if (expDate && expDate < Math.floor(Date.now() / 1000)) {
                return { valid: false, error: 'Account has expired' };
            }

            let resolvedUrl;
            const si = json.server_info;
            if (si && si.url) {
                const proto = si.server_protocol || 'http';
                const port = (proto === 'https' ? si.https_port : si.port) || si.port;
                resolvedUrl = port ? `${proto}://${si.url}:${port}` : `${proto}://${si.url}`;
            }

            return {
                valid: true,
                userInfo: json.user_info,
                resolvedUrl: resolvedUrl || url
            };
        } catch (e) {
            if (url === urls[0] && urls.length > 1) continue;
            const msg = e.name === 'AbortError' ? 'Connection timed out'
                : e.cause?.code === 'ECONNREFUSED' ? 'Connection refused — check server URL and port'
                    : e.cause?.code === 'ENOTFOUND' ? 'Server not found — check the URL'
                        : e.cause?.code === 'ECONNRESET' ? 'Connection reset by server'
                            : e.message || 'Cannot connect to server';
            return { valid: false, error: msg };
        } finally {
            clearTimeout(timer);
        }
    }
    return { valid: false, error: 'Cannot connect to server' };
}

function renderConfigPage({ serverUrl = '', username = '', password = '', status = null, baseUrl = `http://localhost:${PORT}` }) {
    const safeServerUrl = escapeHtml(serverUrl);
    const safeUsername = escapeHtml(username);
    const safePassword = escapeHtml(password);
    let statusHtml = '';
    if (status) {
        if (status.valid) {
            const encoded = encodeConfig({ serverUrl, username, password });
            const installUrl = `stremio://${baseUrl.replace(/^https?:\/\//, '')}/${encoded}/manifest.json`;
            const httpUrl = `${baseUrl}/${encoded}/manifest.json`;
            statusHtml = `
                <div class="status-section">
                    <div class="status-banner status-success">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
                        <span class="status-text">Connected! Welcome, ${escapeHtml(status.userInfo.username || username)}</span>
                    </div>
                    <a href="${installUrl}" class="btn full install-link">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                        Install in Stremio
                    </a>
                    <div style="margin-top: 16px;">
                        <p style="font-size: 13px; color: #555; margin-bottom: 8px; font-weight: 600; text-align: left;">Or copy this link to install:</p>
                        <input type="text" value="${httpUrl}" readonly onclick="this.select(); document.execCommand('copy'); const p = this.previousElementSibling; const orig = p.innerText; p.innerText = '✓ Copied to clipboard!'; p.style.color = '#2e7d32'; setTimeout(() => { p.innerText = orig; p.style.color = '#555'; }, 2000);" style="width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 14px; color: #333; background: #f9f9f9; cursor: pointer; text-align: center; transition: border-color 0.2s;" title="Click to copy install link" onmouseover="this.style.borderColor='#7c4dff'" onmouseout="this.style.borderColor='#e0e0e0'" />
                    </div>
                </div>`;
        } else {
            statusHtml = `
                <div class="status-section">
                    <div class="status-banner status-error">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M6 18L18 6M6 6l12 12"/></svg>
                        <span class="status-text">${status.error}</span>
                    </div>
                </div>`;
        }
    }

    return `<!DOCTYPE html>
    <html><head>
        <title>xTremio Configuration</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                min-height: 100vh; display: flex; align-items: center; justify-content: center;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                padding: 20px;
            }
            .card {
                background: #fff; border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 420px; width: 100%; overflow: hidden;
            }
            .header {
                background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
                padding: 30px; text-align: center;
            }
            .header h1 { color: #fff; font-size: 24px; font-weight: 600; }
            .header p { color: rgba(255,255,255,0.8); font-size: 14px; margin-top: 8px; }
            .btn {
                display: inline-flex; align-items: center; gap: 10px;
                padding: 14px 32px;
                background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
                color: #fff; text-decoration: none; border: none;
                border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(124,77,255,0.4); }
            .btn:active { transform: translateY(0); }
            .btn svg { width: 20px; height: 20px; }
            .form-container { padding: 30px; }
            .input-group { margin-bottom: 20px; }
            .input-group label { display: block; font-size: 13px; font-weight: 600; color: #333; margin-bottom: 8px; }
            .input-wrapper { position: relative; }
            .input-wrapper svg { position: absolute; left: 14px; top: 50%; transform: translateY(-50%); width: 18px; height: 18px; color: #999; }
            .input-wrapper input { width: 100%; padding: 14px 14px 14px 44px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 15px; transition: border-color 0.2s, box-shadow 0.2s; }
            .input-wrapper input:focus { outline: none; border-color: #7c4dff; box-shadow: 0 0 0 3px rgba(124,77,255,0.1); }
            .input-wrapper input::placeholder { color: #aaa; }
            .btn.full { width: 100%; justify-content: center; }
            .status-section { padding: 0 30px 30px; text-align: center; }
            .status-banner { padding: 16px; border-radius: 10px; display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
            .status-banner svg { width: 22px; height: 22px; flex-shrink: 0; }
            .status-banner .status-text { font-size: 14px; font-weight: 500; text-align: left; }
            .status-success { background: #e8f5e9; color: #2e7d32; }
            .status-error { background: #ffebee; color: #c62828; }
            .install-link { margin-top: 4px; }
            .disclaimer {
                background: #fff8e1;
                border: 1px solid #ffe082;
                color: #5d4037;
                border-radius: 10px;
                padding: 12px 14px;
                font-size: 12px;
                line-height: 1.5;
                margin-bottom: 22px;
            }
            .disclaimer strong { color: #ef6c00; display: block; margin-bottom: 4px; font-size: 13px; }
            .disclaimer ul { margin: 6px 0 0 18px; padding: 0; }
            .disclaimer li { margin-bottom: 3px; }
        </style>
    </head><body>
        <div class="card">
            <div class="header">
                <h1>xTremio Addon</h1>
                <p>Configure your credentials</p>
            </div>
            <div class="form-container">
                <div class="disclaimer">
                    <strong>⚠ Disclaimer</strong>
                    This addon is a technical gateway only. It does <b>not</b> host, store, or provide any media content.
                    <ul>
                        <li>You must have a valid, legally obtained Xtream Codes account.</li>
                        <li>You are solely responsible for the content accessed through your provider.</li>
                        <li>Credentials are encoded into your install URL &mdash; keep it private, do not share it.</li>
                    </ul>
                </div>
                <form method="POST">
                    <div class="input-group">
                        <label>Server URL</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>
                            <input type="url" name="serverUrl" value="${safeServerUrl}" placeholder="http://example.com:port" required />
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Username</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
                            <input type="text" name="username" value="${safeUsername}" placeholder="Enter username" required />
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Password</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                            <input type="password" name="password" value="${safePassword}" placeholder="Enter password" required />
                        </div>
                    </div>
                    <button type="submit" class="btn full">Save & Install</button>
                </form>
            </div>
            ${statusHtml}
        </div>
    </body></html>`;
}

app.get('/configure', (req, res) => {
    const existing = decodeConfig(req.query.config) || {};
    res.send(renderConfigPage({
        serverUrl: req.query.serverUrl || existing.serverUrl || '',
        username: req.query.username || existing.username || '',
        password: req.query.password || existing.password || '',
        baseUrl: getBaseUrl(req)
    }));
});

app.post('/configure', async (req, res) => {
    const rawServerUrl = (req.body.serverUrl || '').trim().replace(/\/+$/, '');
    const username = req.body.username || '';
    const password = req.body.password || '';

    try {
        const validation = await validateXtremioCredentials(rawServerUrl, username, password);
        const finalServerUrl = validation.valid
            ? (validation.resolvedUrl || normalizeUrl(rawServerUrl))
            : rawServerUrl;

        res.send(renderConfigPage({
            serverUrl: finalServerUrl,
            username,
            password,
            status: validation,
            baseUrl: getBaseUrl(req)
        }));
    } catch (e) {
        res.send(renderConfigPage({
            serverUrl: rawServerUrl,
            username,
            password,
            status: { valid: false, error: 'Something went wrong. Please try again.' },
            baseUrl: getBaseUrl(req)
        }));
    }
});

app.get(['/:config/catalog/:type/:id.json', '/:config/catalog/:type/:id/:extra.json'], async (req, res) => {
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ metas: [] });

    const { id } = req.params;
    const extra = parseExtra(req.params.extra);
    const skip = parseInt(extra.skip) || 0;
    const genre = extra.genre;

    try {
        if (id === 'xtremio_live') {
            const cats = await getCategories(cfg);
            const selectedGenre = genre || (cats.live[0] && cats.live[0].category_name);
            let categoryId;
            if (selectedGenre) {
                const cat = cats.live.find(c => c.category_name === selectedGenre);
                if (cat) categoryId = cat.category_id;
            }

            // No genre selected and none resolvable -> nothing to show.
            if (!categoryId) return res.json({ metas: [] });

            // Fetch all live channels once (cached), then filter in-memory by selected category.
            const allItems = await getAllLiveStreams(cfg);
            const catIdStr = String(categoryId);
            const selectedGenreLower = (selectedGenre || '').toLowerCase();
            let items = allItems.filter(s => {
                if (s.category_id != null && s.category_id !== '') {
                    return String(s.category_id) === catIdStr;
                }
                return selectedGenreLower && String(s.category_name || '').toLowerCase() === selectedGenreLower;
            });

            if (extra.search) {
                const q = extra.search.toLowerCase();
                items = items.filter(s => s.name?.toLowerCase().includes(q));
            }

            const page = items.slice(skip, skip + PAGE_SIZE);
            const metas = page.map(s => ({
                id: `xtremio_live_${s.stream_id}`,
                type: 'Live TV',
                name: s.name,
                poster: s.stream_icon || undefined,
                posterShape: 'square'
            }));

            return res.json({ metas, cacheMaxAge: 300, staleRevalidate: 600 });
        }

        if (id.startsWith('xtremio_movies_')) {
            const cats = await getCategories(cfg);
            const selectedGenre = genre || (cats.movies[0] && cats.movies[0].category_name);
            const cat = cats.movies.find(c => c.category_name === selectedGenre);
            if (!cat) return res.json({ metas: [] });

            // Reuse the full-list cache if available; fall back to per-category fetch.
            const catIdStr = String(cat.category_id);
            const fullList = vodStreamsCache.get(cfg);
            let items = fullList
                ? fullList.filter(s => String(s.category_id) === catIdStr)
                : await getStreams(cfg, 'get_vod_streams', `&category_id=${catIdStr}`);

            if (extra.search) {
                const q = extra.search.toLowerCase();
                items = items.filter(s => s.name?.toLowerCase().includes(q));
            }

            if (id === 'xtremio_movies_new') {
                items = [...items].sort((a, b) => (parseInt(b.added) || 0) - (parseInt(a.added) || 0));
            } else if (id === 'xtremio_movies_popular') {
                items = [...items].sort((a, b) => (parseFloat(b.rating) || 0) - (parseFloat(a.rating) || 0));
            } else if (id === 'xtremio_movies_featured') {
                // Seeded shuffle based on the day so order is stable across pagination
                const daySeed = Math.floor(Date.now() / 86400000);
                items = [...items].sort((a, b) => {
                    const ha = ((parseInt(a.stream_id) || 0) * 2654435761 + daySeed) & 0x7fffffff;
                    const hb = ((parseInt(b.stream_id) || 0) * 2654435761 + daySeed) & 0x7fffffff;
                    return ha - hb;
                });
            }

            const page = items.slice(skip, skip + PAGE_SIZE);
            const metas = page.map(s => ({
                id: `xtremio_movie_${s.stream_id}`,
                type: 'XT-Movies',
                name: s.name,
                poster: s.stream_icon || undefined,
                posterShape: 'poster'
            }));

            return res.json({ metas, cacheMaxAge: 300, staleRevalidate: 600 });
        }

        if (id.startsWith('xtremio_series_')) {
            const cats = await getCategories(cfg);
            const selectedGenre = genre || (cats.series[0] && cats.series[0].category_name);
            const cat = cats.series.find(c => c.category_name === selectedGenre);
            if (!cat) return res.json({ metas: [] });

            // Reuse the full-list cache if available; fall back to per-category fetch.
            const catIdStr = String(cat.category_id);
            const fullList = seriesStreamsCache.get(cfg);
            let items = fullList
                ? fullList.filter(s => String(s.category_id) === catIdStr)
                : await getStreams(cfg, 'get_series', `&category_id=${catIdStr}`);

            if (extra.search) {
                const q = extra.search.toLowerCase();
                items = items.filter(s => s.name?.toLowerCase().includes(q));
            }

            if (id === 'xtremio_series_new') {
                items = [...items].sort((a, b) => (parseInt(b.last_modified) || 0) - (parseInt(a.last_modified) || 0));
            } else if (id === 'xtremio_series_popular') {
                items = [...items].sort((a, b) => (parseFloat(b.rating) || 0) - (parseFloat(a.rating) || 0));
            } else if (id === 'xtremio_series_featured') {
                const daySeed = Math.floor(Date.now() / 86400000);
                items = [...items].sort((a, b) => {
                    const ha = ((parseInt(a.series_id) || 0) * 2654435761 + daySeed) & 0x7fffffff;
                    const hb = ((parseInt(b.series_id) || 0) * 2654435761 + daySeed) & 0x7fffffff;
                    return ha - hb;
                });
            }

            const page = items.slice(skip, skip + PAGE_SIZE);
            const metas = page.map(s => ({
                id: `xtremio_series_${s.series_id}`,
                type: 'series',
                name: s.name,
                poster: s.cover || undefined,
                posterShape: 'poster'
            }));

            return res.json({ metas, cacheMaxAge: 300, staleRevalidate: 600 });
        }

        // Global search catalogs - fetch all streams once, filter in memory
        if (id === 'xtremio_search_movies' && extra.search) {
            const q = extra.search.toLowerCase();
            const allMovies = await getAllVodStreams(cfg);
            const filtered = allMovies.filter(s => s.name?.toLowerCase().includes(q));
            const page = filtered.slice(skip, skip + PAGE_SIZE);
            const metas = page.map(s => ({
                id: `xtremio_movie_${s.stream_id}`,
                type: 'XT-Movies',
                name: s.name,
                poster: s.stream_icon || undefined,
                posterShape: 'poster'
            }));
            return res.json({ metas, cacheMaxAge: 300, staleRevalidate: 600 });
        }

        if (id === 'xtremio_search_series' && extra.search) {
            const q = extra.search.toLowerCase();
            const allSeries = await getAllSeriesStreams(cfg);
            const filtered = allSeries.filter(s => s.name?.toLowerCase().includes(q));
            const page = filtered.slice(skip, skip + PAGE_SIZE);
            const metas = page.map(s => ({
                id: `xtremio_series_${s.series_id}`,
                type: 'series',
                name: s.name,
                poster: s.cover || undefined,
                posterShape: 'poster'
            }));
            return res.json({ metas, cacheMaxAge: 300, staleRevalidate: 600 });
        }

        res.json({ metas: [] });
    } catch (e) {
        console.error('[catalog] Error:', e.message);
        res.json({ metas: [] });
    }
});

app.get('/:config/meta/:type/:id.json', async (req, res) => {
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ meta: null });
    const { id, type } = req.params;
    console.log(`[meta] type=${type} id=${id}`);

    try {
        if (id.startsWith('xtremio_live_')) {
            const streamId = id.replace('xtremio_live_', '');
            const allLive = await getAllLiveStreams(cfg);
            let s = allLive.find(i => String(i.stream_id) === streamId);

            if (!s) return res.json({ meta: null });
            const meta = {
                id: `xtremio_live_${s.stream_id}`,
                type: 'Live TV',
                name: s.name,
                poster: s.stream_icon || undefined,
                posterShape: 'square',
                genres: s.category_name ? [s.category_name] : [],
                description: s.name || undefined
            };
            return res.json({ meta, cacheMaxAge: 300 });
        }

        if (id.startsWith('xtremio_movie_')) {
            const streamId = id.replace('xtremio_movie_', '');
            const info = await xtremioGet(cfg, 'get_vod_info', `&vod_id=${streamId}`);
            const movie = info?.info ?? info ?? {};
            const cast = splitList(movie.cast);
            const backdrop = pickBackdrop(movie.backdrop_path);

            const meta = {
                id: `xtremio_movie_${streamId}`,
                type: 'XT-Movies',
                name: movie.name || movie.o_name || 'Unknown',
                poster: movie.cover_big || movie.movie_image || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: movie.plot || movie.description || undefined,
                releaseInfo: movie.releasedate ? String(movie.releasedate) : undefined,
                genres: splitList(movie.genre),
                runtime: movie.duration ? String(movie.duration) + ' min' : (movie.episode_run_time ? String(movie.episode_run_time) + ' min' : undefined),
                director: movie.director || undefined,
                cast,
                imdbRating: movie.rating ? String(movie.rating) : undefined,
                year: parseYear(movie.releasedate),
                country: movie.country || undefined,
                trailer: movie.youtube_trailer || undefined
            };
            return res.json({ meta, cacheMaxAge: 86400 });
        }

        if (id.startsWith('xtremio_series_')) {
            const seriesId = id.replace('xtremio_series_', '');
            let info = null;
            try {
                info = await getSeriesInfo(cfg, seriesId);
            } catch (e) {
                const causeMsg = e.cause ? ` (cause: ${e.cause.code || e.cause.message || e.cause})` : '';
                console.warn(`[meta] getSeriesInfo(${seriesId}) failed after retries: ${e.message}${causeMsg}`);
            }
            const series = info?.info ?? info ?? {};

            const videos = [];
            const episodes = info?.episodes ?? {};
            for (const [seasonNum, eps] of Object.entries(episodes)) {
                if (!Array.isArray(eps)) continue;
                for (const ep of eps) {
                    videos.push({
                        id: `xtremio_episode_${seriesId}:${seasonNum}:${ep.id}`,
                        title: ep.title || `Episode ${ep.episode_num}`,
                        season: parseInt(seasonNum),
                        episode: parseInt(ep.episode_num) || 1,
                        released: toIsoDate(ep.info?.releasedate) || '1970-01-01T00:00:00.000Z',
                        overview: ep.info?.plot || undefined,
                        thumbnail: ep.info?.movie_image || undefined
                    });
                }
            }

            const hasContent = Boolean(series.name || videos.length);
            if (!hasContent) {
                console.warn(`[meta] no usable data for series ${seriesId}`);
                return res.json({ meta: null });
            }

            const cast = splitList(series.cast);
            const backdrop = pickBackdrop(series.backdrop_path);

            const meta = {
                id: `xtremio_series_${seriesId}`,
                type: 'series',
                name: series.name || 'Unknown',
                poster: series.cover || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: series.plot || undefined,
                releaseInfo: series.releaseDate ? String(series.releaseDate) : undefined,
                genres: splitList(series.genre),
                runtime: series.episode_run_time ? String(series.episode_run_time) + ' min' : undefined,
                director: series.director || undefined,
                cast,
                imdbRating: series.rating ? String(series.rating) : undefined,
                year: parseYear(series.releaseDate),
                videos
            };
            return res.json({ meta, cacheMaxAge: 3600 });
        }

        res.json({ meta: null });
    } catch (e) {
        console.error('[meta] Error:', e.message);
        res.json({ meta: null });
    }
});

app.get('/:config/stream/:type/:id.json', async (req, res) => {
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ streams: [] });
    const { id, type } = req.params;
    console.log(`[stream] type=${type} id=${id}`);

    try {
        const { username, password } = cfg;
        const serverUrl = normalizeUrl(cfg.serverUrl);

        // --- Handle xTremio's own IDs ---
        if (id.startsWith('xtremio_live_')) {
            const streamId = id.replace('xtremio_live_', '');
            return res.json({
                streams: [
                    { url: `${serverUrl}/live/${username}/${password}/${streamId}.m3u8`, title: 'HLS' },
                    { url: `${serverUrl}/live/${username}/${password}/${streamId}.ts`, title: 'MPEG-TS' }
                ],
                cacheMaxAge: 3600
            });
        }

        if (id.startsWith('xtremio_movie_')) {
            const streamId = id.replace('xtremio_movie_', '');
            const info = await xtremioGet(cfg, 'get_vod_info', `&vod_id=${streamId}`);
            const ext = info?.movie_data?.container_extension || 'mp4';
            const proxyUrl = `${getBaseUrl(req)}/${req.params.config}/proxy/movie/${streamId}.${ext}`;
            return res.json({
                streams: [
                    {
                        url: proxyUrl,
                        title: '▶ Play',
                        behaviorHints: {
                            notWebReady: isNotWebReady(proxyUrl, ext),
                            bingeGroup: `xtremio-movie-${ext}`
                        }
                    }
                ]
            });
        }

        if (id.startsWith('xtremio_episode_')) {
            // Format: xtremio_episode_{seriesId}:{season}:{episodeId}
            const [seriesId, , episodeId] = id.replace('xtremio_episode_', '').split(':');

            const findExt = (data) => {
                const episodes = data?.episodes ?? {};
                for (const eps of Object.values(episodes)) {
                    if (!Array.isArray(eps)) continue;
                    const ep = eps.find(e => String(e.id) === episodeId);
                    if (ep) return ep.container_extension || 'mp4';
                }
                return null;
            };

            const info = await getSeriesInfo(cfg, seriesId);
            let ext = findExt(info);
            if (!ext) {
                console.warn(`[stream] episode ${episodeId} not found in series ${seriesId} info; defaulting to mp4`);
                ext = 'mp4';
            }

            const proxyUrl = `${getBaseUrl(req)}/${req.params.config}/proxy/series/${episodeId}.${ext}`;
            return res.json({
                streams: [
                    {
                        url: proxyUrl,
                        title: '▶ Play',
                        behaviorHints: {
                            notWebReady: isNotWebReady(proxyUrl, ext),
                            bingeGroup: `xtremio-series-${seriesId}-${ext}`
                        }
                    }
                ]
            });
        }

        res.json({ streams: [] });
    } catch (e) {
        console.error('[stream] Error:', e.message);
        res.json({ streams: [] });
    }
});

// Stream proxy. Xtream providers 302-redirect to a CDN URL that carries
// a short-lived signed token (~60s). Handing that URL directly to
// Stremio causes "playback error" after ~1 minute when the token
// expires. By proxying every range request through the addon, we
// re-resolve the origin URL (and get a fresh token) for each request.
app.all('/:config/proxy/:kind/:file', async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return res.status(405).end('method not allowed');
    }
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.status(401).end('unauthorized');

    const { kind, file } = req.params;
    if (!['movie', 'series', 'live'].includes(kind)) {
        return res.status(400).end('bad kind');
    }
    const match = /^([^./]+)\.([A-Za-z0-9]+)$/.exec(file);
    if (!match) return res.status(400).end('bad file');
    const [, streamId, ext] = match;

    const serverUrl = normalizeUrl(cfg.serverUrl);
    const upstreamUrl = `${serverUrl}/${kind}/${encodeURIComponent(cfg.username)}/${encodeURIComponent(cfg.password)}/${streamId}.${ext}`;

    const headers = { 'User-Agent': PROXY_USER_AGENT };
    if (req.headers.range) headers['Range'] = req.headers.range;
    if (req.headers['if-range']) headers['If-Range'] = req.headers['if-range'];

    const controller = new AbortController();
    const abort = () => {
        if (!controller.signal.aborted) {
            try { controller.abort(); } catch {}
        }
    };
    req.on('close', abort);
    req.on('aborted', abort);

    const isAbortErr = (e) => e && (e.name === 'AbortError' || e.code === 'ABORT_ERR' || controller.signal.aborted);

    let upstream;
    try {
        upstream = await fetch(upstreamUrl, {
            method: 'GET',
            headers,
            redirect: 'follow',
            signal: controller.signal
        });
    } catch (e) {
        if (!isAbortErr(e)) {
            console.warn(`[proxy] upstream fetch failed for ${kind}/${streamId}.${ext}: ${e.message}`);
        }
        if (!res.headersSent) res.status(502).end('upstream fetch failed');
        return;
    }

    res.status(upstream.status);

    // Forward headers relevant for seekable playback.
    const forward = [
        'content-type',
        'content-length',
        'content-range',
        'accept-ranges',
        'last-modified',
        'etag'
    ];
    for (const h of forward) {
        const v = upstream.headers.get(h);
        if (v) res.setHeader(h, v);
    }
    if (!upstream.headers.get('accept-ranges')) {
        res.setHeader('Accept-Ranges', 'bytes');
    }
    res.setHeader('Cache-Control', 'no-store');

    if (req.method === 'HEAD' || !upstream.body) {
        return res.end();
    }

    const nodeStream = Readable.fromWeb(upstream.body);
    nodeStream.on('error', (e) => {
        if (!isAbortErr(e)) {
            console.warn(`[proxy] stream error for ${kind}/${streamId}.${ext}: ${e.message}`);
        }
        if (!res.headersSent) res.status(502);
        res.end();
    });
    res.on('error', () => abort());
    res.on('close', () => {
        abort();
        nodeStream.destroy();
    });
    nodeStream.pipe(res);
});

app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>xTremio &mdash; Stremio Addon</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Stremio addon that exposes any Xtream Codes IPTV provider as Live TV, Movies and Series.">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #fff;
            padding: 20px;
            text-align: center;
        }
        .wrap { max-width: 560px; width: 100%; }
        .logo {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 72px; height: 72px;
            background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
            border-radius: 20px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(124,77,255,0.4);
        }
        .logo svg { width: 38px; height: 38px; color: #fff; }
        h1 { font-size: 36px; font-weight: 700; margin-bottom: 12px; letter-spacing: -0.5px; }
        .tagline { font-size: 17px; color: rgba(255,255,255,0.75); margin-bottom: 36px; line-height: 1.5; }
        .features {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 36px;
        }
        .feature {
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 16px 10px;
            font-size: 13px;
            color: rgba(255,255,255,0.85);
        }
        .feature b { display: block; color: #fff; font-size: 14px; margin-bottom: 4px; }
        .btn {
            display: inline-flex; align-items: center; gap: 10px;
            padding: 16px 36px;
            background: linear-gradient(135deg, #7c4dff 0%, #5c6bc0 100%);
            color: #fff; text-decoration: none;
            border-radius: 12px;
            font-size: 16px; font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 8px 20px rgba(124,77,255,0.3);
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 12px 30px rgba(124,77,255,0.5); }
        .btn svg { width: 20px; height: 20px; }
        .links {
            margin-top: 28px;
            font-size: 14px;
            color: rgba(255,255,255,0.6);
        }
        .links a {
            color: rgba(255,255,255,0.85);
            text-decoration: none;
            border-bottom: 1px solid rgba(255,255,255,0.3);
            padding-bottom: 1px;
        }
        .links a:hover { color: #fff; border-bottom-color: #fff; }
        .footer {
            margin-top: 40px;
            font-size: 12px;
            color: rgba(255,255,255,0.4);
            line-height: 1.6;
        }
        @media (max-width: 520px) {
            h1 { font-size: 28px; }
            .features { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="logo">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
        </div>
        <h1>xTremio</h1>
        <p class="tagline">A Stremio addon that turns your Xtream Codes IPTV provider into browseable Live TV, Movies, and Series catalogs.</p>

        <div class="features">
            <div class="feature"><b>Live TV</b>Watch your channels</div>
            <div class="feature"><b>Movies &amp; Series</b>Full VOD catalog</div>
            <div class="feature"><b>Global Search</b>Across everything</div>
        </div>

        <a href="/configure" class="btn">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
            Install Addon
        </a>

        <div class="links">
            <a href="https://github.com/izemhsn/xTremio-stremio-addon" target="_blank" rel="noopener">View on GitHub</a>
        </div>

        <div class="footer">
            This is a self-hosted technical gateway. No media is hosted here.<br>
            You must supply your own legally obtained Xtream Codes account.
        </div>
    </div>
</body>
</html>`);
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
});

const server = app.listen(PORT, HOST, () => {
    console.log(`Addon running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    console.log(`Configure: http://localhost:${PORT}/configure`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Kill the existing process or use a different port: PORT=3001 npm start`);
    } else {
        console.error('Server error:', err.message);
    }
    process.exit(1);
});

process.on('SIGTERM', () => { console.log('SIGTERM received, shutting down...'); server.close(() => process.exit(0)); });
process.on('SIGINT', () => { console.log('SIGINT received, shutting down...'); server.close(() => process.exit(0)); });
process.on('uncaughtException', (err) => {
    // AbortErrors are expected when a client disconnects mid-stream from the proxy.
    if (err && (err.name === 'AbortError' || err.code === 'ABORT_ERR')) return;
    console.error('Uncaught exception:', err);
});
process.on('unhandledRejection', (err) => {
    if (err && (err.name === 'AbortError' || err.code === 'ABORT_ERR')) return;
    console.error('Unhandled rejection:', err);
});