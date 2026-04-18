const express = require('express');

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
                { type: 'XT-Series', id: 'xtremio_series_featured', name: 'Featured' }
            );
        }
    }

    return {
        id: ADDON_ID,
        version: '1.0.1',
        name: 'xTremio',
        description: 'xTremio addon for Stremio',
        resources: ['catalog', 'meta', 'stream'],
        types: ['Live TV', 'XT-Movies', 'XT-Series', 'series'],
        catalogs,
        idPrefixes: ['xtremio_'],
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

async function xtremioGet(cfg, action, extraParams = '', { timeoutMs = 15000 } = {}) {
    const url = `${cfg.serverUrl}/player_api.php?username=${encodeURIComponent(cfg.username)}&password=${encodeURIComponent(cfg.password)}&action=${action}${extraParams}`;
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

const catCache = new Map();
const CACHE_TTL = 30 * 60 * 1000;

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

// Live streams cache - populated when browsing Live TV, used by meta endpoint
const liveStreamsCache = new Map();
const LIVE_STREAMS_CACHE_TTL = 30 * 60 * 1000;

function getCachedLiveStreams(cfg) {
    const key = cfg.serverUrl;
    const cached = liveStreamsCache.get(key);
    if (cached && cached.ts > Date.now() - LIVE_STREAMS_CACHE_TTL) {
        return cached.data;
    }
    return null;
}

function setCachedLiveStreams(cfg, items) {
    liveStreamsCache.set(cfg.serverUrl, { data: items, ts: Date.now() });
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
const SERIES_INFO_CACHE_TTL = 30 * 60 * 1000;

function seriesInfoCacheKey(cfg, seriesId) {
    return `${cfg.serverUrl}\n${cfg.username}\n${cfg.password}\n${seriesId}`;
}

function getCachedSeriesInfo(cfg, seriesId) {
    const entry = seriesInfoCache.get(seriesInfoCacheKey(cfg, seriesId));
    if (entry && entry.ts > Date.now() - SERIES_INFO_CACHE_TTL) return entry.data;
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
        </style>
    </head><body>
        <div class="card">
            <div class="header">
                <h1>xTremio Addon</h1>
                <p>Configure your credentials</p>
            </div>
            <div class="form-container">
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

app.get('/:config/catalog/:type/:id/:extra?.json', async (req, res) => {
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

            // Fetch all live channels once, then filter in-memory by selected category.
            let allItems = getCachedLiveStreams(cfg);
            if (!allItems) {
                allItems = await getStreams(cfg, 'get_live_streams', '');
                setCachedLiveStreams(cfg, allItems);
            }

            let items = allItems;
            if (categoryId) {
                const catIdStr = String(categoryId);
                const selectedGenreLower = (selectedGenre || '').toLowerCase();
                items = allItems.filter(s => {
                    if (s.category_id != null && s.category_id !== '') {
                        return String(s.category_id) === catIdStr;
                    }
                    return selectedGenreLower && String(s.category_name || '').toLowerCase() === selectedGenreLower;
                });
            }

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

            const catParam = `&category_id=${cat.category_id}`;
            let items = await getStreams(cfg, 'get_vod_streams', catParam);

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

            const catParam = `&category_id=${cat.category_id}`;
            let items = await getStreams(cfg, 'get_series', catParam);

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
            // Try cached live streams first, fall back to fetching
            let allLive = getCachedLiveStreams(cfg);
            if (!allLive) {
                allLive = await getStreams(cfg, 'get_live_streams', '');
                setCachedLiveStreams(cfg, allLive);
            }

            let s = allLive.find(i => String(i.stream_id) === streamId);
            if (!s) {
                // Cache may be stale; refresh once and retry by ID.
                allLive = await getStreams(cfg, 'get_live_streams', '');
                setCachedLiveStreams(cfg, allLive);
                s = allLive.find(i => String(i.stream_id) === streamId);
            }

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
            const cast = movie.cast ? movie.cast.split(',').map(c => c.trim()).filter(Boolean) : [];
            const backdrop = Array.isArray(movie.backdrop_path) && movie.backdrop_path[0] ? movie.backdrop_path[0] : undefined;

            const meta = {
                id: `xtremio_movie_${streamId}`,
                type: 'XT-Movies',
                name: movie.name || movie.o_name || 'Unknown',
                poster: movie.cover_big || movie.movie_image || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: movie.plot || movie.description || undefined,
                releaseInfo: movie.releasedate ? String(movie.releasedate) : undefined,
                genres: movie.genre ? movie.genre.split(',').map(g => g.trim()).filter(Boolean) : [],
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

            const cast = series.cast ? series.cast.split(',').map(c => c.trim()).filter(Boolean) : [];
            const backdrop = Array.isArray(series.backdrop_path) && series.backdrop_path[0] ? series.backdrop_path[0] : undefined;

            const meta = {
                id: `xtremio_series_${seriesId}`,
                type: 'series',
                name: series.name || 'Unknown',
                poster: series.cover || undefined,
                posterShape: 'poster',
                background: backdrop,
                description: series.plot || undefined,
                releaseInfo: series.releaseDate ? String(series.releaseDate) : undefined,
                genres: series.genre ? series.genre.split(',').map(g => g.trim()).filter(Boolean) : [],
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
    const { serverUrl, username, password } = cfg;

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
        return res.json({
            streams: [
                { url: `${serverUrl}/movie/${username}/${password}/${streamId}.${ext}`, title: '▶ Play' }
            ],
            cacheMaxAge: 86400
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

        return res.json({
            streams: [
                { url: `${serverUrl}/series/${username}/${password}/${episodeId}.${ext}`, title: '▶ Play' }
            ],
            cacheMaxAge: 3600
        });
    }

    res.json({ streams: [] });
});

app.get('/', (req, res) => {
    const base = getBaseUrl(req);
    res.json({
        message: 'xTremio addon is running',
        configureUrl: `${base}/configure`,
        manifestUrl: `${base}/manifest.json`
    });
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
process.on('uncaughtException', (err) => { console.error('Uncaught exception:', err); });
process.on('unhandledRejection', (err) => { console.error('Unhandled rejection:', err); });