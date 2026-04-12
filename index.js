const express = require('express');
const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, 'config.json');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});

const PORT = process.env.PORT || 3000;
const ADDON_ID = 'org.xtremio.addon';

let config = {
    serverUrl: '',
    username: '',
    password: ''
};

function loadConfig() {
    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const data = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
            config = { ...config, ...data };
            console.log('[config] Loaded saved config for', config.username);
        }
    } catch (e) {
        console.error('[config] Failed to load config:', e.message);
    }
}

function saveConfig() {
    try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
        console.log('[config] Config saved');
    } catch (e) {
        console.error('[config] Failed to save config:', e.message);
    }
}

loadConfig();


async function getManifest() {
    const isConfigured = config.serverUrl && config.username && config.password;
    const catalogs = [];

    if (isConfigured) {
        try {
            const cats = await getCategories();
            const movieGenres = ['Top', ...new Set(cats.movies.map(c => c.category_name).filter(Boolean))];
            const liveGenres = [...new Set(cats.live.map(c => c.category_name).filter(Boolean))];

            catalogs.push(
                {
                    type: 'XT-Live',
                    id: 'xtremio_live',
                    name: 'All',
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
                }
            );
        } catch (e) {
            catalogs.push(
                { type: 'XT-Live', id: 'xtremio_live', name: 'All' },
                { type: 'XT-Movies', id: 'xtremio_movies_popular', name: 'Popular' },
                { type: 'XT-Movies', id: 'xtremio_movies_new', name: 'New' },
                { type: 'XT-Movies', id: 'xtremio_movies_featured', name: 'Featured' }
            );
        }
    }

    return {
        id: ADDON_ID,
        version: '1.0.0',
        name: 'xTremio',
        description: 'xTremio addon for Stremio',
        resources: ['catalog', 'meta', 'stream'],
        types: ['XT-Live', 'XT-Movies'],
        catalogs,
        idPrefixes: ['xtremio_'],
        behaviorHints: {
            configurable: true,
            configurationRequired: !isConfigured
        },
        config: { url: `http://127.0.0.1:${PORT}/configure` }
    };
}

app.get('/manifest.json', async (req, res) => {
    res.json(await getManifest());
});

function normalizeUrl(url) {
    url = url.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//.test(url)) url = 'http://' + url;
    return url;
}

async function xtremioGet(action, extraParams = '') {
    const url = `${config.serverUrl}/player_api.php?username=${encodeURIComponent(config.username)}&password=${encodeURIComponent(config.password)}&action=${action}${extraParams}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
        const res = await fetch(url, { signal: controller.signal, redirect: 'follow' });
        const data = await res.json();

        const sample = Array.isArray(data) ? data.slice(0, 10) : data;
        console.log(`[xtremioGet] ${action} (${Array.isArray(data) ? data.length : '?'} items)`, JSON.stringify(sample, null, 2));

        return data;
    } finally {
        clearTimeout(timer);
    }
}

let catCache = { live: [], movies: [], ts: 0 };
const CACHE_TTL = 5 * 60 * 1000;

async function getCategories() {
    if (catCache.ts > Date.now() - CACHE_TTL && catCache.live.length && catCache.movies.length) return catCache;
    const [live, movies] = await Promise.all([
        xtremioGet('get_live_categories'),
        xtremioGet('get_vod_categories')
    ]);
    catCache = {
        live: Array.isArray(live) ? live : [],
        movies: Array.isArray(movies) ? movies : [],
        ts: Date.now()
    };
    return catCache;
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

const streamCache = new Map();

async function getCachedStreams(action, catParam = '') {
    const key = `${action}${catParam}`;
    const cached = streamCache.get(key);
    if (cached && cached.ts > Date.now() - CACHE_TTL) return cached.data;
    const data = await xtremioGet(action, catParam);
    const items = Array.isArray(data) ? data : [];
    streamCache.set(key, { data: items, ts: Date.now() });
    return items;
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
                serverInfo: si,
                resolvedUrl: resolvedUrl || url,
                expDate: expDate || null,
                maxConnections: json.user_info.max_connections || '1'
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

function renderConfigPage({ serverUrl = '', username = '', password = '', status = null }) {
    let statusHtml = '';
    if (status) {
        if (status.valid) {
            const installUrl = `stremio://127.0.0.1:${PORT}/manifest.json`;
            statusHtml = `
                <div class="status-section">
                    <div class="status-banner status-success">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
                        <span class="status-text">Connected! Welcome, ${status.userInfo.username || username}</span>
                    </div>
                    <a href="${installUrl}" class="btn full install-link">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                        Install in Stremio
                    </a>
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
                            <input type="url" name="serverUrl" value="${serverUrl}" placeholder="http://example.com:port" required />
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Username</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
                            <input type="text" name="username" value="${username}" placeholder="Enter username" required />
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Password</label>
                        <div class="input-wrapper">
                            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                            <input type="password" name="password" value="${password}" placeholder="Enter password" required />
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
    res.send(renderConfigPage({
        serverUrl: req.query.serverUrl || config.serverUrl,
        username: req.query.username || config.username,
        password: req.query.password || config.password
    }));
});

app.post('/configure', async (req, res) => {
    const serverUrl = (req.body.serverUrl || '').trim().replace(/\/+$/, '');
    const username = req.body.username || '';
    const password = req.body.password || '';

    try {
        const validation = await validateXtremioCredentials(serverUrl, username, password);

        if (validation.valid) {
            config.serverUrl = validation.resolvedUrl || normalizeUrl(serverUrl);
            config.username = username;
            config.password = password;
            config.maxConnections = validation.maxConnections;
            config.expDate = validation.expDate;
            saveConfig();
            catCache.ts = 0;
            streamCache.clear();
            getCategories().catch(() => { });
        }

        res.send(renderConfigPage({
            serverUrl: validation.valid ? config.serverUrl : serverUrl,
            username,
            password,
            status: validation
        }));
    } catch (e) {
        res.send(renderConfigPage({
            serverUrl,
            username,
            password,
            status: { valid: false, error: 'Something went wrong. Please try again.' }
        }));
    }
});

app.get('/catalog/:type/:id/:extra?.json', async (req, res) => {
    if (!config.serverUrl) return res.json({ metas: [] });

    const { type, id } = req.params;
    const extra = parseExtra(req.params.extra);
    const skip = parseInt(extra.skip) || 0;
    const genre = extra.genre;

    try {
        if (id === 'xtremio_live') {
            const cats = await getCategories();
            const selectedGenre = genre || (cats.live[0] && cats.live[0].category_name);
            let categoryId;
            if (selectedGenre) {
                const cat = cats.live.find(c => c.category_name === selectedGenre);
                if (cat) categoryId = cat.category_id;
            }

            const catParam = categoryId ? `&category_id=${categoryId}` : '';
            let items = await getCachedStreams('get_live_streams', catParam);

            if (extra.search) {
                const q = extra.search.toLowerCase();
                items = items.filter(s => s.name?.toLowerCase().includes(q));
            }

            const page = items.slice(skip, skip + PAGE_SIZE);
            const metas = page.map(s => ({
                id: `xtremio_live_${s.stream_id}`,
                type: 'XT-Live',
                name: s.name,
                poster: s.stream_icon || undefined,
                posterShape: 'square'
            }));

            return res.json({ metas });
        }

        if (id.startsWith('xtremio_movies_')) {
            const cats = await getCategories();
            const selectedGenre = (genre && genre !== 'Top') ? genre : (cats.movies[0] && cats.movies[0].category_name);
            const cat = cats.movies.find(c => c.category_name === selectedGenre);
            if (!cat) return res.json({ metas: [] });

            const catParam = `&category_id=${cat.category_id}`;
            let items = await getCachedStreams('get_vod_streams', catParam);

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

            return res.json({ metas });
        }

        res.json({ metas: [] });
    } catch (e) {
        res.json({ metas: [] });
    }
});

app.get('/meta/:type/:id.json', async (req, res) => {
    if (!config.serverUrl) return res.json({ meta: null });
    const { type, id } = req.params;

    try {
        if (id.startsWith('xtremio_live_')) {
            const streamId = id.replace('xtremio_live_', '');
            // Search across all cached category streams to find the channel
            const cats = await getCategories();
            let s = null;
            for (const cat of cats.live) {
                const items = await getCachedStreams('get_live_streams', `&category_id=${cat.category_id}`);
                s = items.find(i => String(i.stream_id) === streamId);
                if (s) break;
            }
            if (!s) return res.json({ meta: null });
            return res.json({
                meta: {
                    id: `xtremio_live_${s.stream_id}`,
                    type: 'XT-Live',
                    name: s.name,
                    poster: s.stream_icon || undefined,
                    posterShape: 'square',
                    genres: s.category_name ? [s.category_name] : [],
                    description: s.name || undefined,
                    logo: s.stream_icon || undefined
                }
            });
        }

        if (id.startsWith('xtremio_movie_')) {
            const streamId = id.replace('xtremio_movie_', '');
            const info = await xtremioGet('get_vod_info', `&vod_id=${streamId}`);
            const movie = info?.info ?? info ?? {};
            const cast = movie.cast ? movie.cast.split(',').map(c => c.trim()).filter(Boolean) : [];
            const backdrop = Array.isArray(movie.backdrop_path) && movie.backdrop_path[0] ? movie.backdrop_path[0] : undefined;

            return res.json({
                meta: {
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
                    year: movie.releasedate ? parseInt(movie.releasedate.slice(0, 4)) : undefined,
                    country: movie.country || undefined,
                    trailer: movie.youtube_trailer || undefined
                }
            });
        }

        res.json({ meta: null });
    } catch (e) {
        res.json({ meta: null });
    }
});

app.get('/stream/:type/:id.json', async (req, res) => {
    if (!config.serverUrl) return res.json({ streams: [] });
    const { type, id } = req.params;
    const { serverUrl, username, password } = config;

    if (id.startsWith('xtremio_live_')) {
        const streamId = id.replace('xtremio_live_', '');
        res.json({
            streams: [
                { url: `${serverUrl}/live/${username}/${password}/${streamId}.m3u8`, title: 'HLS' },
                { url: `${serverUrl}/live/${username}/${password}/${streamId}.ts`, title: 'MPEG-TS' }
            ]
        });
    } else if (id.startsWith('xtremio_movie_')) {
        const streamId = id.replace('xtremio_movie_', '');
        const info = await xtremioGet('get_vod_info', `&vod_id=${streamId}`);
        const ext = info?.movie_data?.container_extension || 'mp4';
        res.json({
            streams: [
                { url: `${serverUrl}/movie/${username}/${password}/${streamId}.${ext}`, title: 'Movie' }
            ]
        });
    } else {
        res.json({ streams: [] });
    }
});

app.get('/', (req, res) => {
    res.json({
        message: 'xTremio addon is running',
        configureUrl: `http://127.0.0.1:${PORT}/configure`,
        manifestUrl: `http://127.0.0.1:${PORT}/manifest.json`
    });
});

app.listen(PORT, () => {
    console.log(`Addon running at http://127.0.0.1:${PORT}`);
    console.log(`Configure: http://127.0.0.1:${PORT}/configure`);
});