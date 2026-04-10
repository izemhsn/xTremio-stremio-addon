const express = require('express');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});

const PORT = process.env.PORT || 3000;
const ADDON_ID = 'org.xtream.addon';

let config = {
    serverUrl: '',
    username: '',
    password: ''
};

function getManifest() {
    const isConfigured = config.serverUrl && config.username && config.password;
    return {
        id: ADDON_ID,
        version: '1.0.0',
        name: 'xTremio',
        description: 'xTremio addon for Stremio',
        resources: ['stream', 'catalog'],
        types: ['channel', 'movie', 'series'],
        catalogs: [],
        idPrefixes: ['xtream_'],
        behaviorHints: {
            configurable: true,
            configurationRequired: !isConfigured
        },
        config: { url: `http://127.0.0.1:${PORT}/configure` }
    };
}

app.get('/manifest.json', (req, res) => {
    res.json(getManifest());
});

function normalizeUrl(url) {
    url = url.trim().replace(/\/+$/, '');
    if (!/^https?:\/\//.test(url)) url = 'http://' + url;
    return url;
}

async function validateXtreamCredentials(serverUrl, username, password) {
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
    res.send(renderConfigPage({}));
});

app.post('/configure', async (req, res) => {
    const serverUrl = (req.body.serverUrl || '').trim().replace(/\/+$/, '');
    const username = req.body.username || '';
    const password = req.body.password || '';

    try {
        const validation = await validateXtreamCredentials(serverUrl, username, password);

        if (validation.valid) {
            config.serverUrl = validation.resolvedUrl || normalizeUrl(serverUrl);
            config.username = username;
            config.password = password;
            config.maxConnections = validation.maxConnections;
            config.expDate = validation.expDate;
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