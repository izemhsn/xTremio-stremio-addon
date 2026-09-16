// The /configure page.
//
// A template literal, so every interpolated value goes through escapeHtml —
// credentials and provider-supplied strings alike. Nothing here may be an inline
// onclick/onmouseover attribute: the page is served under a strict CSP and those
// are silently refused, so a handler added that way looks fine and does nothing.
// Behaviour belongs in the nonced <script> block, hover states in <style>.
const { escapeHtml } = require('../html.js');
// The page shows the install URL, which means minting a token from the fields
// just submitted.
const { encodeConfig } = require('../config-token.js');

// Only for the default baseUrl, which is a development and test convenience —
// every caller in the app passes the real one from getBaseUrl.
const PORT = process.env.PORT || 3000;


// `nonce` comes from setPrivateHeaders and is the only thing that lets this
// page's one script run under its CSP. Rendering without one (a caller that
// forgot, or a test) still produces a working page — only the click-to-copy
// convenience goes quiet, since the link is selectable text either way.
function renderConfigPage({ serverUrl = '', username = '', password = '', status = null, baseUrl = `http://localhost:${PORT}`, nonce = '' }) {
    // Base64 contains nothing escapeHtml touches, so this is identical to the
    // value in the header — it just keeps the rule that every interpolation on
    // this page goes through escapeHtml, with no exception to remember.
    const safeNonce = escapeHtml(nonce);
    const safeServerUrl = escapeHtml(serverUrl);
    const safeUsername = escapeHtml(username);
    const safePassword = escapeHtml(password);
    let statusHtml = '';
    if (status) {
        if (status.valid) {
            const encoded = encodeConfig({ serverUrl, username, password });
            const installUrl = escapeHtml(`stremio://${baseUrl.replace(/^https?:\/\//, '')}/${encoded}/manifest.json`);
            const httpUrl = escapeHtml(`${baseUrl}/${encoded}/manifest.json`);
            // The connection was downgraded to http and that choice is now baked
            // into the install token, so say so plainly rather than letting the
            // green "Connected!" banner imply everything is fine.
            const downgradeHtml = status.downgrade ? `
                    <div class="status-banner status-warning">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                        <span class="status-text">
                            <strong>Connected over http, not https.</strong>
                            ${status.downgrade.source === 'fallback'
                                ? 'The https connection failed, so http was used instead.'
                                : 'Your provider asked for http even though https worked.'}
                            Your username and password will be sent in cleartext on every request, and this choice is saved into the install link below.
                            ${status.downgrade.source === 'fallback'
                                ? 'If your provider does support https, fix the URL and configure again.'
                                : ''}
                        </span>
                    </div>` : '';
            statusHtml = `
                <div class="status-section">
                    <div class="status-banner status-success">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
                        <span class="status-text">Connected! Welcome, ${escapeHtml(status.userInfo.username || username)}</span>
                    </div>${downgradeHtml}
                    <a href="${installUrl}" class="btn full install-link">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                        Install in Stremio
                    </a>
                    <div class="copy-block">
                        <p id="copy-label" class="copy-label" data-idle="Or copy this link to install:">Or copy this link to install:</p>
                        <input type="text" id="copy-input" class="copy-input" value="${httpUrl}" readonly title="Click to copy install link" />
                    </div>
                </div>
                <script nonce="${safeNonce}">
                (function () {
                    var input = document.getElementById('copy-input');
                    var label = document.getElementById('copy-label');
                    if (!input || !label) return;
                    var timer = null;

                    function report(copied) {
                        label.textContent = copied ? '✓ Copied to clipboard!' : 'Press Ctrl+C to copy';
                        label.style.color = copied ? '#2e7d32' : '#555';
                        clearTimeout(timer);
                        timer = setTimeout(function () {
                            label.textContent = label.dataset.idle;
                            label.style.color = '#555';
                        }, 2000);
                    }

                    function copyViaSelection() {
                        // execCommand is deprecated but stays as the fallback rather
                        // than the other way round: navigator.clipboard exists only on
                        // secure origins, and this addon is most often reached over
                        // plain http on a LAN, where it is undefined.
                        try { return document.execCommand('copy'); } catch (e) { return false; }
                    }

                    input.addEventListener('click', function () {
                        input.select();
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            navigator.clipboard.writeText(input.value).then(function () {
                                report(true);
                            }, function () {
                                report(copyViaSelection());
                            });
                        } else {
                            report(copyViaSelection());
                        }
                    });
                })();
                </script>`;
        } else {
            statusHtml = `
                <div class="status-section">
                    <div class="status-banner status-error">
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M6 18L18 6M6 6l12 12"/></svg>
                        <span class="status-text">${escapeHtml(status.error)}</span>
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
            .status-warning { background: #fff8e1; color: #8a5a00; }
            .status-warning .status-text { line-height: 1.5; }
            .install-link { margin-top: 4px; }
            .copy-block { margin-top: 16px; }
            .copy-label { font-size: 13px; color: #555; margin-bottom: 8px; font-weight: 600; text-align: left; }
            .copy-input { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 14px; color: #333; background: #f9f9f9; cursor: pointer; text-align: center; transition: border-color 0.2s; }
            .copy-input:hover { border-color: #7c4dff; }
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
                        <li>Credentials are encrypted into your install URL &mdash; keep it private, do not share it.</li>
                    </ul>
                </div>
                <form method="POST" action="/configure">
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

module.exports = { renderConfigPage };
