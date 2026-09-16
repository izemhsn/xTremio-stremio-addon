// The landing page at `/`.
//
// Static: it interpolates nothing, which is why it takes no escapeHtml and no
// arguments. Anything added here that comes from a request, a config token or a
// provider must go through escapeHtml in src/html.js — the rule the /configure
// page follows, and the reason both pages live under src/pages.
function renderLandingPage() {
    return (`<!DOCTYPE html>
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
}

module.exports = { renderLandingPage };
