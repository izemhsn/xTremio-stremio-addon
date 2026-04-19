# xTremio — Stremio Addon for Xtream Codes

A self-hosted [Stremio](https://www.stremio.com/) addon that exposes any [Xtream Codes](https://en.wikipedia.org/wiki/Xtream_Codes) IPTV provider's **Live TV**, **Movies** and **Series** as browseable catalogs inside Stremio.

- **Stateless** — credentials are encoded in the install URL; the server keeps no user files or database.
- **Multi-user** — one running instance serves many users; each one has their own install URL.
- **Fast** — in-memory caching for categories, full stream lists, and series info (30-minute TTL).
- **Global search** — search across all movies and series with a single upstream call per kind.
- **Resilient** — retries `get_series_info` up to 3× with backoff on transient failures.

## Quick start

```bash
git clone https://github.com/izemhsn/xTremio-stremio-addon.git
cd xTremio-stremio-addon
npm install
npm start
```

Server listens on `http://localhost:3000` by default.

1. Open `http://localhost:3000/configure`.
2. Enter your Xtream server URL, username, and password.
3. Click **Save & Install** → validate → **Install in Stremio**.

Catalog sections (Live TV, XT-Movies, XT-Series) then appear in Stremio's sidebar.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port the HTTP server binds to |
| `HOST` | `0.0.0.0` | Interface to bind |

Example: `PORT=4000 HOST=127.0.0.1 npm start`.

## Endpoints

| Path | Purpose |
|---|---|
| `/` | Info payload (configure and manifest URLs) |
| `/health` | Liveness probe for hosting platforms |
| `/configure` | HTML form to enter Xtream credentials and get an install link |
| `/manifest.json` | Unconfigured Stremio manifest |
| `/:config/manifest.json` | Configured manifest with populated genres |
| `/:config/catalog/:type/:id/:extra?.json` | Catalog items |
| `/:config/meta/:type/:id.json` | Meta for a live channel, movie, or series |
| `/:config/stream/:type/:id.json` | Playable stream URLs |

## How install URLs work

When you configure, the addon base64url-encodes `{ serverUrl, username, password }` into the URL path:

```
stremio://your-host/<base64url-config>/manifest.json
```

- No server-side database — every request carries the config in its URL.
- Multiple users can share the same deployed instance without interfering.
- **Security note:** anyone with the install URL has your Xtream credentials. Treat it like a password; don't share it publicly.

## Features

### Catalogs

| Type | Catalogs | Sort modes |
|---|---|---|
| **Live TV** | 1 | by category (as Stremio "genre") |
| **XT-Movies** | 3 + Search | Popular (rating), New (recently added), Featured (day-seeded shuffle) |
| **XT-Series** | 3 + Search | Popular, New, Featured |

Each per-genre catalog supports genre filtering, pagination (100 items/page), and local name search. The two **Search** catalogs hook into Stremio's global search and query across all categories.

### Meta & Streams

- **Live TV** — returns both HLS (`.m3u8`) and MPEG-TS (`.ts`) stream options.
- **Movies** — single direct stream URL with the correct container extension.
- **Series** — full episode list grouped by season; each episode resolves to a direct stream URL. Retries `get_series_info` up to 3 times.

## Deployment

Plain Node.js HTTP server with no persistence. Works on any platform that can run Node 18+:

- **Railway / Render / Fly.io** — push the repo, set the start command to `npm start`.
- **VPS** — `npm ci --omit=dev && pm2 start index.js --name xtremio`.
- **Behind a reverse proxy (nginx, Caddy, Traefik)** — the addon honors `X-Forwarded-Proto` and `X-Forwarded-Host` headers, so HTTPS base URLs work correctly behind TLS-terminating proxies.

## Project structure

```
.
├── index.js        Single-file Express server (routes, caches, Xtream client)
├── package.json
├── README.md
└── LICENSE
```

## Troubleshooting

- **"No streams available"** on an episode — check server logs for `[stream] ...` and `[getSeriesInfo] ... failed`. Usually a specific series triggers an Xtream error; retry resolves most cases.
- **Manifest looks empty** after configuring — your Xtream provider may be blocking category calls. The manifest falls back to minimal catalogs without genre options; reconnecting usually fixes it.
- **Port already in use** — set `PORT=3001` (or any free port) before `npm start`.
- **Premature episode auto-advance** — caused by Stremio's player with direct Xtream streams. Disable "Play next episode automatically" in Stremio settings, or use Stremio Desktop (better MKV handling than web).

## License

Source is publicly viewable but **not licensed for use without permission**. See [`LICENSE`](./LICENSE).