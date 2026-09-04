# xTremio — Stremio Addon for Xtream Codes

A self-hosted [Stremio](https://www.stremio.com/) addon that exposes any [Xtream Codes](https://en.wikipedia.org/wiki/Xtream_Codes) IPTV provider's **Live TV**, **Movies** and **Series** as browseable catalogs inside Stremio.

- **Stateless** — credentials are encrypted into the install URL; the server keeps no user files or database.
- **Multi-user** — one running instance serves many users; each one has their own install URL.
- **Fast** — in-memory caching for categories, full stream lists, and series info (30-minute TTL, LRU-bounded).
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
| `CONFIG_SECRET` | *(random per boot — see below)* | **Effectively mandatory.** Secret from which the config-token encryption and MAC keys are derived. `XTREMIO_CONFIG_SECRET` is accepted as an alias. |
| `PORT` | `3000` | Port the HTTP server binds to |
| `HOST` | `0.0.0.0` | Interface to bind |
| `ALLOW_PRIVATE_NETWORKS` | `false` | Set to `true` to let the addon reach private/loopback addresses. Needed only for an Xtream server on your LAN during development — it disables the SSRF guard, so never enable it on a public deployment. |
| `TRUST_PROXY` | `false` | Set to `true` only when a reverse proxy you control sits in front, so `X-Forwarded-For` identifies the client for rate limiting. Left off, the socket address is used — behind a proxy that means every user shares one bucket. Turned on with no proxy in front, anyone can vary the header to get unlimited fresh buckets. |
| `CONFIGURE_RATE_LIMIT` | `10` | Maximum `POST /configure` attempts per client per window. |
| `CONFIGURE_RATE_WINDOW_MS` | `60000` | Length of that window, in milliseconds. |
| `CACHE_MAX_STREAM_ACCOUNTS` | `4` | How many accounts' full stream lists to hold. These are the largest cached objects (10-50 MB per account per kind), so this is the setting that actually caps memory. Raise it if you serve more than a few concurrent accounts and have the RAM. |
| `CACHE_MAX_ACCOUNTS` | `100` | How many accounts' category lists to hold. Entries are small. |
| `CACHE_MAX_SERIES_INFO` | `500` | How many per-series detail entries to hold across all accounts. |
| `CACHE_SWEEP_INTERVAL_MS` | `300000` | How often expired cache entries are reclaimed. Minimum 30 s. |
| `SERIES_INFO_NEGATIVE_TTL_MS` | `300000` | How long a series whose details could not be loaded is remembered as broken, so repeated requests skip the 3 retries. Lower it if your provider recovers quickly. |
| `PUBLIC_URL` | *(derived from request headers)* | Pins the externally visible base URL used in install links. Recommended behind a reverse proxy — without it the addon derives the base URL from `X-Forwarded-Host`/`Host`, which a client can supply. |
| `MAX_UPSTREAM_MB` | `64` | Ceiling on a single JSON response read from the Xtream provider. Raise it only if a very large provider legitimately exceeds it; a 50k-title catalog is roughly 25 MB. |
| `PROXY_HEADER_TIMEOUT_MS` | `20000` | How long the stream proxy waits for upstream response *headers*. Does not limit the body, so long playback is unaffected. |

Example: `PORT=4000 HOST=127.0.0.1 npm start`.

### Set `CONFIG_SECRET` before you deploy

Install URLs are encrypted under keys derived from `CONFIG_SECRET`. If it is unset, the
addon generates a **random secret at boot** and logs a warning — which means every install
URL it has ever issued stops working the next time the process restarts, and every user has
to reconfigure. Set it once, to a long random value, and keep it stable:

```bash
CONFIG_SECRET=$(openssl rand -base64 48)   # generate once, then store it in your platform config
```

Use at least 32 bytes: the keys are a plain SHA-256 of this value, so a short passphrase can
be brute-forced offline from a single install URL. Changing `CONFIG_SECRET` later invalidates
all existing install URLs, as does bumping `CONFIG_TOKEN_VERSION` in the source.

Also set `NODE_ENV=production` in deployment, so an unhandled route error returns a bare 500
instead of a stack trace with filesystem paths.

## Endpoints

| Path | Purpose |
|---|---|
| `/` | Landing page with project overview and install CTA |
| `/health` | Liveness probe for hosting platforms |
| `/configure` | HTML form to enter Xtream credentials and get an install link (includes disclaimer banner) |
| `/manifest.json` | Unconfigured Stremio manifest |
| `/:config/manifest.json` | Configured manifest with populated genres |
| `/:config/catalog/:type/:id/:extra?.json` | Catalog items |
| `/:config/meta/:type/:id.json` | Meta for a live channel, movie, or series |
| `/:config/stream/:type/:id.json` | Playable stream URLs |
| `/:config/proxy/:kind/:file` | Relays movie and episode bytes from the provider (see [Streaming](#streaming)) |

## How install URLs work

When you configure, the addon encrypts `{ serverUrl, username, password }` into a token that
becomes the first path segment of every request:

```
stremio://your-host/<config-token>/manifest.json
```

The token is a five-part `v2.iv.tag.ciphertext.mac` string: the credentials are encrypted with
AES-256-GCM under a random per-token IV, then the whole body is signed with a separate HMAC key
(encrypt-then-MAC). Both keys derive from `CONFIG_SECRET`. A token that fails its MAC check, its
GCM tag, or its version prefix is rejected, and the route degrades to empty results rather than
an error — Stremio surfaces raw errors to the user.

- No server-side database — every request carries the config in its URL.
- Multiple users can share the same deployed instance without interfering.
- Tokens are opaque to the holder, but they are **bearer credentials**: anyone with the install
  URL can stream through your instance using your provider account. Treat it like a password.
- Tokens are only decryptable by the instance that issued them. Move to a new host and you must
  carry `CONFIG_SECRET` across, or reissue every install URL.

## Streaming

Movies and series are **not** handed to Stremio as provider URLs. Xtream providers 302-redirect
to a CDN URL carrying a token that expires in about a minute, so those streams are served as
`/:config/proxy/:kind/:file` URLs on this server, and each range request re-resolves the origin
to get a fresh token. Live TV is the exception — it returns direct `.m3u8`/`.ts` URLs.

The practical consequence is that **all movie and series bandwidth flows through your host**,
which drives both platform choice and cost. A single 1080p stream is roughly 5-10 Mbps sustained
in *and* out. Platforms that meter egress, or that cap request duration, are a poor fit.

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
- **Behind a reverse proxy (nginx, Caddy, Traefik)** — the addon honors `X-Forwarded-Proto` and `X-Forwarded-Host`, so HTTPS base URLs work correctly behind TLS-terminating proxies. **Set `PUBLIC_URL`** as well: those headers are client-suppliable, and a proxy that forwards a client's `X-Forwarded-Host` unchanged lets an attacker point your install links at their own server. `PUBLIC_URL` overrides the headers entirely and closes that path.

Set `CONFIG_SECRET` and `NODE_ENV=production` on any of these — see [Environment variables](#environment-variables).

## Project structure

```
.
├── index.js        Single-file Express server (routes, caches, Xtream client)
├── test/           Unit tests — node:test, run with `npm test`
├── package.json
├── README.md
└── LICENSE
```

## Troubleshooting

- **"No streams available"** on an episode — check server logs for `[stream] ...` and `[getSeriesInfo] ... failed`. Usually a specific series triggers an Xtream error; retry resolves most cases. A series that fails all 3 attempts is remembered as broken for 5 minutes (logged as `failed recently; skipping 3 retries`) so it stops costing a retry storm on every request — if you have just fixed things upstream, wait out that window or lower `SERIES_INFO_NEGATIVE_TTL_MS`.
- **Manifest looks empty** after configuring — your Xtream provider may be blocking category calls. The manifest falls back to minimal catalogs without genre options. Failed category lookups are only cached for 60 seconds (successful ones for 30 minutes), so this clears itself within about a minute.
- **Every install URL broke after a restart or redeploy** — `CONFIG_SECRET` was not set, so the addon generated a new random one at boot and can no longer decrypt tokens issued under the old key. See [Set `CONFIG_SECRET` before you deploy](#set-config_secret-before-you-deploy). Users must reconfigure once; setting it prevents a recurrence.
- **Port already in use** — set `PORT=3001` (or any free port) before `npm start`.
- **"Too many attempts" on the configure page** — you hit the `POST /configure` rate limit (10 per minute by default). Wait out the window shown in the message, or raise `CONFIGURE_RATE_LIMIT`. If it fires for unrelated users, you are behind a proxy and need `TRUST_PROXY=true` so they are counted separately.
- **"Cannot reach that server"** — the client-facing message is deliberately identical for a bad hostname, a closed port, and a blocked private address, so the page cannot be used to scan hosts. Check the server log for the actual cause.
- **"Connected over http, not https"** — you entered an `https://` URL but the addon ended up on plain http, either because the https connection failed or because your provider's own `server_info` names http. That choice is saved into the install link, so your Xtream username and password are sent in cleartext on every request. If the provider does support https, correct the URL and configure again to get a new link; the old one keeps using http.
- **Premature episode auto-advance** — caused by Stremio's player with direct Xtream streams. Disable "Play next episode automatically" in Stremio settings, or use Stremio Desktop (better MKV handling than web).

## License

Source is publicly viewable but **not licensed for use without permission**. See [`LICENSE`](./LICENSE).