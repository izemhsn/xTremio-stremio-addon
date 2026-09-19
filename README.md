# xTremio — Stremio addon for Xtream Codes

Turn any [Xtream Codes](https://en.wikipedia.org/wiki/Xtream_Codes) IPTV subscription into
**Live TV**, **Movies** and **Series** catalogs inside [Stremio](https://www.stremio.com/).

You run it yourself. There is no database — your credentials are encrypted into your own
install link — and one running instance can serve many people, each with their own link.

---

## Quick start

Needs Node 20.18.1 or newer.

```bash
git clone https://github.com/izemhsn/xTremio-stremio-addon.git
cd xTremio-stremio-addon
npm install
npm start
```

Then:

1. Open <http://localhost:3000/configure>
2. Enter your Xtream **server URL**, **username** and **password**
3. Click **Save & Install** → **Install in Stremio**

Live TV, XT-Movies and XT-Series now show up in Stremio.

> **About the server URL:** use the bare host, with a port if you have one —
> `http://line.example.com:8080`, or just `line.example.com:8080`.
> A URL with a path in it (`http://host/panel`) will not work — drop the path.

---

## Going live (read this before you deploy)

Three things matter. Everything else has a sane default.

### 1. Set `CONFIG_SECRET`

Install links are encrypted with a key made from this secret. If you don't set it, a new
random one is made every time the server starts — so **every install link breaks on each
restart** and everyone has to configure again.

```bash
CONFIG_SECRET=$(openssl rand -base64 48)   # generate once, then save it in your host's config
```

It must be at least 32 bytes. With `NODE_ENV=production` the addon **refuses to start**
without a valid one. Keep it backed up: losing it breaks every install, and leaking it lets
anyone holding an install link decrypt that user's provider password.

Changing it later invalidates all existing links. To rotate without breaking everyone at
once, move the old value to `CONFIG_SECRET_PREVIOUS` and set a new `CONFIG_SECRET`.

### 2. Set `NODE_ENV=production`

This is what turns a missing or weak `CONFIG_SECRET` from a warning into a hard stop.

### 3. Behind a reverse proxy, set `PUBLIC_URL` and `TRUST_PROXY`

`PUBLIC_URL` is your public `https://` address, so install links never depend on a request
header. `TRUST_PROXY` is how many proxies sit in front of you (`true` for one), so client
addresses are read from what your proxy wrote rather than from what the client sent.

---

## Deployment

Plain Node HTTP server, no persistence. Tested on Node 20.18.1, 22 and 24.

| Where | How |
|---|---|
| Railway / Render / Fly.io | Push the repo, start command `npm start` |
| VPS | `npm ci --omit=dev && pm2 start index.js --name xtremio` |
| Behind nginx / Caddy / Traefik | Same, plus `PUBLIC_URL` and `TRUST_PROXY` |

**Bandwidth warning:** every stream is relayed through your server — roughly 5–10 Mbps in
*and* out per 1080p viewer, and a live channel relays continuously rather than for the length
of a file. Platforms that charge for egress or cut off long requests are a poor fit.

<details>
<summary><b>Extra steps for a public instance anyone can use</b></summary>

- **Serve it over HTTPS.** The configure form posts provider passwords.
- **Keep install links out of your proxy's access logs.** The first path segment of every
  request is a bearer credential. The addon redacts it in its own logs; nginx does not:

  ```nginx
  map $request_uri $xtremio_uri {
      ~^/[^/]+/(?<rest>.*)$  /<token>/$rest;
      default                $request_uri;
  }
  log_format xtremio '$remote_addr [$time_local] "$request_method $xtremio_uri" $status $body_bytes_sent';
  access_log /var/log/nginx/xtremio.log xtremio;
  ```

- **Cap the relays to your bandwidth** with `PROXY_MAX_CONCURRENT_TOTAL` (whole instance) and
  `PROXY_MAX_CONCURRENT_PER_CLIENT` (one address). These are what stop someone relaying
  arbitrary downloads through a panel of their own. If you only mean to serve specific
  providers, set `ALLOWED_PANEL_HOSTS` instead — that closes the relay outright.
- **Size memory** with `CACHE_MAX_MB`, allowing for `MAX_UPSTREAM_MB` on top of it.
- **Several instances** behind a load balancer work if they share `CONFIG_SECRET`. Caches and
  relay caps are per instance, so divide the caps between them.
- **Content complaints come to you.** Streams leave from your server's address — check your
  host's acceptable-use terms for proxied IPTV traffic before you launch.

</details>

---

## Settings

All optional except `CONFIG_SECRET` in production. Example: `PORT=4000 npm start`.

| Variable | Default | What it does |
|---|---|---|
| `CONFIG_SECRET` | random each boot | Key for install links. **Required in production**, min 32 bytes. |
| `NODE_ENV` | *(unset)* | Set to `production` to enforce the secret policy. |
| `PUBLIC_URL` | from request headers | Your public base URL, used in install links. |
| `TRUST_PROXY` | `false` | Number of reverse proxies in front (`true` for one). |
| `PORT` | `3000` | Port to listen on. |
| `HOST` | `0.0.0.0` | Interface to bind. |
| `ALLOWED_PANEL_HOSTS` | *(any panel)* | Comma-separated Xtream panels this instance will serve. |
| `LOG_REQUESTS` | `false` | Log every meta and stream request. Failures are logged either way. |
| `ALLOW_PRIVATE_NETWORKS` | `false` | Allow LAN/loopback Xtream servers. **Local development only** — it disables the SSRF guard. |

<details>
<summary><b>Advanced settings</b></summary>

**Secrets**

| Variable | Default | What it does |
|---|---|---|
| `CONFIG_SECRET_PREVIOUS` | *(unset)* | The secret you are rotating away from. Old links keep working while new ones are sealed under `CONFIG_SECRET`. Remove it once the "old secret" log line stops appearing. |
| `HLS_SIGNATURE_TTL_MS` | `3600000` | How long a rewritten HLS link stays valid. Playlists are re-minted on every fetch. |

**Limits and rate limiting**

| Variable | Default | What it does |
|---|---|---|
| `CONFIGURE_RATE_LIMIT` | `10` | Max `POST /configure` attempts per client per window. |
| `CONFIGURE_RATE_WINDOW_MS` | `60000` | Length of that window. |
| `PROXY_MAX_CONCURRENT_PER_TOKEN` | `16` | Relays one account may have in flight. |
| `PROXY_MAX_CONCURRENT_PER_CLIENT` | `32` | Relays one client address may have in flight. |
| `PROXY_MAX_CONCURRENT_TOTAL` | `256` | Relays the whole instance may have in flight. |
| `MAX_UPSTREAM_MB` | `64` | Ceiling on a single JSON response from the provider. |
| `MAX_PLAYLIST_ORIGINS` | `32` | Distinct origins one playlist may name. |
| `HLS_TARGET_ALLOWED_HOSTS` | *(empty)* | Extra hostnames a playlist may point at. |

**Caching** (30-minute TTL, LRU-bounded)

| Variable | Default | What it does |
|---|---|---|
| `CACHE_MAX_MB` | `256` | Memory budget shared by **every** cache. |
| `CACHE_MAX_STREAM_MB` | `64` | Budget for full stream lists, **per kind**. |
| `CACHE_MAX_STREAM_ACCOUNTS` | `64` | Accounts' stream lists held, per kind. |
| `CACHE_MAX_ACCOUNTS` | `100` | Accounts' category lists held. |
| `CACHE_MAX_SERIES_INFO` | `500` | Per-series detail entries held. |
| `CACHE_MAX_VOD_INFO` | `500` | Per-movie detail entries held. |
| `CACHE_MAX_CATEGORY_LISTS` | `100` | Per-category stream lists held. |
| `CACHE_SWEEP_INTERVAL_MS` | `300000` | How often expired entries are reclaimed. Minimum 30 s. |
| `SERIES_INFO_NEGATIVE_TTL_MS` | `300000` | How long a series that failed is remembered as broken. |

**Timeouts**

| Variable | Default | What it does |
|---|---|---|
| `DNS_TIMEOUT_MS` | `5000` | Deadline for resolving an Xtream host. |
| `DNS_SERVERS` | *(empty)* | Nameservers for the built-in resolver, e.g. `8.8.8.8,1.1.1.1`. |
| `UPSTREAM_HEADER_TIMEOUT_MS` | `15000` | Wait for provider response headers. |
| `UPSTREAM_IDLE_TIMEOUT_MS` | `15000` | Max gap with no data during a download. |
| `UPSTREAM_BODY_TIMEOUT_MS` | `300000` | Overall deadline for one provider call. |
| `PROXY_HEADER_TIMEOUT_MS` | `20000` | Wait for upstream headers when relaying. |
| `PLAYLIST_BODY_TIMEOUT_MS` | `30000` | Deadline for reading a whole `.m3u8` body. |
| `PLAYLIST_REWRITE_TIMEOUT_MS` | `15000` | Deadline for the rewrite that follows it. |
| `KEEPALIVE_TIMEOUT_MS` | `65000` | How long an idle keep-alive connection is held. |
| `HEADERS_TIMEOUT_MS` | `66000` | How long a client may take to send request headers. |
| `REQUEST_TIMEOUT_MS` | `120000` | How long a client may take to send a whole request. |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | Grace period on `SIGTERM`/`SIGINT`. |

**Other**

| Variable | Default | What it does |
|---|---|---|
| `PROXY_CORS` | `false` | Escape hatch — adds CORS to `/proxy` if a player turns out to need it. |

</details>

---

## What you get

| Type | Catalogs | Sorting |
|---|---|---|
| **Live TV** | 1 | By category (shown as Stremio "genre") |
| **XT-Movies** | 3 + Search | Popular (rating), New (recently added), Featured (shuffled daily) |
| **XT-Series** | 3 + Search | Popular, New, Featured |

- 100 items per page, with genre filtering.
- The two **Search** catalogs plug into Stremio's global search and cover every category.
- **Live TV** offers both HLS (`.m3u8`) and MPEG-TS (`.ts`).
- **Series** gives the full episode list grouped by season.

---

## How it works

### Your install link

When you configure, `{ serverUrl, username, password }` is encrypted into a token that
becomes the first part of every URL:

```
stremio://your-host/<config-token>/manifest.json
```

The token is AES-256-GCM encrypted and separately HMAC-signed, with keys derived from
`CONFIG_SECRET` using scrypt. That means:

- **No database.** Every request carries its own config.
- **Many users, one instance.** Nobody's link affects anyone else's.
- **Treat the link like a password.** Anyone holding it can stream through your instance on
  your provider account.
- **Links only work on the instance that made them.** Moving hosts means carrying
  `CONFIG_SECRET` across, or reissuing every link.
- Reconfiguring from a link prefills the server URL and username but asks for the password
  again — the token never hands it back.

### Streaming

Stremio is never given a provider URL. Two reasons:

1. Xtream providers redirect to a CDN link that expires in about a minute.
2. The provider's live URL carries your **username and password in the path**, which would
   land in player logs and travel in cleartext on the http-only providers that are common.

So streams are served as `/:config/proxy/...` URLs on your server, and each range request
re-resolves a fresh origin. `.ts` is relayed byte-for-byte. `.m3u8` cannot be — a playlist is
a list of further credential-bearing URLs — so every segment, key and variant URI is rewritten
into a signed, encrypted `/proxy/hls` link. Nested playlists are rewritten in turn, and a
target that turns out not to be a playlist is answered `502` rather than relayed.

---

## Endpoints

| Path | Purpose |
|---|---|
| `/` | Landing page |
| `/health` | Health check — `200 {"status":"ok"}`, or `503` while shutting down |
| `/configure` | The credentials form |
| `/:config/configure` | The same form, opened by Stremio's **Configure** button |
| `/manifest.json` | Unconfigured manifest |
| `/:config/manifest.json` | Configured manifest with genres |
| `/:config/catalog/:type/:id/:extra?.json` | Catalog items |
| `/:config/meta/:type/:id.json` | Channel, movie or series details |
| `/:config/stream/:type/:id.json` | Playable stream URLs |
| `/:config/proxy/:kind/:file` | Relays movie, episode and live bytes |
| `/:config/proxy/hls` | Relays HLS segments and keys |

---

## Troubleshooting

**Every install link broke after a restart**
`CONFIG_SECRET` wasn't set, so a new random one was generated at boot and old tokens can no
longer be decrypted. [Set it](#1-set-config_secret). Everyone reconfigures once, then it won't
happen again.

**"Cannot reach that server"**
The message is intentionally identical for a bad hostname, a closed port and a blocked private
address, so the page can't be used to scan hosts. Check the server log for the real cause, and
make sure your URL has no path in it.

**"Connected over http, not https"**
Your `https://` URL didn't work, or the provider's own `server_info` names http — so your
credentials go in cleartext on every request. If the provider does support https, fix the URL
and configure again for a new link. The old link stays on http.

**"No streams available" on an episode**
Usually one specific series upsetting the provider; a retry normally resolves it. A series that
fails all 3 attempts is remembered as broken for 5 minutes, so it stops costing a retry storm
on every request. Check the log for `[stream]` and `[getSeriesInfo] ... failed`.

**Catalogs show no genres**
Your provider is blocking category calls. Catalogs still work, just unfiltered, and search and
pagination are unaffected. Failed lookups are cached for only 60 seconds, so it clears itself
within about a minute.

**Search or a shelf is briefly empty**
The provider answered with an empty list it later filled, which real providers do transiently.
Empty answers are cached for only 60 seconds, so it recovers within about a minute. If search
stays empty for longer, the provider is refusing the full-catalog request outright.

**A live channel fails with "playlist target refused"**
The playlist named a host that is neither your panel nor its own origin, so it was refused
rather than passing the provider's credential-bearing URLs to the player. The log names the
host — add it to `HLS_TARGET_ALLOWED_HOSTS` if your provider legitimately uses it.

**"Too many attempts" on the configure page**
Rate limit, 10 per minute by default. Wait it out, or raise `CONFIGURE_RATE_LIMIT`. If it fires
for unrelated users, you're behind a proxy and need `TRUST_PROXY`.

**Port already in use**
`PORT=3001 npm start`.

**Episodes auto-advance too early**
A Stremio player quirk. Turn off "Play next episode automatically", or use Stremio Desktop
(better MKV handling than web).

---

## Project structure

```
index.js          Express app — routes in registration order, plus bootstrap
src/              Modules index.js re-exports, so requiring index.js gets everything
  helpers.js          URL, id and value coercions
  config-token.js     Install-token crypto and the CONFIG_SECRET policy
  panel-allowlist.js  Which Xtream panels this instance will serve
  manifest.js         The manifest, built per account from its categories
  lifecycle.js        Socket timeouts, drain flag, graceful shutdown
  html.js             escapeHtml, shared by both pages
  net/                SSRF guard, private-IP ranges, DNS pinning, safeFetch
  upstream/           Capped body reading and byte weighing
  cache/              BoundedMap, the shared budget, cache-aside primitives
  xtream/             One panel call, and every cache and getter over it
  catalog/            Catalog kinds, ids, ordering, filtering, the view memo
  hls/                Playlist signing, encryption and rewriting
  proxy/              The shared relay, HLS target mapper, concurrency caps
  configure/          Credential validation and scheme handling
  routes/             Request identity, base URL, extras and cache hints
  pages/              The /configure and landing pages
test/             Unit tests — node:test, run with `npm test`
```

One dependency note: don't move `undici` to version 8 on its own. It needs Node 22.19+, and
its connection agent fails every request with the `fetch` bundled in Node 22 and 24.

---

## License

Source is publicly viewable but **not licensed for use without permission**.
See [`LICENSE`](./LICENSE).
