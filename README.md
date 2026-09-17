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

The server URL must be a bare host, optionally with a port and scheme —
`http://line.example.com:8080`, or just `line.example.com:8080`. **A path prefix is
not supported**: every upstream URL is built from the origin, so a panel reachable
only at `http://host/panel` is looked up at `http://host/player_api.php` and fails
validation with the deliberately vague "Cannot reach that server". If your provider
gave you a URL with a path in it, the panel host is usually the same URL without it.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CONFIG_SECRET` | *(random per boot — see below)* | **Mandatory under `NODE_ENV=production`**, where the addon refuses to start without it or with fewer than 32 bytes. Secret from which the config-token encryption and MAC keys are derived, via scrypt. `XTREMIO_CONFIG_SECRET` is accepted as an alias. |
| `CONFIG_SECRET_PREVIOUS` | *(unset)* | The secret you are rotating away from. Install URLs sealed under it keep working while every new one is sealed under `CONFIG_SECRET`, so users can reinstall at their own pace instead of every install breaking at once. The first time an old install URL is used after a restart, the log says so; remove this once that line stops appearing for as long as your users take to reinstall. HLS links minted under the old secret stop working at the rotation, which a player recovers from by reloading the playlist. |
| `NODE_ENV` | *(unset)* | Set to `production` in deployment. Enforces the `CONFIG_SECRET` policy above. Error responses no longer depend on it: the addon's own error handler returns a bare 400/500 and logs the stack server-side whatever `NODE_ENV` says. |
| `PROXY_CORS` | `false` | Escape hatch. `Access-Control-Allow-Origin: *` is sent on the Stremio addon resources (manifest, catalog, meta, stream) but **not** on `/proxy`, `/configure`, `/health` or the landing page. Set to `true` if a player turns out to need CORS on the byte proxy. Note that CORS is not what limits who can spend your bandwidth — a plain `<video src>` needs none — the install token is. |
| `PORT` | `3000` | Port the HTTP server binds to |
| `HOST` | `0.0.0.0` | Interface to bind |
| `LOG_REQUESTS` | `false` | Set to `true` to log a line for every meta and stream request and every call to the Xtream provider. Failures and warnings are logged either way. |
| `ALLOW_PRIVATE_NETWORKS` | `false` | Set to `true` to let the addon reach private/loopback addresses. Needed only for an Xtream server on your LAN during development — it disables the SSRF guard, so never enable it on a public deployment. |
| `DNS_TIMEOUT_MS` | `5000` | Deadline for resolving an Xtream host during the SSRF check. Lookups run off Node's thread pool and are cancelled at the deadline, so a panel on a domain whose nameserver never answers cannot stall other users' playback; a host resolved within the last minute is not looked up again. These lookups do not read `/etc/hosts`, so a panel hostname must resolve in DNS. Minimum 500. |
| `DNS_SERVERS` | *(empty)* | Comma-separated nameservers for the built-in resolver, e.g. `8.8.8.8,1.1.1.1`. An entry may be an address, `address:port`, or `[v6address]:port`. Empty — the default — lets the resolver work the list out for itself, which is right on most hosts. Set it when it gets that wrong: it discovers nameservers independently of the OS, and on some hosts (one Windows machine found only `127.0.0.1`) every lookup then fails with `ECONNREFUSED` and `/configure` reports every panel unreachable. You will see a one-off `[dns] the built-in resolver cannot reach its nameservers` warning in that case; the server keeps working by falling back to the OS resolver, but that resolver cannot be cancelled, so a slow nameserver can delay other requests until you set this. An entry that is not an IP address is dropped with a warning at boot rather than taken or treated as fatal. |
| `TRUST_PROXY` | `false` | How many reverse proxies you control sit in front of the addon: `true` for one, or the number. Their forwarded headers then identify the client — for the `/configure` rate limit and the per-client relay cap — and give install links their scheme and host when `PUBLIC_URL` is not set. The client is read from the **right** of `X-Forwarded-For`, counting in by this many hops, because a proxy appends the address it saw and everything to its left was written by the client; count every proxy that appends (a CDN in front of nginx is `2`). Left off, forwarded headers are ignored entirely and the socket address is used — behind a proxy, every user then shares one bucket. Turned on with no proxy in front, a client can choose its own address. IPv6 clients are grouped by /64, so one subscriber is one client. |
| `CONFIGURE_RATE_LIMIT` | `10` | Maximum `POST /configure` attempts per client per window. |
| `CONFIGURE_RATE_WINDOW_MS` | `60000` | Length of that window, in milliseconds. |
| `ALLOWED_PANEL_HOSTS` | *(empty — any panel)* | Xtream panels this instance will serve, comma-separated. **Set it on any instance people you don't know can reach, unless its users must be able to bring their own provider.** Without it, anyone who can reach `/configure` can point it at a fake panel of their own — a few lines that answer the credential check — get an install URL, and have this server fetch and relay whatever public URL that panel redirects to, from this server's address. The per-account relay cap does not bound that, since every made-up username is a new account. Set, the list is enforced everywhere a panel is chosen or used: `/configure` refuses an unlisted host before contacting it, a listed panel's `server_info` cannot move the install URL to an unlisted host, and an install URL for an unlisted host stops working — including ones issued before the list was set, which is logged once per host. Entries may be written as a hostname, `host:port` or a URL. Matching is by exact hostname, so one entry covers both schemes and any port, a subdomain needs its own entry, and wildcards are not supported (an entry that names no host is ignored with a warning at startup). A listed panel is trusted, including wherever it redirects. |
| `CACHE_MAX_STREAM_ACCOUNTS` | `64` | How many accounts' full stream lists to hold, per kind. Memory is bounded by `CACHE_MAX_STREAM_MB` and `CACHE_MAX_MB`, so this only stops many tiny entries accumulating; it used to default to 4, which evicted — and made the addon re-download and re-parse — lists that fitted the memory budget easily whenever a fifth account was active. |
| `CACHE_MAX_STREAM_MB` | `64` | Memory budget for cached stream lists, **per kind**, so the ceiling across live/movies/series is three times it. Measured in *estimated heap* — what a list occupies once parsed, estimated from its body as it downloads. It used to be measured in serialized JSON, of which a realistic list occupies 1.1-1.4× in memory and a hostile one over 20×, so no multiplier could describe it; the estimate lands within 0.8-1.3× of measured heap for realistic lists, and at or above it for hostile ones. A single list larger than this budget is still cached — refetching 50 MB per request would be worse — and logs a warning. `CACHE_MAX_MB` bounds all the caches together. |
| `CACHE_MAX_MB` | `256` | Memory budget shared by **every** cache — stream lists, per-category lists, series and movie details, and categories — in the same estimated-heap unit. This is the number to size a container by: each cache's own bound still applies, but the per-category, series, movie and category caches used to be bounded by entry count alone, so their bounds did not add up to any figure of memory. When the total is over, the least recently used entry across *all* caches is evicted first. A single entry larger than this whole budget is not cached at all, and logs a warning, because keeping it would evict every other account's data and still not fit. Lower it on a small container, but keep it at least twice `MAX_UPSTREAM_MB` — no response can be estimated at more than that, so any list a provider sends can then be cached. |
| `CACHE_MAX_ACCOUNTS` | `100` | How many accounts' category lists to hold. Entries are small. |
| `CACHE_MAX_SERIES_INFO` | `500` | How many per-series detail entries to hold across all accounts. |
| `CACHE_MAX_VOD_INFO` | `500` | How many per-movie detail entries to hold across all accounts. Opening a movie needs this payload twice — once for meta, once for the stream — and it is reused when the movie is opened again. |
| `CACHE_MAX_CATEGORY_LISTS` | `100` | How many per-category stream lists to hold across all accounts. This is the cold-cache path for a genre page; caching it is what makes paginating a genre free rather than one upstream fetch per page. |
| `CACHE_SWEEP_INTERVAL_MS` | `300000` | How often expired cache entries are reclaimed. Minimum 30 s. |
| `SERIES_INFO_NEGATIVE_TTL_MS` | `300000` | How long a series whose details could not be loaded is remembered as broken, so repeated requests skip the 3 retries. Lower it if your provider recovers quickly. |
| `PUBLIC_URL` | *(derived from request headers)* | Pins the externally visible base URL used in install links. Recommended behind a reverse proxy, and always on a public instance — without it the addon derives the base URL from `Host`, which a client can supply, or with `TRUST_PROXY` on from your proxy's `X-Forwarded-Proto`/`X-Forwarded-Host`. A hostname someone else controls, pointed at your instance, then mints install URLs carrying that hostname, and repointing its DNS later collects the config tokens your users installed. With `NODE_ENV=production` and this unset, the addon warns about it once at startup and carries on. |
| `MAX_UPSTREAM_MB` | `64` | Ceiling on a single JSON response read from the Xtream provider. Raise it only if a very large provider legitimately exceeds it; a 50k-title catalog is roughly 25 MB. The byte count is not the whole cost, because what a body *parses to* depends on its shape: a realistic list occupies about 1.1× its size in memory, while a hostile body of `[{},{},…]` measured 21×, so the same 64 MB could become ~1.4 GB. Each body is therefore also weighed as it downloads, and one estimated to parse to more than **twice** this ceiling is refused mid-download, before it is parsed. Realistic lists estimate at 1.0-1.3× their size, so they always reach the byte ceiling first. At the defaults that bounds the graph one response can build at about 128 MB. It is still a **transient** cost that the cache budgets above do not describe: reading a response holds one full copy of the body plus that graph at the moment it is parsed, and the three kinds are fetched independently, so a cold install can pay it three times over. Measured on a 21 MB body, the copies reachable at parse time come to ~1× the body; it was ~3× before the copies were staged. Scale this down along with `CACHE_MAX_MB` on a small container. |
| `UPSTREAM_HEADER_TIMEOUT_MS` | `15000` | How long a call to the Xtream provider waits for response headers. Series details use a shorter 8 s, since they are retried. Minimum 100. |
| `UPSTREAM_IDLE_TIMEOUT_MS` | `15000` | How long a download from the provider may go without receiving any data. Reset by every chunk, so a slow panel sending a large list completes as long as it keeps sending; one timeout used to cover the whole download, and a 25 MB list from a panel slower than ~1.7 MB/s never finished. Minimum 100. |
| `UPSTREAM_BODY_TIMEOUT_MS` | `300000` | Overall deadline for one call to the provider, headers and body together. Stops a panel that sends just enough to beat the idle timeout from holding a request open indefinitely. Minimum 100. |
| `HLS_SIGNATURE_TTL_MS` | `3600000` | How long a rewritten HLS sub-resource link stays valid. Each playlist fetch mints fresh links, and a live playlist is re-fetched every few seconds, so an hour is already far longer than any of them are needed. Minimum 60 s. |
| `PROXY_HEADER_TIMEOUT_MS` | `20000` | How long the stream proxy waits for upstream response *headers*. Does not limit the body, so long playback is unaffected. |
| `PROXY_MAX_CONCURRENT_PER_TOKEN` | `16` | How many relays one account may have in flight at once, across both proxy routes. An install token is a bearer credential, and a leaked or deliberately shared one can otherwise open as many full-rate streams as the sharers have players. Requests over the cap get `429` with `Retry-After: 1`, which a player treats as a segment to retry rather than as the end of the stream. Counted per **account** rather than per token string, because `/configure` will mint a fresh token for the same credentials on demand and a budget a new install URL resets is not a budget. It bounds a real account's install URLs and nothing more: it does not bound a caller who can make accounts, since `/configure` mints one for any panel that passes the credential check and every made-up username gets its own allowance — `PROXY_MAX_CONCURRENT_PER_CLIENT` and `PROXY_MAX_CONCURRENT_TOTAL` are the limits for that. A single player keeps one or two relays open and a live channel two or three, so a household sits far below the default. Set to `0` to disable, e.g. behind a reverse proxy that already limits this. |
| `PROXY_MAX_CONCURRENT_PER_CLIENT` | `32` | How many relays one client address may have in flight, across every account. The per-token cap cannot bound a caller who can make accounts — `/configure` mints one for any panel that passes the credential check — so on an instance open to any provider this is the limit that matters. Clients are identified as for the rate limit (see `TRUST_PROXY`; IPv6 by /64), and the default leaves room for carrier NAT putting many users behind one address. Over the cap: `429` with `Retry-After: 1`. `0` disables. |
| `PROXY_MAX_CONCURRENT_TOTAL` | `256` | How many relays the whole instance may have in flight. Size it to your bandwidth: each relay is a full-rate stream, roughly 5-10 Mbps in *and* out for 1080p, so the default is a ceiling a small host should lower, not a recommendation. Over the cap: `503` with `Retry-After: 5`. `0` disables. |
| `PLAYLIST_BODY_TIMEOUT_MS` | `30000` | Deadline for reading a whole `.m3u8` body, the one path that must buffer before it can answer. Deliberately not a general body timeout — a paused movie is a legitimately idle connection. A playlist is kilobytes, so 30 s is already generous. |
| `PLAYLIST_REWRITE_TIMEOUT_MS` | `15000` | Deadline for the rewrite that follows the playlist read — a separate phase from `PLAYLIST_BODY_TIMEOUT_MS`, which is already cleared by the time it starts. It resolves DNS once per distinct origin named in the playlist, so without a bound a hostile playlist held one request and its socket for as long as the resolver took. Checked between lookups, so a single hung resolution can still overrun it by that lookup's own timeout. Minimum 1 s; rewriting a maximum-size playlist costs roughly 1 s of CPU on its own, so do not set this near the floor. |
| `HLS_TARGET_ALLOWED_HOSTS` | *(empty)* | Extra hostnames a playlist may name, comma-separated, on top of the two the server derives itself: the account's own panel origin and the origin the playlist was finally fetched from. Signed targets are restricted to that set, so a compromised or misbehaving playlist from an honest panel cannot make this server fetch and relay other hosts. It does **not** protect against a panel you don't trust: that panel's own origin, and wherever its playlist is served from, are in the set by definition — `ALLOWED_PANEL_HOSTS` and the relay caps are what bound that. Matched by hostname, so one entry covers both schemes and any port; entries may be written as a hostname, `host:port` or a URL. A playlist naming a host outside the set is refused with a `502` rather than served half-rewritten, and the log names the host to add. Only add a host you are content for this server to fetch from on a provider's instruction. |
| `MAX_PLAYLIST_ORIGINS` | `32` | How many distinct origins in one playlist are worth vetting. Each new origin costs a DNS resolution and a real playlist names one or two, so this is the bound that actually stops the work; the deadline above is the backstop. Past the cap nothing further is signed and the playlist is refused with a `502`, because the lines that would be left unrewritten are the provider's own credential-bearing URLs. Raise it only if a provider legitimately fans out across more hosts. |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | Grace period on `SIGTERM`/`SIGINT` before the process exits regardless. Without a deadline a single in-flight movie stream keeps the socket open and blocks shutdown until the platform sends `SIGKILL`. |
| `KEEPALIVE_TIMEOUT_MS` | `65000` | How long an idle keep-alive connection is held. Deliberately longer than the 60 s idle timeout most load balancers use, so the balancer is the side that closes first — otherwise a request can land on a socket the server just tore down and surface as a 502. |
| `HEADERS_TIMEOUT_MS` | `66000` | How long a client may take to send request headers. Raised automatically to stay above `KEEPALIVE_TIMEOUT_MS`. |
| `REQUEST_TIMEOUT_MS` | `120000` | How long a client may take to send a whole request. Does not limit the *response*, so proxied playback can run for hours. Raised automatically to stay at or above `HEADERS_TIMEOUT_MS`. |

Example: `PORT=4000 HOST=127.0.0.1 npm start`.

### Set `CONFIG_SECRET` before you deploy

Install URLs are encrypted under keys derived from `CONFIG_SECRET`. If it is unset, the
addon generates a **random secret at boot** and logs a warning — which means every install
URL it has ever issued stops working the next time the process restarts, and every user has
to reconfigure. Set it once, to a long random value, and keep it stable:

```bash
CONFIG_SECRET=$(openssl rand -base64 48)   # generate once, then store it in your platform config
```

**At least 32 bytes is required, not advised.** Every install URL carries ciphertext and a MAC,
which is everything an attacker needs to test candidate secrets offline. The keys are derived
with scrypt (N=32768, r=8) rather than a plain hash, so each guess costs roughly 80 ms and 32 MB
instead of being free — but that only buys time for a secret with real entropy behind it. With
`NODE_ENV=production` the addon **refuses to start** if `CONFIG_SECRET` is missing or shorter
than 32 bytes; without it, you get a warning and a running server, so local development and the
test suite still work.

Changing `CONFIG_SECRET` later invalidates all existing install URLs, as does bumping
`CONFIG_TOKEN_VERSION` in the source.

Also set `NODE_ENV=production` in deployment: it is what turns a missing or short
`CONFIG_SECRET` from a warning into a refusal to start. It no longer affects error responses —
the addon's own error handler returns a bare 400/500 and logs the stack server-side either way.

> **Upgrading from an earlier build:** tokens moved from `v2` to `v3` when the key derivation
> changed from SHA-256 to scrypt. Every install URL issued by a `v2` build stops working and
> each user has to visit `/configure` once more. Carrying `CONFIG_SECRET` across does *not*
> preserve them — the derivation itself changed.

## Endpoints

| Path | Purpose |
|---|---|
| `/` | Landing page with project overview and install CTA |
| `/health` | Health and readiness probe. `200 {"status":"ok"}` normally; `503 {"status":"shutting_down"}` once a shutdown signal has been received, so a load balancer drains this instance before it stops serving; `503 {"status":"stalled"}` if the event loop was blocked for more than a second since the previous probe. Every response also carries `eventLoopLagMs` (the peak since the last probe) and `eventLoopLagMeanMs`, which are worth scraping whatever the status: this server parses catalogs and relays video on the same thread that answers this route, so event-loop delay is how a busy instance actually degrades. The measurement window is reset on each read, so poll on a fixed interval. |
| `/configure` | HTML form to enter Xtream credentials and get an install link (includes disclaimer banner) |
| `/:config/configure` | The same form, opened by Stremio's **Configure** button on an installed addon. Prefills the server URL and username from the token; the password must be entered again |
| `/manifest.json` | Unconfigured Stremio manifest |
| `/:config/manifest.json` | Configured manifest with populated genres |
| `/:config/catalog/:type/:id/:extra?.json` | Catalog items |
| `/:config/meta/:type/:id.json` | Meta for a live channel, movie, or series |
| `/:config/stream/:type/:id.json` | Playable stream URLs |
| `/:config/proxy/:kind/:file` | Relays movie, episode and live bytes from the provider (see [Streaming](#streaming)) |
| `/:config/proxy/hls` | Relays the segments and keys of a proxied HLS playlist. Only follows targets this server signed |

## How install URLs work

When you configure, the addon encrypts `{ serverUrl, username, password }` into a token that
becomes the first path segment of every request:

```
stremio://your-host/<config-token>/manifest.json
```

The token is a five-part `v3.iv.tag.ciphertext.mac` string: the credentials are encrypted with
AES-256-GCM under a random per-token IV, then the whole body is signed with a separate HMAC key
(encrypt-then-MAC). Both keys are derived from `CONFIG_SECRET` with scrypt, under different
per-purpose labels so they stay independent; the keys protecting HLS links come from a third
derivation, so those two purposes share no key material. A token that fails its MAC check, its
GCM tag, or its version prefix is rejected, and the route degrades to empty results rather than
an error — Stremio surfaces raw errors to the user.

- No server-side database — every request carries the config in its URL.
- Multiple users can share the same deployed instance without interfering.
- A token does not give its password back: reconfiguring from one prefills the server URL and
  username, but asks for the password again. Tokens are still **bearer credentials**: anyone
  with the install URL can stream through your instance using your provider account. Treat it
  like a password.
- Tokens are only decryptable by the instance that issued them. Move to a new host and you must
  carry `CONFIG_SECRET` across, or reissue every install URL.

## Streaming

Nothing is handed to Stremio as a provider URL. Xtream providers 302-redirect to a CDN URL
carrying a token that expires in about a minute, so streams are served as
`/:config/proxy/:kind/:file` URLs on this server, and each range request re-resolves the origin
to get a fresh token.

Live TV goes through the proxy for a second reason: the provider's live URL embeds the account
username and password in its path. Returning it directly — as this addon did before — put the
credentials in the player's logs, and on the wire in cleartext for the http-only providers that
are the norm. Both formats are still offered:

- **`.ts`** relays byte-for-byte, since a transport stream is just a body.
- **`.m3u8`** cannot be relayed unchanged. An HLS playlist is a list of further URLs, and an
  Xtream one names its segments by absolute URLs that carry the same credentials, so passing the
  body through would move the disclosure from the URL into the body. The playlist is instead
  rewritten: every segment, key and variant URI is replaced with a `/:config/proxy/hls` link.
  Those links carry their target encrypted and signed under their own keys, so the route cannot
  be used to fetch a URL of the caller's choosing, and the provider URL inside — which for many
  panels holds the account's username and password — is not readable from the link. That matters
  because query strings end up in player logs, in Stremio's history and in reverse-proxy access
  logs. Upgrading to this version invalidates HLS links minted by an older one; a player simply
  reloads the playlist, which is re-minted on every fetch, so nothing needs reissuing.
- Nested playlists — the variant playlists a master names — are rewritten in turn, and are
  recognised from the master's own structure rather than from the content type the provider
  returns, which is commonly `text/plain` for a playlist. A target expected to be a playlist
  whose body turns out not to be one is answered `502` rather than relayed, since the lines that
  would go out are the provider's own credential-bearing URLs.

The practical consequence is that **all streaming bandwidth flows through your host**, live
included, which drives both platform choice and cost. A single 1080p stream is roughly 5-10 Mbps
sustained in *and* out. Platforms that meter egress, or that cap request duration, are a poor fit.
Live is the heavier case, because a channel left on relays continuously rather than for the
length of a file.

## Features

### Catalogs

| Type | Catalogs | Sort modes |
|---|---|---|
| **Live TV** | 1 | by category (as Stremio "genre") |
| **XT-Movies** | 3 + Search | Popular (rating), New (recently added), Featured (day-seeded shuffle) |
| **XT-Series** | 3 + Search | Popular, New, Featured |

Each per-genre catalog supports genre filtering and pagination (100 items/page). Searching is done through the two **Search** catalogs, which hook into Stremio's global search and query across all categories.

### Meta & Streams

- **Live TV** — returns both HLS (`.m3u8`) and MPEG-TS (`.ts`) stream options, both proxied.
- **Movies** — single proxied stream URL with the correct container extension.
- **Series** — full episode list grouped by season; each episode resolves to a proxied stream URL. Retries `get_series_info` up to 3 times.

All three route through this server rather than the provider, so the account credentials never
reach the player — see [Streaming](#streaming).

## Deployment

Plain Node.js HTTP server with no persistence. Works on any platform that can run Node 20.18.1+
(the floor comes from `undici`, which supplies the connection agent that pins outbound requests to
the addresses the SSRF guard vetted). The full test suite passes on Node 20.18.1, 22 and 24. Don't
move the `undici` dependency to version 8 on its own: undici 8 needs Node 22.19+, and its connection
agent fails every request with the `fetch` that Node 22 and 24 bundle. It deploys to:

- **Railway / Render / Fly.io** — push the repo, set the start command to `npm start`.
- **VPS** — `npm ci --omit=dev && pm2 start index.js --name xtremio`.
- **Behind a reverse proxy (nginx, Caddy, Traefik)** — set `TRUST_PROXY` to the number of proxies in front (`true` for one), so client addresses and forwarded headers are read from what your proxy wrote rather than from what the client sent, and **set `PUBLIC_URL`** so install links never depend on a request header at all.

Set `CONFIG_SECRET` and `NODE_ENV=production` on any of these — see [Environment variables](#environment-variables).

### Running a public instance

An instance anyone can reach, where anyone can configure their own provider, needs more than the defaults:

- **Serve it over HTTPS.** The configure form posts provider passwords, and every install URL carries one, encrypted. Set `PUBLIC_URL` to the `https://` address, and `TRUST_PROXY` to match your proxies.
- **Keep install URLs out of access logs.** The first path segment of every addon request is the user's install token, a bearer credential for their provider account. The addon's own logs redact it; your reverse proxy's do not. With nginx, for example:

  ```nginx
  map $request_uri $xtremio_uri {
      ~^/[^/]+/(?<rest>.*)$  /<token>/$rest;
      default                $request_uri;
  }
  log_format xtremio '$remote_addr [$time_local] "$request_method $xtremio_uri" $status $body_bytes_sent';
  access_log /var/log/nginx/xtremio.log xtremio;
  ```

  The `/proxy/hls` query strings left in the log are bound to the redacted token and useless without it.
- **Size the relay caps to your bandwidth.** Every stream flows through the server, roughly 5-10 Mbps in *and* out per 1080p viewer. `PROXY_MAX_CONCURRENT_TOTAL` bounds the whole instance and `PROXY_MAX_CONCURRENT_PER_CLIENT` bounds one address. Together they are what stop someone relaying arbitrary downloads through a panel of their own, because `ALLOWED_PANEL_HOSTS` has to stay empty when users bring their own providers. If you only mean to serve particular providers, set that list instead: it closes the relay outright.
- **Size memory with `CACHE_MAX_MB`**, and allow for the transient cost of `MAX_UPSTREAM_MB` on top of it.
- **Keep `CONFIG_SECRET` safe and backed up.** Losing it breaks every install; leaking it lets anyone holding an install URL decrypt that user's provider password. Rotate it by moving the old value to `CONFIG_SECRET_PREVIOUS` and setting a new `CONFIG_SECRET`.
- **Several instances** behind a load balancer work if they share `CONFIG_SECRET`. Caches and relay caps are per instance, so divide the caps between them.
- **Content complaints come to you.** Relayed streams leave from your server's address, so check your host's acceptable-use terms for proxied IPTV traffic before you launch.

## Project structure

```
.
├── index.js        Express app: the routes, in registration order, and the bootstrap
├── src/            Modules index.js re-exports, so requiring index.js gets everything
│   ├── helpers.js          URL, id and value coercions
│   ├── config-token.js     Install-token crypto and the CONFIG_SECRET policy
│   ├── panel-allowlist.js  Which Xtream panels this instance will serve
│   ├── manifest.js         The manifest, built per account from its categories
│   ├── lifecycle.js        Socket timeouts, drain flag, graceful shutdown
│   ├── html.js             escapeHtml, shared by both pages
│   ├── net/                SSRF guard, private-IP ranges, DNS pinning, safeFetch
│   ├── upstream/           Capped body reading and byte weighing
│   ├── cache/              BoundedMap, the shared budget, cache-aside primitives
│   ├── xtream/             One panel call, and every cache and getter over it
│   ├── catalog/            Catalog kinds, ids, ordering, filtering, the view memo
│   ├── hls/                Playlist signing, encryption and rewriting
│   ├── proxy/              The shared relay, HLS target mapper, concurrency caps
│   ├── configure/          Credential validation and scheme handling
│   ├── routes/             Request identity, base URL, extras and cache hints
│   └── pages/              The /configure and landing pages
├── test/           Unit tests — node:test, run with `npm test`
├── package.json
├── README.md
└── LICENSE
```

## Troubleshooting

- **"No streams available"** on an episode — check server logs for `[stream] ...` and `[getSeriesInfo] ... failed`. Usually a specific series triggers an Xtream error; retry resolves most cases. A series that fails all 3 attempts is remembered as broken for 5 minutes (logged as `failed recently; skipping 3 retries`) so it stops costing a retry storm on every request — if you have just fixed things upstream, wait out that window or lower `SERIES_INFO_NEGATIVE_TTL_MS`.
- **Catalogs show no genres** after configuring — your Xtream provider may be blocking category calls. Those catalogs are still advertised, just without the genre filter, and opening one shows the full list for that kind instead of a genre-filtered slice. Search and pagination keep working. Failed category lookups are only cached for 60 seconds (successful ones for 30 minutes), so this clears itself within about a minute.
- **Search or a genre shelf is briefly empty** — the provider answered with an empty list that it later filled, which real providers do transiently. An empty full-catalog answer is logged as `[getStreams] get_vod_streams returned an empty list`; genre shelves fall back to per-category fetches meanwhile, but search has nothing to look through. Empty answers are cached for only 60 seconds and are never marked cacheable for Stremio, so both recover within about a minute. If search stays empty for longer, the provider is refusing the full-catalog request outright.
- **Every install URL broke after a restart or redeploy** — `CONFIG_SECRET` was not set, so the addon generated a new random one at boot and can no longer decrypt tokens issued under the old key. See [Set `CONFIG_SECRET` before you deploy](#set-config_secret-before-you-deploy). Users must reconfigure once; setting it prevents a recurrence.
- **A live channel fails with "playlist target refused"** — the channel's playlist named a host that is neither your panel nor the origin the playlist came from, so the addon refused it rather than passing the provider's own credential-bearing URLs to the player. The server log names the host; if your provider legitimately uses it, add it to `HLS_TARGET_ALLOWED_HOSTS`. The same answer covers a playlist naming more hosts than `MAX_PLAYLIST_ORIGINS`.
- **Port already in use** — set `PORT=3001` (or any free port) before `npm start`.
- **"Too many attempts" on the configure page** — you hit the `POST /configure` rate limit (10 per minute by default). Wait out the window shown in the message, or raise `CONFIGURE_RATE_LIMIT`. If it fires for unrelated users, you are behind a proxy and need `TRUST_PROXY=true` so they are counted separately.
- **"Cannot reach that server"** — the client-facing message is deliberately identical for a bad hostname, a closed port, and a blocked private address, so the page cannot be used to scan hosts. Check the server log for the actual cause.
- **"Connected over http, not https"** — you entered an `https://` URL but the addon ended up on plain http, either because the https connection failed or because your provider's own `server_info` names http. That choice is saved into the install link, so your Xtream username and password are sent in cleartext on every request. If the provider does support https, correct the URL and configure again to get a new link; the old one keeps using http.
- **Premature episode auto-advance** — caused by Stremio's player with direct Xtream streams. Disable "Play next episode automatically" in Stremio settings, or use Stremio Desktop (better MKV handling than web).

## License

Source is publicly viewable but **not licensed for use without permission**. See [`LICENSE`](./LICENSE).