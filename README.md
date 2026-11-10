# xTremio — Stremio addon for Xtream Codes

xTremio lets you watch an [Xtream Codes](https://en.wikipedia.org/wiki/Xtream_Codes) IPTV
subscription in [Stremio](https://www.stremio.com/). It adds three sections to Stremio:
**Live TV**, **Movies** and **Series**.

You host it yourself. It has no database: each user's login details are encrypted into their
own install link. One running copy can serve many users, each with their own link.

**Contents**

- [Run it on your computer](#run-it-on-your-computer)
- [Install it in Stremio](#install-it-in-stremio)
- [Put it on a server](#put-it-on-a-server)
- [Settings](#settings)
- [What you get](#what-you-get)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Working on the code](#working-on-the-code)

---

## Run it on your computer

There are two ways. Both give you the same addon.

| Option | Choose it if |
|---|---|
| [Node](#option-1-node) | You want to try it quickly, or change the code |
| [Docker](#option-2-docker) | You don't want to install Node, or you will run it on a server |

First, download the code:

```bash
git clone https://github.com/izemhsn/xTremio-stremio-addon.git
cd xTremio-stremio-addon
```

### Option 1: Node

You need [Node](https://nodejs.org/) 22 or newer. Check your version with `node --version`.

1. Install the dependencies:

   ```bash
   npm install
   ```

2. Start the addon:

   ```bash
   npm start
   ```

3. Open <http://localhost:3000/configure>, then follow
   [Install it in Stremio](#install-it-in-stremio).

To stop it, press **Ctrl + C**.

Other useful commands:

| Command | What it does |
|---|---|
| `npm run dev` | Starts the addon and restarts it every time you save a file |
| `npm test` | Runs the tests once |
| `npm run test:watch` | Runs the tests again every time you save a file |

> **Your install links stop working after a restart.** Without a
> [secret](#what-is-config_secret), the addon makes a new random one every time it starts.
> That is fine for a quick try. To keep your links working:
>
> 1. Create a `.env` file with a secret (steps 1 and 2 of [Option 2](#option-2-docker)).
> 2. Start the addon with this command instead of `npm start`:
>
>    ```bash
>    node --env-file=.env index.js
>    ```

### Option 2: Docker

You need [Docker](https://docs.docker.com/get-docker/), and it must be running. On Windows and
macOS, install Docker Desktop.

1. **Create your settings file** by copying the example:

   ```bash
   cp .env.example .env
   ```

   In Windows Command Prompt, use `copy .env.example .env` instead.

2. **Add a secret.** [Generate one](#generate-a-secret), open `.env`, and paste it right after
   `CONFIG_SECRET=`. Don't add spaces or quotes:

   ```
   CONFIG_SECRET=k3J9xPq...Q==
   ```

   Generate it **only once** and keep it. A new secret breaks every install link.

3. **Build the image and start the container:**

   ```bash
   docker build -t xtremio .
   docker run -d --name xtremio -p 3000:3000 --env-file .env --restart unless-stopped xtremio
   ```

4. Open <http://localhost:3000/configure>, then follow
   [Install it in Stremio](#install-it-in-stremio).

What the `docker run` options mean:

| Option | Meaning |
|---|---|
| `-d` | Run in the background |
| `--name xtremio` | Give the container a name, so other commands can use it |
| `-p 3000:3000` | Connect port 3000 on your computer to port 3000 in the container. To use another port, change only the first number: `-p 4000:3000` opens it on <http://localhost:4000> |
| `--env-file .env` | Load the settings from `.env` |
| `--restart unless-stopped` | Start again after a crash or a reboot, unless you stopped it yourself |

Everyday commands:

| To... | Run |
|---|---|
| See the logs | `docker logs -f xtremio` |
| Check that it is running | `docker ps` (shows `health: starting` for about 30 seconds, then `healthy`) |
| Stop it | `docker stop xtremio` |
| Start it again | `docker start xtremio` |

**After you change `.env` or update the code** (`git pull`), remove the container and run
step 3 again. `docker restart` is not enough, because Docker reads `.env` only when it creates
the container.

```bash
docker rm -f xtremio
```

**If the container keeps restarting**, run `docker logs xtremio`. The usual cause is a missing
or too short `CONFIG_SECRET`. The Docker image runs in production mode, and in production
mode the addon refuses to start without a valid secret.

**If the logs say `PUBLIC_URL is not set`**, you can ignore it on your own computer. On a
server, set it (see [Put it on a server](#put-it-on-a-server)).

**To skip the build**, use the ready-made image. One is published for each release after
v2.0.0, for regular PCs and servers (amd64) and for ARM boards such as the Raspberry Pi
(arm64). You don't need the code for this, only a `.env` file:

```bash
docker run -d --name xtremio -p 3000:3000 --env-file .env --restart unless-stopped ghcr.io/izemhsn/xtremio-stremio-addon:latest
```

### Generate a secret

Run whichever command works on your computer. It prints one long random line: that is your
secret.

| If you have | Run |
|---|---|
| Node (any terminal) | `node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"` |
| Windows PowerShell | `$b = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)` |
| Docker only | `docker run --rm node:24-alpine node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"` |
| macOS / Linux | `openssl rand -base64 48` |

---

## Install it in Stremio

1. Open <http://localhost:3000/configure>.
2. Enter your Xtream **server URL**, **username** and **password**.
3. Click **Save & Install**, then **Install in Stremio**.

Live TV, XT-Movies and XT-Series now appear in Stremio.

**Tips for the server URL:**

- Enter the address with its port, if it has one: `http://line.example.com:8080`, or just
  `line.example.com:8080`.
- Don't include a path like `/panel`. The addon ignores it and always talks to the root of the
  server, so a provider that only works under a path won't work.
- If you leave out `http://` or `https://`, the addon tries https first. If that fails, it
  uses http without telling you. Type `https://` if you never want http.

---

## Put it on a server

### Checklist

Most settings have good defaults. On a server, set these three:

1. **`CONFIG_SECRET`**: the key that encrypts install links. See
   [What is `CONFIG_SECRET`?](#what-is-config_secret)
2. **`NODE_ENV=production`**: with this, the addon refuses to start if the secret is missing
   or too short. Without it, the addon only prints a warning. (The Docker image already sets
   it.)
3. **`PUBLIC_URL` and `TRUST_PROXY`**, if a reverse proxy sits in front of the addon. A
   reverse proxy is a server such as nginx, Caddy or Traefik that receives requests first
   (and usually handles HTTPS) and then forwards them to the addon.
   - `PUBLIC_URL` is your public address, like `https://xtremio.example.com`. Install links
     are built from it. Without it, they are built from the request, which a client can fake.
   - `TRUST_PROXY` is how many proxies are in front (`true` means one). The addon then reads
     the client's real IP address from what your proxy wrote, not from what the client sent.

### What is `CONFIG_SECRET`?

Every install link is encrypted with a key made from this secret.

- **If you don't set it**, the addon makes a new random one each time it starts. Every install
  link then breaks on each restart, and every user has to configure again.
- **It must be at least 32 characters.** [Generate one](#generate-a-secret) once, then save it
  as `CONFIG_SECRET` in your host's settings (or in `.env`).
- **Back it up.** If you lose it, every install link breaks.
- **Keep it private.** Anyone who has it and an install link can read that user's provider
  password.

**Changing the secret.** A new secret makes all existing links stop working. To change it
without breaking everyone at once:

1. Move the old value to `CONFIG_SECRET_PREVIOUS` and put a new value in `CONFIG_SECRET`.
   Old links keep working, and new links use the new secret.
2. When someone uses an old link, the log says
   `an install URL sealed under CONFIG_SECRET_PREVIOUS was used` (once per run).
3. When that line stops appearing after restarts, remove `CONFIG_SECRET_PREVIOUS`.

### Where to host it

It is a normal Node web server with no database. It is tested on Node 22 and 24.

| Where | How |
|---|---|
| Railway / Render / Fly.io | Push the repo. Start command: `npm start` |
| A VPS (your own server) | `npm ci --omit=dev && pm2 start index.js --name xtremio` |
| A VPS with Docker | Follow [Option 2: Docker](#option-2-docker) |
| Behind nginx / Caddy / Traefik | Same as above, plus `PUBLIC_URL` and `TRUST_PROXY` |

Some platforms (Railway and Fly.io, for example) build the `Dockerfile` when they find one,
instead of running `npm start`. The image already sets `NODE_ENV=production`, so set
`CONFIG_SECRET` before the first deploy, or it won't start.

> **Bandwidth warning:** every stream goes through your server. A 1080p viewer uses roughly
> 5–10 Mbps coming in *and* 5–10 Mbps going out, and a live channel keeps going for as long as
> someone watches. Hosts that charge for outgoing traffic, or that cut long requests, are a
> poor fit.

<details>
<summary><b>Extra steps if anyone on the internet can use your server</b></summary>

- **Use HTTPS.** The configure form sends provider passwords.
- **Keep install links out of your proxy's logs.** The first part of every addon URL is the
  user's encrypted login, so treat it like a password. `/configure` can also receive it as
  `?config=`. The addon hides both in its own logs, but nginx doesn't. This nginx setting
  logs the URL with that part replaced by `<token>`, and without the `?...` part:

  ```nginx
  map $uri $xtremio_uri {
      ~^/[^/]+/(?<rest>.*)$  /<token>/$rest;
      default                $uri;
  }
  log_format xtremio '$remote_addr [$time_local] "$request_method $xtremio_uri" $status $body_bytes_sent';
  access_log /var/log/nginx/xtremio.log xtremio;
  ```

- **Limit the number of streams** to what your bandwidth can handle:
  `PROXY_MAX_CONCURRENT_TOTAL` for the whole server, `PROXY_MAX_CONCURRENT_PER_CLIENT` for
  one IP address. Without limits, someone could set up their own fake provider and use your
  server to download anything. If you only want to serve specific providers, set
  `ALLOWED_PANEL_HOSTS` instead. That blocks every other provider.
- **Plan memory**: `CACHE_MAX_MB`, plus up to `MAX_UPSTREAM_MB` on top of it.
- **Running several copies** behind a load balancer works if they all use the same
  `CONFIG_SECRET`. Each copy has its own cache and its own stream limits, so split the limits
  between them.
- **Complaints about content come to you**, because streams come from your server's address.
  Check your host's rules about IPTV traffic before you launch.

</details>

---

## Settings

All settings are environment variables. Put them in `.env`, or in your host's settings page.
All are optional, except `CONFIG_SECRET` in production.

To set one just for a single run: `PORT=4000 npm start` (in PowerShell:
`$env:PORT=4000; npm start`).

| Variable | Default | What it does |
|---|---|---|
| `CONFIG_SECRET` | random at each start | The key that encrypts install links and live-stream links. **Required in production.** At least 32 characters. |
| `NODE_ENV` | *(not set)* | Set to `production` on a server. The addon then refuses to start without a valid `CONFIG_SECRET`. |
| `PUBLIC_URL` | taken from each request | Your public address, like `https://xtremio.example.com`. Used to build install links. |
| `TRUST_PROXY` | `false` | How many reverse proxies are in front of the addon (`true` means one). |
| `PORT` | `3000` | The port the addon listens on. |
| `HOST` | `0.0.0.0` | The network address to listen on (`0.0.0.0` means all). |
| `ALLOWED_PANEL_HOSTS` | *(any provider)* | Comma-separated list of provider hostnames this server accepts. |
| `LOG_REQUESTS` | `false` | Set to `true` to log every meta and stream request, and every call to the provider. Errors are always logged. |
| `ALLOW_PRIVATE_NETWORKS` | `false` | Set to `true` to allow a provider on your local network (like `192.168.x.x`). **For development only:** it turns off the check that stops people using your server to reach private addresses. |

<details>
<summary><b>Advanced settings</b></summary>

Times are in milliseconds (1000 = 1 second).

**Secrets**

| Variable | Default | What it does |
|---|---|---|
| `XTREMIO_CONFIG_SECRET` | *(not set)* | Another name for `CONFIG_SECRET`. Used only when `CONFIG_SECRET` is not set. |
| `CONFIG_SECRET_PREVIOUS` | *(not set)* | Your old secret while you change to a new one. See [Changing the secret](#what-is-config_secret). |
| `HLS_SIGNATURE_TTL_MS` | `3600000` | How long a live-stream (HLS) link made by the addon stays valid. New links are made every time the player reloads the playlist. |

**Limits**

| Variable | Default | What it does |
|---|---|---|
| `CONFIGURE_RATE_LIMIT` | `10` | How many times one user can submit the configure form per time window. |
| `CONFIGURE_RATE_WINDOW_MS` | `60000` | Length of that time window. |
| `PROXY_MAX_CONCURRENT_PER_TOKEN` | `16` | Streams one install link can play at the same time. |
| `PROXY_MAX_CONCURRENT_PER_CLIENT` | `32` | Streams one IP address can play at the same time. |
| `PROXY_MAX_CONCURRENT_TOTAL` | `256` | Streams the whole server can play at the same time. |
| `MAX_UPSTREAM_MB` | `64` | Largest answer accepted from the provider (for example, a full movie list). |
| `MAX_PLAYLIST_ORIGINS` | `32` | Maximum number of different servers one live playlist may point to. |
| `HLS_TARGET_ALLOWED_HOSTS` | *(empty)* | Extra servers a live playlist may point to. See [Troubleshooting](#troubleshooting). |

**Cache**

The addon keeps the provider's answers in memory for 30 minutes, so it doesn't have to ask
the provider every time. When a limit is reached, the oldest entries are removed first.

| Variable | Default | What it does |
|---|---|---|
| `CACHE_MAX_MB` | `256` | Total memory that **all** caches together may use. |
| `CACHE_MAX_STREAM_MB` | `64` | Memory for full lists, separately for live channels, movies and series. |
| `CACHE_MAX_STREAM_ACCOUNTS` | `64` | How many accounts' full lists are kept, separately for each of the three. |
| `CACHE_MAX_ACCOUNTS` | `100` | How many accounts' category lists are kept. |
| `CACHE_MAX_SERIES_INFO` | `500` | How many series details are kept. |
| `CACHE_MAX_VOD_INFO` | `500` | How many movie details are kept. |
| `CACHE_MAX_CATEGORY_LISTS` | `100` | How many single-category lists are kept. |
| `CACHE_SWEEP_INTERVAL_MS` | `300000` | How often expired entries are cleaned up. At least 30 seconds. |
| `SERIES_INFO_NEGATIVE_TTL_MS` | `300000` | How long a series that keeps failing is skipped before trying again. |

**Timeouts**

| Variable | Default | What it does |
|---|---|---|
| `DNS_TIMEOUT_MS` | `5000` | Maximum time to look up the provider's address. |
| `DNS_SERVERS` | *(empty)* | DNS servers to use instead of the automatic ones, like `8.8.8.8,1.1.1.1`. Only needed if lookups fail. |
| `UPSTREAM_HEADER_TIMEOUT_MS` | `15000` | Maximum wait for the provider to start answering. |
| `UPSTREAM_IDLE_TIMEOUT_MS` | `15000` | Maximum pause in the middle of a provider's answer. |
| `UPSTREAM_BODY_TIMEOUT_MS` | `300000` | Maximum total time for one provider answer. |
| `PROXY_HEADER_TIMEOUT_MS` | `20000` | Maximum wait for a stream to start. |
| `PLAYLIST_BODY_TIMEOUT_MS` | `30000` | Maximum time to download a live playlist (`.m3u8`). |
| `PLAYLIST_REWRITE_TIMEOUT_MS` | `15000` | Maximum time to rewrite that playlist. |
| `KEEPALIVE_TIMEOUT_MS` | `65000` | How long an unused connection is kept open. |
| `HEADERS_TIMEOUT_MS` | `66000` | Maximum time for a client to send its request headers. |
| `REQUEST_TIMEOUT_MS` | `120000` | Maximum time for a client to send its whole request. |
| `SHUTDOWN_TIMEOUT_MS` | `10000` | When stopping, how long to wait for open requests to finish. |

**Other**

| Variable | Default | What it does |
|---|---|---|
| `PROXY_CORS` | `false` | Turns on CORS headers for stream URLs. Only needed if a player asks for them. |

</details>

---

## What you get

| Section | Catalogs | Sorted by |
|---|---|---|
| **Live TV** | 1 | Category (shown as "genre" in Stremio) |
| **XT-Movies** | 3 + Search | Popular (rating), New (recently added), Featured (random order that changes every week) |
| **XT-Series** | 3 + Search | Popular, New, Featured |

- Each page shows 100 items, and you can filter by genre.
- The two **Search** catalogs work with Stremio's search bar and search every category.
- **Live TV** channels come in two formats: HLS (`.m3u8`) and MPEG-TS (`.ts`). If one
  doesn't play, try the other.
- **Series** show every episode, grouped by season.

---

## How it works

### The install link

When you fill in the configure form, the addon encrypts your server URL, username and password
into one long code, called a **token**. The token is the first part of every addon URL:

```
stremio://your-host/<token>/manifest.json
```

The token is encrypted with AES-256-GCM and signed with HMAC. Both keys are made from
`CONFIG_SECRET` (using scrypt). This means:

- **No database.** Every request carries its own login details.
- **Many users, one server.** Each user has their own link, and links don't affect each other.
- **Treat the link like a password.** Anyone who has it can watch streams through your server
  with that provider account.
- **A link only works on the server that made it.** To move to a new host, take
  `CONFIG_SECRET` with you, or everyone must configure again.
- When you click **Configure** on an installed addon, the form fills in the server URL and
  username, but you have to type the password again. The addon never shows it back.

### Streaming

Stremio never gets a direct link to the provider, for two reasons:

1. Providers send players to temporary links that expire after about a minute.
2. Provider links contain your **username and password**. They would end up in player logs,
   and many providers only use http, so they would travel unencrypted.

Instead, every stream goes through the addon (the addon acts as a **proxy**). Stream URLs look
like `/<token>/proxy/...` on your server:

- **Movies, episodes, and `.ts` live channels** are passed through as they are. Every request
  gets a fresh link from the provider.
- **HLS (`.m3u8`) live channels** need more work. An HLS playlist is a list of more links, and
  those links contain your password too. So the addon rewrites each link into a signed,
  encrypted link back to itself (`/proxy/hls`). If a link that should be a playlist turns
  out not to be one, the addon answers with error `502`.

### Endpoints

| URL | What it is |
|---|---|
| `/` | Home page |
| `/health` | Health check. Answers `200` with `"status":"ok"`, or `503` with `"shutting_down"` or `"stalled"` (the server was blocked for over 1 second). Also shows uptime and delay. |
| `/configure` | The configure form |
| `/:config/configure` | The same form, opened by Stremio's **Configure** button |
| `/manifest.json` | Addon description before configuring |
| `/:config/manifest.json` | Addon description for one account, with its genres |
| `/:config/catalog/:type/:id/:extra?.json` | Catalog items |
| `/:config/meta/:type/:id.json` | Details of one channel, movie or series |
| `/:config/stream/:type/:id.json` | Stream links for one item |
| `/:config/proxy/:kind/:file` | Streams movies, episodes and live channels |
| `/:config/proxy/hls` | Streams the parts of a live HLS stream |

`:config` is the user's token.

---

## Troubleshooting

**Every install link stopped working after a restart**
`CONFIG_SECRET` wasn't set, so the addon made a new random one when it started, and it can't
read the old links anymore. [Set it](#what-is-config_secret). Everyone has to configure once
more, and then it won't happen again.

**"Cannot reach that server"**
The addon shows the same message for a wrong address, a closed port, and a blocked private
address. This is on purpose, so nobody can use the form to scan other servers. Check the
server log for the real reason, and make sure your URL has no path in it.

**"Connected over http, not https"**
You typed the address without `https://`. The https connection worked, but the provider said
its main address uses http, and your login worked there, so the link uses http. Your password
is then sent unencrypted with every request. To stay on https, type the address starting with
`https://` and configure again to get a new link. The old link stays on http.

**"No streams available" on an episode**
Usually the provider has a problem with that one series, and trying again fixes it. If a
series fails 3 times in a row, the addon skips it for 5 minutes, so it doesn't keep asking
the provider. Look for `[stream]` and `[getSeriesInfo] ... failed` in the log.

**Catalogs show no genres**
Your provider is blocking the request for categories. Catalogs still work, just without genre
filters, and search and paging are not affected. The addon tries again after 60 seconds, so
it usually fixes itself within a minute.

**Search or a catalog is empty for a moment**
The provider sent an empty list and filled it later, which some providers do. The addon tries
again after 60 seconds, so it fixes itself within about a minute. If search stays empty
longer, the provider is refusing to send its full list.

**A live channel fails with "playlist target refused"**
The channel's playlist points to a server that is neither your provider nor the playlist's
own server. The addon refuses it, so it doesn't send your provider's password-carrying links
somewhere unknown. The log shows that server's name. If your provider really uses it, add it
to `HLS_TARGET_ALLOWED_HOSTS`.

**"Too many attempts" on the configure page**
You hit the limit: 10 tries per minute by default. Wait a minute, or raise
`CONFIGURE_RATE_LIMIT`. If different users all get this message, you are behind a reverse
proxy and need to set `TRUST_PROXY`.

**"Port already in use"**
Another program uses port 3000. Use another port: `PORT=3001 npm start` (in PowerShell:
`$env:PORT=3001; npm start`). With Docker, change the first number in `-p`: `-p 3001:3000`.

**Episodes jump to the next one too early**
This is a Stremio player issue. Turn off "Play next episode automatically", or use Stremio
Desktop, which handles MKV files better than the web version.

---

## Working on the code

### Project structure

```
index.js            Starts the server (checks settings, listens, handles shutdown)
src/
  app.js            The Express app: middleware and every route, in order
  manifest.js       The addon description, built for each account from its categories
  lifecycle.js      Server timeouts and clean shutdown
  helpers.js        Small shared helpers: URLs, ids, value conversions

  routes/           One file per endpoint. Start here to follow a request
                    (catalog, meta, stream, proxy, configure, manifest, health)
  http/             Shared by the routes: CORS, errors, client IP and base URL,
                    catalog "extra" parsing, cache headers
  pages/            The HTML of the home and /configure pages

  config/           The install link: token encryption, CONFIG_SECRET rules,
                    allowed providers, login check, /configure rate limit
  xtream/           Talking to the Xtream provider, and caching its answers
  catalog/          Building catalogs: kinds, sorting, filtering, pages
  proxy/            Streaming through the addon, and rewriting HLS playlists
  net/              Safe outgoing requests: blocks private addresses, DNS, size limits
  cache/            Memory caches with size limits

test/               Tests (Vitest). Run them with `npm test`
  support/internals.js  Every module's exports in one place, for the tests

Dockerfile          How the Docker image is built
.github/workflows/
  ci-cd.yml         Runs the tests on every push and pull request,
                    and publishes the Docker image when you push a version tag
```

**How a request moves through the code:** `routes/` → `xtream/`, `catalog/` or `proxy/` →
`net/`. The folders in the bottom group of `src/` (`config/` to `cache/`) never import from
`routes/`.

### Releasing a new version

Bump the version and tag it in one step, then push both:

```bash
npm version minor        # or patch / major: updates package.json, commits, tags v2.1.0
git push --follow-tags
```

Don't create the tag by hand. The version in `package.json` is the one Stremio shows, so CI
refuses to publish when the tag and `package.json` disagree. When the tests pass, GitHub
publishes the Docker image to `ghcr.io/izemhsn/xtremio-stremio-addon`, tagged `v2.1.0` and
`latest`, for amd64 and arm64.

### Dependency note

Don't update `undici` to version 8 by itself. It needs Node 22.19 or newer, and it breaks every
request when used with the `fetch` built into Node 22 and 24.

---

## License

[MIT](./LICENSE). You can use, copy, change and share this code, as long as you keep the
copyright notice and license text.
