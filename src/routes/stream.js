// GET /:config/stream/:type/:id.json
//
// The "Play" buttons for one item. Every URL handed out here points back at this
// server's own /proxy routes, never at the provider directly: the provider's
// URLs carry the account's username and password in their path, and the proxy
// is what keeps those off the player.
//
// The one thing this route needs from the provider is the file's container
// (mp4, mkv, ...), which becomes the proxy URL's extension. When the provider
// does not say, mp4 is guessed — and a guessed answer is not cached.
const express = require('express');

const { decodeConfig } = require('../config/token.js');
const {
    getPrefixedNumericId,
    parseEpisodeId,
    typeMatchesId,
    statedContainerExt,
    normalizeContainerExt,
    isNotWebReady
} = require('../helpers.js');
const { LOG_REQUESTS } = require('../xtream/client.js');
const { getSeriesInfo, getVodInfo, warmVodItem } = require('../xtream/data.js');
const { getBaseUrl } = require('../http/request.js');
const { withCacheHints } = require('../http/extras.js');
const { isProgrammingError, logRouteError } = require('../http/errors.js');

const router = express.Router();

router.get('/:config/stream/:type/:id.json', async (req, res) => {
    // Failed answers must not be cached; see the catalog route.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ streams: [] });
    const { id, type } = req.params;
    if (LOG_REQUESTS) console.log(`[stream] type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);

    if (!typeMatchesId(type, id)) {
        console.warn(`[stream] type/id mismatch: type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);
        return res.status(404).json({ streams: [] });
    }

    // Every stream URL is built on this prefix, which ends in `/proxy`.
    const proxyBase = `${getBaseUrl(req)}/${req.params.config}/proxy`;

    try {
        // The async senders use `return await`, not `return`: without the
        // await, a rejection would skip this try/catch.
        if (id.startsWith('xtremio_live_')) return sendLiveStreams(res, id, proxyBase);
        if (id.startsWith('xtremio_movie_')) return await sendMovieStream(res, cfg, id, proxyBase);
        if (id.startsWith('xtremio_episode_')) return await sendEpisodeStream(res, cfg, id, proxyBase);
        res.json({ streams: [] });
    } catch (e) {
        logRouteError('stream', e);
        res.json({ streams: [] });
    }
});

// One entry in Stremio's `streams` array.
function playableStream(url, title, ext, bingeGroup) {
    return {
        url,
        title,
        behaviorHints: {
            notWebReady: isNotWebReady(url, ext),
            bingeGroup
        }
    };
}

// --- Live TV ----------------------------------------------------------------

// Two variants of the same channel, so the user can pick whichever format their
// player handles. No provider call is needed: the URLs are fixed.
function sendLiveStreams(res, id, proxyBase) {
    const streamId = getPrefixedNumericId(id, 'xtremio_live_');
    if (!streamId) return res.status(400).json({ streams: [] });

    const variants = [
        { ext: 'm3u8', title: 'HLS' },
        { ext: 'ts', title: 'MPEG-TS' }
    ];
    return res.json({
        streams: variants.map(({ ext, title }) =>
            playableStream(`${proxyBase}/live/${streamId}.${ext}`, title, ext, `xtremio-live-${ext}`)),
        ...withCacheHints(res, 3600)
    });
}

// --- Movies -----------------------------------------------------------------

async function sendMovieStream(res, cfg, id, proxyBase) {
    const streamId = getPrefixedNumericId(id, 'xtremio_movie_');
    if (!streamId) return res.status(400).json({ streams: [] });

    // get_vod_info is where the container is normally found. If that call fails,
    // the movie's entry in the cached catalog list usually names it too, so a
    // failed call need not mean "no streams".
    let info = null;
    try {
        info = await getVodInfo(cfg, streamId);
    } catch (e) {
        if (isProgrammingError(e) || !warmVodItem(cfg, streamId)) throw e;
        console.warn(`[stream] get_vod_info failed for movie ${streamId} (${e.message}); using the catalog item's container`);
    }
    let rawExt = info?.movie_data?.container_extension;
    let fromList = false;
    if (statedContainerExt(rawExt) === null) {
        const listExt = warmVodItem(cfg, streamId)?.container_extension;
        if (statedContainerExt(listExt) !== null) {
            rawExt = listExt;
            fromList = true;
        }
    }
    const ext = normalizeContainerExt(rawExt);
    const extStated = statedContainerExt(rawExt) !== null;

    // Cacheable only when get_vod_info itself named the container — not when
    // mp4 was guessed, and not when the catalog list stood in for it.
    const cacheable = extStated && !fromList && info;
    return res.json({
        streams: [
            playableStream(`${proxyBase}/movie/${streamId}.${ext}`, '▶ Play', ext, `xtremio-movie-${ext}`)
        ],
        ...(cacheable ? withCacheHints(res, 3600) : {})
    });
}

// --- Series episodes --------------------------------------------------------

async function sendEpisodeStream(res, cfg, id, proxyBase) {
    // Format: xtremio_episode_{seriesId}:{season}:{episodeId}
    const parsed = parseEpisodeId(id);
    if (!parsed) return res.status(400).json({ streams: [] });
    const { seriesId, seasonNum, episodeId } = parsed;

    const info = await getSeriesInfo(cfg, seriesId);
    const seasonEpisodes = (info?.episodes ?? {})[seasonNum];
    const episode = Array.isArray(seasonEpisodes)
        ? seasonEpisodes.find(e => String(e.id) === episodeId) || null
        : null;

    const rawExt = episode?.container_extension;
    // Not cached when guessed, for the same reason as the movie branch.
    const extStated = statedContainerExt(rawExt) !== null;
    if (!extStated) {
        console.warn(`[stream] episode ${episodeId} is missing from series ${seriesId} info or names no container; defaulting to mp4`);
    }
    const ext = normalizeContainerExt(rawExt);

    return res.json({
        streams: [
            playableStream(`${proxyBase}/series/${episodeId}.${ext}`, '▶ Play', ext, `xtremio-series-${seriesId}-${ext}`)
        ],
        ...(extStated ? withCacheHints(res, 3600) : {})
    });
}

module.exports = { router };
