// GET /:config/meta/:type/:id.json
//
// The details page for one item: a live channel, a movie, or a series with its
// list of episodes. The id says which kind it is (`xtremio_live_123`,
// `xtremio_movie_123`, `xtremio_series_123`), and each kind has its own
// send*Meta function below.
//
// The build*Meta functions only reshape provider JSON into Stremio's meta
// format. They do no I/O, so they are easy to read and to test on their own.
const express = require('express');

const { decodeConfig } = require('../config/token.js');
const {
    causeSuffix,
    isNumericId,
    getPrefixedNumericId,
    typeMatchesId,
    toIsoDate,
    titleOf,
    ratingOf,
    splitList,
    youtubeTrailers,
    pickBackdrop
} = require('../helpers.js');
const { LOG_REQUESTS } = require('../xtream/client.js');
const {
    findStreamById,
    getAllLiveStreams,
    parseYear,
    getSeriesInfo,
    getVodInfo,
    warmVodItem
} = require('../xtream/data.js');
const { withCacheHints } = require('../http/extras.js');
const { isProgrammingError, logRouteError } = require('../http/errors.js');

const router = express.Router();

router.get('/:config/meta/:type/:id.json', async (req, res) => {
    // Failed answers must not be cached; see the catalog route.
    res.setHeader('Cache-Control', 'no-store');
    const cfg = decodeConfig(req.params.config);
    if (!cfg) return res.json({ meta: null });
    const { id, type } = req.params;
    if (LOG_REQUESTS) console.log(`[meta] type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);

    if (!typeMatchesId(type, id)) {
        console.warn(`[meta] type/id mismatch: type=${JSON.stringify(type)} id=${JSON.stringify(id)}`);
        return res.status(404).json({ meta: null });
    }

    try {
        // `return await`, not `return`: without the await, a rejection would
        // skip this try/catch.
        if (id.startsWith('xtremio_live_')) return await sendLiveMeta(res, cfg, id);
        if (id.startsWith('xtremio_movie_')) return await sendMovieMeta(res, cfg, id);
        if (id.startsWith('xtremio_series_')) return await sendSeriesMeta(res, cfg, id);
        res.json({ meta: null });
    } catch (e) {
        logRouteError('meta', e);
        res.json({ meta: null });
    }
});

// --- Live TV ----------------------------------------------------------------

async function sendLiveMeta(res, cfg, id) {
    const streamId = getPrefixedNumericId(id, 'xtremio_live_');
    if (!streamId) return res.status(400).json({ meta: null });

    const channel = findStreamById(await getAllLiveStreams(cfg), streamId);
    if (!channel) return res.json({ meta: null });
    return res.json({ meta: buildLiveMeta(channel), ...withCacheHints(res, 300) });
}

function buildLiveMeta(channel) {
    return {
        id: `xtremio_live_${channel.stream_id}`,
        type: 'Live TV',
        name: titleOf(channel.name) || undefined,
        poster: channel.stream_icon || undefined,
        posterShape: 'square',
        genres: channel.category_name ? [channel.category_name] : [],
        description: titleOf(channel.name) || undefined
    };
}

// --- Movies -----------------------------------------------------------------

async function sendMovieMeta(res, cfg, id) {
    const streamId = getPrefixedNumericId(id, 'xtremio_movie_');
    if (!streamId) return res.status(400).json({ meta: null });

    let info;
    try {
        info = await getVodInfo(cfg, streamId);
    } catch (e) {
        // When get_vod_info fails, a movie the catalog lists still gets a page,
        // built from the name and poster in the cached catalog list. It is
        // served without cache hints, so the full details replace it as soon as
        // get_vod_info answers again.
        const item = isProgrammingError(e) ? null : warmVodItem(cfg, streamId);
        if (!item) throw e;
        console.warn(`[meta] get_vod_info failed for movie ${streamId} (${e.message}); serving the catalog item`);
        return res.json({ meta: buildMovieMetaFromCatalogItem(streamId, item) });
    }
    return res.json({ meta: buildMovieMeta(streamId, info), ...withCacheHints(res, 86400) });
}

// "90" -> "90 min". Empty values stay undefined so the field is omitted.
function asMinutes(value) {
    return value ? `${value} min` : undefined;
}

function buildMovieMeta(streamId, info) {
    // Most panels nest the details under `info`; some put them at the root.
    const movie = info?.info ?? info ?? {};
    return {
        id: `xtremio_movie_${streamId}`,
        type: 'XT-Movies',
        name: titleOf(movie.name || movie.o_name || info?.movie_data?.name) || 'Unknown',
        poster: movie.cover_big || movie.movie_image || undefined,
        posterShape: 'poster',
        background: pickBackdrop(movie.backdrop_path),
        description: movie.plot || movie.description || undefined,
        releaseInfo: movie.releasedate ? String(movie.releasedate) : undefined,
        genres: splitList(movie.genre),
        runtime: asMinutes(movie.duration) || asMinutes(movie.episode_run_time),
        director: splitList(movie.director),
        cast: splitList(movie.cast),
        imdbRating: ratingOf(movie.rating),
        year: parseYear(movie.releasedate),
        country: movie.country || undefined,
        trailers: youtubeTrailers(movie.youtube_trailer)
    };
}

function buildMovieMetaFromCatalogItem(streamId, item) {
    return {
        id: `xtremio_movie_${streamId}`,
        type: 'XT-Movies',
        name: titleOf(item.name) || 'Unknown',
        poster: item.stream_icon || undefined,
        posterShape: 'poster',
        imdbRating: ratingOf(item.rating)
    };
}

// --- Series -----------------------------------------------------------------

async function sendSeriesMeta(res, cfg, id) {
    const seriesId = getPrefixedNumericId(id, 'xtremio_series_');
    if (!seriesId) return res.status(400).json({ meta: null });

    // getSeriesInfo already retries. If it still fails, carry on with nothing:
    // the check below turns that into `meta: null`.
    let info = null;
    try {
        info = await getSeriesInfo(cfg, seriesId);
    } catch (e) {
        console.warn(`[meta] getSeriesInfo(${seriesId}) failed after retries: ${e.message}${causeSuffix(e)}`);
    }
    const series = info?.info ?? info ?? {};
    const videos = buildEpisodeVideos(seriesId, info?.episodes ?? {});

    // Must match isUsableSeriesInfo in src/xtream/data.js exactly, or a payload
    // one of them accepts and the other rejects gets cached.
    const hasContent = Boolean(series.name || videos.length);
    if (!hasContent) {
        console.warn(`[meta] no usable data for series ${seriesId}`);
        return res.json({ meta: null });
    }
    return res.json({ meta: buildSeriesMeta(seriesId, series, videos), ...withCacheHints(res, 3600) });
}

function buildSeriesMeta(seriesId, series, videos) {
    return {
        id: `xtremio_series_${seriesId}`,
        type: 'series',
        name: titleOf(series.name) || 'Unknown',
        poster: series.cover || undefined,
        posterShape: 'poster',
        background: pickBackdrop(series.backdrop_path),
        description: series.plot || undefined,
        releaseInfo: series.releaseDate ? String(series.releaseDate) : undefined,
        genres: splitList(series.genre),
        runtime: asMinutes(series.episode_run_time),
        director: splitList(series.director),
        cast: splitList(series.cast),
        imdbRating: ratingOf(series.rating),
        year: parseYear(series.releaseDate),
        videos
    };
}

// The provider's `episodes` object is `{ "<season>": [episode, ...] }`. Each
// episode becomes one Stremio "video", whose id the stream route later parses
// back into series, season and episode.
function buildEpisodeVideos(seriesId, episodes) {
    const videos = [];
    let skipped = 0;
    for (const [seasonNum, eps] of Object.entries(episodes)) {
        if (!Array.isArray(eps)) continue;
        // parseEpisodeId requires all three parts of the id to be numeric, so
        // an episode with a non-numeric season or id would show in the UI and
        // then fail when played. Drop it here instead.
        if (!isNumericId(seasonNum)) {
            skipped += eps.length;
            continue;
        }
        for (const ep of eps) {
            if (!isNumericId(ep?.id)) {
                skipped++;
                continue;
            }
            // Episode 0 is real (specials, pilots); only a value that will not
            // parse falls back to 1.
            const parsedEpisode = parseInt(ep.episode_num);
            const episodeNum = Number.isInteger(parsedEpisode) ? parsedEpisode : 1;
            videos.push({
                id: `xtremio_episode_${seriesId}:${seasonNum}:${ep.id}`,
                title: titleOf(ep.title) || `Episode ${episodeNum}`,
                season: parseInt(seasonNum),
                episode: episodeNum,
                // Left out when unknown, never defaulted: Stremio renders
                // whatever date it is given, so a fake one would show as 1970.
                released: toIsoDate(ep.info?.releasedate) || undefined,
                overview: ep.info?.plot || undefined,
                thumbnail: ep.info?.movie_image || undefined
            });
        }
    }
    if (skipped) {
        console.warn(`[meta] series ${seriesId}: skipped ${skipped} episode(s) with non-numeric season/episode ids`);
    }
    return videos;
}

module.exports = { router };
