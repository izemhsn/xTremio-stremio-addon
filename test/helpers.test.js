// Pure helper functions — no network, no server.
process.env.CONFIG_SECRET = process.env.CONFIG_SECRET || 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const {
    escapeHtml,
    normalizeUrl,
    buildUrl,
    buildXtremioApiUrl,
    isNumericId,
    getPrefixedNumericId,
    parseEpisodeId,
    normalizeContainerExt,
    isNotWebReady,
    parseExtra,
    rawExtraSegment,
    parseYear,
    toIsoDate,
    splitList,
    pickBackdrop,
    isUsableSeriesInfo
} = require('../index.js');

test('escapeHtml neutralizes the characters that break out of attributes', () => {
    assert.strictEqual(escapeHtml('<script>'), '&lt;script&gt;');
    assert.strictEqual(escapeHtml('a"b'), 'a&quot;b');
    assert.strictEqual(escapeHtml("a'b"), 'a&#039;b');
    // Ampersand must be escaped first or the other entities get double-encoded.
    assert.strictEqual(escapeHtml('&lt;'), '&amp;lt;');
    assert.strictEqual(escapeHtml(null), '');
    assert.strictEqual(escapeHtml(undefined), '');
});

test('normalizeUrl adds a scheme and strips trailing slashes', () => {
    assert.strictEqual(normalizeUrl('example.com:8080'), 'http://example.com:8080');
    assert.strictEqual(normalizeUrl('http://example.com/'), 'http://example.com');
    assert.strictEqual(normalizeUrl('https://example.com///'), 'https://example.com');
    assert.strictEqual(normalizeUrl('  http://example.com  '), 'http://example.com');
    assert.throws(() => normalizeUrl(''), /serverUrl is required/);
    assert.throws(() => normalizeUrl(null), /serverUrl is required/);
});

test('buildUrl skips null and undefined params but keeps empty strings', () => {
    const url = buildUrl('http://example.com', '/player_api.php', {
        a: 'x', b: null, c: undefined, d: '', e: 0
    });
    assert.match(url, /a=x/);
    assert.ok(!url.includes('b='));
    assert.ok(!url.includes('c='));
    assert.match(url, /d=/);
    assert.match(url, /e=0/);
});

test('buildXtremioApiUrl encodes credentials containing URL metacharacters', () => {
    const url = buildXtremioApiUrl(
        { serverUrl: 'http://example.com', username: 'a&b=c', password: 'p?d#e' },
        'get_vod_streams'
    );
    const parsed = new URL(url);
    assert.strictEqual(parsed.searchParams.get('username'), 'a&b=c');
    assert.strictEqual(parsed.searchParams.get('password'), 'p?d#e');
    assert.strictEqual(parsed.searchParams.get('action'), 'get_vod_streams');
    assert.strictEqual(parsed.pathname, '/player_api.php');
});

test('isNumericId accepts only digit strings', () => {
    assert.ok(isNumericId('123'));
    assert.ok(isNumericId(456));
    assert.ok(!isNumericId('12a'));
    assert.ok(!isNumericId('-1'));
    assert.ok(!isNumericId('1.5'));
    assert.ok(!isNumericId(''));
    assert.ok(!isNumericId(null));
});

test('getPrefixedNumericId rejects anything non-numeric after the prefix', () => {
    assert.strictEqual(getPrefixedNumericId('xtremio_movie_42', 'xtremio_movie_'), '42');
    // Catalog ids share the series prefix and must not parse as an item id.
    assert.strictEqual(getPrefixedNumericId('xtremio_series_popular', 'xtremio_series_'), null);
    assert.strictEqual(getPrefixedNumericId('xtremio_movie_../etc', 'xtremio_movie_'), null);
    assert.strictEqual(getPrefixedNumericId('other_42', 'xtremio_movie_'), null);
    assert.strictEqual(getPrefixedNumericId(null, 'xtremio_movie_'), null);
});

test('parseEpisodeId requires exactly three numeric parts', () => {
    assert.deepStrictEqual(
        parseEpisodeId('xtremio_episode_10:2:305'),
        { seriesId: '10', seasonNum: '2', episodeId: '305' }
    );
    assert.strictEqual(parseEpisodeId('xtremio_episode_10:2'), null);
    assert.strictEqual(parseEpisodeId('xtremio_episode_10:2:305:9'), null);
    assert.strictEqual(parseEpisodeId('xtremio_episode_a:2:305'), null);
    assert.strictEqual(parseEpisodeId('xtremio_movie_10'), null);
    assert.strictEqual(parseEpisodeId(''), null);
});

test('normalizeContainerExt falls back to mp4 on anything not alphanumeric', () => {
    assert.strictEqual(normalizeContainerExt('mkv'), 'mkv');
    assert.strictEqual(normalizeContainerExt('  mp4  '), 'mp4');
    assert.strictEqual(normalizeContainerExt('../../etc/passwd'), 'mp4');
    assert.strictEqual(normalizeContainerExt('a.b'), 'mp4');
    assert.strictEqual(normalizeContainerExt(''), 'mp4');
    assert.strictEqual(normalizeContainerExt(undefined), 'mp4');
});

test('isNotWebReady is false only for https + mp4', () => {
    // Getting this wrong makes the player stop after ~1 min and Stremio
    // treats it as the stream ending.
    assert.strictEqual(isNotWebReady('https://x/y.mp4', 'mp4'), false);
    assert.strictEqual(isNotWebReady('http://x/y.mp4', 'mp4'), true);
    assert.strictEqual(isNotWebReady('https://x/y.mkv', 'mkv'), true);
    assert.strictEqual(isNotWebReady('https://x/y.mp4', 'MP4'), false);
});

test('parseExtra decodes the raw segment exactly once', () => {
    assert.deepStrictEqual(parseExtra('skip=100&genre=News'), { skip: '100', genre: 'News' });
    assert.deepStrictEqual(parseExtra('genre=News%20%26%20Sports'), { genre: 'News & Sports' });
    assert.deepStrictEqual(
        parseExtra('skip=100&genre=Kids%20%26%20Family'),
        { skip: '100', genre: 'Kids & Family' }
    );
    // A literal '%' in a search term used to throw URIError and surface as an
    // HTTP 500, so a part that will not decode is kept verbatim instead.
    assert.deepStrictEqual(parseExtra('search=100%'), { search: '100%' });
    assert.deepStrictEqual(parseExtra('skip=%zz'), { skip: '%zz' });
    // A value containing '=' keeps everything after the first separator.
    assert.deepStrictEqual(parseExtra('search=a=b'), { search: 'a=b' });
    assert.deepStrictEqual(parseExtra(''), {});
    assert.deepStrictEqual(parseExtra(undefined), {});
});

test("parseExtra keeps a '&' that belongs to a value, encoded or not", () => {
    // The bug this closes: the manifest advertises these genres verbatim from
    // category_name, and splitting on every '&' made both shelves unopenable.
    assert.deepStrictEqual(
        parseExtra('genre=%7CSLO%7C%20SLOVAKIA%20%26%20Czechia'),
        { genre: '|SLO| SLOVAKIA & Czechia' }
    );
    // Same value with the '&' sent raw rather than escaped. Pairs split only
    // before a declared key, so this survives too.
    assert.deepStrictEqual(parseExtra('genre=Kids & Family'), { genre: 'Kids & Family' });
    assert.deepStrictEqual(
        parseExtra('skip=100&genre=Kids & Family'),
        { skip: '100', genre: 'Kids & Family' }
    );
    assert.deepStrictEqual(
        parseExtra('genre=GLORY PPV & VIDEOLAND EVENT & BOXING &'),
        { genre: 'GLORY PPV & VIDEOLAND EVENT & BOXING &' }
    );
});

test("parseExtra leaves '+' alone", () => {
    // '+' is an ordinary character in a path segment, not a space. Parsing the
    // segment as a form body (URLSearchParams) would decode it to a space and
    // break every "CANAL+ SPORT" style category name — 17 of them on the account
    // this was tested against, against the 2 that the '&' handling repairs.
    assert.deepStrictEqual(parseExtra('genre=CANAL+%20SPORT'), { genre: 'CANAL+ SPORT' });
    assert.deepStrictEqual(
        parseExtra('genre=%7CFR%7C%20CANAL%2B%20SPORT'),
        { genre: '|FR| CANAL+ SPORT' }
    );
    assert.deepStrictEqual(parseExtra('search=rock+roll'), { search: 'rock+roll' });
});

test('parseExtra accepts a pair whose separators are escaped too', () => {
    // How much of the segment is escaped is the client's choice. Stremio itself
    // escapes only the value and leaves `genre=` literal, but a client that
    // escapes the whole pair must still parse, so '=' and '&' are matched in
    // both forms.
    assert.deepStrictEqual(parseExtra('search%3Dmatrix'), { search: 'matrix' });
    assert.deepStrictEqual(parseExtra('SEARCH%3Dmatrix'), { search: 'matrix' });
    assert.deepStrictEqual(
        parseExtra('skip%3D100%26genre%3DNews'),
        { skip: '100', genre: 'News' }
    );
});

test('rawExtraSegment reads the segment before Express decodes it', () => {
    const req = (originalUrl, extra) => ({ originalUrl, params: { extra } });

    assert.strictEqual(
        rawExtraSegment(req('/tok/catalog/Live%20TV/xtremio_live/genre=A%20%26%20B.json', 'genre=A & B')),
        'genre=A%20%26%20B'
    );
    // The route pattern without an :extra has nothing to parse.
    assert.strictEqual(
        rawExtraSegment(req('/tok/catalog/Live%20TV/xtremio_live.json', undefined)),
        undefined
    );
    // A query string is not part of the segment.
    assert.strictEqual(
        rawExtraSegment(req('/tok/catalog/XT-Movies/xtremio_movies_new/skip=100.json?x=1', 'skip=100')),
        'skip=100'
    );
    // An encoded '/' stays inside the segment rather than splitting it.
    assert.strictEqual(
        rawExtraSegment(req('/tok/catalog/Live%20TV/xtremio_live/genre=24%2F7.json', 'genre=24/7')),
        'genre=24%2F7'
    );
});

test('parseYear pulls the first 4-digit run, or undefined', () => {
    assert.strictEqual(parseYear('2019-05-01'), 2019);
    assert.strictEqual(parseYear('May 1998'), 1998);
    assert.strictEqual(parseYear('no year here'), undefined);
    assert.strictEqual(parseYear(''), undefined);
    assert.strictEqual(parseYear(null), undefined);
});

test('toIsoDate returns undefined rather than an Invalid Date', () => {
    assert.strictEqual(toIsoDate('2020-01-02'), '2020-01-02T00:00:00.000Z');
    assert.strictEqual(toIsoDate('not a date'), undefined);
    assert.strictEqual(toIsoDate(''), undefined);
    assert.strictEqual(toIsoDate(null), undefined);
});

test('splitList handles the string-or-array shapes providers return', () => {
    assert.deepStrictEqual(splitList('a, b ,c'), ['a', 'b', 'c']);
    assert.deepStrictEqual(splitList(['a', ' b ']), ['a', 'b']);
    assert.deepStrictEqual(splitList('a,,b'), ['a', 'b']);
    assert.deepStrictEqual(splitList(''), []);
    assert.deepStrictEqual(splitList(null), []);
});

test('pickBackdrop takes the first entry of an array form', () => {
    assert.strictEqual(pickBackdrop(['http://a', 'http://b']), 'http://a');
    assert.strictEqual(pickBackdrop('http://a'), 'http://a');
    assert.strictEqual(pickBackdrop([]), undefined);
    assert.strictEqual(pickBackdrop(null), undefined);
});

test('isUsableSeriesInfo accepts partial payloads but rejects empty ones', () => {
    assert.ok(isUsableSeriesInfo({ info: { name: 'Show' } }));
    assert.ok(isUsableSeriesInfo({ episodes: { 1: [{ id: '1' }] } }));
    assert.ok(!isUsableSeriesInfo({ info: {}, episodes: {} }));
    assert.ok(!isUsableSeriesInfo({}));
    assert.ok(!isUsableSeriesInfo(null));
    assert.ok(!isUsableSeriesInfo('string'));
});
