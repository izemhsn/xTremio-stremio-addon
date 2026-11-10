// Pure helper functions — no network, no server.
process.env.CONFIG_SECRET = process.env.CONFIG_SECRET || 'test-secret-for-unit-tests';

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
} = require('./support/internals.js');

test('escapeHtml neutralizes the characters that break out of attributes', () => {
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;');
    expect(escapeHtml('a"b')).toBe('a&quot;b');
    expect(escapeHtml("a'b")).toBe('a&#039;b');
    // Ampersand must be escaped first or the other entities get double-encoded.
    expect(escapeHtml('&lt;')).toBe('&amp;lt;');
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
});

test('normalizeUrl adds a scheme and strips trailing slashes', () => {
    expect(normalizeUrl('example.com:8080')).toBe('http://example.com:8080');
    expect(normalizeUrl('http://example.com/')).toBe('http://example.com');
    expect(normalizeUrl('https://example.com///')).toBe('https://example.com');
    expect(normalizeUrl('  http://example.com  ')).toBe('http://example.com');
    expect(() => normalizeUrl('')).toThrow(/serverUrl is required/);
    expect(() => normalizeUrl(null)).toThrow(/serverUrl is required/);
});

// Audit F1. A phone auto-capitalizes the first letter of a text field, so
// `Http://panel` reaches the server routinely. The scheme test was
// case-sensitive, so that counted as no scheme at all and got a second one
// prefixed: `http://Http://panel`, which /configure then tried to resolve as a
// host called `http` and reported as unreachable.
//
// The scheme is lowercased rather than merely matched case-insensitively,
// because schemeOf, the http -> https upgrade and describeDowngrade all compare
// it as a plain string. An `i` flag here alone would have let a typed `HTTPS://`
// count as http and be tried over http, which audit S7 forbids.
test('normalizeUrl lowercases a capitalized scheme instead of prefixing another', () => {
    expect(normalizeUrl('Http://example.com:8080')).toBe('http://example.com:8080');
    expect(normalizeUrl('HTTP://example.com')).toBe('http://example.com');
    expect(normalizeUrl('HTTPS://example.com')).toBe('https://example.com');
    expect(normalizeUrl('HtTpS://example.com//')).toBe('https://example.com');
    expect(normalizeUrl('  Https://example.com  ')).toBe('https://example.com');
    // Only the scheme. The host keeps its case here; URL parsing lowercases it,
    // and the path is case-sensitive and must not be touched.
    expect(normalizeUrl('HTTP://Example.COM/Path')).toBe('http://Example.COM/Path');
});

test('buildUrl skips null and undefined params but keeps empty strings', () => {
    const url = buildUrl('http://example.com', '/player_api.php', {
        a: 'x', b: null, c: undefined, d: '', e: 0
    });
    expect(url).toMatch(/a=x/);
    expect(url).not.toContain('b=');
    expect(url).not.toContain('c=');
    expect(url).toMatch(/d=/);
    expect(url).toMatch(/e=0/);
});

test('buildXtremioApiUrl encodes credentials containing URL metacharacters', () => {
    const url = buildXtremioApiUrl(
        { serverUrl: 'http://example.com', username: 'a&b=c', password: 'p?d#e' },
        'get_vod_streams'
    );
    const parsed = new URL(url);
    expect(parsed.searchParams.get('username')).toBe('a&b=c');
    expect(parsed.searchParams.get('password')).toBe('p?d#e');
    expect(parsed.searchParams.get('action')).toBe('get_vod_streams');
    expect(parsed.pathname).toBe('/player_api.php');
});

test('isNumericId accepts only digit strings', () => {
    expect(isNumericId('123')).toBeTruthy();
    expect(isNumericId(456)).toBeTruthy();
    expect(isNumericId('12a')).toBeFalsy();
    expect(isNumericId('-1')).toBeFalsy();
    expect(isNumericId('1.5')).toBeFalsy();
    expect(isNumericId('')).toBeFalsy();
    expect(isNumericId(null)).toBeFalsy();
});

test('getPrefixedNumericId rejects anything non-numeric after the prefix', () => {
    expect(getPrefixedNumericId('xtremio_movie_42', 'xtremio_movie_')).toBe('42');
    // Catalog ids share the series prefix and must not parse as an item id.
    expect(getPrefixedNumericId('xtremio_series_popular', 'xtremio_series_')).toBeNull();
    expect(getPrefixedNumericId('xtremio_movie_../etc', 'xtremio_movie_')).toBeNull();
    expect(getPrefixedNumericId('other_42', 'xtremio_movie_')).toBeNull();
    expect(getPrefixedNumericId(null, 'xtremio_movie_')).toBeNull();
});

test('parseEpisodeId requires exactly three numeric parts', () => {
    expect(parseEpisodeId('xtremio_episode_10:2:305')).toStrictEqual({ seriesId: '10', seasonNum: '2', episodeId: '305' });
    expect(parseEpisodeId('xtremio_episode_10:2')).toBeNull();
    expect(parseEpisodeId('xtremio_episode_10:2:305:9')).toBeNull();
    expect(parseEpisodeId('xtremio_episode_a:2:305')).toBeNull();
    expect(parseEpisodeId('xtremio_movie_10')).toBeNull();
    expect(parseEpisodeId('')).toBeNull();
});

test('normalizeContainerExt falls back to mp4 on anything not alphanumeric', () => {
    expect(normalizeContainerExt('mkv')).toBe('mkv');
    expect(normalizeContainerExt('  mp4  ')).toBe('mp4');
    expect(normalizeContainerExt('../../etc/passwd')).toBe('mp4');
    expect(normalizeContainerExt('a.b')).toBe('mp4');
    expect(normalizeContainerExt('')).toBe('mp4');
    expect(normalizeContainerExt(undefined)).toBe('mp4');
});

test('isNotWebReady is false only for https + mp4', () => {
    // Getting this wrong makes the player stop after ~1 min and Stremio
    // treats it as the stream ending.
    expect(isNotWebReady('https://x/y.mp4', 'mp4')).toBe(false);
    expect(isNotWebReady('http://x/y.mp4', 'mp4')).toBe(true);
    expect(isNotWebReady('https://x/y.mkv', 'mkv')).toBe(true);
    expect(isNotWebReady('https://x/y.mp4', 'MP4')).toBe(false);
});

test('parseExtra decodes the raw segment exactly once', () => {
    expect(parseExtra('skip=100&genre=News')).toStrictEqual({ skip: '100', genre: 'News' });
    expect(parseExtra('genre=News%20%26%20Sports')).toStrictEqual({ genre: 'News & Sports' });
    expect(parseExtra('skip=100&genre=Kids%20%26%20Family')).toStrictEqual({ skip: '100', genre: 'Kids & Family' });
    // A literal '%' in a search term used to throw URIError and surface as an
    // HTTP 500, so a part that will not decode is kept verbatim instead.
    expect(parseExtra('search=100%')).toStrictEqual({ search: '100%' });
    expect(parseExtra('skip=%zz')).toStrictEqual({ skip: '%zz' });
    // A value containing '=' keeps everything after the first separator.
    expect(parseExtra('search=a=b')).toStrictEqual({ search: 'a=b' });
    expect(parseExtra('')).toStrictEqual({});
    expect(parseExtra(undefined)).toStrictEqual({});
});

test("parseExtra keeps a '&' that belongs to a value, encoded or not", () => {
    // The bug this closes: the manifest advertises these genres verbatim from
    // category_name, and splitting on every '&' made both shelves unopenable.
    expect(parseExtra('genre=%7CSLO%7C%20SLOVAKIA%20%26%20Czechia')).toStrictEqual({ genre: '|SLO| SLOVAKIA & Czechia' });
    // Same value with the '&' sent raw rather than escaped. Pairs split only
    // before a declared key, so this survives too.
    expect(parseExtra('genre=Kids & Family')).toStrictEqual({ genre: 'Kids & Family' });
    expect(parseExtra('skip=100&genre=Kids & Family')).toStrictEqual({ skip: '100', genre: 'Kids & Family' });
    expect(parseExtra('genre=GLORY PPV & VIDEOLAND EVENT & BOXING &')).toStrictEqual({ genre: 'GLORY PPV & VIDEOLAND EVENT & BOXING &' });
});

test("parseExtra leaves '+' alone", () => {
    // '+' is an ordinary character in a path segment, not a space. Parsing the
    // segment as a form body (URLSearchParams) would decode it to a space and
    // break every "CANAL+ SPORT" style category name — 17 of them on the account
    // this was tested against, against the 2 that the '&' handling repairs.
    expect(parseExtra('genre=CANAL+%20SPORT')).toStrictEqual({ genre: 'CANAL+ SPORT' });
    expect(parseExtra('genre=%7CFR%7C%20CANAL%2B%20SPORT')).toStrictEqual({ genre: '|FR| CANAL+ SPORT' });
    expect(parseExtra('search=rock+roll')).toStrictEqual({ search: 'rock+roll' });
});

test('parseExtra accepts a pair whose separators are escaped too', () => {
    // How much of the segment is escaped is the client's choice. Stremio itself
    // escapes only the value and leaves `genre=` literal, but a client that
    // escapes the whole pair must still parse, so '=' and '&' are matched in
    // both forms.
    expect(parseExtra('search%3Dmatrix')).toStrictEqual({ search: 'matrix' });
    expect(parseExtra('SEARCH%3Dmatrix')).toStrictEqual({ search: 'matrix' });
    expect(parseExtra('skip%3D100%26genre%3DNews')).toStrictEqual({ skip: '100', genre: 'News' });
});

test('rawExtraSegment reads the segment before Express decodes it', () => {
    const req = (originalUrl, extra) => ({ originalUrl, params: { extra } });

    expect(
        rawExtraSegment(req('/tok/catalog/Live%20TV/xtremio_live/genre=A%20%26%20B.json', 'genre=A & B'))
    ).toBe('genre=A%20%26%20B');
    // The route pattern without an :extra has nothing to parse.
    expect(rawExtraSegment(req('/tok/catalog/Live%20TV/xtremio_live.json', undefined))).toBeUndefined();
    // A query string is not part of the segment.
    expect(
        rawExtraSegment(req('/tok/catalog/XT-Movies/xtremio_movies_new/skip=100.json?x=1', 'skip=100'))
    ).toBe('skip=100');
    // An encoded '/' stays inside the segment rather than splitting it.
    expect(
        rawExtraSegment(req('/tok/catalog/Live%20TV/xtremio_live/genre=24%2F7.json', 'genre=24/7'))
    ).toBe('genre=24%2F7');
});

test('parseYear pulls the first 4-digit run, or undefined', () => {
    expect(parseYear('2019-05-01')).toBe(2019);
    expect(parseYear('May 1998')).toBe(1998);
    expect(parseYear('no year here')).toBeUndefined();
    expect(parseYear('')).toBeUndefined();
    expect(parseYear(null)).toBeUndefined();
});

test('toIsoDate returns undefined rather than an Invalid Date', () => {
    expect(toIsoDate('2020-01-02')).toBe('2020-01-02T00:00:00.000Z');
    expect(toIsoDate('not a date')).toBeUndefined();
    expect(toIsoDate('')).toBeUndefined();
    expect(toIsoDate(null)).toBeUndefined();
});

test('splitList handles the string-or-array shapes providers return', () => {
    expect(splitList('a, b ,c')).toStrictEqual(['a', 'b', 'c']);
    expect(splitList(['a', ' b '])).toStrictEqual(['a', 'b']);
    expect(splitList('a,,b')).toStrictEqual(['a', 'b']);
    expect(splitList('')).toStrictEqual([]);
    expect(splitList(null)).toStrictEqual([]);
});

test('pickBackdrop takes the first entry of an array form', () => {
    expect(pickBackdrop(['http://a', 'http://b'])).toBe('http://a');
    expect(pickBackdrop('http://a')).toBe('http://a');
    expect(pickBackdrop([])).toBeUndefined();
    expect(pickBackdrop(null)).toBeUndefined();
});

test('isUsableSeriesInfo accepts partial payloads but rejects empty ones', () => {
    expect(isUsableSeriesInfo({ info: { name: 'Show' } })).toBeTruthy();
    expect(isUsableSeriesInfo({ episodes: { 1: [{ id: '1' }] } })).toBeTruthy();
    expect(isUsableSeriesInfo({ info: {}, episodes: {} })).toBeFalsy();
    expect(isUsableSeriesInfo({})).toBeFalsy();
    expect(isUsableSeriesInfo(null)).toBeFalsy();
    expect(isUsableSeriesInfo('string')).toBeFalsy();
});
